//! The real autopilot link: a MAVLink 2 connection over UDP or TCP
//! (`udpout:`, `udpin:`, `tcpout:` ...).
//!
//! It reads raw frames and checks signatures itself, because the signer must
//! see frames signed by either of two keys (and unsigned ones), and it signs
//! what it sends itself, because it must choose the key and the timestamp
//! (the library signs with one configured key and its own clock).

use std::io::ErrorKind;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mavlink::dialects::common::MavMessage;
use mavlink::error::MessageReadError;
use mavlink::{
    MAVLinkMessageRaw, MAVLinkV2MessageRaw, MavConnection, MavHeader, MavlinkVersion, Message,
    consts,
};

use zeroize::Zeroize;

use super::{Inbound, Port, Sig};
use crate::signing::{SigningKey, mavlink_timestamp_now};
use crate::{Error, Result};

const COMMAND_ACK_ID: u32 = 77;

type Conn = mavlink::Connection<MavMessage>;

pub struct UdpPort {
    conn: Arc<Conn>,
    rx: Receiver<MAVLinkV2MessageRaw>,
    start: Instant,
    header: MavHeader,
    link_id: u8,
    last_ts: Mutex<u64>,
}

fn io(e: impl std::fmt::Display) -> Error {
    Error::Io(std::io::Error::other(e.to_string()))
}

impl UdpPort {
    /// Connect. `sys` is the autopilot's system id; we speak as its onboard
    /// computer (component 191) on signing link id `link_id`.
    pub fn connect(address: &str, sys: u8, link_id: u8) -> Result<Self> {
        let mut conn = mavlink::connect::<MavMessage>(address)?;
        conn.set_protocol_version(MavlinkVersion::V2);
        // No signing set up: every frame arrives, and we check them ourselves.
        let conn = Arc::new(conn);
        let (tx, rx) = mpsc::channel();
        let reader = conn.clone();
        std::thread::spawn(move || {
            loop {
                match reader.recv_raw() {
                    Ok(MAVLinkMessageRaw::V2(m)) => {
                        if tx.send(m).is_err() {
                            return;
                        }
                    }
                    Ok(MAVLinkMessageRaw::V1(_)) => {}
                    Err(MessageReadError::Io(e))
                        if matches!(
                            e.kind(),
                            ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                        ) => {}
                    Err(_) => return,
                }
            }
        });
        Ok(Self {
            conn,
            rx,
            start: Instant::now(),
            header: MavHeader {
                system_id: sys.into(), // always <= 255, so frames keep the 1-byte system id
                component_id: super::SIGNER_COMP, // MAV_COMP_ID_ONBOARD_COMPUTER
                sequence: 0,
            },
            link_id,
            last_ts: Mutex::new(0),
        })
    }
}

fn signature_ok(raw: &MAVLinkV2MessageRaw, key: &SigningKey) -> bool {
    let mut sig = [0u8; consts::v2::SIGNATURE_VALUE_SIZE];
    raw.calculate_signature(key.as_bytes(), &mut sig);
    // Not constant-time: the signature is public on the wire.
    sig == raw.signature_value()
}

impl Port for UdpPort {
    fn now(&mut self) -> Duration {
        self.start.elapsed()
    }

    fn send(&mut self, key: Option<&SigningKey>, msg: &MavMessage, min_ts: u64) -> Result<u64> {
        let mut raw = MAVLinkV2MessageRaw::new();
        self.header.sequence = self.header.sequence.wrapping_add(1);
        let header = self.header;
        let used = match key {
            None => {
                raw.serialize_message(header, msg);
                0
            }
            Some(k) => {
                raw.serialize_message_for_signing(header, msg);
                let mut last = self.last_ts.lock().map_err(|_| io("lock poisoned"))?;
                let ts = mavlink_timestamp_now()
                    .max(min_ts)
                    .max(last.saturating_add(1));
                *last = ts;
                raw.signature_timestamp_bytes_mut()
                    .copy_from_slice(&ts.to_le_bytes()[..consts::v2::SIGNATURE_TIMESTAMP_SIZE]);
                *raw.signature_link_id_mut() = self.link_id;
                let mut sig = [0u8; consts::v2::SIGNATURE_VALUE_SIZE];
                raw.calculate_signature(k.as_bytes(), &mut sig);
                raw.signature_value_mut().copy_from_slice(&sig);
                ts
            }
        };
        // The frame may carry a signing key (SETUP_SIGNING): wipe our copy
        // once it is sent.
        let raw = MAVLinkMessageRaw::V2(raw);
        let sent = self.conn.send_raw(&raw);
        if let MAVLinkMessageRaw::V2(mut r) = raw {
            r.as_mut_slice().zeroize();
        }
        sent.map_err(io)?;
        Ok(used)
    }

    fn recv(&mut self, wait: Duration, keys: &[&SigningKey]) -> Result<Option<Inbound>> {
        let raw = match self.rx.recv_timeout(wait) {
            Ok(r) => r,
            Err(RecvTimeoutError::Timeout) => return Ok(None),
            Err(RecvTimeoutError::Disconnected) => return Err(io("autopilot link closed")),
        };
        Ok(inbound(&raw, keys))
    }
}

/// A received frame as the signer sees it: the parsed message, the header
/// (a `system_id` above 255 comes from an `IFLAG_SYSID32` frame) and which of
/// `keys`, if any, its signature verifies under. `None` if it does not parse.
fn inbound(raw: &MAVLinkV2MessageRaw, keys: &[&SigningKey]) -> Option<Inbound> {
    let Ok(msg) = MavMessage::parse(MavlinkVersion::V2, raw.message_id(), raw.payload()) else {
        return None;
    };
    let sig = (raw.incompatibility_flags() & consts::v2::IFLAG_SIGNED != 0).then(|| Sig {
        timestamp: raw.signature_timestamp(),
        verified_by: keys.iter().position(|k| signature_ok(raw, k)),
    });
    // `MavMessage` has no extension fields, so read a COMMAND_ACK's
    // target_system and target_component (bytes 8 and 9; a MAVLink 2
    // payload drops trailing zeros) from the raw payload.
    let ack_target = (raw.message_id() == COMMAND_ACK_ID).then(|| {
        let p = raw.payload();
        (
            p.get(8).copied().unwrap_or(0),
            p.get(9).copied().unwrap_or(0),
        )
    });
    Some(Inbound {
        header: MavHeader {
            system_id: raw.system_id(),
            component_id: raw.component_id(),
            sequence: raw.sequence(),
        },
        msg,
        sig,
        ack_target,
    })
}

#[cfg(test)]
mod tests {
    use mavlink::dialects::common::{COMMAND_ACK_DATA, MavCmd, MavResult};

    use super::*;

    /// A frame signed under `key`, as an autopilot would send it. A system id
    /// above 255 makes the crate write an `IFLAG_SYSID32` frame.
    fn signed(sys: u32, key: &SigningKey) -> MAVLinkV2MessageRaw {
        let msg = MavMessage::COMMAND_ACK(COMMAND_ACK_DATA {
            command: MavCmd::MAV_CMD_REQUEST_MESSAGE,
            result: MavResult::MAV_RESULT_ACCEPTED,
        });
        let header = MavHeader {
            system_id: sys,
            component_id: 1,
            sequence: 7,
        };
        let mut raw = MAVLinkV2MessageRaw::new();
        raw.serialize_message_for_signing(header, &msg);
        raw.signature_timestamp_bytes_mut()
            .copy_from_slice(&5_000u64.to_le_bytes()[..consts::v2::SIGNATURE_TIMESTAMP_SIZE]);
        let mut sig = [0u8; consts::v2::SIGNATURE_VALUE_SIZE];
        raw.calculate_signature(key.as_bytes(), &mut sig);
        raw.signature_value_mut().copy_from_slice(&sig);
        raw
    }

    #[test]
    fn a_32_bit_system_id_frame_is_read_with_its_full_id() {
        let key = SigningKey::generate().unwrap();
        let other = SigningKey::generate().unwrap();
        let wide = signed(0x101, &key);
        let narrow = signed(1, &key);
        assert_ne!(wide.incompatibility_flags() & consts::v2::IFLAG_SYSID32, 0);
        assert_eq!(
            narrow.incompatibility_flags() & consts::v2::IFLAG_SYSID32,
            0
        );

        let w = inbound(&wide, &[&other, &key]).unwrap();
        let n = inbound(&narrow, &[&other, &key]).unwrap();
        assert_eq!(w.header.system_id, 0x101, "the full id, not its low byte");
        assert_eq!(n.header.system_id, 1);
        // Everything after the longer header is read from the right place.
        assert_eq!(wide.payload(), narrow.payload());
        assert_eq!((w.header.component_id, w.header.sequence), (1, 7));
        assert_eq!(w.msg, n.msg);
        assert_eq!(w.ack_target, n.ack_target);
        // Signatures verify under the key that made them, and only that one.
        assert_eq!(w.sig.unwrap().verified_by, Some(1));
        assert_eq!(w.sig.unwrap().timestamp, 5_000);
        assert_eq!(
            inbound(&wide, &[&other]).unwrap().sig.unwrap().verified_by,
            None
        );
    }

    #[test]
    fn a_32_bit_frame_read_as_a_normal_one_does_not_verify() {
        // The flag byte is inside the signature, so a frame cannot be passed
        // off as the other layout and still verify.
        let key = SigningKey::generate().unwrap();
        let mut raw = signed(0x101, &key);
        *raw.incompatibility_flags_mut() &= !consts::v2::IFLAG_SYSID32;
        let verified = inbound(&raw, &[&key]).and_then(|f| f.sig?.verified_by);
        assert_eq!(verified, None);
    }
}
