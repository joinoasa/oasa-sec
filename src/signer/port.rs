//! The real autopilot link: MAVLink 2 over UDP or TCP (`udpout:HOST:PORT`
//! or `tcpout:HOST:PORT`).
//!
//! It reads raw frames and checks signatures itself, because the signer must
//! see frames signed by either of two keys (and unsigned ones), and it signs
//! what it sends itself, because it must choose the key and the timestamp
//! (the library signs with one configured key and its own clock).
//!
//! The link survives what an autopilot link meets in the field:
//! - **UDP** uses a socket bound to the local address on the route to the
//!   autopilot and connected to the autopilot's address, so the kernel drops
//!   datagrams from anyone else. An empty datagram, or an ICMP "port
//!   unreachable" while the autopilot restarts, is not the end of the link.
//! - **TCP**: an autopilot that closes the connection (a reboot) or a write
//!   that fails drops the link; the next call reconnects, with backoff (0.5 s,
//!   doubling to 10 s). Until then calls fail, so the signer's next round
//!   starts with the probe, as after any I/O error.
//!
//! Listening modes (`udpin:`, `tcpin:`) are refused: the library answers
//! whoever spoke last, so anyone who can reach the port would be sent the
//! next `SETUP_SIGNING`, which carries the new key.

use std::io::{self, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::time::{Duration, Instant};

use mavlink::dialects::common::MavMessage;
use mavlink::error::MessageReadError;
use mavlink::{
    MAVLinkMessageRaw, MAVLinkV2MessageRaw, MavHeader, MavlinkReader, MavlinkVersion, Message,
    consts,
};

use zeroize::Zeroize;

use super::{Inbound, Port, Sig};
use crate::signing::{SigningKey, mavlink_timestamp_now};
use crate::{Error, Result};

const COMMAND_ACK_ID: u32 = 77;

/// How often a reader thread wakes to see whether its link was dropped.
const POLL: Duration = Duration::from_millis(200);
/// How long a TCP connect or a blocked write may take.
const TCP_TIMEOUT: Duration = Duration::from_secs(3);
/// Reconnect backoff.
pub const BACKOFF_MIN: Duration = Duration::from_millis(500);
pub const BACKOFF_MAX: Duration = Duration::from_secs(10);

fn io(e: impl std::fmt::Display) -> Error {
    Error::Io(std::io::Error::other(e.to_string()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Udp,
    Tcp,
}

/// Where the autopilot is.
#[derive(Clone, Debug)]
struct Target {
    kind: Kind,
    /// `HOST:PORT`, resolved again at every connect.
    address: String,
}

impl Target {
    fn parse(address: &str) -> Result<Self> {
        let (kind, rest) = if let Some(r) = address.strip_prefix("udpout:") {
            (Kind::Udp, r)
        } else if let Some(r) = address.strip_prefix("tcpout:") {
            (Kind::Tcp, r)
        } else {
            return Err(Error::Link(
                "the signer's autopilot link must be udpout:HOST:PORT or tcpout:HOST:PORT \
                 (a listening link would send the new key to whoever spoke last)",
            ));
        };
        if rest.is_empty() {
            return Err(Error::Link("no autopilot address"));
        }
        Ok(Self {
            kind,
            address: rest.to_string(),
        })
    }

    fn resolve(&self) -> io::Result<SocketAddr> {
        self.address
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::new(ErrorKind::AddrNotAvailable, "no address"))
    }

    fn open(&self) -> io::Result<Live> {
        let addr = self.resolve()?;
        let (tx, rx) = mpsc::channel();
        let closed = Arc::new(AtomicBool::new(false));
        let writer = match self.kind {
            Kind::Udp => {
                // Bind to the local address the route to the autopilot uses,
                // then connect: only the autopilot's datagrams arrive.
                let local = {
                    let probe = UdpSocket::bind(unspecified(&addr))?;
                    probe.connect(addr)?;
                    probe.local_addr()?.ip()
                };
                let s = UdpSocket::bind(SocketAddr::new(local, 0))?;
                s.connect(addr)?;
                s.set_read_timeout(Some(POLL))?;
                spawn_reader(
                    MavlinkReader::with_capacity(1 << 17, Datagrams(s.try_clone()?)),
                    tx,
                    closed.clone(),
                );
                Writer::Udp(s)
            }
            Kind::Tcp => {
                let s = TcpStream::connect_timeout(&addr, TCP_TIMEOUT)?;
                s.set_nodelay(true)?;
                s.set_read_timeout(Some(POLL))?;
                s.set_write_timeout(Some(TCP_TIMEOUT))?;
                spawn_reader(MavlinkReader::new(s.try_clone()?), tx, closed.clone());
                Writer::Tcp(s)
            }
        };
        Ok(Live { writer, rx, closed })
    }
}

fn unspecified(addr: &SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(_) => SocketAddr::from(([0u8; 4], 0)),
        SocketAddr::V6(_) => SocketAddr::from(([0u16; 8], 0)),
    }
}

/// A connected UDP socket read as a stream of datagrams. UDP has no end of
/// stream: an empty datagram (which the reader would take for one) and an
/// ICMP error from an earlier send (the autopilot not listening for a
/// moment) are skipped.
struct Datagrams(UdpSocket);

impl Read for Datagrams {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.0.recv(buf) {
                Ok(0) => continue,
                Err(e) if e.kind() == ErrorKind::ConnectionRefused => continue,
                r => return r,
            }
        }
    }
}

/// Read frames until the link ends (EOF or a hard error) or is dropped.
fn spawn_reader<R: Read + Send + 'static>(
    mut reader: MavlinkReader<R>,
    tx: Sender<MAVLinkV2MessageRaw>,
    closed: Arc<AtomicBool>,
) {
    std::thread::spawn(move || {
        while !closed.load(Ordering::Relaxed) {
            match reader.read_raw_message::<MavMessage>(MavlinkVersion::V2) {
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
                // EOF (the autopilot closed a TCP link) or a dead socket.
                Err(MessageReadError::Io(_)) => return,
                // A frame we cannot read: skip it.
                Err(_) => {}
            }
        }
    });
}

enum Writer {
    Udp(UdpSocket),
    Tcp(TcpStream),
}

/// One open connection and its reader thread.
struct Live {
    writer: Writer,
    rx: Receiver<MAVLinkV2MessageRaw>,
    closed: Arc<AtomicBool>,
}

impl Drop for Live {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Relaxed);
        if let Writer::Tcp(s) = &self.writer {
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
    }
}

pub struct AutopilotPort {
    target: Target,
    live: Option<Live>,
    start: Instant,
    header: MavHeader,
    link_id: u8,
    last_ts: u64,
    /// No reconnect before this.
    retry_at: Instant,
    backoff: Duration,
    /// Set when a lost link came back; read with [`Self::take_reconnected`].
    reconnected: bool,
}

impl AutopilotPort {
    /// Connect. `sys` is the autopilot's system id; we speak as its onboard
    /// computer (component 191) on signing link id `link_id`. The first
    /// connect must work; later losses are reconnected.
    pub fn connect(address: &str, sys: u8, link_id: u8) -> Result<Self> {
        let target = Target::parse(address)?;
        let live = target.open()?;
        Ok(Self {
            target,
            live: Some(live),
            start: Instant::now(),
            header: MavHeader {
                system_id: sys.into(), // always <= 255, so frames keep the 1-byte system id
                component_id: super::SIGNER_COMP, // MAV_COMP_ID_ONBOARD_COMPUTER
                sequence: 0,
            },
            link_id,
            last_ts: 0,
            retry_at: Instant::now(),
            backoff: BACKOFF_MIN,
            reconnected: false,
        })
    }

    /// True once after a lost link was connected again.
    pub fn take_reconnected(&mut self) -> bool {
        std::mem::take(&mut self.reconnected)
    }

    /// The open link, reconnecting if it was lost and the backoff has passed.
    fn live(&mut self) -> Result<&mut Live> {
        if self.live.is_none() {
            let now = Instant::now();
            if now < self.retry_at {
                return Err(io("autopilot link lost; reconnecting"));
            }
            match self.target.open() {
                Ok(l) => {
                    self.live = Some(l);
                    self.backoff = BACKOFF_MIN;
                    self.reconnected = true;
                }
                Err(e) => {
                    self.retry_at = now + self.backoff;
                    self.backoff = (self.backoff * 2).min(BACKOFF_MAX);
                    return Err(io(format!("autopilot link lost ({e}); reconnecting")));
                }
            }
        }
        self.live.as_mut().ok_or_else(|| io("autopilot link lost"))
    }

    /// Drop the link; the next call after the backoff reconnects.
    fn lost(&mut self, why: impl std::fmt::Display) -> Error {
        self.live = None;
        self.retry_at = Instant::now() + self.backoff;
        io(format!("autopilot link lost ({why}); reconnecting"))
    }
}

fn signature_ok(raw: &MAVLinkV2MessageRaw, key: &SigningKey) -> bool {
    let mut sig = [0u8; consts::v2::SIGNATURE_VALUE_SIZE];
    raw.calculate_signature(key.as_bytes(), &mut sig);
    // Not constant-time: the signature is public on the wire.
    sig == raw.signature_value()
}

impl Port for AutopilotPort {
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
                let ts = mavlink_timestamp_now()
                    .max(min_ts)
                    .max(self.last_ts.saturating_add(1));
                self.last_ts = ts;
                raw.signature_timestamp_bytes_mut()
                    .copy_from_slice(&ts.to_le_bytes()[..consts::v2::SIGNATURE_TIMESTAMP_SIZE]);
                *raw.signature_link_id_mut() = self.link_id;
                let mut sig = [0u8; consts::v2::SIGNATURE_VALUE_SIZE];
                raw.calculate_signature(k.as_bytes(), &mut sig);
                raw.signature_value_mut().copy_from_slice(&sig);
                ts
            }
        };
        let sent = match self.live() {
            Ok(live) => match &mut live.writer {
                Writer::Udp(s) => match s.send(raw.raw_bytes()) {
                    // The autopilot is not listening right now (an ICMP
                    // error from an earlier datagram): a lost datagram.
                    Err(e) if e.kind() == ErrorKind::ConnectionRefused => Ok(()),
                    r => r.map(|_| ()),
                },
                Writer::Tcp(s) => s.write_all(raw.raw_bytes()),
            },
            Err(e) => {
                raw.as_mut_slice().zeroize();
                return Err(e);
            }
        };
        // The frame may carry a signing key (SETUP_SIGNING): wipe our copy
        // once it is sent.
        raw.as_mut_slice().zeroize();
        match sent {
            Ok(()) => Ok(used),
            Err(e) => Err(self.lost(e)),
        }
    }

    fn recv(&mut self, wait: Duration, keys: &[&SigningKey]) -> Result<Option<Inbound>> {
        let raw = match self.live()?.rx.recv_timeout(wait) {
            Ok(r) => r,
            Err(RecvTimeoutError::Timeout) => return Ok(None),
            Err(RecvTimeoutError::Disconnected) => return Err(self.lost("closed")),
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

/// 32-bit system ids (from mavlink 0.21, #17). The socket tests are in `port/tests.rs`.
#[cfg(test)]
mod sysid32_tests {
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

#[cfg(test)]
mod tests;
