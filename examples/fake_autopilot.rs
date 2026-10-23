//! A stand-in autopilot for testing `oasa-pair` without PX4 or ArduPilot.
//!
//! Test tool only. It copies PX4's and ArduPilot's signing rules:
//! - With no key, it accepts the first SETUP_SIGNING (even unsigned).
//! - Once it has a key, it only accepts signed messages, including any
//!   SETUP_SIGNING that changes the key, and it signs what it sends.
//! - It answers signed COMMAND_LONG with a signed COMMAND_ACK.
//! - It sends a HEARTBEAT once a second, with the armed flag.
//!
//! Switches, so a script can break it on purpose (a file's presence is the switch):
//! - `--armed-file F`: armed while F exists; it refuses SETUP_SIGNING then.
//! - `--silent-file F`: sends and answers nothing while F exists.
//! - `--drop-acks-file F`: takes commands but sends no COMMAND_ACK while F exists.
//! - `--ignore-setup-file F`: ignores SETUP_SIGNING (keeps its key) while F exists.
//! - `--state-file F`: keeps the signing key in F (like autopilot storage), so a
//!   restart keeps it. Without it, a restart forgets the key.
//!
//! Usage: cargo run --example fake_autopilot -- udpin:127.0.0.1:14540 [switches]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use mavlink::dialects::common::{
    HEARTBEAT_DATA, MavAutopilot, MavMessage, MavModeFlag, MavState, MavType,
};
use mavlink::{
    MAVLinkMessageRaw, MAVLinkV2MessageRaw, MavConnection, MavHeader, Message, SigningConfig,
    consts,
};

/// A signed (or, with no key, unsigned) `COMMAND_ACK` that names who it
/// answers, as real autopilots do. The library's message type has no
/// extension fields, so the frame is built by hand.
fn ack_frame(
    me: MavHeader,
    command: u16,
    to: (u8, u8),
    key: Option<[u8; 32]>,
    ts: u64,
) -> MAVLinkV2MessageRaw {
    let mut raw = MAVLinkV2MessageRaw::new();
    let buf = raw.as_mut_slice();
    buf.fill(0);
    let mut payload = [0u8; 10];
    payload[..2].copy_from_slice(&command.to_le_bytes());
    // result 0 = ACCEPTED; progress, result_param2 stay 0.
    payload[8] = to.0;
    payload[9] = to.1;
    buf[0] = 0xFD;
    buf[1] = 10;
    buf[2] = if key.is_some() { 1 } else { 0 }; // IFLAG_SIGNED
    buf[4] = me.sequence;
    buf[5] = me.system_id;
    buf[6] = me.component_id;
    buf[7..10].copy_from_slice(&77u32.to_le_bytes()[..3]);
    buf[10..20].copy_from_slice(&payload);
    let extra = <MavMessage as Message>::extra_crc(77);
    let crc = mavlink::calculate_crc(&buf[1..20], extra);
    buf[20..22].copy_from_slice(&crc.to_le_bytes());
    if let Some(k) = key {
        raw.signature_link_id_mut().clone_from(&0);
        raw.signature_timestamp_bytes_mut()
            .copy_from_slice(&ts.to_le_bytes()[..consts::v2::SIGNATURE_TIMESTAMP_SIZE]);
        let mut sig = [0u8; consts::v2::SIGNATURE_VALUE_SIZE];
        raw.calculate_signature(&k, &mut sig);
        raw.signature_value_mut().copy_from_slice(&sig);
    }
    raw
}

/// MAVLink signature time: 10 microsecond units since 2015-01-01.
fn mavlink_ts_now() -> u64 {
    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_micros() as u64);
    (unix / 10).saturating_sub(1_420_070_400_000_000 / 10)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let addr = args
        .next()
        .unwrap_or_else(|| "udpin:127.0.0.1:14540".into());
    let mut armed_file = None::<PathBuf>;
    let mut silent_file = None::<PathBuf>;
    let mut drop_acks_file = None::<PathBuf>;
    let mut ignore_setup_file = None::<PathBuf>;
    let mut state_file = None::<PathBuf>;
    while let Some(a) = args.next() {
        let v = args.next().map(PathBuf::from);
        match a.as_str() {
            "--armed-file" => armed_file = v,
            "--silent-file" => silent_file = v,
            "--drop-acks-file" => drop_acks_file = v,
            "--ignore-setup-file" => ignore_setup_file = v,
            "--state-file" => state_file = v,
            other => return Err(format!("unknown switch {other}").into()),
        }
    }
    let on = |f: &Option<PathBuf>| f.as_ref().is_some_and(|p| p.exists());

    let mut conn = mavlink::connect::<MavMessage>(&addr)?;
    conn.set_protocol_version(mavlink::MavlinkVersion::V2);
    let me = MavHeader {
        system_id: 1,
        component_id: 1,
        sequence: 0,
    };
    let mut has_key = false;
    let mut key_bytes = None::<[u8; 32]>;
    let mut seq = 0u8;
    let mut last_ts = 0u64;
    if let Some(key) = state_file
        .as_ref()
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
    {
        conn.setup_signing(Some(SigningConfig::new(key, 0, true, false)));
        has_key = true;
        key_bytes = Some(key);
    }
    println!(
        "fake autopilot listening on {addr} ({} signing key yet)",
        if has_key { "has a" } else { "no" }
    );

    let mut next_heartbeat = Instant::now();
    loop {
        if on(&silent_file) {
            // Drain and ignore.
            let _ = conn.try_recv();
            std::thread::sleep(Duration::from_millis(20));
            continue;
        }
        if Instant::now() >= next_heartbeat {
            next_heartbeat = Instant::now() + Duration::from_secs(1);
            let hb = MavMessage::HEARTBEAT(HEARTBEAT_DATA {
                custom_mode: 0,
                mavtype: MavType::MAV_TYPE_QUADROTOR,
                autopilot: MavAutopilot::MAV_AUTOPILOT_PX4,
                base_mode: if on(&armed_file) {
                    MavModeFlag::MAV_MODE_FLAG_SAFETY_ARMED
                } else {
                    MavModeFlag::empty()
                },
                system_status: MavState::MAV_STATE_STANDBY,
                mavlink_version: 3,
            });
            let _ = conn.send(&me, &hb);
        }
        let (hdr, msg) = match conn.try_recv() {
            Ok(m) => m,
            Err(mavlink::error::MessageReadError::Io(_)) => {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(e) => {
                // Unsigned or badly signed messages are dropped by the
                // library once signing is on; other errors we just report.
                eprintln!("dropped: {e}");
                continue;
            }
        };
        match msg {
            MavMessage::SETUP_SIGNING(s) if s.target_system == me.system_id => {
                if on(&armed_file) {
                    println!("refused SETUP_SIGNING: armed");
                } else if on(&ignore_setup_file) {
                    println!("ignored SETUP_SIGNING");
                } else if s.secret_key == [0u8; 32] {
                    conn.setup_signing(None);
                    has_key = false;
                    key_bytes = None;
                    if let Some(p) = &state_file {
                        let _ = std::fs::remove_file(p);
                    }
                    println!("signing disabled by {}:{}", hdr.system_id, hdr.component_id);
                } else {
                    conn.setup_signing(Some(SigningConfig::new(s.secret_key, 0, true, false)));
                    if let Some(p) = &state_file {
                        let _ = std::fs::write(p, s.secret_key);
                    }
                    println!(
                        "signing key {} from {}:{}; signed messages only from now on",
                        if has_key { "changed" } else { "set" },
                        hdr.system_id,
                        hdr.component_id
                    );
                    has_key = true;
                    key_bytes = Some(s.secret_key);
                }
            }
            MavMessage::COMMAND_LONG(c) if c.target_system == me.system_id => {
                println!(
                    "accepted {:?} from {}:{} (signed: {has_key})",
                    c.command, hdr.system_id, hdr.component_id
                );
                if on(&drop_acks_file) {
                    println!("dropping the COMMAND_ACK");
                    continue;
                }
                seq = seq.wrapping_add(1);
                last_ts = mavlink_ts_now().max(last_ts + 1);
                let raw = ack_frame(
                    MavHeader {
                        sequence: seq,
                        ..me
                    },
                    c.command as u16,
                    (hdr.system_id, hdr.component_id),
                    key_bytes,
                    last_ts,
                );
                conn.send_raw(&MAVLinkMessageRaw::V2(raw))?;
            }
            _ => {}
        }
    }
}
