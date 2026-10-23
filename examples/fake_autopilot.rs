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
    COMMAND_ACK_DATA, HEARTBEAT_DATA, MavAutopilot, MavMessage, MavModeFlag, MavResult, MavState,
    MavType,
};
use mavlink::{MavConnection, MavHeader, SigningConfig};

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
    if let Some(key) = state_file
        .as_ref()
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
    {
        conn.setup_signing(Some(SigningConfig::new(key, 0, true, false)));
        has_key = true;
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
                let ack = MavMessage::COMMAND_ACK(COMMAND_ACK_DATA {
                    command: c.command,
                    result: MavResult::MAV_RESULT_ACCEPTED,
                });
                conn.send(&me, &ack)?;
            }
            _ => {}
        }
    }
}
