//! A stand-in autopilot for testing `oasa-pair` without PX4 or ArduPilot.
//!
//! Test tool only. It copies PX4's signing rules:
//! - With no key, it accepts the first SETUP_SIGNING (even unsigned).
//! - Once it has a key, it only accepts signed messages, including any
//!   SETUP_SIGNING that changes the key.
//! - It answers signed COMMAND_LONG with a signed COMMAND_ACK.
//!
//! Usage: cargo run --example fake_autopilot -- udpin:127.0.0.1:14540

use mavlink::dialects::common::{COMMAND_ACK_DATA, MavMessage, MavResult};
use mavlink::{MavConnection, MavHeader, SigningConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "udpin:127.0.0.1:14540".into());
    let mut conn = mavlink::connect::<MavMessage>(&addr)?;
    conn.set_protocol_version(mavlink::MavlinkVersion::V2);
    let me = MavHeader {
        system_id: 1,
        component_id: 1,
        sequence: 0,
    };
    let mut has_key = false;
    println!("fake autopilot listening on {addr} (no signing key yet)");

    loop {
        let (hdr, msg) = match conn.recv() {
            Ok(m) => m,
            Err(e) => {
                // Unsigned or badly signed messages are dropped by the
                // library once signing is on; other errors we just report.
                eprintln!("dropped: {e}");
                continue;
            }
        };
        match msg {
            MavMessage::SETUP_SIGNING(s) if s.target_system == me.system_id => {
                if s.secret_key == [0u8; 32] {
                    conn.setup_signing(None);
                    has_key = false;
                    println!("signing disabled by {}:{}", hdr.system_id, hdr.component_id);
                } else {
                    conn.setup_signing(Some(SigningConfig::new(s.secret_key, 0, true, false)));
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
