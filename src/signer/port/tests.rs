//! The real autopilot link over real sockets (review R-SEC2 M1 and L1).

use std::net::{TcpListener, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mavlink::dialects::common::{
    HEARTBEAT_DATA, MavAutopilot, MavCmd, MavModeFlag, MavState, MavType,
};
use mavlink::{MAVLinkMessageRaw, MAVLinkV2MessageRaw, MavHeader, MavlinkReader, Message, consts};

use super::*;
use crate::files::tempdir;
use crate::rotation;
use crate::signer::{Config, Event, Signer};
use crate::signing::AUTOPILOT_KEY_FILE;

const AP: MavHeader = MavHeader {
    system_id: 1,
    component_id: 1,
    sequence: 0,
};

fn heartbeat() -> MavMessage {
    MavMessage::HEARTBEAT(HEARTBEAT_DATA {
        custom_mode: 0,
        mavtype: MavType::MAV_TYPE_QUADROTOR,
        autopilot: MavAutopilot::MAV_AUTOPILOT_PX4,
        base_mode: MavModeFlag::empty(),
        system_status: MavState::MAV_STATE_STANDBY,
        mavlink_version: 3,
    })
}

/// A heartbeat frame from the autopilot, with this sequence number, signed
/// with `key` if given.
fn frame(seq: u8, key: Option<&[u8; 32]>, ts: u64) -> Vec<u8> {
    let h = MavHeader {
        sequence: seq,
        ..AP
    };
    let mut raw = MAVLinkV2MessageRaw::new();
    match key {
        None => raw.serialize_message(h, &heartbeat()),
        Some(k) => {
            raw.serialize_message_for_signing(h, &heartbeat());
            sign(&mut raw, k, ts);
        }
    }
    raw.raw_bytes().to_vec()
}

fn sign(raw: &mut MAVLinkV2MessageRaw, k: &[u8; 32], ts: u64) {
    raw.signature_timestamp_bytes_mut()
        .copy_from_slice(&ts.to_le_bytes()[..consts::v2::SIGNATURE_TIMESTAMP_SIZE]);
    *raw.signature_link_id_mut() = 0;
    let mut sig = [0u8; consts::v2::SIGNATURE_VALUE_SIZE];
    raw.calculate_signature(k, &mut sig);
    raw.signature_value_mut().copy_from_slice(&sig);
}

/// Wait up to `limit` for a frame, going through errors (a lost link).
fn next_frame(p: &mut AutopilotPort, limit: Duration) -> Option<Inbound> {
    let end = Instant::now() + limit;
    while Instant::now() < end {
        match p.recv(Duration::from_millis(100), &[]) {
            Ok(Some(f)) => return Some(f),
            Ok(None) => {}
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    None
}

#[test]
fn listening_addresses_are_refused() {
    for a in [
        "udpin:127.0.0.1:14550",
        "tcpin:127.0.0.1:5760",
        "udpbcast:127.0.0.1:1",
        "serial:/dev/ttyS0:57600",
        "udpout:",
        "127.0.0.1:14550",
    ] {
        assert!(AutopilotPort::connect(a, 1, 0).is_err(), "{a}");
    }
}

#[test]
fn an_empty_datagram_does_not_stop_the_link_and_strangers_are_not_heard() {
    let ap = UdpSocket::bind("127.0.0.1:0").unwrap();
    ap.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut p =
        AutopilotPort::connect(&format!("udpout:{}", ap.local_addr().unwrap()), 1, 0).unwrap();
    // The signer speaks first; the autopilot learns its address.
    p.send(None, &heartbeat(), 0).unwrap();
    let mut buf = [0u8; 300];
    let (_, signer) = ap.recv_from(&mut buf).unwrap();
    // Empty datagrams: from the autopilot's own address and from a stranger.
    ap.send_to(&[], signer).unwrap();
    let stranger = UdpSocket::bind("127.0.0.1:0").unwrap();
    stranger.send_to(&[], signer).unwrap();
    // A stranger's frame (that looks like the autopilot's) is not heard.
    stranger.send_to(&frame(99, None, 0), signer).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    ap.send_to(&frame(5, None, 0), signer).unwrap();
    let f = p
        .recv(Duration::from_secs(2), &[])
        .expect("the link must survive an empty datagram")
        .expect("the autopilot's frame");
    assert_eq!(f.header.sequence, 5);
    assert!(p.recv(Duration::from_millis(300), &[]).unwrap().is_none());
    // And it still works both ways.
    p.send(None, &heartbeat(), 0).unwrap();
    ap.recv_from(&mut buf).unwrap();
    ap.send_to(&frame(6, None, 0), signer).unwrap();
    let f = p.recv(Duration::from_secs(2), &[]).unwrap().unwrap();
    assert_eq!(f.header.sequence, 6);
}

#[test]
fn a_udp_autopilot_that_is_not_listening_for_a_moment_does_not_stop_the_link() {
    let ap = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = ap.local_addr().unwrap();
    let mut p = AutopilotPort::connect(&format!("udpout:{addr}"), 1, 0).unwrap();
    // The autopilot restarts: nothing listens on its port, the kernel answers
    // "port unreachable".
    drop(ap);
    for _ in 0..3 {
        p.send(None, &heartbeat(), 0).unwrap();
        assert!(p.recv(Duration::from_millis(100), &[]).unwrap().is_none());
    }
    let ap = UdpSocket::bind(addr).unwrap();
    ap.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    p.send(None, &heartbeat(), 0).unwrap();
    let mut buf = [0u8; 300];
    let (_, signer) = ap.recv_from(&mut buf).unwrap();
    ap.send_to(&frame(8, None, 0), signer).unwrap();
    let f = p.recv(Duration::from_secs(2), &[]).unwrap().unwrap();
    assert_eq!(f.header.sequence, 8);
}

#[test]
fn a_tcp_autopilot_that_closes_and_comes_back_is_reconnected() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let mut p = AutopilotPort::connect(&format!("tcpout:{addr}"), 1, 0).unwrap();
    let (mut c, _) = l.accept().unwrap();
    c.write_all(&frame(1, None, 0)).unwrap();
    assert_eq!(
        next_frame(&mut p, Duration::from_secs(2))
            .unwrap()
            .header
            .sequence,
        1
    );
    // The autopilot reboots: the connection closes and, for a moment, nothing
    // listens.
    drop(c);
    drop(l);
    assert!(
        p.recv(Duration::from_secs(2), &[]).is_err(),
        "a closed link is reported"
    );
    assert!(p.send(None, &heartbeat(), 0).is_err(), "still down");
    std::thread::sleep(Duration::from_millis(700));
    let l = TcpListener::bind(addr).unwrap();
    let back = std::thread::spawn(move || {
        let (mut c, _) = l.accept().unwrap();
        for seq in 2..40u8 {
            if c.write_all(&frame(seq, None, 0)).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    });
    let f = next_frame(&mut p, Duration::from_secs(15)).expect("reconnected");
    assert!(f.header.sequence >= 2);
    assert!(p.take_reconnected());
    assert!(!p.take_reconnected());
    p.send(None, &heartbeat(), 0).unwrap();
    back.join().unwrap();
}

// ---- a rotation against a TCP autopilot that reboots -------------------------

/// A minimal keyed autopilot on a TCP port, as ArduPilot on `tcp:`: it signs
/// its heartbeats, takes a `SETUP_SIGNING` signed with its key, and answers a
/// signed `MAV_CMD_REQUEST_MESSAGE` with a signed `COMMAND_ACK` naming the
/// sender. Its key survives reboots (`eeprom.bin`).
struct Ap {
    key: [u8; 32],
    /// Close the connection right after taking a new key (a reboot).
    reboot_after_setup: bool,
    connections: u32,
    setups: u32,
}

fn verifies(raw: &MAVLinkV2MessageRaw, key: &[u8; 32]) -> bool {
    if raw.incompatibility_flags() & consts::v2::IFLAG_SIGNED == 0 {
        return false;
    }
    let mut sig = [0u8; consts::v2::SIGNATURE_VALUE_SIZE];
    raw.calculate_signature(key, &mut sig);
    sig == raw.signature_value()
}

fn ack(seq: u8, to: (u8, u8), key: &[u8; 32], ts: u64) -> Vec<u8> {
    // COMMAND_ACK with its extension fields target_system and
    // target_component, built by hand (the library's type lacks them).
    let mut raw = MAVLinkV2MessageRaw::new();
    let buf = raw.as_mut_slice();
    buf.fill(0);
    buf[0] = 0xFD;
    buf[1] = 10;
    buf[2] = consts::v2::IFLAG_SIGNED;
    buf[4] = seq;
    buf[5] = u8::try_from(AP.system_id).expect("the test autopilot's id fits a byte");
    buf[6] = AP.component_id;
    buf[7..10].copy_from_slice(&77u32.to_le_bytes()[..3]);
    buf[10..12].copy_from_slice(&(MavCmd::MAV_CMD_REQUEST_MESSAGE as u16).to_le_bytes());
    buf[18] = to.0;
    buf[19] = to.1;
    let crc = mavlink::calculate_crc(&buf[1..20], MavMessage::extra_crc(77));
    buf[20..22].copy_from_slice(&crc.to_le_bytes());
    sign(&mut raw, key, ts);
    raw.raw_bytes().to_vec()
}

fn serve(l: TcpListener, ap: Arc<Mutex<Ap>>) {
    let mut ts = crate::signing::mavlink_timestamp_now();
    loop {
        let Ok((c, _)) = l.accept() else { return };
        ap.lock().unwrap().connections += 1;
        c.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        let mut out = c.try_clone().unwrap();
        let mut r = MavlinkReader::new(c);
        let mut seq = 0u8;
        let mut next_hb = Instant::now();
        'conn: loop {
            let key = ap.lock().unwrap().key;
            if Instant::now() >= next_hb {
                next_hb = Instant::now() + Duration::from_millis(250);
                seq = seq.wrapping_add(1);
                ts += 1;
                if out.write_all(&frame(seq, Some(&key), ts)).is_err() {
                    break 'conn;
                }
            }
            let raw = match r.read_raw_message::<MavMessage>(mavlink::MavlinkVersion::V2) {
                Ok(MAVLinkMessageRaw::V2(raw)) => raw,
                Ok(_) => continue,
                Err(mavlink::error::MessageReadError::Io(e))
                    if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                {
                    continue;
                }
                Err(_) => break 'conn,
            };
            if !verifies(&raw, &key) {
                continue;
            }
            match MavMessage::parse(mavlink::MavlinkVersion::V2, raw.message_id(), raw.payload()) {
                Ok(MavMessage::SETUP_SIGNING(s)) => {
                    let mut a = ap.lock().unwrap();
                    a.key = s.secret_key;
                    a.setups += 1;
                    if a.reboot_after_setup {
                        a.reboot_after_setup = false;
                        break 'conn;
                    }
                }
                Ok(MavMessage::COMMAND_LONG(c)) if c.command == MavCmd::MAV_CMD_REQUEST_MESSAGE => {
                    seq = seq.wrapping_add(1);
                    ts += 1;
                    // Answer only 8-bit senders, as the stand-in autopilot does (a
                    // 32-bit id is never narrowed to its low byte).
                    let Ok(sys) = u8::try_from(raw.system_id()) else {
                        continue;
                    };
                    let to = (sys, raw.component_id());
                    if out.write_all(&ack(seq, to, &key, ts)).is_err() {
                        break 'conn;
                    }
                }
                _ => {}
            }
        }
        // Rebooting: closed, and refusing connections for a moment.
        let _ = out.shutdown(std::net::Shutdown::Both);
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Run signer rounds until `done` says so or 60 s pass; errors (a lost link)
/// are waited out as `oasa-pair signer` does, only faster.
fn run_until(
    s: &mut Signer<AutopilotPort>,
    mut done: impl FnMut(&[Event]) -> bool,
) -> (Vec<Event>, usize) {
    let end = Instant::now() + Duration::from_secs(60);
    let mut all = Vec::new();
    let mut errors = 0;
    while Instant::now() < end {
        match s.tick() {
            Ok(ev) => {
                all.extend(ev);
                if done(&all) {
                    return (all, errors);
                }
            }
            Err(_) => {
                errors += 1;
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
    panic!("no result in 60 s: {all:?}, {errors} errors");
}

#[test]
fn a_rotation_completes_across_a_tcp_autopilot_reboot() {
    let dir = tempdir("port-reboot");
    let old = SigningKey::generate().unwrap();
    old.save(&dir.join(AUTOPILOT_KEY_FILE)).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let ap = Arc::new(Mutex::new(Ap {
        key: *old.as_bytes(),
        reboot_after_setup: false,
        connections: 0,
        setups: 0,
    }));
    let a = ap.clone();
    std::thread::spawn(move || serve(l, a));
    let port = AutopilotPort::connect(&format!("tcpout:{addr}"), 1, 0).unwrap();
    let mut s = Signer::new(&dir, port, Config { sys: 1, comp: 1 });
    // Every event as it happens, also those of a round that then failed.
    let log = Arc::new(Mutex::new(Vec::new()));
    let l2 = log.clone();
    s.on_event(move |e| l2.lock().unwrap().push(e.clone()));
    // A first round: the signer hears the signed, disarmed heartbeats.
    s.tick().unwrap();
    ap.lock().unwrap().reboot_after_setup = true;
    rotation::request(&dir, "requested", "-", 1).unwrap();
    // The autopilot takes the key and reboots before it answers; the signer
    // reconnects, works out which key it has, and commits generation 1.
    let (_, errors) = run_until(&mut s, |e| e.contains(&Event::Rotated(1)));
    let events = log.lock().unwrap().clone();
    assert!(events.contains(&Event::Issued(1)), "{events:?}");
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, Event::Issued(g) if *g != 1)),
        "no second generation: {events:?}"
    );
    assert!(errors > 0, "the link was lost");
    let keys = rotation::load_drone_keys(&dir).unwrap().unwrap();
    assert!(keys.next.is_none());
    assert_eq!(keys.current_gen, 1);
    let a = ap.lock().unwrap();
    assert_eq!(&a.key, keys.current.as_bytes(), "the autopilot has the key");
    assert_eq!(a.setups, 1);
    assert!(a.connections >= 2, "reconnected");
    drop(a);
    assert!(s.port().take_reconnected());

    // And the next rotation, on the new connection, works as usual.
    rotation::request(&dir, "requested", "-", 2).unwrap();
    let (events, _) = run_until(&mut s, |e| e.contains(&Event::Rotated(2)));
    assert!(events.contains(&Event::Issued(2)), "{events:?}");
    assert_eq!(
        &ap.lock().unwrap().key,
        rotation::load_drone_keys(&dir)
            .unwrap()
            .unwrap()
            .current
            .as_bytes()
    );
}
