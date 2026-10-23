//! Control layer tests: every message, hostile and replayed, driven without
//! a link (the link's own tests cover the transport).

use std::collections::VecDeque;

use super::*;
use crate::files::{tempdir, write_private_file};
use crate::removal::{
    self, LOG_FILE, REMOVED_FILE, ROTATION_PENDING_FILE, SYNC_DIR, VOTES_FILE, load_removed,
};
use crate::signing::SigningKey;
use crate::store::{Peer, TRUST_FILE};

const DEVICE: [u8; 32] = [1; 32];
const ADMIN: [u8; 32] = [11; 32];
const ADMIN2: [u8; 32] = [12; 32];
const ADMIN3: [u8; 32] = [13; 32];
const OPERATOR: [u8; 32] = [21; 32];
const PLAIN: [u8; 32] = [31; 32];
const X1: [u8; 32] = [51; 32];
const X2: [u8; 32] = [52; 32];
const X3: [u8; 32] = [53; 32];

struct Rng(u64);

impl Entropy for Rng {
    fn fill(&mut self, dst: &mut [u8]) {
        for b in dst {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            *b = (z ^ (z >> 31)) as u8;
        }
    }
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

fn trust(dir: &Path, key: [u8; 32], name: &str, role: Role) {
    store::add(
        dir,
        &Peer {
            public: key,
            name: name.into(),
            role,
        },
    )
    .unwrap();
}

fn control(dir: &Path, own: [u8; 32], peer: [u8; 32], seed: u64) -> Control {
    Control::new(dir, own, peer, Box::new(Rng(seed)))
}

fn sends(actions: &[Action]) -> Vec<Vec<u8>> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::Send(b) => Some(b.to_vec()),
            _ => None,
        })
        .collect()
}

fn drops(actions: &[Action]) -> Vec<&'static str> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::Drop(r) => Some(*r),
            _ => None,
        })
        .collect()
}

fn notes(actions: &[Action]) -> Vec<&'static str> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::Note(n) => Some(n.what),
            _ => None,
        })
        .collect()
}

fn parsed(bytes: &[u8]) -> Message {
    Message::parse(bytes).unwrap()
}

fn is_removed(dir: &Path, key: &[u8; 32]) -> bool {
    load_removed(dir).unwrap().is_removed(key)
}

/// An admin device (log with `n` entries X1, X2, X3...) and a device that lists it.
fn fleet(n: usize) -> (PathBuf, PathBuf) {
    let admin = tempdir("ctl-admin");
    let device = tempdir("ctl-device");
    trust(&admin, DEVICE, "device", Role::Peer);
    trust(&device, ADMIN, "admin", Role::Admin);
    for i in 0..n {
        let k = [51 + i as u8; 32];
        trust(&device, k, &format!("victim-{i}"), Role::Peer);
        removal::revoke(&admin, &ADMIN, &k, 100 + i as u64).unwrap();
    }
    (admin, device)
}

/// Carry every `Send` between the two until nothing more is sent. Returns
/// all the notes, drops and messages seen, in order.
fn pump(
    a: &mut Control,
    b: &mut Control,
    first_from_a: Vec<Action>,
    now: Duration,
) -> Vec<(bool, Message)> {
    let mut queue: VecDeque<(bool, Vec<u8>)> = sends(&first_from_a)
        .into_iter()
        .map(|m| (true, m))
        .collect();
    let mut seen = Vec::new();
    let mut guard = 0;
    while let Some((from_a, bytes)) = queue.pop_front() {
        guard += 1;
        assert!(guard < 500, "messages never stop");
        seen.push((from_a, parsed(&bytes)));
        let out = if from_a {
            b.handle(now, 1000, &bytes)
        } else {
            a.handle(now, 1000, &bytes)
        };
        queue.extend(sends(&out).into_iter().map(|m| (!from_a, m)));
    }
    seen
}

// ---- the wire ------------------------------------------------------------

fn samples() -> Vec<(Message, Vec<u8>)> {
    let id = [1, 2, 3, 4];
    let mut entry = vec![0x22, 1, 2, 3, 4, 0xA, 0xB, 0xC, 0xD, 0, 0, 1, 2];
    entry.extend_from_slice(&[9u8; 32]);
    entry.extend_from_slice(&[0, 0, 0, 0, 0, 0, 3, 4]);
    let mut next = vec![0x10, 1, 2, 3, 4, 0, 0, 0, 7];
    next.extend_from_slice(&[5u8; 32]);
    vec![
        (
            Message::Ack { id, acked: 0x22 },
            vec![0x01, 1, 2, 3, 4, 0x22],
        ),
        (
            Message::SigningKeyNext {
                id,
                generation: 7,
                key: SecretKey::new([5; 32]),
            },
            next,
        ),
        (
            Message::SigningKeyCommit { id, generation: 7 },
            vec![0x11, 1, 2, 3, 4, 0, 0, 0, 7],
        ),
        (
            Message::RemoveHead {
                id,
                log_id: [0xA, 0xB, 0xC, 0xD],
                highest: 258,
            },
            vec![0x20, 1, 2, 3, 4, 0xA, 0xB, 0xC, 0xD, 0, 0, 1, 2],
        ),
        (
            Message::RemoveHave {
                id,
                held: 0x0102_0304,
            },
            vec![0x21, 1, 2, 3, 4, 1, 2, 3, 4],
        ),
        (
            Message::RemoveEntry {
                id,
                log_id: [0xA, 0xB, 0xC, 0xD],
                seq: 258,
                key: [9; 32],
                time: 0x0304,
            },
            entry,
        ),
        (Message::NotAdmin { id }, vec![0x23, 1, 2, 3, 4]),
    ]
}

#[test]
fn every_message_has_exactly_the_bytes_in_the_spec_table() {
    let sizes = [6usize, 41, 9, 13, 9, 53, 5];
    for ((msg, bytes), size) in samples().into_iter().zip(sizes) {
        assert_eq!(&msg.encode()[..], &bytes[..], "{msg:?}");
        assert_eq!(bytes.len(), size);
        assert_eq!(Message::parse(&bytes).unwrap(), msg);
        assert_eq!(msg.id(), [1, 2, 3, 4]);
        assert_eq!(msg.type_byte(), bytes[0]);
        // The largest control message plus the data overhead fits 128 bytes.
        assert!(bytes.len() + 22 + 2 <= 128);
    }
}

#[test]
fn truncated_extended_and_unknown_messages_are_refused() {
    for (_, bytes) in samples() {
        for n in 0..bytes.len() {
            assert!(Message::parse(&bytes[..n]).is_err(), "cut to {n}");
        }
        for extra in 1..=3 {
            let mut longer = bytes.clone();
            longer.extend(std::iter::repeat_n(0u8, extra));
            assert_eq!(Message::parse(&longer), Err(ParseError::BadLength));
        }
    }
    assert_eq!(Message::parse(&[]), Err(ParseError::Empty));
    let known = [0x01u8, 0x10, 0x11, 0x20, 0x21, 0x22, 0x23];
    for t in 0..=255u8 {
        if known.contains(&t) {
            continue;
        }
        assert_eq!(
            Message::parse(&[t, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
            Err(ParseError::UnknownType(t))
        );
    }
}

#[test]
fn random_bytes_never_panic_or_parse_as_the_wrong_thing() {
    let mut rng = Rng(5);
    for _ in 0..30_000 {
        let mut len = [0u8; 1];
        rng.fill(&mut len);
        let mut buf = vec![0u8; (len[0] % 60) as usize];
        rng.fill(&mut buf);
        if let Ok(m) = Message::parse(&buf) {
            // Whatever parses, encodes back to the same bytes.
            assert_eq!(&m.encode()[..], &buf[..]);
        }
    }
}

#[test]
fn a_signing_key_never_shows_in_debug_output() {
    let m = Message::SigningKeyNext {
        id: [1; 4],
        generation: 1,
        key: SecretKey::new([0xEE; 32]),
    };
    let shown = format!("{m:?} {:?}", Action::Send(m.encode()));
    assert!(
        !shown.contains("238") && !shown.to_lowercase().contains("ee, ee"),
        "{shown}"
    );
    assert!(shown.contains("SecretKey(..)"));
    // Equality does not depend on where the keys differ.
    let a = SecretKey::new([1; 32]);
    let mut other = [1u8; 32];
    other[31] = 2;
    assert!(a != SecretKey::new(other));
    assert!(a == a.clone());
}

// ---- roles ----------------------------------------------------------------

fn entry_bytes(id: u8, seq: u32, key: [u8; 32]) -> Vec<u8> {
    Message::RemoveEntry {
        id: [id; 4],
        log_id: [7; 4],
        seq,
        key,
        time: 5,
    }
    .encode()
    .to_vec()
}

fn head_bytes(id: u8, highest: u32) -> Vec<u8> {
    Message::RemoveHead {
        id: [id; 4],
        log_id: [7; 4],
        highest,
    }
    .encode()
    .to_vec()
}

#[test]
fn remove_entry_from_anyone_but_an_admin_is_dropped_as_bad_role() {
    let dir = tempdir("ctl-roles");
    trust(&dir, ADMIN, "admin", Role::Admin);
    trust(&dir, OPERATOR, "operator", Role::Operator);
    trust(&dir, PLAIN, "plain", Role::Peer);
    trust(&dir, X1, "victim", Role::Peer);
    let before = std::fs::read(dir.join(TRUST_FILE)).unwrap();
    for sender in [OPERATOR, PLAIN] {
        let mut c = control(&dir, DEVICE, sender, 1);
        let out = c.handle(secs(1), 1, &entry_bytes(1, 1, X1));
        assert_eq!(drops(&out), vec!["bad_role"], "{sender:?}");
        assert!(sends(&out).is_empty(), "no ack for a forbidden message");
    }
    assert_eq!(std::fs::read(dir.join(TRUST_FILE)).unwrap(), before);
    assert!(!dir.join(REMOVED_FILE).exists());
    // The admin may.
    let mut c = control(&dir, DEVICE, ADMIN, 1);
    let out = c.handle(secs(1), 1, &entry_bytes(1, 1, X1));
    assert_eq!(sends(&out).len(), 1);
    assert!(is_removed(&dir, &X1));
}

#[test]
fn remove_head_from_a_non_admin_is_answered_not_admin_and_nothing_else() {
    let dir = tempdir("ctl-notadmin");
    trust(&dir, OPERATOR, "operator", Role::Operator);
    trust(&dir, PLAIN, "plain", Role::Peer);
    for sender in [OPERATOR, PLAIN] {
        let mut c = control(&dir, DEVICE, sender, 1);
        let out = c.handle(secs(1), 1, &head_bytes(9, 3));
        assert_eq!(
            sends(&out),
            vec![vec![0x23, 9, 9, 9, 9]],
            "NOT_ADMIN echoes the request id"
        );
        assert!(drops(&out).is_empty());
    }
    assert!(
        !dir.join(SYNC_DIR).exists(),
        "no state was made for a non-admin"
    );
}

#[test]
fn have_ack_and_not_admin_need_no_role_but_do_need_a_matching_request() {
    let dir = tempdir("ctl-anyrole");
    trust(&dir, PLAIN, "plain", Role::Peer);
    let mut c = control(&dir, DEVICE, PLAIN, 1);
    c.session_started(secs(0));
    for bytes in [
        Message::RemoveHave {
            id: [1; 4],
            held: 0,
        }
        .encode()
        .to_vec(),
        Message::NotAdmin { id: [1; 4] }.encode().to_vec(),
        Message::Ack {
            id: [1; 4],
            acked: REMOVE_ENTRY,
        }
        .encode()
        .to_vec(),
    ] {
        let out = c.handle(secs(1), 1, &bytes);
        assert!(out.is_empty(), "{out:?}");
    }
}

fn next_msg(id: u8, generation: u32, key: u8) -> Vec<u8> {
    Message::SigningKeyNext {
        id: [id; 4],
        generation,
        key: SecretKey::new([key; 32]),
    }
    .encode()
    .to_vec()
}

fn commit_msg(id: u8, generation: u32) -> Vec<u8> {
    Message::SigningKeyCommit {
        id: [id; 4],
        generation,
    }
    .encode()
    .to_vec()
}

fn ack_of(out: &[Action]) -> Vec<(RequestId, u8)> {
    sends(out)
        .iter()
        .filter_map(|b| match parsed(b) {
            Message::Ack { id, acked } => Some((id, acked)),
            _ => None,
        })
        .collect()
}

#[test]
fn signing_key_messages_only_from_a_known_drone() {
    let dir = tempdir("ctl-signing");
    trust(&dir, PLAIN, "drone", Role::Peer);
    trust(&dir, ADMIN, "admin", Role::Admin);
    trust(&dir, OPERATOR, "operator", Role::Operator);
    let (next, commit) = (next_msg(1, 3, 9), commit_msg(2, 3));
    // No signing key held for the sender: dropped, whatever its role.
    for sender in [PLAIN, ADMIN, OPERATOR] {
        let mut c = control(&dir, DEVICE, sender, 1);
        for m in [&next, &commit] {
            assert_eq!(drops(&c.handle(secs(1), 1, m)), vec!["bad_role"]);
        }
    }
    // A ground station holding that drone's key accepts them from it only.
    write_private_file(&peer_key_path(&dir, &fingerprint(&PLAIN)), &[1u8; 40]).unwrap();
    let mut c = control(&dir, DEVICE, PLAIN, 1);
    let out = c.handle(secs(1), 1, &next);
    assert_eq!(notes(&out), vec!["signing_key_next"]);
    assert_eq!(ack_of(&out), vec![([1; 4], SIGNING_KEY_NEXT)]);
    let mut c = control(&dir, DEVICE, ADMIN, 1);
    assert_eq!(drops(&c.handle(secs(1), 1, &next)), vec!["bad_role"]);
    // A drone itself (it holds an autopilot key) takes none: the flow is drone to operators.
    write_private_file(&dir.join(AUTOPILOT_KEY_FILE), &[2u8; 40]).unwrap();
    let mut c = control(&dir, DEVICE, PLAIN, 1);
    assert_eq!(drops(&c.handle(secs(1), 1, &next)), vec!["bad_role"]);
    assert_eq!(drops(&c.handle(secs(1), 1, &commit)), vec!["bad_role"]);
    assert!(!dir.join(ROTATION_PENDING_FILE).exists());
}

fn ground_with_drone() -> (PathBuf, Control) {
    let dir = tempdir("ctl-ground");
    trust(&dir, PLAIN, "drone", Role::Peer);
    write_private_file(&peer_key_path(&dir, &fingerprint(&PLAIN)), &[1u8; 40]).unwrap();
    let c = control(&dir, DEVICE, PLAIN, 1);
    (dir, c)
}

#[test]
fn an_operator_stores_acks_and_switches_only_on_commit_and_every_reply_echoes_the_id() {
    let (dir, mut c) = ground_with_drone();
    let fp = fingerprint(&PLAIN);
    let held = || SigningKey::load(&peer_key_path(&dir, &fp)).unwrap();
    let out = c.handle(secs(1), 1, &next_msg(5, 1, 9));
    assert_eq!(ack_of(&out), vec![([5; 4], SIGNING_KEY_NEXT)]);
    assert_ne!(held().as_bytes(), &[9u8; 32], "not switched by NEXT");
    // A repeat is acked again (the ack may have been lost) and changes nothing.
    let out = c.handle(secs(2), 1, &next_msg(6, 1, 9));
    assert_eq!(ack_of(&out), vec![([6; 4], SIGNING_KEY_NEXT)]);
    let out = c.handle(secs(3), 1, &commit_msg(7, 1));
    assert_eq!(ack_of(&out), vec![([7; 4], SIGNING_KEY_COMMIT)]);
    assert_eq!(held().as_bytes(), &[9u8; 32]);
    // Replays after the switch: acked, and nothing moves.
    for m in [commit_msg(8, 1), next_msg(9, 1, 9), next_msg(10, 0, 3)] {
        let out = c.handle(secs(4), 1, &m);
        assert_eq!(ack_of(&out).len(), 1, "{out:?}");
        assert_eq!(held().as_bytes(), &[9u8; 32]);
    }
}

#[test]
fn hostile_signing_messages_change_nothing() {
    let (dir, mut c) = ground_with_drone();
    let fp = fingerprint(&PLAIN);
    let before = std::fs::read(peer_key_path(&dir, &fp)).unwrap();
    c.handle(secs(1), 1, &next_msg(1, 2, 9));
    // The same generation with another key: refused, not acked.
    let out = c.handle(secs(1), 1, &next_msg(2, 2, 8));
    assert_eq!(drops(&out), vec!["bad_control"]);
    assert!(sends(&out).is_empty());
    // An all-zero key would turn signing off.
    let out = c.handle(secs(1), 1, &next_msg(3, 3, 0));
    assert_eq!(drops(&out), vec!["bad_control"]);
    // A commit for a generation never sent: noted, not acked, nothing switched.
    for g in [1, 3, u32::MAX] {
        let out = c.handle(secs(1), 1, &commit_msg(4, g));
        assert_eq!(notes(&out), vec!["signing_key_commit_unknown"]);
        assert!(sends(&out).is_empty());
    }
    assert_eq!(std::fs::read(peer_key_path(&dir, &fp)).unwrap(), before);
    // Truncated and padded messages are not messages.
    let mut long = next_msg(1, 2, 9);
    long.push(0);
    for bad in [
        next_msg(1, 2, 9)[..40].to_vec(),
        long,
        commit_msg(1, 2)[..8].to_vec(),
    ] {
        assert_eq!(drops(&c.handle(secs(1), 1, &bad)), vec!["bad_control"]);
    }
    // A removed drone's messages go nowhere.
    c.peer_removed();
    assert_eq!(
        drops(&c.handle(secs(1), 1, &commit_msg(1, 2))),
        vec!["peer_removed"]
    );
}

/// A drone with one operator.
fn drone_with_operator() -> (PathBuf, Control) {
    let dir = tempdir("ctl-drone");
    write_private_file(&dir.join(AUTOPILOT_KEY_FILE), &{
        let mut b = [7u8; 40];
        b[32..].fill(0);
        b
    })
    .unwrap();
    trust(&dir, OPERATOR, "operator", Role::Operator);
    let c = control(&dir, DEVICE, OPERATOR, 1);
    (dir, c)
}

fn only_send(out: &[Action]) -> Message {
    let s = sends(out);
    assert_eq!(s.len(), 1, "{out:?}");
    parsed(&s[0])
}

#[test]
fn a_drone_sends_next_then_commit_and_remembers_what_was_acked() {
    let (dir, mut d) = drone_with_operator();
    let fp = fingerprint(&OPERATOR);
    // Nothing owed for the key from pairing.
    assert!(sends(&d.session_started(secs(0))).is_empty());
    // A rotation begins: the pending key goes out at once.
    let b = rotation::begin(&dir).unwrap();
    let Message::SigningKeyNext {
        id,
        generation,
        key,
    } = only_send(&d.signing_changed(secs(1)))
    else {
        panic!()
    };
    assert_eq!(
        (generation, key.as_bytes()),
        (b.generation, b.key.as_bytes())
    );
    // No second message while it waits for its ack; an ack for another id or type is ignored.
    assert!(sends(&d.signing_changed(secs(1))).is_empty());
    assert!(
        d.handle(
            secs(1),
            1,
            &Message::Ack {
                id: [9; 4],
                acked: SIGNING_KEY_NEXT
            }
            .encode()
        )
        .is_empty()
    );
    assert!(
        d.handle(
            secs(1),
            1,
            &Message::Ack {
                id,
                acked: SIGNING_KEY_COMMIT
            }
            .encode()
        )
        .is_empty()
    );
    assert_eq!(
        rotation::read_acked(&dir, &fp).unwrap(),
        rotation::Acked::default()
    );
    // Its ack: remembered. And no commit yet: the autopilot has not taken it.
    let out = d.handle(
        secs(1),
        1,
        &Message::Ack {
            id,
            acked: SIGNING_KEY_NEXT,
        }
        .encode(),
    );
    assert_eq!(notes(&out), vec!["signing_key_acked"]);
    assert!(sends(&out).is_empty());
    assert_eq!(rotation::read_acked(&dir, &fp).unwrap().next, 1);
    // The autopilot took it: the commit.
    rotation::commit(&dir, 1).unwrap();
    let Message::SigningKeyCommit { id, generation } = only_send(&d.signing_changed(secs(2)))
    else {
        panic!()
    };
    assert_eq!(generation, 1);
    d.handle(
        secs(2),
        1,
        &Message::Ack {
            id,
            acked: SIGNING_KEY_COMMIT,
        }
        .encode(),
    );
    assert_eq!(
        rotation::read_acked(&dir, &fp).unwrap(),
        rotation::Acked { next: 1, commit: 1 }
    );
    assert!(sends(&d.signing_changed(secs(3))).is_empty());
    // A new session starts over from the files: nothing owed.
    assert!(sends(&d.session_started(secs(4))).is_empty());
}

#[test]
fn a_drone_and_an_operator_talk_through_a_rotation_even_with_a_lost_message() {
    let (ddir, mut d) = drone_with_operator();
    let (odir, mut o) = ground_with_drone_fp(&fingerprint(&DEVICE));
    // The operator pairs with the drone: holds its current key (same bytes).
    d.session_started(secs(0));
    o.session_started(secs(0));
    let b = rotation::begin(&ddir).unwrap();
    let first = d.signing_changed(secs(1));
    // The first NEXT is lost. The retry (2 s later) arrives.
    assert_eq!(sends(&first).len(), 1);
    let retry = d.poll(secs(3));
    let seen = pump(&mut d, &mut o, retry, secs(3));
    assert!(
        seen.iter()
            .any(|(_, m)| matches!(m, Message::Ack { acked, .. } if *acked == SIGNING_KEY_NEXT))
    );
    assert_eq!(
        rotation::operator_pending(&odir, &fingerprint(&DEVICE))
            .unwrap()
            .unwrap()
            .0,
        1
    );
    // The autopilot took it.
    rotation::commit(&ddir, b.generation).unwrap();
    let out = d.signing_changed(secs(4));
    pump(&mut d, &mut o, out, secs(4));
    assert_eq!(
        SigningKey::load(&peer_key_path(&odir, &fingerprint(&DEVICE)))
            .unwrap()
            .as_bytes(),
        b.key.as_bytes()
    );
    assert_eq!(
        rotation::operator_gen(&odir, &fingerprint(&DEVICE)).unwrap(),
        1
    );
    assert!(
        sends(&d.poll(secs(1000))).is_empty(),
        "nothing left to resend"
    );
}

fn ground_with_drone_fp(drone_fp: &str) -> (PathBuf, Control) {
    let dir = tempdir("ctl-ground2");
    trust(&dir, DEVICE, "drone", Role::Peer);
    write_private_file(&peer_key_path(&dir, drone_fp), &[7u8; 40]).unwrap();
    // This ground station is the drone's OPERATOR key.
    let c = control(&dir, OPERATOR, DEVICE, 2);
    (dir, c)
}

#[test]
fn a_reconnecting_operator_that_missed_a_rotation_catches_up() {
    let (ddir, mut d) = drone_with_operator();
    let dfp = fingerprint(&DEVICE);
    let (odir, mut o) = ground_with_drone_fp(&dfp);
    // Two rotations happen while the operator is away.
    for g in 1..=2 {
        let b = rotation::begin(&ddir).unwrap();
        assert_eq!(b.generation, g);
        rotation::commit(&ddir, g).unwrap();
    }
    // It comes back: NEXT(2) for the current key, then COMMIT(2).
    let start = d.session_started(secs(10));
    let seen = pump(&mut d, &mut o, start, secs(10));
    let kinds: Vec<u8> = seen.iter().map(|(_, m)| m.type_byte()).collect();
    assert_eq!(kinds, vec![SIGNING_KEY_NEXT, ACK, SIGNING_KEY_COMMIT, ACK]);
    assert_eq!(rotation::operator_gen(&odir, &dfp).unwrap(), 2);
    let cur = rotation::load_drone_keys(&ddir).unwrap().unwrap().current;
    assert_eq!(SigningKey::load(&peer_key_path(&odir, &dfp)).unwrap(), cur);
}

#[test]
fn only_operators_get_keys_and_a_removed_one_never_does() {
    let (dir, mut d) = drone_with_operator();
    let _ = rotation::begin(&dir).unwrap();
    // A peer or an admin on the same link gets nothing.
    for (key, role) in [(PLAIN, Role::Peer), (ADMIN, Role::Admin)] {
        trust(&dir, key, "x", role);
        let mut c = control(&dir, DEVICE, key, 3);
        assert!(sends(&c.session_started(secs(0))).is_empty());
    }
    assert_eq!(sends(&d.session_started(secs(0))).len(), 1);
    // The operator is removed: the very next call sends nothing, and retries stop.
    removal::remove_local(&dir, &DEVICE, &OPERATOR, 5).unwrap();
    assert!(sends(&d.signing_changed(secs(1))).is_empty());
    d.peer_removed();
    assert!(sends(&d.poll(secs(100))).is_empty());
    // A new Control for the removed key (a restart) sends nothing either.
    let mut c = control(&dir, DEVICE, OPERATOR, 4);
    assert!(sends(&c.session_started(secs(0))).is_empty());
    // And removing the operator asked for a rotation.
    assert!(dir.join(ROTATION_PENDING_FILE).exists());
}

#[test]
fn an_unacked_commit_starts_over_with_next_and_retries_back_off() {
    let (dir, mut d) = drone_with_operator();
    d.session_started(secs(0));
    let b = rotation::begin(&dir).unwrap();
    let Message::SigningKeyNext { id, .. } = only_send(&d.signing_changed(secs(0))) else {
        panic!()
    };
    d.handle(
        secs(0),
        1,
        &Message::Ack {
            id,
            acked: SIGNING_KEY_NEXT,
        }
        .encode(),
    );
    rotation::commit(&dir, b.generation).unwrap();
    assert!(matches!(
        only_send(&d.signing_changed(secs(1))),
        Message::SigningKeyCommit { .. }
    ));
    // Resends at 2 s, then 4, 8, 16 ...
    let mut t = 1;
    let mut gaps = Vec::new();
    let mut last = 1;
    let mut restarted = false;
    while t < 400 && !restarted {
        t += 1;
        let out = d.poll(secs(t));
        for m in sends(&out) {
            gaps.push(t - last);
            last = t;
            restarted |= matches!(parsed(&m), Message::SigningKeyNext { .. });
        }
    }
    assert_eq!(&gaps[..3], &[2u64, 4, 8][..], "{gaps:?}");
    assert!(
        restarted,
        "after four resends it sends NEXT again, then the commit follows its ack"
    );
}

#[test]
fn garbage_and_unlisted_senders_are_dropped_with_a_reason() {
    let dir = tempdir("ctl-garbage");
    trust(&dir, ADMIN, "admin", Role::Admin);
    let mut c = control(&dir, DEVICE, ADMIN, 1);
    for bad in [vec![], vec![0x99], vec![0x22, 1, 2, 3], vec![0x01; 7]] {
        assert_eq!(
            drops(&c.handle(secs(1), 1, &bad)),
            vec!["bad_control"],
            "{bad:?}"
        );
    }
    // An entry with seq 0 or an impossible key is not an entry.
    assert_eq!(
        drops(&c.handle(secs(1), 1, &entry_bytes(1, 0, X1))),
        vec!["bad_control"]
    );
    assert_eq!(
        drops(&c.handle(secs(1), 1, &entry_bytes(1, 1, [0; 32]))),
        vec!["bad_control"]
    );
    // A peer that is not trusted (any more) gets nothing.
    let mut stranger = control(&dir, DEVICE, PLAIN, 1);
    assert_eq!(
        drops(&stranger.handle(secs(1), 1, &head_bytes(1, 1))),
        vec!["peer_removed"]
    );
    assert!(!dir.join(REMOVED_FILE).exists());
}

// ---- the sync, end to end ---------------------------------------------------

#[test]
fn an_admin_syncs_its_log_to_a_device_and_the_device_acks_each_entry() {
    let (admin, device) = fleet(3);
    let mut a = control(&admin, ADMIN, DEVICE, 1);
    let mut d = control(&device, DEVICE, ADMIN, 2);
    let first = a.session_started(secs(0));
    assert!(
        d.session_started(secs(0)).is_empty(),
        "a device without a log sends nothing"
    );
    let seen = pump(&mut a, &mut d, first, secs(0));
    let kinds: Vec<u8> = seen.iter().map(|(_, m)| m.type_byte()).collect();
    // HEAD, HAVE 0, then entries and acks (HEAD and HAVE are not acked).
    assert_eq!(&kinds[..2], &[REMOVE_HEAD, REMOVE_HAVE]);
    assert_eq!(kinds.iter().filter(|k| **k == REMOVE_ENTRY).count(), 3);
    assert_eq!(kinds.iter().filter(|k| **k == ACK).count(), 3);
    assert_eq!(kinds.iter().filter(|k| **k == REMOVE_HEAD).count(), 1);
    for k in [X1, X2, X3] {
        assert!(is_removed(&device, &k));
    }
    // Each ACK echoes its entry's request id and names the acked type.
    let mut ids: Vec<RequestId> = Vec::new();
    for (from_a, m) in &seen {
        match m {
            Message::RemoveEntry { id, .. } => {
                assert!(*from_a);
                ids.push(*id);
            }
            Message::Ack { id, acked } => {
                assert!(!*from_a);
                assert_eq!(*acked, REMOVE_ENTRY);
                assert!(ids.contains(id));
            }
            _ => {}
        }
    }
    let log = removal::load_log(&admin).unwrap().unwrap();
    assert_eq!(
        removal::sync_state(&device, &fingerprint(&ADMIN)).unwrap(),
        Some((log.id, 3))
    );
    // Nothing is left to retry.
    assert!(a.poll(secs(1000)).is_empty());
    // A new session: HEAD again, HAVE 3, and no entries.
    let first = a.session_started(secs(2000));
    let seen = pump(&mut a, &mut d, first, secs(2000));
    let kinds: Vec<u8> = seen.iter().map(|(_, m)| m.type_byte()).collect();
    assert_eq!(kinds, vec![REMOVE_HEAD, REMOVE_HAVE]);
    assert!(matches!(seen[1].1, Message::RemoveHave { held: 3, .. }));
}

#[test]
fn entries_are_sent_a_window_at_a_time() {
    let (admin, _device) = fleet(0);
    for i in 0..20u8 {
        removal::revoke(&admin, &ADMIN, &[100 + i; 32], 1).unwrap();
    }
    let mut a = control(&admin, ADMIN, DEVICE, 1);
    let first = a.session_started(secs(0));
    let have = Message::RemoveHave {
        id: parsed(&sends(&first)[0]).id(),
        held: 0,
    }
    .encode()
    .to_vec();
    let out = a.handle(secs(0), 1, &have);
    assert_eq!(sends(&out).len(), ENTRY_WINDOW);
    // Acking one frees one place.
    let Message::RemoveEntry { id, seq, .. } = parsed(&sends(&out)[0]) else {
        panic!()
    };
    assert_eq!(seq, 1);
    let out = a.handle(
        secs(1),
        1,
        &Message::Ack {
            id,
            acked: REMOVE_ENTRY,
        }
        .encode(),
    );
    let next = sends(&out);
    assert_eq!(next.len(), 1);
    assert!(matches!(
        parsed(&next[0]),
        Message::RemoveEntry { seq: 9, .. }
    ));
    // An ack for the wrong type, or a made-up id, frees nothing.
    assert!(
        a.handle(
            secs(1),
            1,
            &Message::Ack {
                id: [0xEE; 4],
                acked: REMOVE_ENTRY
            }
            .encode()
        )
        .is_empty()
    );
    let Message::RemoveEntry { id, .. } = parsed(&sends(&out)[0]) else {
        panic!()
    };
    assert!(
        a.handle(
            secs(1),
            1,
            &Message::Ack {
                id,
                acked: REMOVE_HEAD
            }
            .encode()
        )
        .is_empty()
    );
}

#[test]
fn an_unanswered_message_is_resent_after_2_s_doubling_to_60_s_for_the_whole_session() {
    let (admin, _device) = fleet(1);
    let mut a = control(&admin, ADMIN, DEVICE, 1);
    let first = sends(&a.session_started(secs(0)));
    assert_eq!(first.len(), 1);
    let mut t = 0u64;
    let mut gaps = Vec::new();
    for _ in 0..12 {
        // Nothing until it is due; then the same bytes again.
        let mut next = t;
        loop {
            next += 1;
            let out = a.poll(secs(next));
            if !out.is_empty() {
                assert_eq!(sends(&out), first, "a resend is the same message");
                break;
            }
            assert!(next < t + 100);
        }
        gaps.push(next - t);
        t = next;
    }
    assert_eq!(gaps, vec![2, 4, 8, 16, 32, 60, 60, 60, 60, 60, 60, 60]);
}

#[test]
fn head_have_and_not_admin_stop_the_head_retries() {
    let (admin, device) = fleet(1);
    // An answer stops the retries.
    let mut a = control(&admin, ADMIN, DEVICE, 1);
    let mut d = control(&device, DEVICE, ADMIN, 2);
    let first = a.session_started(secs(0));
    pump(&mut a, &mut d, first, secs(0));
    assert!(a.poll(secs(500)).is_empty());
    // A device that does not list us answers NOT_ADMIN: stop for the session.
    let stranger = tempdir("ctl-stranger");
    trust(&stranger, ADMIN, "admin", Role::Peer);
    let mut a = control(&admin, ADMIN, DEVICE, 1);
    let mut s = control(&stranger, DEVICE, ADMIN, 2);
    let first = a.session_started(secs(0));
    let seen = pump(&mut a, &mut s, first, secs(0));
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[1].1.type_byte(), NOT_ADMIN);
    assert!(a.poll(secs(500)).is_empty(), "no more heads this session");
    assert!(
        a.log_changed(secs(500)).is_empty(),
        "not even when the log grows"
    );
    // The next session tries again.
    assert_eq!(sends(&a.session_started(secs(600))).len(), 1);
    assert!(!stranger.join(REMOVED_FILE).exists());
}

#[test]
fn an_admin_with_no_log_sends_nothing() {
    let dir = tempdir("ctl-nolog");
    trust(&dir, DEVICE, "device", Role::Peer);
    let mut a = control(&dir, ADMIN, DEVICE, 1);
    assert!(a.session_started(secs(0)).is_empty());
    assert!(a.poll(secs(100)).is_empty());
    assert!(a.log_changed(secs(100)).is_empty());
}

#[test]
fn a_new_entry_while_the_link_is_up_is_announced_and_sent() {
    let (admin, device) = fleet(1);
    let mut a = control(&admin, ADMIN, DEVICE, 1);
    let mut d = control(&device, DEVICE, ADMIN, 2);
    let first = a.session_started(secs(0));
    pump(&mut a, &mut d, first, secs(0));
    // The admin revokes one more device now.
    trust(&device, X2, "late-victim", Role::Peer);
    removal::revoke(&admin, &ADMIN, &X2, 9).unwrap();
    let out = a.log_changed(secs(10));
    let seen = pump(&mut a, &mut d, out, secs(10));
    assert!(is_removed(&device, &X2));
    let entries: Vec<u32> = seen
        .iter()
        .filter_map(|(_, m)| match m {
            Message::RemoveEntry { seq, .. } => Some(*seq),
            _ => None,
        })
        .collect();
    assert_eq!(entries, vec![2], "only the missing entry is sent");
}

#[test]
fn answers_with_unknown_request_ids_do_nothing_and_old_answers_die_with_the_session() {
    let (admin, _device) = fleet(2);
    let mut a = control(&admin, ADMIN, DEVICE, 1);
    let head1 = sends(&a.session_started(secs(0)));
    let id1 = parsed(&head1[0]).id();
    // A made-up id.
    let wrong = Message::RemoveHave {
        id: [0xAB; 4],
        held: 0,
    }
    .encode();
    assert!(a.handle(secs(1), 1, &wrong).is_empty());
    assert!(
        a.handle(secs(1), 1, &Message::NotAdmin { id: [0xAB; 4] }.encode())
            .is_empty()
    );
    // A new session; the answer to the first session's head is now stale.
    let head2 = sends(&a.session_started(secs(5)));
    let id2 = parsed(&head2[0]).id();
    assert_ne!(id1, id2, "request ids are random per message");
    let stale = Message::RemoveHave { id: id1, held: 0 }.encode();
    assert!(
        a.handle(secs(6), 1, &stale).is_empty(),
        "replayed across sessions"
    );
    // The right answer still works.
    let fresh = Message::RemoveHave { id: id2, held: 0 }.encode();
    assert_eq!(sends(&a.handle(secs(6), 1, &fresh)).len(), 2);
    // And the same answer twice does not send everything twice.
    assert!(a.handle(secs(7), 1, &fresh).is_empty());
}

#[test]
fn request_ids_differ_between_messages() {
    let (admin, _device) = fleet(3);
    let mut a = control(&admin, ADMIN, DEVICE, 99);
    let head = sends(&a.session_started(secs(0)));
    let have = Message::RemoveHave {
        id: parsed(&head[0]).id(),
        held: 0,
    }
    .encode();
    let out = sends(&a.handle(secs(0), 1, &have));
    let mut ids: Vec<RequestId> = out.iter().map(|m| parsed(m).id()).collect();
    ids.push(parsed(&head[0]).id());
    let unique: BTreeSet<_> = ids.iter().collect();
    assert_eq!(unique.len(), ids.len());
}

// ---- receiving entries: idempotence, order, replay ---------------------------

#[test]
fn a_repeated_entry_is_acked_again_and_changes_nothing() {
    let (admin, device) = fleet(1);
    let mut d = control(&device, DEVICE, ADMIN, 2);
    let log = removal::load_log(&admin).unwrap().unwrap();
    d.handle(secs(0), 1, &head_bytes_for(&log));
    let bytes = Message::RemoveEntry {
        id: [3; 4],
        log_id: log.id,
        seq: 1,
        key: X1,
        time: 1,
    }
    .encode()
    .to_vec();
    let first = d.handle(secs(1), 10, &bytes);
    assert_eq!(sends(&first), vec![vec![0x01, 3, 3, 3, 3, 0x22]]);
    let removed_before = std::fs::read(device.join(REMOVED_FILE)).unwrap();
    for _ in 0..3 {
        let again = d.handle(secs(2), 99, &bytes);
        assert_eq!(sends(&again), sends(&first), "acked again, same id echoed");
    }
    assert_eq!(
        std::fs::read(device.join(REMOVED_FILE)).unwrap(),
        removed_before
    );
}

fn head_bytes_for(log: &removal::RemovalLog) -> Vec<u8> {
    Message::RemoveHead {
        id: [8; 4],
        log_id: log.id,
        highest: log.highest(),
    }
    .encode()
    .to_vec()
}

#[test]
fn entries_in_any_order_all_apply_and_the_held_number_catches_up() {
    let (admin, device) = fleet(3);
    let log = removal::load_log(&admin).unwrap().unwrap();
    let mut d = control(&device, DEVICE, ADMIN, 2);
    let have = sends(&d.handle(secs(0), 1, &head_bytes_for(&log)));
    assert!(matches!(
        parsed(&have[0]),
        Message::RemoveHave { held: 0, .. }
    ));
    for seq in [3u32, 1, 2] {
        let e = log.entry(seq).unwrap();
        let out = d.handle(
            secs(1),
            1,
            &Message::RemoveEntry {
                id: [seq as u8; 4],
                log_id: log.id,
                seq,
                key: e.key,
                time: e.time,
            }
            .encode(),
        );
        assert_eq!(sends(&out).len(), 1, "seq {seq} acked");
    }
    for k in [X1, X2, X3] {
        assert!(is_removed(&device, &k));
    }
    let held = removal::sync_state(&device, &fingerprint(&ADMIN))
        .unwrap()
        .unwrap()
        .1;
    assert_eq!(held, 3);
}

#[test]
fn a_reinstalled_admin_with_a_new_log_id_is_taken_from_the_start() {
    let (admin, device) = fleet(2);
    let mut a = control(&admin, ADMIN, DEVICE, 1);
    let mut d = control(&device, DEVICE, ADMIN, 2);
    let first = a.session_started(secs(0));
    pump(&mut a, &mut d, first, secs(0));
    // The admin loses its folder and starts again: a new log, one entry.
    std::fs::remove_file(admin.join(LOG_FILE)).unwrap();
    trust(&device, X3, "victim-3", Role::Peer);
    removal::revoke(&admin, &ADMIN, &X3, 5).unwrap();
    let mut a = control(&admin, ADMIN, DEVICE, 1);
    let first = a.session_started(secs(100));
    let seen = pump(&mut a, &mut d, first, secs(100));
    // HAVE 0 although the device held 2 of the old log, and the entry came.
    assert!(matches!(seen[1].1, Message::RemoveHave { held: 0, .. }));
    assert!(is_removed(&device, &X3));
    // Nothing from the old log was undone.
    assert!(is_removed(&device, &X1) && is_removed(&device, &X2));
    let new_log = removal::load_log(&admin).unwrap().unwrap();
    assert_eq!(
        removal::sync_state(&device, &fingerprint(&ADMIN)).unwrap(),
        Some((new_log.id, 1))
    );
}

#[test]
fn a_head_below_what_the_device_holds_restarts_that_log() {
    let (admin, device) = fleet(3);
    let log = removal::load_log(&admin).unwrap().unwrap();
    let mut d = control(&device, DEVICE, ADMIN, 2);
    d.handle(secs(0), 1, &head_bytes_for(&log));
    for e in &log.entries {
        d.handle(
            secs(0),
            1,
            &Message::RemoveEntry {
                id: [9; 4],
                log_id: log.id,
                seq: e.seq,
                key: e.key,
                time: e.time,
            }
            .encode(),
        );
    }
    let out = d.handle(secs(1), 1, &head_bytes(4, 1));
    // log id [7;4] differs from the real one too, so 0 either way; now the real id, lower head:
    assert!(matches!(
        parsed(&sends(&out)[0]),
        Message::RemoveHave { held: 0, .. }
    ));
    let mut d2 = control(&device, DEVICE, ADMIN, 3);
    d2.handle(secs(0), 1, &head_bytes_for(&log));
    let lower = Message::RemoveHead {
        id: [5; 4],
        log_id: log.id,
        highest: 1,
    }
    .encode();
    let out = d2.handle(secs(1), 1, &lower);
    assert!(matches!(
        parsed(&sends(&out)[0]),
        Message::RemoveHave { held: 0, .. }
    ));
}

#[test]
fn entries_for_our_own_key_are_acked_and_ignored() {
    let dir = tempdir("ctl-ownkey");
    trust(&dir, ADMIN, "admin", Role::Admin);
    let mut d = control(&dir, DEVICE, ADMIN, 1);
    let out = d.handle(secs(1), 1, &entry_bytes(4, 1, DEVICE));
    assert_eq!(sends(&out), vec![vec![0x01, 4, 4, 4, 4, 0x22]]);
    assert!(!is_removed(&dir, &DEVICE));
    assert!(store::get(&dir, &ADMIN).unwrap().is_some());
}

#[test]
fn removing_an_admin_needs_two_admins_through_two_links() {
    let device = tempdir("ctl-twoadmin");
    trust(&device, ADMIN, "admin-1", Role::Admin);
    trust(&device, ADMIN2, "admin-2", Role::Admin);
    trust(&device, ADMIN3, "admin-3", Role::Admin);
    let mut from1 = control(&device, DEVICE, ADMIN, 1);
    let mut from2 = control(&device, DEVICE, ADMIN2, 2);
    let out = from1.handle(secs(1), 1, &entry_bytes(1, 1, ADMIN3));
    assert!(notes(&out).contains(&"removal_entry"));
    assert_eq!(sends(&out).len(), 1, "a vote is acked");
    assert!(store::get(&device, &ADMIN3).unwrap().is_some());
    assert!(
        std::fs::read_to_string(device.join(VOTES_FILE))
            .unwrap()
            .lines()
            .count()
            == 1
    );
    // The same admin again changes nothing.
    from1.handle(secs(2), 1, &entry_bytes(2, 2, ADMIN3));
    assert!(store::get(&device, &ADMIN3).unwrap().is_some());
    // The second one, on a different link (another oasa-link process).
    from2.handle(secs(3), 1, &entry_bytes(3, 1, ADMIN3));
    assert!(store::get(&device, &ADMIN3).unwrap().is_none());
    assert!(is_removed(&device, &ADMIN3));
}

#[test]
fn a_vote_is_lost_when_its_admin_is_removed_mid_way() {
    let device = tempdir("ctl-voteloss");
    trust(&device, ADMIN, "admin-1", Role::Admin);
    trust(&device, ADMIN2, "admin-2", Role::Admin);
    trust(&device, ADMIN3, "admin-3", Role::Admin);
    let mut from1 = control(&device, DEVICE, ADMIN, 1);
    let mut from2 = control(&device, DEVICE, ADMIN2, 2);
    from1.handle(secs(1), 1, &entry_bytes(1, 1, ADMIN3));
    // Admin 1 turns out to be the stolen one and is removed by hand.
    removal::remove_local(&device, &DEVICE, &ADMIN, 2).unwrap();
    // Its link is closed: anything it still sends is dropped.
    from1.peer_removed();
    assert_eq!(
        drops(&from1.handle(secs(3), 1, &entry_bytes(9, 2, ADMIN3))),
        vec!["peer_removed"]
    );
    from2.handle(secs(4), 1, &entry_bytes(3, 1, ADMIN3));
    assert!(
        store::get(&device, &ADMIN3).unwrap().is_some(),
        "one vote is not enough"
    );
}

#[test]
fn messages_for_a_removed_peer_are_dropped_and_unsent_ones_forgotten() {
    let (admin, device) = fleet(2);
    // The admin is removed on the device by hand, between two entries.
    let mut a = control(&admin, ADMIN, DEVICE, 1);
    let mut d = control(&device, DEVICE, ADMIN, 2);
    let head = a.session_started(secs(0));
    let have = d.handle(secs(0), 1, &sends(&head)[0]);
    let entries = a.handle(secs(0), 1, &sends(&have)[0]);
    let msgs = sends(&entries);
    assert_eq!(msgs.len(), 2);
    assert!(!sends(&d.handle(secs(1), 1, &msgs[0])).is_empty());
    removal::remove_local(&device, &DEVICE, &ADMIN, 5).unwrap();
    let out = d.handle(secs(2), 1, &msgs[1]);
    assert_eq!(drops(&out), vec!["peer_removed"]);
    assert!(sends(&out).is_empty());
    assert!(
        !is_removed(&device, &X2),
        "an entry from a removed admin does nothing"
    );
    // The admin side of a removed peer sends nothing more.
    a.peer_removed();
    assert!(a.poll(secs(1000)).is_empty());
    assert!(a.session_started(secs(1001)).is_empty());
    assert!(a.log_changed(secs(1002)).is_empty());
}

#[test]
fn nothing_hostile_changes_the_trust_files() {
    let dir = tempdir("ctl-fuzz");
    trust(&dir, ADMIN, "admin", Role::Admin);
    trust(&dir, OPERATOR, "operator", Role::Operator);
    trust(&dir, X1, "victim", Role::Peer);
    let snapshot = |d: &Path| {
        let mut v = vec![std::fs::read(d.join(TRUST_FILE)).unwrap()];
        for f in [REMOVED_FILE, VOTES_FILE, ROTATION_PENDING_FILE] {
            v.push(std::fs::read(d.join(f)).unwrap_or_default());
        }
        v
    };
    let before = snapshot(&dir);
    let mut rng = Rng(77);
    for sender in [OPERATOR, PLAIN] {
        let mut c = control(&dir, DEVICE, sender, 4);
        c.session_started(secs(0));
        for i in 0..4000 {
            let mut len = [0u8; 1];
            rng.fill(&mut len);
            let mut buf = vec![0u8; (len[0] % 60) as usize];
            rng.fill(&mut buf);
            if i % 2 == 0 && !buf.is_empty() {
                // Real-looking types, so the parsers and role checks run.
                buf[0] = [0x01, 0x10, 0x11, 0x20, 0x21, 0x22, 0x23][i % 7];
            }
            let out = c.handle(secs(i as u64), 1, &buf);
            // Nothing is acked for a role that may not send it, and a
            // NOT_ADMIN is the only possible answer to a head.
            for s in sends(&out) {
                assert!(matches!(parsed(&s), Message::NotAdmin { .. }), "{s:?}");
            }
        }
    }
    assert_eq!(snapshot(&dir), before);
}

#[test]
fn a_session_may_add_only_so_many_new_removals_and_the_rest_are_refused_not_acked() {
    let dir = tempdir("ctl-budget");
    trust(&dir, ADMIN, "admin", Role::Admin);
    let key = |i: u32| {
        let mut k = [0x55u8; 32];
        k[..4].copy_from_slice(&i.to_be_bytes());
        k[31] = 0x40;
        k
    };
    let mut c = control(&dir, DEVICE, ADMIN, 1);
    c.session_started(secs(0));
    for i in 1..=SESSION_NEW_REMOVALS {
        let out = c.handle(secs(1), 10, &entry_bytes(1, i, key(i)));
        assert_eq!(sends(&out).len(), 1, "entry {i} is acked");
    }
    let before = std::fs::read(dir.join(REMOVED_FILE)).unwrap();
    let over = SESSION_NEW_REMOVALS + 1;
    let out = c.handle(secs(2), 10, &entry_bytes(2, over, key(over)));
    assert!(sends(&out).is_empty(), "a refused entry is not acked");
    assert_eq!(notes(&out), vec!["removal_refused"]);
    assert_eq!(std::fs::read(dir.join(REMOVED_FILE)).unwrap(), before);
    assert!(!is_removed(&dir, &key(over)));
    // An entry we already hold is still acked.
    let again = c.handle(secs(3), 10, &entry_bytes(3, 1, key(1)));
    assert_eq!(sends(&again).len(), 1);
    // A new session gets a new budget.
    let mut c2 = control(&dir, DEVICE, ADMIN, 2);
    c2.session_started(secs(0));
    let out = c2.handle(secs(1), 10, &entry_bytes(4, over, key(over)));
    assert_eq!(sends(&out).len(), 1);
    assert!(is_removed(&dir, &key(over)));
}
