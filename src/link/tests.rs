//! Link tests that need access to a pair of links and raw packets.

use std::time::Duration;

use super::*;

/// Small deterministic generator for indexes and test data.
pub(super) struct TestRng(pub u64);

impl TestRng {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

impl Entropy for TestRng {
    fn fill(&mut self, dst: &mut [u8]) {
        for b in dst {
            *b = self.next() as u8;
        }
    }
}

pub(super) fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

pub(super) struct Pair {
    pub a: Link,
    pub b: Link,
    pub a_key: [u8; 32],
    pub b_key: [u8; 32],
}

fn random_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    getrandom::fill(&mut k).unwrap();
    k
}

pub(super) fn pair(cfg: Config) -> Pair {
    let (a_key, b_key) = (random_key(), random_key());
    let ia = Identity::from_private_bytes(&a_key).unwrap();
    let ib = Identity::from_private_bytes(&b_key).unwrap();
    let a = Link::new(
        &ia,
        *ib.public_key(),
        cfg.clone(),
        Box::new(TestRng(1)),
        Duration::from_secs(1_000_000),
        Box::new(MemoryTimestampStore::default()),
    )
    .unwrap();
    let b = Link::new(
        &ib,
        *ia.public_key(),
        cfg,
        Box::new(TestRng(2)),
        Duration::from_secs(1_000_000),
        Box::new(MemoryTimestampStore::default()),
    )
    .unwrap();
    Pair { a, b, a_key, b_key }
}

pub(super) fn sends(events: &[Event]) -> Vec<Vec<u8>> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::Send { packet, .. } => Some(packet.clone()),
            _ => None,
        })
        .collect()
}

pub(super) fn delivered(events: &[Event]) -> Vec<Vec<u8>> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::Deliver(p) => Some(p.clone()),
            _ => None,
        })
        .collect()
}

pub(super) fn drops(events: &[Event]) -> Vec<DropReason> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::Dropped(r) => Some(*r),
            _ => None,
        })
        .collect()
}

/// A established link: `a` is the initiator. Returns the pair and the time.
pub(super) fn established(cfg: Config) -> (Pair, Duration) {
    let cl = cfg.counter_len;
    let mut p = pair(cfg);
    let now = ms(10);
    let ev = p.a.start_handshake(now).unwrap();
    let hs1 = sends(&ev).remove(0);
    assert_eq!(hs1.len(), 111);
    let ev = p.b.handle_packet(now, &hs1);
    let hs2 = sends(&ev).remove(0);
    assert_eq!(hs2.len(), 53);
    let ev = p.a.handle_packet(now, &hs2);
    assert!(ev.contains(&Event::SessionEstablished {
        initiator: true,
        rekey: false
    }));
    // The initiator's keepalive makes the responder switch.
    let ka = sends(&ev).remove(0);
    assert_eq!(ka.len(), data_overhead(cl));
    let ev = p.b.handle_packet(now, &ka);
    assert!(ev.contains(&Event::SessionEstablished {
        initiator: false,
        rekey: false
    }));
    (p, now)
}

#[test]
fn handshake_then_data_both_ways() {
    for len in [CounterLen::Short, CounterLen::Long] {
        let cfg = Config {
            counter_len: len,
            ..Config::default()
        };
        let (mut p, now) = established(cfg);
        for i in 0..5u8 {
            let pkt = p.a.send(now, &[i, 1, 2, 3]).unwrap();
            assert_eq!(pkt.len(), 4 + data_overhead(len));
            let ev = p.b.handle_packet(now, &pkt);
            assert_eq!(delivered(&ev), vec![vec![i, 1, 2, 3]]);
            let pkt = p.b.send(now, &[9, i]).unwrap();
            let ev = p.a.handle_packet(now, &pkt);
            assert_eq!(delivered(&ev), vec![vec![9, i]]);
        }
        assert_eq!(p.a.stats().sent, 5);
        assert_eq!(p.b.stats().delivered, 5);
    }
}

#[test]
fn send_refuses_empty_oversized_and_no_session() {
    let mut p = pair(Config::default());
    assert_eq!(p.a.send(ms(0), b"x"), Err(SendError::NoSession));
    let (mut p, now) = established(Config::default());
    assert_eq!(p.a.send(now, b""), Err(SendError::Empty));
    assert!(p.a.send(now, &[0u8; 107]).is_ok());
    assert_eq!(p.a.send(now, &[0u8; 108]), Err(SendError::TooLarge));
    let long = Config {
        counter_len: CounterLen::Long,
        ..Config::default()
    };
    let (mut p, now) = established(long);
    assert!(p.a.send(now, &[0u8; 105]).is_ok());
    assert_eq!(p.a.send(now, &[0u8; 106]), Err(SendError::TooLarge));
}

#[test]
fn bits_flipped_in_any_byte_of_a_data_packet_are_never_delivered() {
    for len in [CounterLen::Short, CounterLen::Long] {
        let cfg = Config {
            counter_len: len,
            ..Config::default()
        };
        let (mut p, now) = established(cfg);
        let good = p.a.send(now, b"hello world").unwrap();
        let mut seen_reasons = std::collections::HashSet::new();
        for byte in 0..good.len() {
            for bit in 0..8 {
                let mut bad = good.clone();
                bad[byte] ^= 1 << bit;
                let ev = p.b.handle_packet(now, &bad);
                assert!(delivered(&ev).is_empty(), "byte {byte} bit {bit}");
                assert!(
                    sends(&ev).is_empty(),
                    "never answers: byte {byte} bit {bit}"
                );
                let d = drops(&ev);
                assert_eq!(d.len(), 1, "byte {byte} bit {bit}: {ev:?}");
                // Header fields give bad_header, the index unknown_index, the
                // counter or ciphertext or tag bad_tag (or too_old).
                let want: &[DropReason] = match byte {
                    0 => &[DropReason::BadHeader, DropReason::BadTag],
                    1 | 2 => &[DropReason::UnknownIndex],
                    _ => &[DropReason::BadTag, DropReason::TooOld],
                };
                assert!(want.contains(&d[0]), "byte {byte} bit {bit}: {:?}", d[0]);
                seen_reasons.insert(d[0]);
            }
        }
        assert!(seen_reasons.contains(&DropReason::BadTag));
        assert!(seen_reasons.contains(&DropReason::UnknownIndex));
        assert!(seen_reasons.contains(&DropReason::BadHeader));
        // The unchanged packet still works: forged packets moved nothing.
        let ev = p.b.handle_packet(now, &good);
        assert_eq!(delivered(&ev), vec![b"hello world".to_vec()]);
        // And is a replay the second time.
        let ev = p.b.handle_packet(now, &good);
        assert_eq!(drops(&ev), vec![DropReason::Replay]);
    }
}

#[test]
fn truncated_and_extended_data_packets_are_dropped() {
    let (mut p, now) = established(Config::default());
    let good = p.a.send(now, b"abcdef").unwrap();
    for n in 0..good.len() {
        let ev = p.b.handle_packet(now, &good[..n]);
        assert!(delivered(&ev).is_empty());
        assert_eq!(drops(&ev).len(), 1, "cut to {n}");
        assert!(sends(&ev).is_empty());
    }
    let mut longer = good.clone();
    longer.push(0);
    let ev = p.b.handle_packet(now, &longer);
    assert_eq!(drops(&ev), vec![DropReason::BadTag]);
    let ev = p.b.handle_packet(now, &vec![0x30u8; 5000]);
    assert_eq!(drops(&ev), vec![DropReason::BadHeader]);
}

#[test]
fn random_bytes_are_dropped_and_never_answered() {
    let (mut p, now) = established(Config::default());
    let mut rng = TestRng(77);
    for count in 0..5000u64 {
        let len = (rng.next() % 129) as usize;
        let mut buf = vec![0u8; len];
        rng.fill(&mut buf);
        // Make a third of them look like real headers.
        if len > 0 && rng.next().is_multiple_of(3) {
            buf[0] = [0x10, 0x20, 0x30, 0x38][(rng.next() % 4) as usize];
        }
        let ev = p.b.handle_packet(now + ms(count * 10), &buf);
        assert!(delivered(&ev).is_empty());
        assert!(sends(&ev).is_empty(), "answered garbage: {ev:?}");
    }
    assert_eq!(p.b.stats().total_dropped(), 5000);
}

#[test]
fn wrong_index_and_wrong_version_and_reserved_types() {
    let (mut p, now) = established(Config::default());
    let good = p.a.send(now, b"x").unwrap();
    // Wrong index: every other 16-bit value is unknown.
    let real = u16::from_be_bytes([good[1], good[2]]);
    for idx in [0u16, 1, real ^ 1, real.wrapping_add(1), u16::MAX] {
        if idx == real {
            continue;
        }
        let mut bad = good.clone();
        bad[1..3].copy_from_slice(&idx.to_be_bytes());
        let ev = p.b.handle_packet(now, &bad);
        assert_eq!(drops(&ev), vec![DropReason::UnknownIndex], "index {idx}");
    }
    for v in 1..8u8 {
        let mut bad = good.clone();
        bad[0] = (bad[0] & !7) | v;
        assert_eq!(
            drops(&p.b.handle_packet(now, &bad)),
            vec![DropReason::BadHeader]
        );
    }
    for t in [0u8, 4, 5, 8, 15] {
        let mut bad = good.clone();
        bad[0] = (t << 4) | (bad[0] & 0x0F);
        assert_eq!(
            drops(&p.b.handle_packet(now, &bad)),
            vec![DropReason::BadHeader]
        );
    }
    // After all that, the real packet is still accepted once.
    assert_eq!(delivered(&p.b.handle_packet(now, &good)).len(), 1);
}

#[test]
fn counter_flag_flip_changes_the_meaning_and_fails_the_tag() {
    let (mut p, now) = established(Config::default());
    let good = p.a.send(now, b"payload").unwrap();
    // Claim a long counter: two ciphertext bytes become counter bytes.
    let mut bad = good.clone();
    bad[0] |= 0x08;
    let ev = p.b.handle_packet(now, &bad);
    assert!(delivered(&ev).is_empty());
    assert_eq!(drops(&ev).len(), 1);
}

#[test]
fn handshake_packets_with_flipped_bits_get_no_reply() {
    let mut p = pair(Config::default());
    let ev = p.a.start_handshake(ms(5)).unwrap();
    let hs1 = sends(&ev).remove(0);
    for byte in 0..hs1.len() {
        for bit in 0..8 {
            let mut bad = hs1.clone();
            bad[byte] ^= 1 << bit;
            // A fresh responder each time keeps rate limits out of this test.
            let mut b = fresh_responder(&p);
            let ev = b.handle_packet(ms(5), &bad);
            if byte == 1 || byte == 2 {
                // The sender index is not authenticated (it only says where
                // the reply's "receiver" field points), so this one is
                // accepted. The reply then carries the changed index.
                assert_eq!(sends(&ev).len(), 1);
            } else {
                assert!(sends(&ev).is_empty(), "byte {byte} bit {bit}: {ev:?}");
                assert_eq!(drops(&ev).len(), 1);
            }
        }
    }
}

fn fresh_responder(p: &Pair) -> Link {
    let ia = Identity::from_private_bytes(&p.a_key).unwrap();
    let ib = Identity::from_private_bytes(&p.b_key).unwrap();
    Link::new(
        &ib,
        *ia.public_key(),
        Config::default(),
        Box::new(TestRng(5)),
        Duration::from_secs(1_000_000),
        Box::new(MemoryTimestampStore::default()),
    )
    .unwrap()
}
