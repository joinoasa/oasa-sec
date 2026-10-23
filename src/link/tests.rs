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
    assert_eq!(hs1.len(), 113);
    let ev = p.b.handle_packet(now, &hs1);
    let hs2 = sends(&ev).remove(0);
    assert_eq!(hs2.len(), 57);
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
    // The responder's confirmation reaches the initiator.
    let confirm = sends(&ev).remove(0);
    p.a.handle_packet(now, &confirm);
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
            assert!(sends(&ev).is_empty(), "byte {byte} bit {bit}: {ev:?}");
            assert_eq!(drops(&ev).len(), 1);
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

fn index_of(data_packet: &[u8]) -> u16 {
    u16::from_be_bytes([data_packet[1], data_packet[2]])
}

fn link_from(
    my_key: &[u8; 32],
    peer_pub: [u8; 32],
    seed: u64,
    store: Box<dyn TimestampStore>,
    wall: Duration,
) -> Link {
    Link::new(
        &Identity::from_private_bytes(my_key).unwrap(),
        peer_pub,
        Config::default(),
        Box::new(TestRng(seed)),
        wall,
        store,
    )
    .unwrap()
}

fn pub_of(key: &[u8; 32]) -> [u8; 32] {
    *Identity::from_private_bytes(key).unwrap().public_key()
}

#[test]
fn untrusted_initiator_gets_no_reply_and_is_counted() {
    let p = pair(Config::default());
    let mut b = fresh_responder(&p);
    let c_key = random_key();
    let mut c = link_from(
        &c_key,
        pub_of(&p.b_key),
        9,
        Box::new(MemoryTimestampStore::default()),
        Duration::from_secs(1_000_000),
    );
    let hs1 = sends(&c.start_handshake(ms(1)).unwrap()).remove(0);
    let ev = b.handle_packet(ms(1), &hs1);
    assert!(sends(&ev).is_empty());
    assert_eq!(drops(&ev), vec![DropReason::UntrustedPeer]);
    assert_eq!(b.stats().dropped(DropReason::UntrustedPeer), 1);
    assert_eq!(b.stats().handshakes_accepted, 0);
}

#[test]
fn replayed_handshake_is_stale_and_does_not_break_the_session() {
    let mut p = pair(Config::default());
    let hs1 = sends(&p.a.start_handshake(ms(10)).unwrap()).remove(0);
    let hs2 = sends(&p.b.handle_packet(ms(10), &hs1)).remove(0);
    let ka = sends(&p.a.handle_packet(ms(10), &hs2)).remove(0);
    p.b.handle_packet(ms(10), &ka);
    let first = p.a.send(ms(20), b"one").unwrap();
    // The attacker replays the recorded handshake 1, much later.
    let ev = p.b.handle_packet(ms(5000), &hs1);
    assert_eq!(drops(&ev), vec![DropReason::StaleHandshake]);
    assert!(sends(&ev).is_empty());
    // The working session carries on, both ways.
    assert_eq!(delivered(&p.b.handle_packet(ms(5001), &first)).len(), 1);
    let back = p.b.send(ms(5002), b"two").unwrap();
    assert_eq!(delivered(&p.a.handle_packet(ms(5003), &back)).len(), 1);
    // And again, and a replayed handshake 2 does nothing at the initiator.
    assert_eq!(
        drops(&p.b.handle_packet(ms(9000), &hs1)),
        vec![DropReason::StaleHandshake]
    );
    let ev = p.a.handle_packet(ms(9001), &hs2);
    assert_eq!(drops(&ev), vec![DropReason::UnknownIndex]);
    assert!(sends(&ev).is_empty());
}

#[test]
fn responder_keeps_its_old_session_until_a_valid_data_packet() {
    let (mut p, _) = established(Config::default());
    let old_b = index_of(&p.b.send(ms(100), b"x").unwrap());
    // Rekey: a sends a new handshake 1.
    let hs1 = sends(&p.a.start_handshake(ms(2000)).unwrap()).remove(0);
    let ev = p.b.handle_packet(ms(2000), &hs1);
    let hs2 = sends(&ev).remove(0);
    // After answering, b still sends on the old session.
    assert!(
        !ev.iter()
            .any(|e| matches!(e, Event::SessionEstablished { .. }))
    );
    assert_eq!(index_of(&p.b.send(ms(2001), b"y").unwrap()), old_b);
    // A forged packet on the new session's index changes nothing.
    let ev = p.a.handle_packet(ms(2002), &hs2);
    let ka = sends(&ev).remove(0);
    let mut forged = ka.clone();
    let last = forged.len() - 1;
    forged[last] ^= 1;
    p.b.handle_packet(ms(2003), &forged);
    assert_eq!(index_of(&p.b.send(ms(2004), b"z").unwrap()), old_b);
    // The old session still delivers from b to a (a keeps it readable).
    let from_old = p.b.send(ms(2005), b"still old").unwrap();
    assert_eq!(delivered(&p.a.handle_packet(ms(2006), &from_old)).len(), 1);
    // The real keepalive switches b over.
    let ev = p.b.handle_packet(ms(2007), &ka);
    assert!(ev.contains(&Event::SessionEstablished {
        initiator: false,
        rekey: true
    }));
    let new_b = index_of(&p.b.send(ms(2008), b"w").unwrap());
    assert_ne!(new_b, old_b);
    // a now sends on the new session and b reads it.
    let pkt = p.a.send(ms(2009), b"fresh").unwrap();
    assert_eq!(delivered(&p.b.handle_packet(ms(2010), &pkt)).len(), 1);
}

#[test]
fn global_and_per_peer_handshake_rate_limits() {
    let p = pair(Config::default());
    // 30 handshakes from an untrusted device at one instant: 20 get far
    // enough to be refused as untrusted, the other 10 are rate limited.
    let mut b = fresh_responder(&p);
    let mut c = link_from(
        &random_key(),
        pub_of(&p.b_key),
        3,
        Box::new(MemoryTimestampStore::default()),
        Duration::from_secs(1_000_000),
    );
    let mut reasons = Vec::new();
    for _ in 0..30 {
        let hs1 = sends(&c.start_handshake(ms(500)).unwrap()).remove(0);
        reasons.extend(drops(&b.handle_packet(ms(500), &hs1)));
    }
    let untrusted = reasons
        .iter()
        .filter(|r| **r == DropReason::UntrustedPeer)
        .count();
    let limited = reasons
        .iter()
        .filter(|r| **r == DropReason::RateLimited)
        .count();
    assert_eq!((untrusted, limited), (20, 10));
    // A second later, tokens are back.
    let hs1 = sends(&c.start_handshake(ms(1500)).unwrap()).remove(0);
    assert_eq!(
        drops(&b.handle_packet(ms(1500), &hs1)),
        vec![DropReason::UntrustedPeer]
    );

    // Per peer: one accepted handshake a second.
    let mut a = link_from(
        &p.a_key,
        pub_of(&p.b_key),
        4,
        Box::new(MemoryTimestampStore::default()),
        Duration::from_secs(1_000_000),
    );
    let mut b = fresh_responder(&p);
    let h1 = sends(&a.start_handshake(ms(0)).unwrap()).remove(0);
    assert_eq!(sends(&b.handle_packet(ms(0), &h1)).len(), 1);
    let h2 = sends(&a.start_handshake(ms(300)).unwrap()).remove(0);
    let ev = b.handle_packet(ms(300), &h2);
    assert_eq!(drops(&ev), vec![DropReason::RateLimited]);
    assert!(sends(&ev).is_empty());
    // The same message a second later is accepted: rate limits are not
    // staleness (the timestamp was not recorded).
    assert_eq!(sends(&b.handle_packet(ms(1100), &h2)).len(), 1);
}

#[test]
fn handshake_retries_back_off_to_the_cap() {
    let mut p = pair(Config::default());
    let mut t = ms(0);
    let ev = p.a.start_handshake(t).unwrap();
    assert!(ev.contains(&Event::HandshakeSent {
        retry: false,
        rekey: false
    }));
    // No answer ever. Retries at +5, +10, +20, +40, +60, +60.
    let mut gaps = Vec::new();
    let mut last = t;
    while gaps.len() < 7 {
        t += ms(100);
        let ev = p.a.poll_timers(t);
        let sent = sends(&ev);
        if !sent.is_empty() {
            assert_eq!(sent.len(), 1);
            assert!(ev.contains(&Event::HandshakeSent {
                retry: true,
                rekey: false
            }));
            gaps.push((t - last).as_secs());
            last = t;
        }
    }
    assert_eq!(gaps, vec![5, 10, 20, 40, 60, 60, 60]);
    // Never before the delay.
    let mut q = pair(Config::default());
    q.a.start_handshake(ms(0)).unwrap();
    assert!(sends(&q.a.poll_timers(ms(4999))).is_empty());
    assert_eq!(sends(&q.a.poll_timers(ms(5000))).len(), 1);
}

#[test]
fn only_the_initiator_rekeys_and_only_when_due() {
    let cfg = Config {
        rekey_after: Duration::from_secs(100),
        reject_after: Duration::from_secs(150),
        keepalive: None,
        ..Config::default()
    };
    let (mut p, t0) = established(cfg);
    for s in [10u64, 50, 99] {
        assert!(p.a.poll_timers(t0 + Duration::from_secs(s)).is_empty());
        assert!(p.b.poll_timers(t0 + Duration::from_secs(s)).is_empty());
    }
    // The responder never starts one, even long past the rekey age.
    assert!(sends(&p.b.poll_timers(t0 + Duration::from_secs(120))).is_empty());
    let ev = p.a.poll_timers(t0 + Duration::from_secs(100));
    assert!(ev.contains(&Event::HandshakeSent {
        retry: false,
        rekey: true
    }));
    assert_eq!(sends(&ev)[0].len(), 113);
}

#[test]
fn rekey_by_packet_count() {
    let cfg = Config {
        rekey_after_packets: 5,
        reject_after_packets: 8,
        keepalive: None,
        ..Config::default()
    };
    let (mut p, t0) = established(cfg);
    // The keepalive already used counter 0.
    for i in 0..3 {
        p.a.send(t0, &[i]).unwrap();
        assert!(sends(&p.a.poll_timers(t0)).is_empty(), "after {i}");
    }
    p.a.send(t0, b"x").unwrap(); // counter 4 sent; 5 packets used
    assert_eq!(sends(&p.a.poll_timers(t0)).len(), 1, "handshake due");
    // Nobody sends past the hard limit.
    for _ in 0..3 {
        let _ = p.a.send(t0, b"y");
    }
    assert_eq!(p.a.send(t0, b"z"), Err(SendError::NoSession));
}

#[test]
fn sessions_expire_and_are_not_used_or_accepted() {
    let cfg = Config {
        rekey_after: Duration::from_secs(100),
        reject_after: Duration::from_secs(150),
        keepalive: None,
        ..Config::default()
    };
    let (mut p, t0) = established(cfg);
    let pkt = p.a.send(t0 + Duration::from_secs(149), b"late").unwrap();
    assert_eq!(
        delivered(&p.b.handle_packet(t0 + Duration::from_secs(149), &pkt)).len(),
        1
    );
    let after = t0 + Duration::from_secs(151);
    assert_eq!(p.a.send(after, b"x"), Err(SendError::NoSession));
    assert_eq!(p.b.send(after, b"x"), Err(SendError::NoSession));
    let before_pkt = p.a.send(t0 + Duration::from_secs(1), b"y").unwrap();
    let ev = p.b.handle_packet(after, &before_pkt);
    assert_eq!(drops(&ev), vec![DropReason::UnknownIndex]);
    p.a.poll_timers(after);
    p.b.poll_timers(after);
    assert!(!p.a.can_send());
    assert!(!p.b.can_send());
}

#[test]
fn expired_initiator_session_is_replaced_by_a_new_handshake() {
    let cfg = Config {
        rekey_after: Duration::from_secs(100),
        reject_after: Duration::from_secs(150),
        keepalive: None,
        ..Config::default()
    };
    let (mut p, t0) = established(cfg);
    // Everything lost for a long time, including the rekey handshake.
    let mut t = t0;
    let mut started = 0;
    while t < t0 + Duration::from_secs(400) {
        t += Duration::from_millis(500);
        let ev = p.a.poll_timers(t);
        started += sends(&ev).len();
    }
    assert!(started >= 5, "kept retrying: {started}");
    assert!(!p.a.can_send());
}

#[test]
fn keepalive_is_sent_when_idle_and_is_not_delivered() {
    let cfg = Config {
        keepalive: Some(Duration::from_secs(25)),
        ..Config::default()
    };
    let (mut p, t0) = established(cfg);
    assert!(p.a.poll_timers(t0 + Duration::from_secs(24)).is_empty());
    let ev = p.a.poll_timers(t0 + Duration::from_secs(25));
    let ka = sends(&ev);
    assert_eq!(ka.len(), 1);
    assert_eq!(ka[0].len(), 21);
    // Not repeated at once.
    assert!(p.a.poll_timers(t0 + Duration::from_secs(26)).is_empty());
    let ev = p.b.handle_packet(t0 + Duration::from_secs(26), &ka[0]);
    assert!(delivered(&ev).is_empty());
    assert!(ev.contains(&Event::Authenticated));
    assert_eq!(p.b.stats().keepalives_received, 2); // the first one made it switch
    // Sending data resets the idle timer.
    p.a.send(t0 + Duration::from_secs(40), b"d").unwrap();
    assert!(p.a.poll_timers(t0 + Duration::from_secs(60)).is_empty());
    // Off when not configured.
    let cfg = Config {
        keepalive: None,
        ..Config::default()
    };
    let (mut p, t0) = established(cfg);
    assert!(p.a.poll_timers(t0 + Duration::from_secs(500)).is_empty());
}

#[test]
fn timestamp_survives_restarts_on_both_sides() {
    let dir = crate::files::tempdir("link-ts");
    let a_key = random_key();
    let b_key = random_key();
    let (a_pub, b_pub) = (pub_of(&a_key), pub_of(&b_key));
    // A has no trusted clock (wall 0): timestamps come from the saved value.
    let mk_a = || {
        link_from(
            &a_key,
            b_pub,
            1,
            Box::new(FileTimestampStore::new(&dir, &b_pub)),
            Duration::ZERO,
        )
    };
    let dir_b = crate::files::tempdir("link-ts-b");
    let mk_b = || {
        link_from(
            &b_key,
            a_pub,
            2,
            Box::new(FileTimestampStore::new(&dir_b, &a_pub)),
            Duration::ZERO,
        )
    };
    let mut a = mk_a();
    let mut b = mk_b();
    let first = sends(&a.start_handshake(Duration::from_secs(50)).unwrap()).remove(0);
    assert_eq!(
        sends(&b.handle_packet(Duration::from_secs(50), &first)).len(),
        1
    );
    // Both reboot: monotonic time starts again near zero.
    let mut a = mk_a();
    let mut b = mk_b();
    // The recorded message is refused by the restarted responder.
    let ev = b.handle_packet(Duration::from_secs(1), &first);
    assert_eq!(drops(&ev), vec![DropReason::StaleHandshake]);
    // The restarted initiator's new message is newer even though its clock restarted.
    let second = sends(&a.start_handshake(Duration::from_secs(1)).unwrap()).remove(0);
    let ev = b.handle_packet(Duration::from_secs(2), &second);
    assert_eq!(sends(&ev).len(), 1, "{ev:?}");
}

#[test]
fn a_failing_timestamp_store_means_no_handshake_is_sent() {
    struct Broken;
    impl TimestampStore for Broken {
        fn load(&mut self) -> Result<StoredStamps> {
            Ok(StoredStamps::default())
        }
        fn save(&mut self, _: &StoredStamps) -> Result<()> {
            Err(Error::Link("disk full"))
        }
    }
    let p = pair(Config::default());
    let mut a = link_from(
        &p.a_key,
        pub_of(&p.b_key),
        1,
        Box::new(Broken),
        Duration::from_secs(5),
    );
    assert!(a.start_handshake(ms(1)).is_err());
    // A responder that cannot save does not answer.
    let mut good_a = link_from(
        &p.a_key,
        pub_of(&p.b_key),
        1,
        Box::new(MemoryTimestampStore::default()),
        Duration::from_secs(5),
    );
    let hs1 = sends(&good_a.start_handshake(ms(1)).unwrap()).remove(0);
    let mut b = link_from(
        &p.b_key,
        pub_of(&p.a_key),
        2,
        Box::new(Broken),
        Duration::ZERO,
    );
    let ev = b.handle_packet(ms(1), &hs1);
    assert!(sends(&ev).is_empty());
    assert!(ev.iter().any(|e| matches!(e, Event::Failure(_))));
}

#[test]
fn crossed_handshakes_still_deliver_both_ways() {
    let (mut p, t0) = established(Config::default());
    // Both sides start a new handshake at once.
    let t = t0 + Duration::from_secs(3);
    let h_a = sends(&p.a.start_handshake(t).unwrap()).remove(0);
    let h_b = sends(&p.b.start_handshake(t).unwrap()).remove(0);
    let r_b = sends(&p.b.handle_packet(t, &h_a)).remove(0); // b answers a
    let r_a = sends(&p.a.handle_packet(t, &h_b)).remove(0); // a answers b
    let ka_a = sends(&p.a.handle_packet(t, &r_b)); // a is initiator of its own
    let ka_b = sends(&p.b.handle_packet(t, &r_a));
    for pkt in ka_a {
        p.b.handle_packet(t, &pkt);
    }
    for pkt in ka_b {
        p.a.handle_packet(t, &pkt);
    }
    for i in 0..20u8 {
        let t = t + ms(u64::from(i) * 100);
        let x = p.a.send(t, &[1, i]).unwrap();
        assert_eq!(delivered(&p.b.handle_packet(t, &x)), vec![vec![1, i]]);
        let y = p.b.send(t, &[2, i]).unwrap();
        assert_eq!(delivered(&p.a.handle_packet(t, &y)), vec![vec![2, i]]);
    }
}

#[test]
fn endpoint_serves_several_peers_and_routes_by_index() {
    let ground = Identity::generate().unwrap();
    let d1 = random_key();
    let d2 = random_key();
    let d3 = random_key(); // not added
    let mut g = Endpoint::new(
        &ground,
        Config::default(),
        Box::new(TestRng(1)),
        Duration::from_secs(1_000_000),
    )
    .unwrap();
    let p1 = g
        .add_peer(pub_of(&d1), Box::new(MemoryTimestampStore::default()))
        .unwrap();
    let p2 = g
        .add_peer(pub_of(&d2), Box::new(MemoryTimestampStore::default()))
        .unwrap();
    assert!(
        g.add_peer(pub_of(&d1), Box::new(MemoryTimestampStore::default()))
            .is_err(),
        "duplicate"
    );
    assert!(
        g.add_peer(
            *ground.public_key(),
            Box::new(MemoryTimestampStore::default())
        )
        .is_err(),
        "own key"
    );
    let gpub = *ground.public_key();
    let mk = |k: &[u8; 32], seed| {
        link_from(
            k,
            gpub,
            seed,
            Box::new(MemoryTimestampStore::default()),
            Duration::from_secs(1_000_000),
        )
    };
    let (mut l1, mut l2, mut l3) = (mk(&d1, 11), mk(&d2, 12), mk(&d3, 13));
    let mut who = Vec::new();
    for l in [&mut l1, &mut l2, &mut l3] {
        let hs1 = sends(&l.start_handshake(ms(10)).unwrap()).remove(0);
        let evs = g.handle_packet(ms(10), &hs1);
        let hs2 = evs.iter().find_map(|(p, e)| match e {
            Event::Send { packet, .. } => {
                who.push(*p);
                Some(packet.clone())
            }
            _ => None,
        });
        if let Some(hs2) = hs2 {
            let ka = sends(&l.handle_packet(ms(10), &hs2)).remove(0);
            let evs = g.handle_packet(ms(10), &ka);
            assert!(
                evs.iter().any(|(_, e)| matches!(
                    e,
                    Event::Deliver(_) | Event::SessionEstablished { .. }
                ))
            );
        } else {
            assert!(
                evs.iter()
                    .any(|(p, e)| p.is_none() && *e == Event::Dropped(DropReason::UntrustedPeer))
            );
        }
    }
    assert_eq!(who, vec![Some(p1), Some(p2)]);
    assert!(g.can_send(p1) && g.can_send(p2));
    // Messages go to the right drone and nowhere else.
    let to1 = g.send(p1, ms(20), b"for one").unwrap();
    let to2 = g.send(p2, ms(20), b"for two").unwrap();
    assert_eq!(
        delivered(&l1.handle_packet(ms(20), &to1)),
        vec![b"for one".to_vec()]
    );
    assert_eq!(drops(&l2.handle_packet(ms(20), &to1)).len(), 1);
    assert_eq!(
        delivered(&l2.handle_packet(ms(20), &to2)),
        vec![b"for two".to_vec()]
    );
    let up = l2.send(ms(21), b"from two").unwrap();
    let evs = g.handle_packet(ms(21), &up);
    assert!(
        evs.iter()
            .any(|(p, e)| *p == Some(p2) && *e == Event::Deliver(b"from two".to_vec()))
    );
    // Removing a peer ends its sessions.
    g.remove_peer(p1);
    assert_eq!(g.send(p1, ms(30), b"x"), Err(SendError::UnknownPeer));
    let up = l1.send(ms(31), b"after removal").unwrap();
    let evs = g.handle_packet(ms(31), &up);
    assert!(evs.iter().all(|(_, e)| !matches!(e, Event::Deliver(_))));
    // And it cannot come back with a new handshake.
    let hs1 = sends(&l1.start_handshake(ms(5000)).unwrap()).remove(0);
    let evs = g.handle_packet(ms(5000), &hs1);
    assert!(
        evs.iter()
            .any(|(_, e)| *e == Event::Dropped(DropReason::UntrustedPeer))
    );
}

#[test]
fn indexes_never_collide_with_live_ones() {
    // A generator that always proposes the same index forces the retry path.
    struct Stuck(u64);
    impl Entropy for Stuck {
        fn fill(&mut self, dst: &mut [u8]) {
            self.0 += 1;
            // The first 100 calls return index 7; then it varies.
            let v: u16 = if self.0 < 100 { 7 } else { self.0 as u16 };
            dst.copy_from_slice(&v.to_be_bytes());
        }
    }
    let ground = Identity::generate().unwrap();
    let mut g = Endpoint::new(
        &ground,
        Config::default(),
        Box::new(Stuck(0)),
        Duration::ZERO,
    )
    .unwrap();
    let a = g
        .add_peer([1; 32], Box::new(MemoryTimestampStore::default()))
        .unwrap();
    let b = g
        .add_peer([2; 32], Box::new(MemoryTimestampStore::default()))
        .unwrap();
    let ev1 = g.start_handshake(a, ms(1)).unwrap();
    let ev2 = g.start_handshake(b, ms(1)).unwrap();
    let i1 = u16::from_be_bytes([sends(&ev1)[0][1], sends(&ev1)[0][2]]);
    let i2 = u16::from_be_bytes([sends(&ev2)[0][1], sends(&ev2)[0][2]]);
    assert_eq!(i1, 7);
    assert_ne!(i2, 7);
}

#[test]
fn config_validation_refuses_unsafe_settings() {
    let ok = Config::default();
    assert!(ok.validate().is_ok());
    let bad = [
        Config {
            mtu: 127,
            ..ok.clone()
        },
        Config {
            mtu: 70_000,
            ..ok.clone()
        },
        Config {
            reject_after_packets: (1 << 60) + 1,
            ..ok.clone()
        },
        Config {
            rekey_after_packets: 1 << 60,
            ..ok.clone()
        },
        Config {
            rekey_after: ok.reject_after,
            ..ok.clone()
        },
        Config {
            rekey_after: Duration::ZERO,
            ..ok.clone()
        },
        Config {
            retry_max: Duration::from_secs(1),
            ..ok.clone()
        },
        Config {
            handshakes_per_second: 0,
            ..ok.clone()
        },
    ];
    for c in bad {
        assert!(c.validate().is_err(), "{c:?}");
    }
}

#[test]
fn debug_output_never_shows_contents_or_keys() {
    let (mut p, now) = established(Config::default());
    let pkt = p.a.send(now, b"TOP-SECRET-MARKER").unwrap();
    let ev = p.b.handle_packet(now, &pkt);
    let text = format!("{ev:?} {:?} {:?} {:?}", p.a, p.b, p.a.stats());
    assert!(!text.contains("TOP-SECRET-MARKER"));
    assert!(!text.contains("84, 79, 80")); // the bytes of the marker
    assert!(text.contains("Deliver(17 bytes)"));
}

#[test]
fn ciphertext_does_not_contain_the_plaintext() {
    let (mut p, now) = established(Config::default());
    let marker = b"PLAINTEXT-MARKER-0123456789";
    let pkt = p.a.send(now, marker).unwrap();
    assert!(!pkt.windows(marker.len()).any(|w| w == marker));
    // The same plaintext twice gives different ciphertext (new counter).
    let pkt2 = p.a.send(now, marker).unwrap();
    assert_ne!(pkt[5..], pkt2[5..]);
}

#[test]
fn changed_handshake_indexes_are_refused_without_side_effects() {
    // Handshake 1: the clear sender index must equal the encrypted one.
    let mut p = pair(Config::default());
    let hs1 = sends(&p.a.start_handshake(ms(0)).unwrap()).remove(0);
    for byte in [1usize, 2] {
        let mut bad = hs1.clone();
        bad[byte] ^= 0x5A;
        let ev = p.b.handle_packet(ms(0), &bad);
        assert_eq!(drops(&ev), vec![DropReason::BadHeader]);
        assert!(sends(&ev).is_empty());
    }
    // Nothing was recorded: the real one is still accepted at once (no
    // stale timestamp, no per-peer allowance used).
    let ev = p.b.handle_packet(ms(10), &hs1);
    assert_eq!(sends(&ev).len(), 1);
    assert_eq!(p.b.stats().dropped(DropReason::StaleHandshake), 0);
    assert_eq!(p.b.stats().dropped(DropReason::RateLimited), 0);
    let hs2 = sends(&ev).remove(0);

    // Handshake 2: either clear index changed: dropped, no session.
    for byte in [1usize, 2, 3, 4] {
        let mut q = pair(Config::default());
        let h1 = sends(&q.a.start_handshake(ms(0)).unwrap()).remove(0);
        let mut h2 = sends(&q.b.handle_packet(ms(0), &h1)).remove(0);
        h2[byte] ^= 0x5A;
        let ev = q.a.handle_packet(ms(10), &h2);
        let d = drops(&ev);
        // A changed receiver index may also simply not match any handshake.
        assert!(
            d == vec![DropReason::BadHeader] || (byte >= 3 && d == vec![DropReason::UnknownIndex]),
            "byte {byte}: {d:?}"
        );
        assert!(
            !ev.iter()
                .any(|e| matches!(e, Event::SessionEstablished { .. }))
        );
        assert!(sends(&ev).is_empty());
        assert!(!q.a.can_send());
    }
    // The untouched hs2 still completes (with the first pair).
    let ev = p.a.handle_packet(ms(20), &hs2);
    assert!(
        ev.iter()
            .any(|e| matches!(e, Event::SessionEstablished { .. }))
    );
}

#[test]
fn a_changed_handshake_2_is_retried_by_the_timer() {
    let mut p = pair(Config::default());
    let hs1 = sends(&p.a.start_handshake(ms(0)).unwrap()).remove(0);
    let mut hs2 = sends(&p.b.handle_packet(ms(0), &hs1)).remove(0);
    hs2[1] ^= 0x55;
    assert_eq!(
        drops(&p.a.handle_packet(ms(10), &hs2)),
        vec![DropReason::BadHeader]
    );
    let hs1 = sends(&p.a.poll_timers(ms(5100))).remove(0);
    let hs2 = sends(&p.b.handle_packet(ms(5200), &hs1)).remove(0);
    let ka = sends(&p.a.handle_packet(ms(5300), &hs2)).remove(0);
    p.b.handle_packet(ms(5300), &ka);
    let data = p.a.send(ms(5400), b"through").unwrap();
    assert_eq!(
        delivered(&p.b.handle_packet(ms(5400), &data)),
        vec![b"through".to_vec()]
    );
}

#[test]
fn an_unconfirmed_session_is_replaced_and_does_not_push_out_the_working_one() {
    let (mut p, t0) = established(Config::default());
    let first = p.b.send(t0, b"hello").unwrap();
    p.a.handle_packet(t0, &first); // a has seen data on the old session
    let old_b = index_of(&first);
    // Rekey: a gets hs2, but nothing it sends on the new session reaches b.
    let t = t0 + Duration::from_secs(2);
    let hs1 = sends(&p.a.start_handshake(t).unwrap()).remove(0);
    let hs2 = sends(&p.b.handle_packet(t, &hs1)).remove(0);
    p.a.handle_packet(t, &hs2); // keepalive lost
    assert!(sends(&p.a.poll_timers(t + ms(4900))).is_empty());
    // After the retry time with no valid packet back, a asks again.
    let t2 = t + ms(5100);
    let hs1 = sends(&p.a.poll_timers(t2)).remove(0);
    let hs2 = sends(&p.b.handle_packet(t2, &hs1)).remove(0);
    p.a.handle_packet(t2, &hs2); // keepalive lost again
    // b still sends on its old session; a must still read it.
    let still = p.b.send(t2 + ms(100), b"still on old").unwrap();
    assert_eq!(index_of(&still), old_b);
    assert_eq!(
        delivered(&p.a.handle_packet(t2 + ms(100), &still)),
        vec![b"still on old".to_vec()]
    );
}
