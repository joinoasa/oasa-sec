//! Link security, test plan F19: every tampered packet is rejected and
//! counted, a nonce never repeats under a key, and a rekey at full load
//! loses nothing.
//!
//! Done when (F19): at least 1,000 each of replayed, bit-flipped, truncated
//! and wrong-key packets are 100 % rejected and counted; the nonce never
//! repeats across a rekey, a restart or a power cycle; a rekey at full load
//! loses 0 packets.
//!
//! Two links joined by a lossless in-memory channel with a fixed delay and a
//! virtual clock. Seeds are fixed (they pick session indexes and the
//! attacks); handshake keys come from the operating system through `snow`.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::time::Duration;

use oasa_sec::identity::Identity;
use oasa_sec::link::{
    Config, CounterLen, DropReason, Entropy, Event, Link, MemoryTimestampStore, Stats,
    data_overhead,
};

/// splitmix64, as in `link_sim.rs`.
#[derive(Clone)]
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

impl Entropy for Rng {
    fn fill(&mut self, dst: &mut [u8]) {
        for b in dst {
            *b = self.next() as u8;
        }
    }
}

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn key(rng: &mut Rng) -> [u8; 32] {
    let mut k = [0u8; 32];
    rng.fill(&mut k);
    k
}

fn public(k: &[u8; 32]) -> [u8; 32] {
    *Identity::from_private_bytes(k).unwrap().public_key()
}

fn config(len: CounterLen) -> Config {
    Config {
        counter_len: len,
        rekey_after: Duration::from_secs(60),
        reject_after: Duration::from_secs(180),
        ..Config::default()
    }
}

fn new_link(own: &[u8; 32], peer: &[u8; 32], cfg: &Config, seed: u64, now: Duration) -> Link {
    Link::new(
        &Identity::from_private_bytes(own).unwrap(),
        public(peer),
        cfg.clone(),
        Box::new(Rng(seed)),
        Duration::from_secs(1_700_000_000) + now,
        Box::new(MemoryTimestampStore::default()),
    )
    .unwrap()
}

/// Delivery time, tie-break sequence number, receiving side, bytes.
type Queued = (Duration, u64, usize, Vec<u8>);

const A: usize = 0;
const B: usize = 1;

/// Two links, a channel with a fixed one-way delay, a virtual clock.
struct Pair {
    links: [Link; 2],
    keys: [[u8; 32]; 2],
    cfg: Config,
    now: Duration,
    delay: Duration,
    queue: BinaryHeap<Reverse<Queued>>,
    seq: u64,
    delivered: [Vec<Vec<u8>>; 2],
    established: [u32; 2],
    /// Data packets each side put on the wire (handshakes left out).
    data_wire: [Vec<Vec<u8>>; 2],
}

impl Pair {
    fn new(seed: u64, cfg: Config) -> Self {
        let mut rng = Rng(seed);
        let keys = [key(&mut rng), key(&mut rng)];
        let links = [
            new_link(&keys[A], &keys[B], &cfg, seed ^ 0xA, Duration::ZERO),
            new_link(&keys[B], &keys[A], &cfg, seed ^ 0xB, Duration::ZERO),
        ];
        Self {
            links,
            keys,
            cfg,
            now: Duration::ZERO,
            delay: ms(5),
            queue: BinaryHeap::new(),
            seq: 0,
            delivered: [Vec::new(), Vec::new()],
            established: [0, 0],
            data_wire: [Vec::new(), Vec::new()],
        }
    }

    fn put(&mut self, from: usize, bytes: Vec<u8>) {
        if bytes[0] >> 4 == 3 {
            self.data_wire[from].push(bytes.clone());
        }
        self.seq += 1;
        self.queue
            .push(Reverse((self.now + self.delay, self.seq, 1 - from, bytes)));
    }

    fn events(&mut self, side: usize, evs: Vec<Event>) {
        for e in evs {
            match e {
                Event::Send { packet, .. } => self.put(side, packet),
                Event::Deliver(p) => self.delivered[side].push(p),
                Event::SessionEstablished { .. } => self.established[side] += 1,
                Event::Failure(why) => panic!("side {side}: local failure {why}"),
                _ => {}
            }
        }
    }

    /// Advance the clock to `to`, delivering what falls due and running the timers.
    fn run_until(&mut self, to: Duration) {
        while let Some(Reverse((t, _, _, _))) = self.queue.peek() {
            if *t > to {
                break;
            }
            let Reverse((t, _, dst, bytes)) = self.queue.pop().unwrap();
            self.now = t;
            let evs = self.links[dst].handle_packet(t, &bytes);
            self.events(dst, evs);
        }
        self.now = to;
        for side in [A, B] {
            let evs = self.links[side].poll_timers(to);
            self.events(side, evs);
        }
    }

    fn handshake(&mut self, initiator: usize) {
        // The responder answers a peer at most once a second (peer_handshake_gap).
        let t = self.now + Duration::from_secs(2);
        self.run_until(t);
        let before = self.established;
        let evs = self.links[initiator].start_handshake(self.now).unwrap();
        self.events(initiator, evs);
        for _ in 0..100 {
            let t = self.now + ms(5);
            self.run_until(t);
            if self.established[A] > before[A] && self.established[B] > before[B] {
                return;
            }
        }
        panic!("no handshake");
    }

    /// `side` makes one data packet and keeps it off the channel.
    fn make(&mut self, side: usize, payload: &[u8]) -> Vec<u8> {
        let p = self.links[side].send(self.now, payload).unwrap();
        self.data_wire[side].push(p.clone());
        p
    }

    /// Hand `bytes` to `side` directly (an attacker on the path).
    fn inject(&mut self, side: usize, bytes: &[u8]) -> Vec<Event> {
        let evs = self.links[side].handle_packet(self.now, bytes);
        let keep = evs.clone();
        self.events(side, evs);
        keep
    }

    /// The device on `side` loses all session state (a restart or a power
    /// cycle): same key and settings, new process.
    fn restart(&mut self, side: usize, seed: u64) {
        let peer = self.keys[1 - side];
        self.links[side] = new_link(&self.keys[side], &peer, &self.cfg, seed, self.now);
    }

    fn stats(&self, side: usize) -> Stats {
        self.links[side].stats().clone()
    }
}

/// An injected packet must be dropped: no delivery, nothing sent back, exactly
/// one `Dropped` event. Returns the reason.
fn rejected(evs: &[Event]) -> DropReason {
    let drops: Vec<DropReason> = evs
        .iter()
        .filter_map(|e| match e {
            Event::Dropped(r) => Some(*r),
            _ => None,
        })
        .collect();
    assert!(
        evs.iter()
            .all(|e| matches!(e, Event::Dropped(_)) || matches!(e, Event::Send { .. })),
        "an attack packet got through: {evs:?}"
    );
    assert!(
        !evs.iter().any(|e| matches!(e, Event::Authenticated)),
        "an attack packet authenticated: {evs:?}"
    );
    assert_eq!(drops.len(), 1, "one drop per attack packet: {evs:?}");
    drops[0]
}

fn tally(reasons: &[DropReason]) -> HashMap<&'static str, u64> {
    let mut m = HashMap::new();
    for r in reasons {
        *m.entry(r.as_str()).or_insert(0) += 1;
    }
    m
}

/// Each drop reason went up in `Stats` by exactly what the attack produced.
fn counters_match(before: &Stats, after: &Stats, reasons: &[DropReason]) {
    let t = tally(reasons);
    for r in DropReason::ALL {
        let want = t.get(r.as_str()).copied().unwrap_or(0);
        assert_eq!(
            after.dropped(r) - before.dropped(r),
            want,
            "counter {} does not match the attack",
            r.as_str()
        );
    }
    assert_eq!(
        after.delivered, before.delivered,
        "nothing may be delivered"
    );
}

fn payload(i: u32) -> Vec<u8> {
    let mut p = b"F19-".to_vec();
    p.extend_from_slice(&i.to_be_bytes());
    p.resize(32, 0x5A);
    p
}

const N: u32 = 1000;

#[test]
fn replayed_packets_are_all_rejected_and_counted() {
    for len in [CounterLen::Short, CounterLen::Long] {
        let mut p = Pair::new(19, config(len));
        p.handshake(A);
        // 1,000 packets delivered once, in order.
        let mut sent = Vec::new();
        for i in 0..N {
            let pkt = p.make(A, &payload(i));
            let evs = p.inject(B, &pkt);
            assert!(evs.iter().any(|e| matches!(e, Event::Deliver(_))));
            sent.push(pkt);
        }
        let delivered = p.delivered[B].len();
        // Replay every one of them, newest first, then oldest first again.
        let before = p.stats(B);
        let mut reasons = Vec::new();
        for pkt in sent.iter().rev().chain(sent.iter()) {
            reasons.push(rejected(&p.inject(B, pkt)));
        }
        counters_match(&before, &p.stats(B), &reasons);
        assert_eq!(p.delivered[B].len(), delivered);
        let t = tally(&reasons);
        assert_eq!(reasons.len(), 2 * N as usize);
        // Inside the replay window: `replay`; behind it: `too_old`.
        assert!(t.keys().all(|k| *k == "replay" || *k == "too_old"), "{t:?}");
        println!(
            "F19 replay ({len:?}): {} injected, all rejected: {t:?}",
            reasons.len()
        );

        // Old packets after a rekey, once the old session's grace is over.
        p.handshake(A);
        let after_grace = p.now + p.cfg.previous_grace + ms(10);
        p.run_until(after_grace);
        let before = p.stats(B);
        let mut reasons = Vec::new();
        for pkt in &sent {
            reasons.push(rejected(&p.inject(B, pkt)));
        }
        counters_match(&before, &p.stats(B), &reasons);
        println!(
            "F19 replay after rekey ({len:?}): {} injected, all rejected: {:?}",
            reasons.len(),
            tally(&reasons)
        );
        // The link still works.
        let pkt = p.make(A, &payload(9999));
        assert!(
            p.inject(B, &pkt)
                .iter()
                .any(|e| matches!(e, Event::Deliver(_)))
        );
    }
}

#[test]
fn bit_flipped_packets_are_all_rejected_and_counted() {
    for len in [CounterLen::Short, CounterLen::Long] {
        let mut p = Pair::new(1919, config(len));
        p.handshake(A);
        let mut rng = Rng(7);
        let mut single = Vec::new();
        let mut multi = Vec::new();
        let mut positions = HashSet::new();
        for i in 0..2 * N {
            let pkt = p.make(A, &payload(i));
            let before = p.stats(B);
            let mut bad = pkt.clone();
            if i < N {
                // Every bit position in turn: header, index, counter, ciphertext, tag.
                let bit = (i as usize) % (pkt.len() * 8);
                positions.insert(bit);
                bad[bit / 8] ^= 1 << (bit % 8);
            } else {
                // 2 to 16 random bits.
                let n = 2 + rng.below(15) as usize;
                let mut done = HashSet::new();
                while done.len() < n {
                    let bit = rng.below(pkt.len() as u64 * 8) as usize;
                    if done.insert(bit) {
                        bad[bit / 8] ^= 1 << (bit % 8);
                    }
                }
            }
            let r = rejected(&p.inject(B, &bad));
            counters_match(&before, &p.stats(B), &[r]);
            if i < N { &mut single } else { &mut multi }.push(r);
            // The genuine packet still goes through after the forgery.
            assert!(
                p.inject(B, &pkt)
                    .iter()
                    .any(|e| matches!(e, Event::Deliver(_))),
                "packet {i}: a forgery spoiled the real one"
            );
        }
        let plen = data_overhead(len) + 32;
        assert_eq!(positions.len(), plen * 8, "every bit position was flipped");
        println!(
            "F19 single-bit flips ({len:?}, every one of {} bit positions): {} rejected: {:?}",
            plen * 8,
            single.len(),
            tally(&single)
        );
        println!(
            "F19 multi-bit flips ({len:?}): {} rejected: {:?}",
            multi.len(),
            tally(&multi)
        );
    }
}

#[test]
fn truncated_packets_are_all_rejected_and_counted() {
    for len in [CounterLen::Short, CounterLen::Long] {
        let mut p = Pair::new(191919, config(len));
        p.handshake(A);
        let mut reasons = Vec::new();
        let mut i = 0;
        while reasons.len() < N as usize {
            let pkt = p.make(A, &payload(i));
            i += 1;
            for cut in 0..pkt.len() {
                let before = p.stats(B);
                let r = rejected(&p.inject(B, &pkt[..cut]));
                counters_match(&before, &p.stats(B), &[r]);
                reasons.push(r);
            }
            assert!(
                p.inject(B, &pkt)
                    .iter()
                    .any(|e| matches!(e, Event::Deliver(_)))
            );
        }
        println!(
            "F19 truncations ({len:?}, every length 0..{} of {i} packets): {} rejected: {:?}",
            data_overhead(len) + 32,
            reasons.len(),
            tally(&reasons)
        );
    }
}

#[test]
fn wrong_key_packets_are_all_rejected_and_counted() {
    for len in [CounterLen::Short, CounterLen::Long] {
        let mut p = Pair::new(19191919, config(len));
        p.handshake(A);
        // Another pair with its own identities and session: its packets are
        // under keys B never agreed.
        let mut q = Pair::new(42, config(len));
        q.handshake(A);
        let real = p.make(A, &payload(0));
        assert!(
            p.inject(B, &real)
                .iter()
                .any(|e| matches!(e, Event::Deliver(_)))
        );
        let idx = &real[1..3];
        let mut as_is = Vec::new();
        let mut on_index = Vec::new();
        for i in 0..N {
            let foreign = q.make(A, &payload(i));
            let before = p.stats(B);
            let r = rejected(&p.inject(B, &foreign));
            counters_match(&before, &p.stats(B), &[r]);
            as_is.push(r);
            // The same, aimed at B's live session index: the key is wrong.
            let mut aimed = foreign.clone();
            aimed[1..3].copy_from_slice(idx);
            let before = p.stats(B);
            let r = rejected(&p.inject(B, &aimed));
            counters_match(&before, &p.stats(B), &[r]);
            assert_eq!(r, DropReason::BadTag, "a live index with the wrong key");
            on_index.push(r);
        }
        println!(
            "F19 wrong key ({len:?}): {} foreign packets rejected: {:?}; {} aimed at the live index rejected: {:?}",
            as_is.len(),
            tally(&as_is),
            on_index.len(),
            tally(&on_index)
        );
        let pkt = p.make(A, &payload(1));
        assert!(
            p.inject(B, &pkt)
                .iter()
                .any(|e| matches!(e, Event::Deliver(_)))
        );
    }
}

/// The receiver index and the counter carried in a data packet.
fn index_and_counter(pkt: &[u8]) -> (u16, u32) {
    let long = pkt[0] & 0x08 != 0;
    let idx = u16::from_be_bytes([pkt[1], pkt[2]]);
    let ctr = if long {
        u32::from_be_bytes([pkt[3], pkt[4], pkt[5], pkt[6]])
    } else {
        u16::from_be_bytes([pkt[3], pkt[4]]) as u32
    };
    (idx, ctr)
}

#[test]
fn nonces_never_repeat_across_rekey_restart_and_power_cycle() {
    // The same plaintext at the same counter under the same key gives the
    // same ciphertext (ChaCha20-Poly1305 is deterministic). So: send one
    // fixed plaintext K times in every session and check that no ciphertext
    // ever repeats. A repeat would mean a key and nonce were used twice.
    const K: usize = 300;
    let fixed = payload(0xF19);
    let mut p = Pair::new(2026, config(CounterLen::Short));
    p.handshake(A);
    let mut sessions: Vec<(&str, Vec<Vec<u8>>)> = Vec::new();
    let burst = |p: &mut Pair, from: usize| -> Vec<Vec<u8>> {
        let mut v = Vec::new();
        for _ in 0..K {
            let pkt = p.make(from, &fixed);
            assert!(
                p.inject(1 - from, &pkt)
                    .iter()
                    .any(|e| matches!(e, Event::Deliver(_)))
            );
            v.push(pkt);
        }
        v
    };
    sessions.push(("first session A->B", burst(&mut p, A)));
    sessions.push(("first session B->A", burst(&mut p, B)));
    // Rekey started by A, then one started by B.
    p.handshake(A);
    sessions.push(("after rekey (A) A->B", burst(&mut p, A)));
    p.handshake(B);
    sessions.push(("after rekey (B) A->B", burst(&mut p, A)));
    // A restarts (process restart: state gone, key kept); A starts again.
    p.restart(A, 0xA);
    p.handshake(A);
    sessions.push(("after A restarts A->B", burst(&mut p, A)));
    // A power cycle of both sides, with each side's index generator
    // starting from exactly the seed it had at first (worst case for a
    // device whose own random state repeats after power-up).
    p.restart(A, 2026 ^ 0xA);
    p.restart(B, 2026 ^ 0xB);
    p.handshake(A);
    sessions.push(("after power cycle A->B", burst(&mut p, A)));
    sessions.push(("after power cycle B->A", burst(&mut p, B)));

    let mut seen: HashMap<Vec<u8>, &str> = HashMap::new();
    let mut total = 0;
    for (name, pkts) in &sessions {
        // Inside a session: counters start at 0 and go up by one, never repeat.
        let first_idx = index_and_counter(&pkts[0]).0;
        let mut last: Option<u32> = None;
        for pkt in pkts {
            let (idx, ctr) = index_and_counter(pkt);
            assert_eq!(idx, first_idx, "{name}: one session for the burst");
            if let Some(l) = last {
                assert_eq!(ctr, l + 1, "{name}: counter must go up by one");
            }
            last = Some(ctr);
            // Across all sessions: the encrypted body (after header, index and
            // counter) never repeats.
            let body = pkt[3 + 2..].to_vec();
            if let Some(other) = seen.insert(body, name) {
                panic!("ciphertext repeated: {name} and {other} used one key and nonce twice");
            }
            total += 1;
        }
    }
    println!(
        "F19 nonce: {total} packets with one fixed plaintext over {} sessions (2 rekeys, a restart, a power cycle with repeated index seeds): no ciphertext repeated, counters strictly increasing",
        sessions.len()
    );
}

#[test]
fn rekey_at_full_load_loses_nothing() {
    // 100 packets a second each way for 20 minutes, a rekey every 60 s:
    // every packet the application handed over is delivered, once, in order.
    let mut cfg = config(CounterLen::Short);
    cfg.rekey_after = Duration::from_secs(60);
    cfg.reject_after = Duration::from_secs(180);
    let mut p = Pair::new(100, cfg);
    p.handshake(A);
    let end = Duration::from_secs(20 * 60);
    let mut next = [0u32; 2];
    let mut refused = [0u32; 2];
    let start_established = p.established;
    let mut t = p.now;
    while t < end {
        t += ms(10);
        p.run_until(t);
        for side in [A, B] {
            match p.links[side].send(p.now, &payload(next[side])) {
                Ok(pkt) => {
                    p.put(side, pkt);
                    next[side] += 1;
                }
                Err(_) => refused[side] += 1,
            }
        }
    }
    p.run_until(end + Duration::from_secs(1));
    for side in [A, B] {
        let got = &p.delivered[1 - side];
        assert_eq!(
            refused[side], 0,
            "side {side}: a send was refused during a rekey"
        );
        assert_eq!(got.len(), next[side] as usize, "side {side}: packets lost");
        for (i, g) in got.iter().enumerate() {
            assert_eq!(
                g,
                &payload(i as u32),
                "side {side}: packet {i} out of order or changed"
            );
        }
        let st = p.stats(1 - side);
        assert_eq!(
            st.total_dropped(),
            0,
            "side {}: drops on a clean link: {st:?}",
            1 - side
        );
    }
    let rekeys = p.established[A] - start_established[A];
    assert!(rekeys >= 19, "rekeys: {rekeys}");
    println!(
        "F19 rekey at full load: {} + {} packets at 100/s each way over 20 min, {rekeys} rekeys, 0 lost, 0 refused, 0 dropped",
        next[A], next[B]
    );
}
