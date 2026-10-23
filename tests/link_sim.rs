//! The link through a seeded, simulated channel with a virtual clock.
//!
//! No sockets and no sleeping: packets go into a queue with a delivery
//! time, and the test loop advances the clock. The channel loses, delays,
//! reorders, duplicates and corrupts packets, and an attacker replays old
//! packets and injects packets from an untrusted identity. Everything is
//! driven by one seed, so a failing run can be repeated.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::time::Duration;

use oasa_sec::identity::Identity;
use oasa_sec::link::{
    Config, CounterLen, DropReason, Entropy, Event, Link, MemoryTimestampStore, SendError,
    data_overhead,
};

/// splitmix64: small, fast, good enough for test randomness.
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
    fn chance(&mut self, p: f64) -> bool {
        ((self.next() >> 11) as f64 / (1u64 << 53) as f64) < p
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

fn key(rng: &mut Rng) -> [u8; 32] {
    let mut k = [0u8; 32];
    rng.fill(&mut k);
    k
}

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
enum Side {
    A,
    B,
}

impl Side {
    fn other(self) -> Side {
        match self {
            Side::A => Side::B,
            Side::B => Side::A,
        }
    }
}

#[derive(Clone)]
struct Channel {
    loss: f64,
    duplicate: f64,
    corrupt: f64,
    base_delay_ms: u64,
    /// Extra random delay: this is what reorders packets.
    jitter_ms: u64,
}

impl Channel {
    fn clean() -> Self {
        Self {
            loss: 0.0,
            duplicate: 0.0,
            corrupt: 0.0,
            base_delay_ms: 5,
            jitter_ms: 0,
        }
    }
    fn rough(loss: f64) -> Self {
        Self {
            loss,
            duplicate: 0.05,
            corrupt: 0.03,
            base_delay_ms: 20,
            jitter_ms: 120,
        }
    }
}

#[derive(Default)]
struct SideLog {
    /// Payloads the application handed to `send` and that were accepted.
    sent: HashMap<u32, Vec<u8>>,
    delivered: Vec<(Duration, Vec<u8>)>,
    established: Vec<(Duration, bool, bool)>, // time, initiator, rekey
    handshakes_sent: u32,
    packets_arrived: u64,
    failures: u32,
    /// Replies the link wanted to send to packets that were injected.
    replies_to_injected: u32,
    injected: u32,
}

/// Delivery time, tie-break sequence number, receiver, bytes.
type Queued = (Duration, u64, Side, Vec<u8>);

struct Sim {
    rng: Rng,
    now: Duration,
    links: HashMap<Side, Link>,
    keys: HashMap<Side, [u8; 32]>,
    channel: Channel,
    queue: BinaryHeap<Reverse<Queued>>,
    seq: u64,
    /// Everything either side put on the wire, with its destination.
    wire: Vec<(Side, Vec<u8>)>,
    logs: HashMap<Side, SideLog>,
    next_id: u32,
    /// While true the channel drops everything.
    blackout: bool,
}

fn pub_of(k: &[u8; 32]) -> [u8; 32] {
    *Identity::from_private_bytes(k).unwrap().public_key()
}

impl Sim {
    fn new(seed: u64, cfg: Config, channel: Channel) -> Self {
        let mut rng = Rng(seed);
        let ka = key(&mut rng);
        let kb = key(&mut rng);
        let mk = |own: &[u8; 32], peer: [u8; 32], seed: u64| {
            Link::new(
                &Identity::from_private_bytes(own).unwrap(),
                peer,
                cfg.clone(),
                Box::new(Rng(seed)),
                Duration::from_secs(1_700_000_000),
                Box::new(MemoryTimestampStore::default()),
            )
            .unwrap()
        };
        let mut links = HashMap::new();
        links.insert(Side::A, mk(&ka, pub_of(&kb), seed ^ 0xA));
        links.insert(Side::B, mk(&kb, pub_of(&ka), seed ^ 0xB));
        let mut keys = HashMap::new();
        keys.insert(Side::A, ka);
        keys.insert(Side::B, kb);
        let mut logs = HashMap::new();
        logs.insert(Side::A, SideLog::default());
        logs.insert(Side::B, SideLog::default());
        Self {
            rng,
            now: Duration::ZERO,
            links,
            keys,
            channel,
            queue: BinaryHeap::new(),
            seq: 0,
            wire: Vec::new(),
            logs,
            next_id: 0,
            blackout: false,
        }
    }

    fn link(&mut self, s: Side) -> &mut Link {
        self.links.get_mut(&s).unwrap()
    }
    fn log(&mut self, s: Side) -> &mut SideLog {
        self.logs.get_mut(&s).unwrap()
    }

    /// Put `bytes`, sent by `from`, on the channel towards the other side.
    fn transmit(&mut self, from: Side, bytes: Vec<u8>) {
        self.wire.push((from.other(), bytes.clone()));
        if self.blackout || self.rng.chance(self.channel.loss) {
            return;
        }
        let copies = if self.rng.chance(self.channel.duplicate) {
            2
        } else {
            1
        };
        for _ in 0..copies {
            let mut b = bytes.clone();
            if self.rng.chance(self.channel.corrupt) {
                let i = self.rng.below(b.len() as u64) as usize;
                b[i] ^= 1 << self.rng.below(8);
            }
            let delay = self.channel.base_delay_ms + self.rng.below(self.channel.jitter_ms + 1);
            self.seq += 1;
            self.queue
                .push(Reverse((self.now + ms(delay), self.seq, from.other(), b)));
        }
    }

    fn apply(&mut self, side: Side, events: Vec<Event>) {
        for e in events {
            match e {
                Event::Send { packet, .. } => self.transmit(side, packet),
                Event::Deliver(p) => {
                    let now = self.now;
                    self.log(side).delivered.push((now, p));
                }
                Event::SessionEstablished { initiator, rekey } => {
                    let now = self.now;
                    self.log(side).established.push((now, initiator, rekey));
                }
                Event::HandshakeSent { .. } => self.log(side).handshakes_sent += 1,
                Event::Failure(_) => self.log(side).failures += 1,
                Event::Authenticated | Event::Dropped(_) => {}
            }
        }
    }

    /// Give `bytes` to `to`'s link, as if it had arrived.
    fn handle(&mut self, to: Side, bytes: &[u8]) -> Vec<Event> {
        let now = self.now;
        self.log(to).packets_arrived += 1;
        let ev = self.link(to).handle_packet(now, bytes);
        self.apply(to, ev.clone());
        ev
    }

    /// Hand every packet that is due to its receiver.
    fn deliver_due(&mut self) {
        while let Some(Reverse((t, ..))) = self.queue.peek() {
            if *t > self.now {
                break;
            }
            let Reverse((_, _, to, bytes)) = self.queue.pop().unwrap();
            self.handle(to, &bytes);
        }
    }

    fn poll(&mut self) {
        for s in [Side::A, Side::B] {
            let now = self.now;
            let ev = self.link(s).poll_timers(now);
            self.apply(s, ev);
        }
    }

    /// Send a fresh, unique payload from `side`. Returns false if the link
    /// had no session.
    fn app_send(&mut self, side: Side) -> bool {
        let id = self.next_id;
        self.next_id += 1;
        let len = 4 + 8 + (self.rng.below(60) as usize);
        let mut payload = Vec::with_capacity(len);
        payload.extend_from_slice(&id.to_be_bytes());
        payload.extend_from_slice(if side == Side::A { MARK_A } else { MARK_B });
        while payload.len() < len {
            payload.push((id as u8).wrapping_add(payload.len() as u8));
        }
        let now = self.now;
        match self.link(side).send(now, &payload) {
            Ok(pkt) => {
                self.log(side).sent.insert(id, payload);
                self.transmit(side, pkt);
                true
            }
            Err(SendError::NoSession) => false,
            Err(e) => panic!("unexpected send error {e}"),
        }
    }

    fn step(&mut self, tick: Duration) {
        self.deliver_due();
        self.poll();
        self.now += tick;
    }

    /// Run for `total`, sending from both sides every `send_every`, and
    /// calling `hook` after every tick.
    fn run(
        &mut self,
        total: Duration,
        tick: Duration,
        send_every: Duration,
        mut hook: impl FnMut(&mut Sim),
    ) {
        let end = self.now + total;
        let mut next_send = self.now;
        while self.now < end {
            self.step(tick);
            if self.now >= next_send {
                next_send += send_every;
                self.app_send(Side::A);
                self.app_send(Side::B);
            }
            hook(self);
        }
    }

    /// Let everything in flight arrive, with no new traffic.
    fn drain(&mut self) {
        for _ in 0..200 {
            self.step(ms(10));
        }
    }

    fn start(&mut self) {
        let now = self.now;
        let ev = self.link(Side::A).start_handshake(now).unwrap();
        self.apply(Side::A, ev);
    }

    /// An attacker replays a random earlier packet to its original destination.
    fn replay_random(&mut self) {
        if self.wire.is_empty() {
            return;
        }
        let i = self.rng.below(self.wire.len() as u64) as usize;
        let (to, bytes) = self.wire[i].clone();
        self.inject(to, &bytes);
    }

    /// Hand a packet straight to `to`, outside the channel. Anything the
    /// link sends in reply is counted, because for an untrusted or stale
    /// packet nothing may be.
    fn inject(&mut self, to: Side, bytes: &[u8]) -> Vec<Event> {
        self.log(to).injected += 1;
        let ev = self.handle(to, bytes);
        let replies = ev
            .iter()
            .filter(|e| matches!(e, Event::Send { .. }))
            .count() as u32;
        self.log(to).replies_to_injected += replies;
        ev
    }

    fn stats(&mut self, side: Side) -> oasa_sec::link::Stats {
        self.link(side).stats().clone()
    }

    /// What each side sent must be exactly what the other delivered, once.
    fn check_delivery_integrity(&self) {
        for side in [Side::A, Side::B] {
            let sent = &self.logs[&side].sent;
            let got = &self.logs[&side.other()].delivered;
            let mut seen = HashSet::new();
            for (_, p) in got {
                let id = u32::from_be_bytes(p[..4].try_into().unwrap());
                assert!(
                    seen.insert(id),
                    "payload {id} from {side:?} delivered twice"
                );
                assert_eq!(
                    sent.get(&id),
                    Some(p),
                    "{side:?}'s payload {id} arrived changed or was never sent"
                );
            }
        }
    }

    /// Every packet that reached `handle_packet` is accounted for exactly once.
    fn check_accounting(&mut self) {
        for side in [Side::A, Side::B] {
            let st = self.stats(side);
            let arrived = self.logs[&side].packets_arrived;
            let counted = st.received
                + st.keepalives_received
                + st.total_dropped()
                + st.handshakes_accepted
                + st.handshakes_completed;
            assert_eq!(arrived, counted, "{side:?}: {st:?}");
            assert_eq!(st.delivered as usize, self.logs[&side].delivered.len());
            assert_eq!(self.logs[&side].failures, 0);
        }
    }

    /// The payloads one side delivered, in order.
    fn delivered_ids(&self, side: Side) -> Vec<u32> {
        self.logs[&side]
            .delivered
            .iter()
            .map(|(_, p)| u32::from_be_bytes(p[..4].try_into().unwrap()))
            .collect()
    }

    /// No wire packet contains either marker.
    fn check_no_plaintext_on_the_wire(&self) {
        assert!(!self.wire.is_empty());
        for (_, p) in &self.wire {
            for m in [MARK_A, MARK_B] {
                assert!(
                    !p.windows(m.len()).any(|w| w == m),
                    "plaintext marker on the wire"
                );
            }
        }
    }
}

const MARK_A: &[u8] = b"from-A!!";
const MARK_B: &[u8] = b"from-B!!";

fn config(len: CounterLen) -> Config {
    Config {
        counter_len: len,
        rekey_after: Duration::from_secs(60),
        reject_after: Duration::from_secs(180),
        ..Config::default()
    }
}

fn rekeys(sim: &Sim, side: Side) -> usize {
    sim.logs[&side]
        .established
        .iter()
        .filter(|(_, _, rekey)| *rekey)
        .count()
}

/// The longest stretch with no delivery between `from` and `to` (seconds).
fn longest_gap(sim: &Sim, receiver: Side, from: Duration, to: Duration) -> f64 {
    let mut last = from;
    let mut worst = Duration::ZERO;
    for (t, _) in &sim.logs[&receiver].delivered {
        if *t < from || *t > to {
            continue;
        }
        worst = worst.max(*t - last);
        last = *t;
    }
    worst = worst.max(to - last);
    worst.as_secs_f64()
}

#[test]
fn random_channel_many_seeds_and_both_counter_lengths() {
    for len in [CounterLen::Short, CounterLen::Long] {
        for seed in 1..=6u64 {
            let mut sim = Sim::new(seed, config(len), Channel::rough(0.10));
            sim.start();
            sim.run(Duration::from_secs(300), ms(10), ms(100), |s| {
                if s.rng.chance(0.03) {
                    s.replay_random();
                }
            });
            sim.check_delivery_integrity();
            sim.check_accounting();
            for side in [Side::A, Side::B] {
                let st = sim.stats(side);
                let other = sim.stats(side.other());
                assert!(
                    st.delivered * 100 >= other.sent * 55,
                    "seed {seed} {len:?}: {side:?} got {} of {}",
                    st.delivered,
                    other.sent
                );
                assert_eq!(st.dropped(DropReason::UntrustedPeer), 0);
                // Replays and corruption were seen and refused.
                assert!(st.dropped(DropReason::Replay) > 0, "seed {seed} {side:?}");
                assert!(st.dropped(DropReason::BadTag) > 0, "seed {seed} {side:?}");
                assert!(rekeys(&sim, side) >= 3, "seed {seed} {side:?}");
            }
            sim.check_no_plaintext_on_the_wire();
        }
    }
}

#[test]
fn same_seed_gives_the_same_run() {
    let run = || {
        let mut sim = Sim::new(42, config(CounterLen::Short), Channel::rough(0.15));
        sim.start();
        sim.run(Duration::from_secs(120), ms(10), ms(100), |s| {
            if s.rng.chance(0.03) {
                s.replay_random();
            }
        });
        (
            sim.stats(Side::A),
            sim.stats(Side::B),
            sim.delivered_ids(Side::A),
            sim.delivered_ids(Side::B),
        )
    };
    assert_eq!(run(), run());
}

#[test]
fn untrusted_identity_gets_no_reply_and_is_counted() {
    for seed in 1..=3u64 {
        let mut sim = Sim::new(seed, config(CounterLen::Short), Channel::clean());
        let mut rng = Rng(seed + 100);
        let kc = key(&mut rng);
        let c_to = |victim: Side, sim: &Sim, seed: u64| {
            Link::new(
                &Identity::from_private_bytes(&kc).unwrap(),
                pub_of(&sim.keys[&victim]),
                config(CounterLen::Short),
                Box::new(Rng(seed)),
                Duration::from_secs(1_700_000_000),
                Box::new(MemoryTimestampStore::default()),
            )
            .unwrap()
        };
        let mut c_b = c_to(Side::B, &sim, 1);
        let mut c_a = c_to(Side::A, &sim, 2);
        sim.start();
        let mut attempts = 0u32;
        let mut next = Duration::ZERO;
        sim.run(Duration::from_secs(60), ms(10), ms(100), |s| {
            if s.now >= next {
                next += ms(250);
                attempts += 1;
                for (victim, c) in [(Side::B, &mut c_b), (Side::A, &mut c_a)] {
                    // The untrusted device does a real handshake attempt...
                    let hs1 = c
                        .start_handshake(s.now)
                        .unwrap()
                        .into_iter()
                        .find_map(|e| match e {
                            Event::Send { packet, .. } => Some(packet),
                            _ => None,
                        })
                        .unwrap();
                    let ev = s.inject(victim, &hs1);
                    assert_eq!(
                        ev.iter()
                            .filter_map(|e| if let Event::Dropped(r) = e {
                                Some(*r)
                            } else {
                                None
                            })
                            .collect::<Vec<_>>(),
                        vec![DropReason::UntrustedPeer]
                    );
                    // ...and sprays data packets with guessed indexes.
                    let mut junk = vec![0x30u8, 0, 0];
                    junk.extend_from_slice(&(s.rng.next() as u32).to_be_bytes());
                    junk.extend_from_slice(&[7u8; 40]);
                    let idx = (s.rng.next() as u16).to_be_bytes();
                    junk[1..3].copy_from_slice(&idx);
                    s.inject(victim, &junk);
                }
            }
        });
        sim.drain();
        sim.check_delivery_integrity();
        sim.check_accounting();
        for side in [Side::A, Side::B] {
            assert_eq!(
                sim.logs[&side].replies_to_injected, 0,
                "never answers an untrusted device"
            );
            let st = sim.stats(side);
            assert_eq!(st.dropped(DropReason::UntrustedPeer), u64::from(attempts));
            assert_eq!(st.dropped(DropReason::RateLimited), 0);
        }
        // The trusted pair carried on untouched: clean channel, nothing lost.
        let (a, b) = (sim.stats(Side::A), sim.stats(Side::B));
        assert_eq!(b.delivered, a.sent);
        assert_eq!(a.delivered, b.sent);
        assert!(a.sent > 100);
    }
}

#[test]
fn replayed_handshakes_are_stale_and_the_session_survives() {
    let mut cfg = config(CounterLen::Short);
    cfg.rekey_after = Duration::from_secs(20);
    let mut sim = Sim::new(5, cfg, Channel::clean());
    sim.start();
    sim.run(Duration::from_secs(10), ms(10), ms(100), |_| {});
    let hs1_first = sim
        .wire
        .iter()
        .find(|(to, p)| *to == Side::B && p[0] == 0x10 && p.len() == 111)
        .unwrap()
        .1
        .clone();
    let hs2_first = sim
        .wire
        .iter()
        .find(|(to, p)| *to == Side::A && p[0] == 0x20 && p.len() == 53)
        .unwrap()
        .1
        .clone();
    let mut replays = 0u64;
    let mut hs2_replays = 0u64;
    let mut next = ms(100);
    // Cover more than one rekey, replaying every handshake 1 and 2 seen so far.
    sim.run(Duration::from_secs(70), ms(10), ms(100), |s| {
        if s.now >= next {
            next += ms(1500);
            let hs1s: Vec<_> = s
                .wire
                .iter()
                .filter(|(to, p)| *to == Side::B && p[0] == 0x10 && p.len() == 111)
                .map(|(_, p)| p.clone())
                .collect();
            for h in hs1s {
                // All of them are older than the newest one B accepted, except
                // possibly the very newest if it is still in flight.
                let ev = s.inject(Side::B, &h);
                let stale = ev.contains(&Event::Dropped(DropReason::StaleHandshake));
                if stale {
                    replays += 1;
                } else {
                    // Only the newest, still in flight at this very moment, may pass.
                    panic!("a replayed handshake 1 was accepted: {ev:?}");
                }
            }
            let hs2s: Vec<_> = s
                .wire
                .iter()
                .filter(|(to, p)| *to == Side::A && p[0] == 0x20 && p.len() == 53)
                .map(|(_, p)| p.clone())
                .collect();
            for h in hs2s {
                let ev = s.inject(Side::A, &h);
                assert_eq!(
                    ev.iter()
                        .filter_map(|e| if let Event::Dropped(r) = e {
                            Some(*r)
                        } else {
                            None
                        })
                        .collect::<Vec<_>>(),
                    vec![DropReason::UnknownIndex]
                );
                hs2_replays += 1;
            }
        }
    });
    assert!(replays > 20 && hs2_replays > 20);
    assert!(rekeys(&sim, Side::A) >= 2);
    assert!(sim.link(Side::B).can_send() && sim.link(Side::A).can_send());
    assert_eq!(
        sim.stats(Side::B).dropped(DropReason::StaleHandshake),
        replays
    );
    assert_eq!(sim.logs[&Side::B].replies_to_injected, 0);
    assert_eq!(sim.logs[&Side::A].replies_to_injected, 0);
    // The very first recorded messages are still refused now.
    assert!(
        sim.inject(Side::B, &hs1_first)
            .contains(&Event::Dropped(DropReason::StaleHandshake))
    );
    sim.inject(Side::A, &hs2_first);
    sim.drain();
    sim.check_delivery_integrity();
    sim.check_accounting();
    // The clean channel lost nothing, replays included.
    let (a, b) = (sim.stats(Side::A), sim.stats(Side::B));
    assert_eq!(b.delivered, a.sent);
    assert_eq!(a.delivered, b.sent);
}

#[test]
fn rekey_under_twenty_percent_loss_leaves_no_gap() {
    for seed in 1..=5u64 {
        let mut cfg = config(CounterLen::Short);
        cfg.rekey_after = Duration::from_secs(30);
        // Like the defaults (10 and 15 minutes), a long margin to retry handshakes in.
        cfg.reject_after = Duration::from_secs(150);
        cfg.retry_initial = Duration::from_secs(2);
        cfg.retry_max = Duration::from_secs(10);
        cfg.keepalive = Some(Duration::from_secs(10));
        let channel = Channel {
            loss: 0.20,
            duplicate: 0.0,
            corrupt: 0.0,
            base_delay_ms: 20,
            jitter_ms: 100,
        };
        let mut sim = Sim::new(seed, cfg, channel);
        sim.start();
        sim.run(Duration::from_secs(600), ms(10), ms(100), |_| {});
        sim.check_delivery_integrity();
        sim.check_accounting();
        for side in [Side::A, Side::B] {
            assert!(
                rekeys(&sim, side) >= 15,
                "seed {seed} {side:?}: {}",
                rekeys(&sim, side)
            );
            // Once both sides have their first session (which can need a few
            // handshake retries at 20% loss), no stretch longer than 2.5 s
            // without a delivery.
            let first = |s: Side| sim.logs[&s].established[0].0;
            let from = first(Side::A).max(first(Side::B)) + Duration::from_secs(1);
            let gap = longest_gap(&sim, side, from, Duration::from_secs(600));
            assert!(gap < 2.5, "seed {seed}: {side:?} was silent for {gap:.2}s");
            let st = sim.stats(side);
            let other = sim.stats(side.other());
            assert!(st.delivered * 100 >= other.sent * 70, "seed {seed}");
            assert!(
                st.delivered * 100 <= other.sent * 90,
                "20% loss should show"
            );
        }
        // Rekeys happened on both sides at the same pace (one per 30 s).
        assert!(rekeys(&sim, Side::A).abs_diff(rekeys(&sim, Side::B)) <= 2);
    }
}

#[test]
fn counter_rebuilds_across_65536_packets_and_survives_a_long_blackout() {
    let mut cfg = config(CounterLen::Short);
    cfg.rekey_after = Duration::from_secs(600);
    cfg.reject_after = Duration::from_secs(900);
    let channel = Channel {
        loss: 0.05,
        duplicate: 0.02,
        corrupt: 0.0,
        base_delay_ms: 5,
        jitter_ms: 30, // reorders packets sent a millisecond apart
    };
    let mut sim = Sim::new(9, cfg, channel);
    sim.start();
    let mut tick = 0u64;
    let mut after_blackout = 0usize;
    sim.run(Duration::from_secs(100), ms(1), ms(1), |s| {
        tick += 1;
        // 20,000 packets in a row vanish: below the 32,768 limit.
        s.blackout = (30_000..50_000).contains(&tick);
        if tick == 50_100 {
            after_blackout = s.logs[&Side::B].delivered.len();
        }
    });
    sim.check_delivery_integrity();
    sim.check_accounting();
    let a = sim.stats(Side::A);
    let b = sim.stats(Side::B);
    assert!(a.sent > 65_536 * 11 / 10, "sent {}", a.sent);
    // Delivery resumed straight after the blackout.
    assert!(sim.logs[&Side::B].delivered.len() > after_blackout + 20_000);
    // Outside the blackout, loss is the channel's 5% (plus little reordering).
    let expected = (a.sent - 20_000) as f64 * 0.95;
    assert!(
        b.delivered as f64 > expected * 0.97,
        "delivered {} of expected {expected}",
        b.delivered
    );
    assert_eq!(rekeys(&sim, Side::A), 0, "one session the whole time");
    // The counter really went past 16 bits with only two bytes on the wire.
    assert!(a.sent > 65_536);
}

#[test]
fn a_blackout_over_32768_packets_stops_the_short_counter_until_rekey() {
    // The documented limit (spec section 3): with the 2-byte counter, losing
    // 32,768 or more packets in a row makes the counter ambiguous, and the
    // session is dead until the next rekey. The 4-byte counter is fine.
    for (len, dies) in [(CounterLen::Short, true), (CounterLen::Long, false)] {
        let mut cfg = config(len);
        cfg.rekey_after = Duration::from_secs(100);
        cfg.reject_after = Duration::from_secs(400);
        cfg.keepalive = None;
        let mut sim = Sim::new(11, cfg, Channel::clean());
        sim.start();
        let mut tick = 0u64;
        sim.run(Duration::from_secs(130), ms(1), ms(1), |s| {
            tick += 1;
            s.blackout = (40_000..80_000).contains(&tick); // 40,000 lost
        });
        sim.check_delivery_integrity();
        let between = sim.logs[&Side::B]
            .delivered
            .iter()
            .filter(|(t, _)| *t > ms(82_000) && *t < ms(98_000))
            .count();
        let after_rekey = sim.logs[&Side::B]
            .delivered
            .iter()
            .filter(|(t, _)| *t > ms(105_000))
            .count();
        if dies {
            assert_eq!(between, 0, "{len:?}");
            assert!(sim.stats(Side::B).dropped(DropReason::TooOld) > 10_000);
        } else {
            assert!(between > 15_000, "{len:?}: {between}");
        }
        assert!(
            after_rekey > 10_000,
            "{len:?}: recovers after the rekey: {after_rekey}"
        );
    }
}

#[test]
fn forged_handshake_2_does_not_spoil_the_real_one() {
    let mut sim = Sim::new(21, config(CounterLen::Short), Channel::clean());
    sim.start();
    // Hold B's answer in the queue; forge one meanwhile with A's real index.
    let hs1 = sim
        .wire
        .iter()
        .find(|(to, _)| *to == Side::B)
        .unwrap()
        .1
        .clone();
    let a_index = u16::from_be_bytes([hs1[1], hs1[2]]);
    let mut forged = vec![0x20u8, 0x12, 0x34];
    forged.extend_from_slice(&a_index.to_be_bytes());
    let mut r = Rng(1);
    let mut noise = [0u8; 48];
    r.fill(&mut noise);
    forged.extend_from_slice(&noise);
    assert_eq!(forged.len(), 53);
    let ev = sim.inject(Side::A, &forged);
    assert!(ev.contains(&Event::Dropped(DropReason::BadTag)));
    assert_eq!(sim.logs[&Side::A].replies_to_injected, 0);
    // The real exchange still completes.
    sim.run(Duration::from_secs(5), ms(10), ms(100), |_| {});
    assert!(sim.link(Side::A).can_send() && sim.link(Side::B).can_send());
    sim.check_delivery_integrity();
    sim.check_accounting();
    assert!(sim.stats(Side::B).delivered > 20);
}

#[test]
fn hostile_flood_changes_nothing() {
    let mut sim = Sim::new(31, config(CounterLen::Short), Channel::clean());
    sim.start();
    sim.run(Duration::from_secs(5), ms(10), ms(100), |_| {});
    let sent_before = (sim.stats(Side::A).sent, sim.stats(Side::B).sent);
    let mut junk_count = 0u64;
    sim.run(Duration::from_secs(20), ms(10), ms(100), |s| {
        // Random packets, sizes from 0 to 140, to both sides, 20 per tick.
        for _ in 0..20 {
            let len = s.rng.below(141) as usize;
            let mut p = vec![0u8; len];
            s.rng.fill(&mut p);
            if !p.is_empty() && s.rng.chance(0.5) {
                p[0] = [0x10u8, 0x20, 0x30, 0x38][s.rng.below(4) as usize];
            }
            let to = if s.rng.chance(0.5) { Side::A } else { Side::B };
            s.inject(to, &p);
            junk_count += 1;
        }
    });
    sim.drain();
    assert!(junk_count > 30_000);
    assert_eq!(
        sim.logs[&Side::A].replies_to_injected + sim.logs[&Side::B].replies_to_injected,
        0
    );
    sim.check_delivery_integrity();
    sim.check_accounting();
    // Real traffic kept flowing, all of it.
    let (a, b) = (sim.stats(Side::A), sim.stats(Side::B));
    assert!(a.sent > sent_before.0 + 150);
    assert_eq!(b.delivered, a.sent);
    assert_eq!(a.delivered, b.sent);
}

#[test]
fn sizes_on_the_wire_match_the_spec() {
    for (len, overhead) in [(CounterLen::Short, 21usize), (CounterLen::Long, 23)] {
        assert_eq!(data_overhead(len), overhead);
        let mut sim = Sim::new(3, config(len), Channel::clean());
        sim.start();
        sim.run(Duration::from_secs(2), ms(10), ms(100), |_| {});
        let handshakes: Vec<usize> = sim
            .wire
            .iter()
            .filter(|(_, p)| p[0] == 0x10 || p[0] == 0x20)
            .map(|(_, p)| p.len())
            .collect();
        assert_eq!(handshakes, vec![111, 53]);
        let min_data = sim
            .wire
            .iter()
            .filter(|(_, p)| p[0] == 0x30 || p[0] == 0x38)
            .map(|(_, p)| p.len())
            .min()
            .unwrap();
        assert_eq!(
            min_data, overhead,
            "a keepalive is header + index + counter + tag"
        );
        assert!(sim.wire.iter().all(|(_, p)| p.len() <= 128));
    }
}
