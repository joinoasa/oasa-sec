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

use std::path::{Path, PathBuf};

use oasa_sec::control::{Action, Control, Message};
use oasa_sec::identity::{Identity, fingerprint};
use oasa_sec::link::{
    Config, CounterLen, DropReason, Entropy, Event, Link, MemoryTimestampStore, SendError,
    SourceLimiter, data_overhead, keepalive_len, looks_like_handshake1,
};
use oasa_sec::removal;
use oasa_sec::store::{self, Peer, Role};

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
    /// Change the sender index in this many handshake 2 packets on the way.
    tamper_hs2: u32,
    /// This side's application sends nothing.
    mute: Option<Side>,
    /// Neither side's application sends anything (keepalives still go).
    mute_both: bool,
    cfgs: (Config, Config),
    /// The control layer on a side, if the test attached one (a real device
    /// runs one next to its link, in `oasa-link`).
    ctl: HashMap<Side, Control>,
    /// Every control message a side sent, parsed.
    ctl_sent: HashMap<Side, Vec<Message>>,
    /// Every drop the control layer asked to be counted.
    ctl_drops: HashMap<Side, Vec<&'static str>>,
}

/// Wall clock at virtual time zero, for the control layer's records.
const WALL: u64 = 1_700_000_000;

fn pub_of(k: &[u8; 32]) -> [u8; 32] {
    *Identity::from_private_bytes(k).unwrap().public_key()
}

impl Sim {
    fn new(seed: u64, cfg: Config, channel: Channel) -> Self {
        Self::new_with(seed, cfg.clone(), cfg, channel)
    }

    /// Each side with its own settings (a misconfigured pair).
    fn new_with(seed: u64, cfg_a: Config, cfg_b: Config, channel: Channel) -> Self {
        let wall = Duration::from_secs(1_700_000_000);
        Self::new_clocks(seed, (cfg_a, wall), (cfg_b, wall), channel)
    }

    /// Each side with its own settings and its own wall clock at time zero.
    fn new_clocks(
        seed: u64,
        cfgs_a: (Config, Duration),
        cfgs_b: (Config, Duration),
        channel: Channel,
    ) -> Self {
        Self::new_keyed(seed, cfgs_a, cfgs_b, channel, None)
    }

    /// Like `new_clocks`, with the two private keys given (so a device can
    /// have the same identity in two simulations).
    fn new_keyed(
        seed: u64,
        (cfg_a, wall_a): (Config, Duration),
        (cfg_b, wall_b): (Config, Duration),
        channel: Channel,
        keys: Option<([u8; 32], [u8; 32])>,
    ) -> Self {
        let mut rng = Rng(seed);
        let (ka, kb) = match keys {
            Some(k) => k,
            None => (key(&mut rng), key(&mut rng)),
        };
        let mk = |own: &[u8; 32], peer: [u8; 32], seed: u64, cfg: &Config, wall: Duration| {
            Link::new(
                &Identity::from_private_bytes(own).unwrap(),
                peer,
                cfg.clone(),
                Box::new(Rng(seed)),
                wall,
                Box::new(MemoryTimestampStore::default()),
            )
            .unwrap()
        };
        let mut links = HashMap::new();
        links.insert(Side::A, mk(&ka, pub_of(&kb), seed ^ 0xA, &cfg_a, wall_a));
        links.insert(Side::B, mk(&kb, pub_of(&ka), seed ^ 0xB, &cfg_b, wall_b));
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
            tamper_hs2: 0,
            mute: None,
            mute_both: false,
            cfgs: (cfg_a, cfg_b),
            ctl: HashMap::new(),
            ctl_sent: HashMap::new(),
            ctl_drops: HashMap::new(),
        }
    }

    /// Run the control layer on `side`, as `oasa-link` does, with its device
    /// folder at `dir`. Replaces an earlier one (a restarted process).
    fn attach_control(&mut self, side: Side, dir: &Path, seed: u64) {
        let own = pub_of(&self.keys[&side]);
        let peer = pub_of(&self.keys[&side.other()]);
        self.ctl
            .insert(side, Control::new(dir, own, peer, Box::new(Rng(seed))));
    }

    fn unix(&self) -> u64 {
        WALL + self.now.as_secs()
    }

    /// Do what the control layer asked: send, count drops.
    fn run_ctl(&mut self, side: Side, actions: Vec<Action>) {
        let now = self.now;
        for a in actions {
            match a {
                Action::Send(bytes) => {
                    self.ctl_sent
                        .entry(side)
                        .or_default()
                        .push(Message::parse(&bytes).expect("we only send what parses"));
                    if let Ok(pkt) = self.link(side).send_control(now, &bytes) {
                        self.transmit(side, pkt);
                    }
                }
                Action::Drop(r) => self.ctl_drops.entry(side).or_default().push(r),
                Action::Note(_) => {}
            }
        }
    }

    /// Control messages of one kind that `side` sent, in order.
    fn ctl_messages(&self, side: Side) -> &[Message] {
        self.ctl_sent.get(&side).map_or(&[], |v| v.as_slice())
    }

    /// The device on `side` reboots: all session state is gone, the key and
    /// the settings stay, the wall clock has moved on.
    fn restart(&mut self, side: Side) {
        let wall = Duration::from_secs(1_700_000_000) + self.now;
        self.restart_with_wall(side, wall);
    }

    fn restart_with_wall(&mut self, side: Side, wall: Duration) {
        let cfg = if side == Side::A {
            self.cfgs.0.clone()
        } else {
            self.cfgs.1.clone()
        };
        let seed = self.rng.below(u64::MAX);
        let k = self.keys[&side];
        let peer = pub_of(&self.keys[&side.other()]);
        let link = Link::new(
            &Identity::from_private_bytes(&k).unwrap(),
            peer,
            cfg,
            Box::new(Rng(seed)),
            wall,
            Box::new(MemoryTimestampStore::default()),
        )
        .unwrap();
        self.links.insert(side, link);
    }

    fn link(&mut self, s: Side) -> &mut Link {
        self.links.get_mut(&s).unwrap()
    }
    fn log(&mut self, s: Side) -> &mut SideLog {
        self.logs.get_mut(&s).unwrap()
    }

    /// Put `bytes`, sent by `from`, on the channel towards the other side.
    fn transmit(&mut self, from: Side, mut bytes: Vec<u8>) {
        if self.tamper_hs2 > 0 && bytes[0] == 0x21 {
            self.tamper_hs2 -= 1;
            bytes[1] ^= 0x5A; // not covered by any tag
        }
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
                    if let Some(c) = self.ctl.get_mut(&side) {
                        let acts = c.session_started(now);
                        self.run_ctl(side, acts);
                    }
                }
                Event::Control(bytes) => {
                    let (now, unix) = (self.now, self.unix());
                    if let Some(c) = self.ctl.get_mut(&side) {
                        let acts = c.handle(now, unix, &bytes);
                        self.run_ctl(side, acts);
                    }
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
            if let Some(c) = self.ctl.get_mut(&s) {
                let acts = c.poll(now);
                self.run_ctl(s, acts);
            }
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
                for side in [Side::A, Side::B] {
                    if self.mute != Some(side) && !self.mute_both {
                        self.app_send(side);
                    }
                }
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
                + st.control_received
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
                    let mut junk = vec![0x31u8, 0, 0];
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
        .find(|(to, p)| *to == Side::B && p[0] == 0x11 && p.len() == 119)
        .unwrap()
        .1
        .clone();
    let hs2_first = sim
        .wire
        .iter()
        .find(|(to, p)| *to == Side::A && p[0] == 0x21 && p.len() == 55)
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
                .filter(|(to, p)| *to == Side::B && p[0] == 0x11 && p.len() == 119)
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
                .filter(|(to, p)| *to == Side::A && p[0] == 0x21 && p.len() == 55)
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
    // 32,768 or more packets in a row makes the counter ambiguous. The
    // session is dead, but the stale rule (nothing heard for 30 s after we
    // sent) starts a new handshake without waiting for the rekey timer.
    // The 4-byte counter is fine.
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
            .filter(|(t, _)| *t > ms(80_000) && *t < ms(84_000))
            .count();
        let after_rekey = sim.logs[&Side::B]
            .delivered
            .iter()
            .filter(|(t, _)| *t > ms(105_000))
            .count();
        if dies {
            assert_eq!(between, 0, "{len:?}");
            assert!(sim.stats(Side::B).dropped(DropReason::TooOld) > 100);
            // Recovered by the stale rule, before the rekey at 100 s.
            let early = sim.logs[&Side::B]
                .delivered
                .iter()
                .filter(|(t, _)| *t > ms(90_000) && *t < ms(99_000))
                .count();
            assert!(early > 1_000, "{len:?}: stale rule restarts: {early}");
        } else {
            assert!(between > 2_000, "{len:?}: {between}");
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
    // B's answer is still in the queue. An attacker who cannot see A's
    // index tries every one with random Noise bytes: exactly one routes to
    // A's handshake and fails its tag, and A's state survives that.
    let mut r = Rng(1);
    let (mut bad_tag, mut unknown) = (0, 0);
    for idx in 0..=u16::MAX {
        let mut forged = vec![0x21u8];
        forged.extend_from_slice(&idx.to_be_bytes());
        let mut noise = [0u8; 52];
        r.fill(&mut noise);
        forged.extend_from_slice(&noise);
        assert_eq!(forged.len(), 55);
        let ev = sim.inject(Side::A, &forged);
        if ev.contains(&Event::Dropped(DropReason::BadTag)) {
            bad_tag += 1;
        } else if ev.contains(&Event::Dropped(DropReason::UnknownIndex)) {
            unknown += 1;
        }
    }
    assert_eq!((bad_tag, unknown), (1, 65_535));
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
                p[0] = [0x11u8, 0x21, 0x31, 0x39][s.rng.below(4) as usize];
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
    for (len, overhead, keepalive) in [
        (CounterLen::Short, 22usize, 21usize),
        (CounterLen::Long, 24, 23),
    ] {
        assert_eq!(data_overhead(len), overhead);
        assert_eq!(keepalive_len(len), keepalive);
        let mut sim = Sim::new(3, config(len), Channel::clean());
        sim.start();
        sim.run(Duration::from_secs(2), ms(10), ms(100), |_| {});
        let handshakes: Vec<usize> = sim
            .wire
            .iter()
            .filter(|(_, p)| p[0] == 0x11 || p[0] == 0x21)
            .map(|(_, p)| p.len())
            .collect();
        assert_eq!(handshakes, vec![119, 55]);
        let min_data = sim
            .wire
            .iter()
            .filter(|(_, p)| p[0] == 0x31 || p[0] == 0x39)
            .map(|(_, p)| p.len())
            .min()
            .unwrap();
        assert_eq!(
            min_data, keepalive,
            "a keepalive is header + index + counter + tag, no content type byte"
        );
        // Application packets carry the content type byte on top.
        let min_app = sim
            .wire
            .iter()
            .filter(|(_, p)| (p[0] == 0x31 || p[0] == 0x39) && p.len() > keepalive)
            .map(|(_, p)| p.len())
            .min()
            .unwrap();
        assert!(
            min_app >= overhead + 12,
            "payload is at least 12 bytes here"
        );
        assert!(sim.wire.iter().all(|(_, p)| p.len() <= 128));
    }
}

#[test]
fn a_handshake_2_changed_on_the_way_costs_seconds_not_minutes() {
    // The indexes in handshake 2 are inside the Noise payload, so a changed
    // clear index is refused (bad_header) and the timer simply tries again.
    for seed in 1..=3u64 {
        let mut sim = Sim::new(seed, config(CounterLen::Short), Channel::clean());
        sim.tamper_hs2 = 2; // the first two attempts (the second a retry)
        sim.start();
        sim.run(Duration::from_secs(90), ms(10), ms(100), |_| {});
        sim.drain();
        sim.check_delivery_integrity();
        sim.check_accounting();
        // Two changed handshake 2 packets were refused, and then it worked.
        let first = sim.logs[&Side::B].established[0].0;
        assert!(
            first < Duration::from_secs(25),
            "seed {seed}: first good session at {first:?}"
        );
        let gap = longest_gap(
            &sim,
            Side::B,
            first + Duration::from_secs(1),
            Duration::from_secs(90),
        );
        assert!(gap < 1.0, "seed {seed}: {gap}");
        let gap = longest_gap(
            &sim,
            Side::A,
            first + Duration::from_secs(1),
            Duration::from_secs(90),
        );
        assert!(gap < 1.0, "seed {seed}: {gap}");
        assert!(sim.stats(Side::A).dropped(DropReason::UnknownIndex) >= 1);
    }
}

/// A genuine peer rekeys every 5 s while an attacker floods the responder
/// with junk handshake 1 packets and replays of a recorded real one, 50 a
/// second each. Returns (rekeys at the initiator, rate_limited at the
/// responder, mac1 junk drops at the responder).
fn handshake_flood(use_source_limit: bool) -> (usize, u64, u64) {
    let mut cfg = config(CounterLen::Short);
    cfg.rekey_after = Duration::from_secs(5);
    cfg.reject_after = Duration::from_secs(60);
    let mut sim = Sim::new(77, cfg, Channel::clean());
    sim.start();
    sim.run(Duration::from_secs(1), ms(10), ms(100), |_| {});
    let recorded = sim
        .wire
        .iter()
        .find(|(to, p)| *to == Side::B && looks_like_handshake1(p))
        .unwrap()
        .1
        .clone();
    let mut limiter = SourceLimiter::new(5);
    let junk_before = sim.stats(Side::B).dropped(DropReason::BadHeader);
    let mut tick = 0u64;
    sim.run(Duration::from_secs(30), ms(10), ms(100), |s| {
        tick += 1;
        if !tick.is_multiple_of(2) {
            return; // 50 a second each: one of each every other 10 ms tick
        }
        // Junk: right size and header, wrong mac1. From address Y.
        let mut junk = vec![0u8; recorded.len()];
        s.rng.fill(&mut junk);
        junk[0] = 0x11;
        s.inject(Side::B, &junk);
        // A recorded real handshake 1, replayed from address Z.
        if !use_source_limit || limiter.allow(s.now, "Z") {
            s.inject(Side::B, &recorded);
        }
    });
    sim.drain();
    sim.check_delivery_integrity();
    let b = sim.stats(Side::B);
    assert_eq!(sim.logs[&Side::B].replies_to_injected, 0);
    (
        rekeys(&sim, Side::A),
        b.dropped(DropReason::RateLimited),
        b.dropped(DropReason::BadHeader) - junk_before,
    )
}

#[test]
fn junk_and_replayed_handshakes_do_not_stop_a_genuine_peer() {
    let (rekeys_a, limited, junk) = handshake_flood(true);
    // 30 s at one rekey every ~5 s.
    assert!(rekeys_a >= 5, "rekeys {rekeys_a}");
    assert_eq!(limited, 0, "the genuine peer was never rate limited");
    assert!(junk >= 1400, "the junk was thrown away by mac1: {junk}");
}

#[test]
fn without_the_per_source_limit_replays_do_starve_the_budget() {
    // Shows why the per-address limit exists, and that the test above bites.
    let (_, limited, _) = handshake_flood(false);
    assert!(limited > 100, "limited {limited}");
}

#[test]
fn a_rebooted_peer_is_noticed_and_the_link_heals() {
    // B reboots and loses its session. If B has data it starts a handshake
    // itself; if it only listens, A notices after the stale time.
    for (mute_b, bound) in [(None, 6u64), (Some(Side::B), 40)] {
        let mut cfg = config(CounterLen::Short);
        cfg.keepalive = None;
        let mut sim = Sim::new(41, cfg, Channel::clean());
        sim.mute = mute_b;
        sim.start();
        sim.run(Duration::from_secs(10), ms(10), ms(100), |_| {});
        sim.restart(Side::B);
        let at = sim.now;
        sim.run(Duration::from_secs(60), ms(10), ms(100), |_| {});
        sim.check_delivery_integrity();
        // B's new link got a session, and soon enough.
        let first_new = sim.logs[&Side::B]
            .established
            .iter()
            .map(|(t, ..)| *t)
            .filter(|t| *t > at)
            .min()
            .expect("B has a session again");
        assert!(
            first_new - at <= Duration::from_secs(bound),
            "mute={mute_b:?}: took {:?}",
            first_new - at
        );
        // Delivery in both directions goes on to the end (A to B always).
        let late = sim.logs[&Side::B]
            .delivered
            .iter()
            .filter(|(t, _)| *t > at + Duration::from_secs(50))
            .count();
        assert!(late > 50, "mute={mute_b:?}: {late}");
    }
}

#[test]
fn mismatched_expiry_settings_cost_seconds_and_recover_by_themselves() {
    // B rejects sessions after 60 s while A would use them for 150 s.
    // Not a supported setup (the spec says to set the same limits on both
    // sides) but it must not wedge.
    let mut a = config(CounterLen::Short);
    a.rekey_after = Duration::from_secs(100);
    a.reject_after = Duration::from_secs(150);
    let mut b = a.clone();
    b.rekey_after = Duration::from_secs(50);
    b.reject_after = Duration::from_secs(60);
    let mut sim = Sim::new_with(51, a, b, Channel::clean());
    sim.start();
    sim.run(Duration::from_secs(400), ms(10), ms(100), |_| {});
    sim.check_delivery_integrity();
    sim.check_accounting();
    for side in [Side::A, Side::B] {
        let gap = longest_gap(&sim, side, Duration::from_secs(5), Duration::from_secs(400));
        assert!(gap < 8.0, "{side:?} was silent for {gap:.1}s");
    }
}

#[test]
fn a_clock_a_day_behind_connects_unless_the_future_check_is_on() {
    let day = Duration::from_secs(86_400);
    let base = Duration::from_secs(1_700_000_000);
    // Check off (the default): the initiator is a day ahead, still fine.
    let cfg = config(CounterLen::Short);
    let mut sim = Sim::new_clocks(61, (cfg.clone(), base + day), (cfg, base), Channel::clean());
    sim.start();
    sim.run(Duration::from_secs(5), ms(10), ms(100), |_| {});
    assert!(sim.link(Side::A).can_send() && sim.link(Side::B).can_send());
    sim.check_delivery_integrity();
    // Check on, at the responder: refused, and not recorded.
    let mut strict = config(CounterLen::Short);
    strict.max_future = Some(Duration::from_secs(600));
    let mut sim = Sim::new_clocks(
        62,
        (config(CounterLen::Short), base + day),
        (strict, base),
        Channel::clean(),
    );
    // Only A's application sends: B would otherwise dial A itself.
    sim.mute = Some(Side::B);
    sim.start();
    sim.run(Duration::from_secs(20), ms(10), ms(100), |_| {});
    assert!(!sim.link(Side::B).can_send() && !sim.link(Side::A).can_send());
    assert!(sim.stats(Side::B).dropped(DropReason::StaleHandshake) >= 2);
    assert_eq!(sim.stats(Side::B).handshakes_accepted, 0);
    // B's clock is corrected (it is read at each check, here by a restart
    // with a right clock; nothing was recorded, so the same peer gets in).
    sim.cfgs.1.max_future = Some(Duration::from_secs(600));
    sim.restart_with_wall(Side::B, base + day);
    sim.mute = None;
    sim.run(Duration::from_secs(20), ms(10), ms(100), |_| {});
    assert!(sim.link(Side::A).can_send() && sim.link(Side::B).can_send());
    sim.check_delivery_integrity();
}

#[test]
fn a_restarted_peer_is_found_even_when_only_keepalives_flow() {
    let mut cfg = config(CounterLen::Short);
    cfg.keepalive = Some(Duration::from_secs(25));
    cfg.rekey_after = Duration::from_secs(600);
    cfg.reject_after = Duration::from_secs(900);
    let mut sim = Sim::new(71, cfg, Channel::clean());
    sim.mute_both = true;
    sim.start();
    sim.run(Duration::from_secs(30), ms(100), ms(100), |_| {});
    sim.restart(Side::B);
    let at = sim.now;
    sim.run(Duration::from_secs(150), ms(100), ms(100), |_| {});
    let back = sim.logs[&Side::B]
        .established
        .iter()
        .map(|(t, ..)| *t)
        .filter(|t| *t > at)
        .min()
        .expect("A started a new handshake");
    // Keepalive at 25 s, then 2 x 30 s without an answer.
    assert!(back - at >= Duration::from_secs(55), "{:?}", back - at);
    assert!(back - at <= Duration::from_secs(100), "{:?}", back - at);
}

// ---- removal sync (R-SEC2) through the simulated channel ---------------------
//
// Each side runs the real control layer next to its link, with a real device
// folder in a temporary directory, exactly as `oasa-link` does.

fn tmpdir(tag: &str) -> PathBuf {
    let mut r = [0u8; 8];
    getrandom::fill(&mut r).unwrap();
    let d = std::env::temp_dir().join(format!(
        "oasa-sim-{tag}-{}",
        data_encoding::HEXLOWER.encode(&r)
    ));
    std::fs::create_dir_all(&d).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    d
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

fn victim(i: usize) -> [u8; 32] {
    [60 + i as u8; 32]
}

fn is_removed(dir: &Path, key: &[u8; 32]) -> bool {
    removal::load_removed(dir).unwrap().is_removed(key)
}

fn is_listed(dir: &Path, key: &[u8; 32]) -> bool {
    store::get(dir, key).unwrap().is_some()
}

/// An admin on side A with `n` revoked victims in its log, and a device on
/// side B that lists the admin as `admin` and every victim as a peer.
struct Fleet {
    sim: Sim,
    admin: PathBuf,
    device: PathBuf,
    admin_key: [u8; 32],
    device_key: [u8; 32],
}

fn fleet(seed: u64, channel: Channel, n: usize) -> Fleet {
    let mut sim = Sim::new(seed, config(CounterLen::Short), channel);
    let (admin_key, device_key) = (pub_of(&sim.keys[&Side::A]), pub_of(&sim.keys[&Side::B]));
    let (admin, device) = (tmpdir("admin"), tmpdir("device"));
    trust(&admin, device_key, "device", Role::Peer);
    trust(&device, admin_key, "admin", Role::Admin);
    for i in 0..n {
        trust(&device, victim(i), &format!("victim-{i}"), Role::Peer);
        removal::revoke(&admin, &admin_key, &victim(i), 1000 + i as u64).unwrap();
    }
    sim.attach_control(Side::A, &admin, seed ^ 0xAD);
    sim.attach_control(Side::B, &device, seed ^ 0xDE);
    Fleet {
        sim,
        admin,
        device,
        admin_key,
        device_key,
    }
}

impl Fleet {
    fn revoke(&mut self, i: usize) {
        trust(&self.device, victim(i), &format!("victim-{i}"), Role::Peer);
        removal::revoke(&self.admin, &self.admin_key, &victim(i), 2000 + i as u64).unwrap();
        // oasa-link notices the log file changed and announces it.
        let now = self.sim.now;
        let acts = self.sim.ctl.get_mut(&Side::A).unwrap().log_changed(now);
        self.sim.run_ctl(Side::A, acts);
    }

    fn all_removed(&self, n: usize) -> bool {
        (0..n).all(|i| is_removed(&self.device, &victim(i)) && !is_listed(&self.device, &victim(i)))
    }

    fn held(&self) -> Option<u32> {
        removal::sync_state(&self.device, &fingerprint(&self.admin_key))
            .unwrap()
            .map(|(_, h)| h)
    }

    /// Nothing is waiting for an answer on the admin side: polling far in the
    /// future would resend anything still pending, and sends nothing.
    fn admin_has_nothing_pending(&mut self) -> bool {
        let far = self.sim.now + Duration::from_secs(100_000);
        self.sim.ctl.get_mut(&Side::A).unwrap().poll(far).is_empty()
    }

    fn entries_sent(&self) -> Vec<u32> {
        self.sim
            .ctl_messages(Side::A)
            .iter()
            .filter_map(|m| match m {
                Message::RemoveEntry { seq, .. } => Some(*seq),
                _ => None,
            })
            .collect()
    }
}

#[test]
fn removal_sync_converges_through_a_lossy_reordering_channel_on_many_seeds() {
    for seed in 1..=8u64 {
        let mut f = fleet(seed, Channel::rough(0.30), 6);
        f.sim.start();
        f.sim.run(Duration::from_secs(400), ms(10), ms(250), |s| {
            if s.rng.chance(0.02) {
                s.replay_random();
            }
        });
        assert!(
            f.all_removed(6),
            "seed {seed}: not every victim was removed"
        );
        assert_eq!(f.held(), Some(6), "seed {seed}");
        assert!(f.admin_has_nothing_pending(), "seed {seed}");
        // Only the victims went: the admin itself is still trusted.
        assert!(is_listed(&f.device, &f.admin_key));
        assert!(!is_removed(&f.device, &f.admin_key));
        // Control never reached the application, and the books still add up.
        f.sim.check_delivery_integrity();
        f.sim.check_accounting();
        f.sim.check_no_plaintext_on_the_wire();
        assert!(f.sim.stats(Side::B).control_received >= 6, "seed {seed}");
        assert!(
            f.sim.stats(Side::A).control_received >= 6,
            "seed {seed}: acks came back"
        );
    }
}

#[test]
fn an_admin_that_was_offline_catches_the_device_up_and_only_sends_what_is_missing() {
    let mut f = fleet(11, Channel::rough(0.10), 3);
    f.sim.start();
    f.sim.run(Duration::from_secs(60), ms(10), ms(500), |_| {});
    assert!(f.all_removed(3));
    assert_eq!(f.held(), Some(3));
    // The admin is cut off and revokes four more devices meanwhile.
    f.sim.blackout = true;
    f.sim.run(Duration::from_secs(10), ms(10), ms(500), |_| {});
    for i in 3..7 {
        f.revoke(i);
    }
    f.sim.run(Duration::from_secs(150), ms(10), ms(500), |_| {});
    assert!(
        !is_removed(&f.device, &victim(3)),
        "nothing can arrive in a blackout"
    );
    // The link comes back; the stale rule and the handshake retries find it.
    f.sim.blackout = false;
    let mark = f.entries_sent().len();
    f.sim.run(Duration::from_secs(300), ms(10), ms(500), |_| {});
    assert!(f.all_removed(7));
    assert_eq!(f.held(), Some(7));
    assert!(f.admin_has_nothing_pending());
    let after: Vec<u32> = f.entries_sent()[mark..].to_vec();
    assert!(
        after.iter().all(|seq| *seq >= 4),
        "entries 1 to 3 were already held and must not be sent again: {after:?}"
    );
    assert!(after.contains(&7));
    f.sim.check_delivery_integrity();
    f.sim.check_accounting();
}

#[test]
fn a_restarted_admin_and_a_restarted_device_resume_from_the_saved_state() {
    let mut f = fleet(13, Channel::rough(0.15), 5);
    f.sim.start();
    f.sim.run(Duration::from_secs(4), ms(10), ms(500), |_| {});
    // The device's process dies part-way (new link, new control, same folder).
    f.sim.restart(Side::B);
    f.sim.attach_control(Side::B, &f.device, 91);
    f.sim.run(Duration::from_secs(200), ms(10), ms(500), |_| {});
    assert!(f.all_removed(5));
    let held_before = f.held();
    assert_eq!(held_before, Some(5));
    // The admin's process restarts: it sends a head, the device says 5, and
    // not one entry goes out again.
    f.sim.restart(Side::A);
    f.sim.attach_control(Side::A, &f.admin, 92);
    let mark = f.entries_sent().len();
    f.sim.run(Duration::from_secs(200), ms(10), ms(500), |_| {});
    assert_eq!(f.entries_sent()[mark..], [] as [u32; 0]);
    assert!(
        f.sim
            .ctl_messages(Side::A)
            .iter()
            .any(|m| matches!(m, Message::RemoveHead { .. }))
    );
    f.sim.check_delivery_integrity();
}

#[test]
fn an_admin_that_lost_its_folder_starts_a_new_log_and_the_device_takes_it_whole() {
    let mut f = fleet(17, Channel::rough(0.10), 3);
    f.sim.start();
    f.sim.run(Duration::from_secs(100), ms(10), ms(500), |_| {});
    assert!(f.all_removed(3));
    // New folder, same key: a new log with a new id and one entry.
    std::fs::remove_file(f.admin.join(removal::LOG_FILE)).unwrap();
    f.sim.restart(Side::A);
    f.sim.attach_control(Side::A, &f.admin, 93);
    trust(&f.device, victim(9), "victim-9", Role::Peer);
    removal::revoke(&f.admin, &f.admin_key, &victim(9), 5).unwrap();
    f.sim.run(Duration::from_secs(300), ms(10), ms(500), |_| {});
    assert!(is_removed(&f.device, &victim(9)));
    // Union: the earlier removals stand.
    assert!(f.all_removed(3));
    assert_eq!(f.held(), Some(1));
}

#[test]
fn after_a_device_removes_its_admin_nothing_more_from_it_applies() {
    let mut f = fleet(19, Channel::clean(), 1);
    f.sim.start();
    f.sim.run(Duration::from_secs(30), ms(10), ms(500), |_| {});
    assert!(f.all_removed(1));
    // A person at the device removes the admin (it was stolen). The device's
    // oasa-link for it would exit; here its control is told, as the program does.
    removal::remove_local(&f.device, &f.device_key, &f.admin_key, 9).unwrap();
    f.sim.ctl.get_mut(&Side::B).unwrap().peer_removed();
    trust(&f.device, victim(5), "victim-5", Role::Peer);
    removal::revoke(&f.admin, &f.admin_key, &victim(5), 10).unwrap();
    let now = f.sim.now;
    let acts = f.sim.ctl.get_mut(&Side::A).unwrap().log_changed(now);
    f.sim.run_ctl(Side::A, acts);
    f.sim.run(Duration::from_secs(60), ms(10), ms(500), |_| {});
    assert!(!is_removed(&f.device, &victim(5)));
    assert!(is_listed(&f.device, &victim(5)));
    assert!(f.sim.ctl_drops[&Side::B].contains(&"peer_removed"));
}

/// Two admins on two links into one device (two `oasa-link` processes on one
/// folder), and an admin target listed on the device.
fn two_admin_device(seed: u64) -> (Sim, Sim, PathBuf, [u8; 32], [u8; 32], [u8; 32]) {
    let (kd, k1, k2) = {
        let mut r = Rng(seed);
        (key(&mut r), key(&mut r), key(&mut r))
    };
    let wall = Duration::from_secs(WALL);
    let mk = |s: u64, ka: [u8; 32]| {
        Sim::new_keyed(
            s,
            (config(CounterLen::Short), wall),
            (config(CounterLen::Short), wall),
            Channel::rough(0.20),
            Some((ka, kd)),
        )
    };
    let (s1, s2) = (mk(seed, k1), mk(seed + 1, k2));
    let device = tmpdir("two-admin-device");
    let (p1, p2, pd) = (pub_of(&k1), pub_of(&k2), pub_of(&kd));
    trust(&device, p1, "admin-1", Role::Admin);
    trust(&device, p2, "admin-2", Role::Admin);
    (s1, s2, device, p1, p2, pd)
}

fn admin_dir(admin: [u8; 32], device_pub: [u8; 32], targets: &[[u8; 32]]) -> PathBuf {
    let d = tmpdir("two-admin-admin");
    trust(&d, device_pub, "device", Role::Peer);
    for (i, t) in targets.iter().enumerate() {
        removal::revoke(&d, &admin, t, 50 + i as u64).unwrap();
    }
    d
}

#[test]
fn removing_an_admin_takes_entries_from_two_admins_on_two_links() {
    let (mut s1, mut s2, device, p1, p2, pd) = two_admin_device(23);
    let third = pub_of(&key(&mut Rng(777)));
    trust(&device, third, "admin-3", Role::Admin);
    let (d1, d2) = (admin_dir(p1, pd, &[third]), admin_dir(p2, pd, &[third]));
    s1.attach_control(Side::A, &d1, 1);
    s1.attach_control(Side::B, &device, 2);
    s2.attach_control(Side::A, &d2, 3);
    s2.attach_control(Side::B, &device, 4);
    s1.start();
    s1.run(Duration::from_secs(200), ms(10), ms(500), |_| {});
    assert!(is_listed(&device, &third), "one admin is not enough");
    assert!(!is_removed(&device, &third));
    assert!(device.join(removal::VOTES_FILE).exists());
    s2.start();
    s2.run(Duration::from_secs(200), ms(10), ms(500), |_| {});
    assert!(
        is_removed(&device, &third),
        "the second admin's entry completes it"
    );
    assert!(!is_listed(&device, &third));
    s1.check_accounting();
    s2.check_accounting();
}

#[test]
fn a_vote_from_an_admin_removed_before_the_second_arrives_is_lost() {
    let (mut s1, mut s2, device, p1, p2, pd) = two_admin_device(29);
    let third = pub_of(&key(&mut Rng(778)));
    trust(&device, third, "admin-3", Role::Admin);
    let (d1, d2) = (admin_dir(p1, pd, &[third]), admin_dir(p2, pd, &[third]));
    s1.attach_control(Side::A, &d1, 1);
    s1.attach_control(Side::B, &device, 2);
    s2.attach_control(Side::A, &d2, 3);
    s2.attach_control(Side::B, &device, 4);
    s1.start();
    s1.run(Duration::from_secs(200), ms(10), ms(500), |_| {});
    assert!(device.join(removal::VOTES_FILE).exists());
    // Admin 1 turns out to be the stolen one, and is removed on the device by hand.
    removal::remove_local(&device, &pd, &p1, 77).unwrap();
    s2.start();
    s2.run(Duration::from_secs(200), ms(10), ms(500), |_| {});
    assert!(
        is_listed(&device, &third),
        "admin 1's vote was dropped, so admin 2 alone is not enough"
    );
    assert!(!is_removed(&device, &third));
}

#[test]
fn the_same_entry_needs_one_vote_for_a_peer_and_two_for_an_admin() {
    let (mut s1, _s2, device, p1, _p2, pd) = two_admin_device(31);
    let as_admin = pub_of(&key(&mut Rng(779)));
    let as_peer = pub_of(&key(&mut Rng(780)));
    trust(&device, as_admin, "target-admin", Role::Admin);
    trust(&device, as_peer, "target-peer", Role::Peer);
    let d1 = admin_dir(p1, pd, &[as_admin, as_peer]);
    s1.attach_control(Side::A, &d1, 1);
    s1.attach_control(Side::B, &device, 2);
    s1.start();
    s1.run(Duration::from_secs(200), ms(10), ms(500), |_| {});
    assert!(
        is_removed(&device, &as_peer),
        "a peer goes on one admin's word"
    );
    assert!(is_listed(&device, &as_admin), "an admin needs a second");
}

// ---- signing-key rotation through the simulated channel (R-SEC2 phase B) ------
//
// Side A is the drone (it holds an autopilot key), side B its operator.

struct Pair {
    sim: Sim,
    drone: PathBuf,
    operator: PathBuf,
    drone_fp: String,
}

fn rotation_pair(seed: u64, channel: Channel) -> Pair {
    let mut sim = Sim::new(seed, config(CounterLen::Short), channel);
    let (a, b) = (pub_of(&sim.keys[&Side::A]), pub_of(&sim.keys[&Side::B]));
    let (drone, operator) = (tmpdir("rot-drone"), tmpdir("rot-operator"));
    // Both start with the key from pairing.
    let key = oasa_sec::signing::SigningKey::generate().unwrap();
    key.save(&drone.join(oasa_sec::signing::AUTOPILOT_KEY_FILE))
        .unwrap();
    let drone_fp = fingerprint(&a);
    key.save(&oasa_sec::signing::peer_key_path(&operator, &drone_fp))
        .unwrap();
    trust(&drone, b, "operator", Role::Operator);
    trust(&operator, a, "drone", Role::Peer);
    sim.attach_control(Side::A, &drone, seed ^ 1);
    sim.attach_control(Side::B, &operator, seed ^ 2);
    Pair {
        sim,
        drone,
        operator,
        drone_fp,
    }
}

impl Pair {
    fn tell_drone(&mut self) {
        let now = self.sim.now;
        let acts = self.sim.ctl.get_mut(&Side::A).unwrap().signing_changed(now);
        self.sim.run_ctl(Side::A, acts);
    }

    /// The signer's side of a rotation, without an autopilot: issue, and commit.
    fn issue(&mut self) -> oasa_sec::rotation::Begun {
        let b = oasa_sec::rotation::begin(&self.drone).unwrap();
        self.tell_drone();
        b
    }

    fn commit(&mut self, g: u32) {
        oasa_sec::rotation::commit(&self.drone, g).unwrap();
        self.tell_drone();
    }

    fn operator_key(&self) -> oasa_sec::signing::SigningKey {
        oasa_sec::signing::SigningKey::load(&oasa_sec::signing::peer_key_path(
            &self.operator,
            &self.drone_fp,
        ))
        .unwrap()
    }

    fn operator_gen(&self) -> u32 {
        oasa_sec::rotation::operator_gen(&self.operator, &self.drone_fp).unwrap()
    }
}

#[test]
fn a_rotation_reaches_the_operator_through_a_lossy_channel_on_many_seeds() {
    for seed in 1..=8u64 {
        let mut p = rotation_pair(seed, Channel::rough(0.30));
        p.sim.start();
        p.sim.run(Duration::from_secs(20), ms(10), ms(250), |_| {});
        let b = p.issue();
        p.sim.run(Duration::from_secs(300), ms(10), ms(250), |s| {
            if s.rng.chance(0.02) {
                s.replay_random();
            }
        });
        // The pending key arrived; the operator still uses the old one.
        let pending = oasa_sec::rotation::operator_pending(&p.operator, &p.drone_fp)
            .unwrap()
            .unwrap_or_else(|| panic!("seed {seed}: no pending key"));
        assert_eq!((pending.0, pending.1.as_bytes()), (1, b.key.as_bytes()));
        assert_eq!(
            p.operator_gen(),
            0,
            "seed {seed}: switched before the commit"
        );
        p.commit(1);
        p.sim.run(Duration::from_secs(300), ms(10), ms(250), |_| {});
        assert_eq!(p.operator_gen(), 1, "seed {seed}");
        assert_eq!(p.operator_key().as_bytes(), b.key.as_bytes(), "seed {seed}");
        let acked =
            oasa_sec::rotation::read_acked(&p.drone, &fingerprint(&pub_of(&p.sim.keys[&Side::B])))
                .unwrap();
        assert_eq!(
            acked,
            oasa_sec::rotation::Acked { next: 1, commit: 1 },
            "seed {seed}"
        );
        // Nothing left to send, and the key was never on the wire in the clear.
        let far = p.sim.now + Duration::from_secs(100_000);
        assert!(p.sim.ctl.get_mut(&Side::A).unwrap().poll(far).is_empty());
        for (_, w) in &p.sim.wire {
            assert!(
                !w.windows(32).any(|x| x == b.key.as_bytes()),
                "seed {seed}: the key is on the wire"
            );
        }
        p.sim.check_accounting();
        p.sim.check_delivery_integrity();
    }
}

#[test]
fn an_operator_that_was_away_for_two_rotations_catches_up_when_it_returns() {
    let mut p = rotation_pair(41, Channel::rough(0.15));
    p.sim.blackout = true;
    p.sim.start();
    p.sim.run(Duration::from_secs(10), ms(10), ms(500), |_| {});
    for g in 1..=2 {
        let b = p.issue();
        assert_eq!(b.generation, g);
        p.commit(g);
    }
    p.sim.run(Duration::from_secs(60), ms(10), ms(500), |_| {});
    assert_eq!(p.operator_gen(), 0, "nothing gets through a blackout");
    p.sim.blackout = false;
    p.sim.run(Duration::from_secs(400), ms(10), ms(500), |_| {});
    assert_eq!(p.operator_gen(), 2);
    let cur = oasa_sec::rotation::load_drone_keys(&p.drone)
        .unwrap()
        .unwrap()
        .current;
    assert_eq!(p.operator_key(), cur);
    p.sim.check_accounting();
}

#[test]
fn a_new_next_replaces_a_pending_one_after_a_dropped_rotation() {
    let mut p = rotation_pair(43, Channel::clean());
    p.sim.start();
    p.sim.run(Duration::from_secs(10), ms(10), ms(500), |_| {});
    let first = p.issue();
    p.sim.run(Duration::from_secs(20), ms(10), ms(500), |_| {});
    assert_eq!(
        oasa_sec::rotation::operator_pending(&p.operator, &p.drone_fp)
            .unwrap()
            .unwrap()
            .0,
        1
    );
    // The autopilot kept the old key: the signer drops it and tries again.
    oasa_sec::rotation::abandon(&p.drone).unwrap();
    let second = p.issue();
    assert_eq!(second.generation, 2);
    p.sim.run(Duration::from_secs(20), ms(10), ms(500), |_| {});
    let (g, k) = oasa_sec::rotation::operator_pending(&p.operator, &p.drone_fp)
        .unwrap()
        .unwrap();
    assert_eq!((g, k.as_bytes()), (2, second.key.as_bytes()));
    p.commit(2);
    p.sim.run(Duration::from_secs(20), ms(10), ms(500), |_| {});
    assert_eq!(p.operator_gen(), 2);
    assert_ne!(p.operator_key().as_bytes(), first.key.as_bytes());
}

#[test]
fn a_removed_operator_is_never_sent_the_new_key() {
    let mut p = rotation_pair(47, Channel::clean());
    let (a, b) = (pub_of(&p.sim.keys[&Side::A]), pub_of(&p.sim.keys[&Side::B]));
    p.sim.start();
    p.sim.run(Duration::from_secs(10), ms(10), ms(500), |_| {});
    // The operator is removed on the drone; its link process learns of it.
    removal::remove_local(&p.drone, &a, &b, 5).unwrap();
    p.sim.ctl.get_mut(&Side::A).unwrap().peer_removed();
    assert!(p.drone.join("rotation-pending").exists());
    let issued = p.issue();
    p.commit(issued.generation);
    p.sim.run(Duration::from_secs(60), ms(10), ms(500), |_| {});
    assert!(
        oasa_sec::rotation::operator_pending(&p.operator, &p.drone_fp)
            .unwrap()
            .is_none()
    );
    assert_eq!(p.operator_gen(), 0);
    for (_, w) in &p.sim.wire {
        assert!(!w.windows(32).any(|x| x == issued.key.as_bytes()));
    }
}
