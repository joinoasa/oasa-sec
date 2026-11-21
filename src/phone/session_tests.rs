//! The phone link session, its messages and held packets in simulated time
//! (spec sections 3 to 5): tests named after the section 8 cases they
//! cover (`case_NN_...`), and the refusals.
//!
//! The radio is a [`RadioNode`] over [`MemStore`], a flash that can fail a
//! write or lose power, and a reboot reads the same flash back. The phone is
//! the real link ([`phone_link`]) with its own timestamp store, talking to
//! the radio over a simulated BLE stream or USB datagrams.

use std::cell::RefCell;
use std::rc::Rc;
use std::result::Result;
use std::time::Duration;

use zeroize::Zeroizing;

use super::frame::{Deframer, frame};
use super::hold::{
    Filter, Filters, HOLD_BYTES, HOLD_FOR, HOLD_PACKETS, HoldNumber, HoldStore, Signal, WakeLimit,
    handshake_filter,
};
use super::msg::*;
use super::*;
use crate::identity::Identity;
use crate::link::{
    DropReason, Entropy, EntropyFailed, Event, Link, OsEntropy, StoredStamps, TimestampStore,
};

const MTU: usize = 256;
type N = RadioNode<MemStore, TestEntropy, TestFormat, 3, 2, 3, MTU>;

/// The phone's wall clock at monotonic zero (it has a clock).
const WALL: Duration = Duration::from_secs(1_800_000_000);
/// Text that must never appear on the phone link (case 26).
const MARK: &[u8] = b"test-plaintext-7f3c";

fn s(secs: f64) -> Duration {
    Duration::from_secs_f64(secs)
}

// ---- the simulated flash ----

#[derive(Default)]
struct Flash {
    marker: Option<Marker>,
    trust: Option<([u8; 32], String, [u8; 32])>,
    stamps: Vec<([u8; 32], StoredStamps)>,
    filters: Option<Vec<Filter>>,
    rate_count: u8,
    ops: usize,
    crash_at: Option<usize>,
    dead: bool,
    /// Operation number `n` fails with a write error.
    error_at: Option<usize>,
    reads_fail: bool,
}

#[derive(Clone)]
struct MemStore(Rc<RefCell<Flash>>);

impl MemStore {
    fn step(&self) -> Result<(), StoreFailed> {
        let mut f = self.0.borrow_mut();
        if f.dead || f.crash_at == Some(f.ops) {
            f.dead = true;
            return Err(StoreFailed);
        }
        if f.error_at == Some(f.ops) {
            f.error_at = None;
            return Err(StoreFailed);
        }
        f.ops += 1;
        Ok(())
    }
    fn alive(&self) -> Result<(), StoreFailed> {
        let f = self.0.borrow();
        if f.dead || f.reads_fail {
            Err(StoreFailed)
        } else {
            Ok(())
        }
    }
}

impl RadioStore for MemStore {
    fn marker(&mut self) -> Result<Option<Marker>, StoreFailed> {
        self.alive()?;
        Ok(self.0.borrow().marker)
    }
    fn set_marker(&mut self, m: Marker) -> Result<(), StoreFailed> {
        self.step()?;
        self.0.borrow_mut().marker = Some(m);
        Ok(())
    }
    fn clear_marker(&mut self) -> Result<(), StoreFailed> {
        self.step()?;
        self.0.borrow_mut().marker = None;
        Ok(())
    }
    fn erase_owner_state(&mut self) -> Result<(), StoreFailed> {
        self.step()?;
        let mut f = self.0.borrow_mut();
        f.stamps.clear();
        f.filters = None;
        Ok(())
    }
    fn trust(&mut self) -> Result<Option<SavedPhone>, StoreFailed> {
        self.alive()?;
        Ok(self.0.borrow().trust.as_ref().map(|(p, n, l)| SavedPhone {
            phone_public: *p,
            name: Name::new(n).unwrap(),
            link_private: Zeroizing::new(*l),
        }))
    }
    fn write_trust(&mut self, t: Option<&SavedPhone>) -> Result<(), StoreFailed> {
        self.step()?;
        self.0.borrow_mut().trust =
            t.map(|t| (t.phone_public, t.name.as_str().to_string(), *t.link_private));
        Ok(())
    }
    fn rate_count(&mut self) -> Result<u8, StoreFailed> {
        self.alive()?;
        Ok(self.0.borrow().rate_count)
    }
    fn write_rate_count(&mut self, n: u8) -> Result<(), StoreFailed> {
        self.step()?;
        self.0.borrow_mut().rate_count = n;
        Ok(())
    }
}

impl PhoneStateStore for MemStore {
    fn stamps(&mut self, phone: &[u8; 32]) -> Result<StoredStamps, StoreFailed> {
        self.alive()?;
        let f = self.0.borrow();
        Ok(f.stamps
            .iter()
            .find(|(p, _)| p == phone)
            .map(|(_, s)| *s)
            .unwrap_or_default())
    }
    fn write_stamps(&mut self, phone: &[u8; 32], st: &StoredStamps) -> Result<(), StoreFailed> {
        self.step()?;
        let mut f = self.0.borrow_mut();
        f.stamps.retain(|(p, _)| p != phone);
        f.stamps.push((*phone, *st));
        Ok(())
    }
    fn filters(&mut self) -> Result<Filters, StoreFailed> {
        self.alive()?;
        let f = self.0.borrow();
        Ok(f.filters
            .as_ref()
            .map(|l| Filters::new(l).unwrap())
            .unwrap_or_default())
    }
    fn write_filters(&mut self, filters: &Filters) -> Result<(), StoreFailed> {
        self.step()?;
        self.0.borrow_mut().filters = Some(filters.list().collect());
        Ok(())
    }
}

#[derive(Clone, Default)]
struct TestEntropy(Rc<std::cell::Cell<bool>>);

impl Entropy for TestEntropy {
    fn fill(&mut self, dst: &mut [u8]) {
        self.try_fill(dst).expect("random source failed");
    }
    fn try_fill(&mut self, dst: &mut [u8]) -> Result<(), EntropyFailed> {
        if self.0.get() {
            return Err(EntropyFailed);
        }
        getrandom::fill(dst).map_err(|_| EntropyFailed)
    }
}

// ---- a body format for tests (the spec has none yet) ----

/// Filters: `[1][index: 2]`, `[2][group: 2]`, `[3][key: 32]`; `FETCH`:
/// empty; `FETCH_ACK`: hold numbers, 4 bytes each; `HELD`: 2-byte count;
/// `RECEIVED`: hold number (4), signal (2), packet.
#[derive(Default)]
struct TestFormat;

impl BodyFormat for TestFormat {
    fn decode_filters(&mut self, mut b: &[u8]) -> Option<Filters> {
        let mut list = vec![];
        while let Some((&k, rest)) = b.split_first() {
            match k {
                1 | 2 if rest.len() >= 2 => {
                    let v = u16::from_be_bytes([rest[0], rest[1]]);
                    list.push(if k == 1 {
                        Filter::Index(v)
                    } else {
                        Filter::Group(v)
                    });
                    b = &rest[2..];
                }
                3 if rest.len() >= 32 => {
                    list.push(Filter::Handshake(rest[..32].try_into().unwrap()));
                    b = &rest[32..];
                }
                _ => return None,
            }
        }
        Filters::new(&list)
    }
    fn decode_fetch(&mut self, b: &[u8]) -> bool {
        b.is_empty()
    }
    fn decode_fetch_ack(&mut self, b: &[u8], out: &mut [HoldNumber; MAX_ACK]) -> Option<usize> {
        if !b.len().is_multiple_of(4) || b.len() / 4 > MAX_ACK {
            return None;
        }
        for (i, c) in b.chunks(4).enumerate() {
            out[i] = HoldNumber(u32::from_be_bytes(c.try_into().unwrap()));
        }
        Some(b.len() / 4)
    }
    fn encode_held(&mut self, count: usize, out: &mut Vec<u8>) {
        out.extend_from_slice(&(count as u16).to_be_bytes());
    }
    fn encode_received(&mut self, h: HoldNumber, sig: Signal, p: &[u8], out: &mut Vec<u8>) {
        out.extend_from_slice(&h.0.to_be_bytes());
        out.extend_from_slice(&sig.0.to_be_bytes());
        out.extend_from_slice(p);
    }
}

fn filters_msg(list: &[Filter]) -> Vec<u8> {
    let mut v = vec![MSG_FILTERS];
    for f in list {
        match f {
            Filter::Index(i) => {
                v.push(1);
                v.extend(i.to_be_bytes());
            }
            Filter::Group(g) => {
                v.push(2);
                v.extend(g.to_be_bytes());
            }
            Filter::Handshake(k) => {
                v.push(3);
                v.extend(k);
            }
        }
    }
    v
}

fn ack_msg(holds: &[u32]) -> Vec<u8> {
    let mut v = vec![MSG_FETCH_ACK];
    for h in holds {
        v.extend(h.to_be_bytes());
    }
    v
}

fn send_msg(tag: u8) -> Vec<u8> {
    let mut v = vec![MSG_SEND, tag];
    v.extend_from_slice(MARK);
    v
}

/// A link data packet on the air for receiver `index`.
fn data_pkt(index: u16, tag: u8, len: usize) -> Vec<u8> {
    let mut v = vec![0x31];
    v.extend(index.to_be_bytes());
    v.extend([0, tag]);
    v.resize(len.max(21), tag);
    v
}

/// A group packet on the air.
fn group_pkt(g: u16, tag: u8) -> Vec<u8> {
    let mut v = vec![0x41];
    v.extend(g.to_be_bytes());
    v.resize(40, tag);
    v
}

/// A real link handshake 1 to `to` on the air.
fn hs_pkt(to: &[u8; 32]) -> Vec<u8> {
    let me = Identity::generate().unwrap();
    let mut l = Link::new(
        &me,
        *to,
        crate::link::Config::default(),
        Box::new(OsEntropy),
        WALL,
        Box::new(crate::link::MemoryTimestampStore::default()),
    )
    .unwrap();
    packets(&l.start_handshake(s(0.0)).unwrap()).remove(0)
}

fn packets(evs: &[Event]) -> Vec<Vec<u8>> {
    evs.iter()
        .filter_map(|e| match e {
            Event::Send { packet, .. } => Some(packet.clone()),
            _ => None,
        })
        .collect()
}

// ---- the phone ----

#[derive(Clone, Default)]
struct PhoneStamps(Rc<RefCell<StoredStamps>>);

impl TimestampStore for PhoneStamps {
    fn load(&mut self) -> crate::Result<StoredStamps> {
        Ok(*self.0.borrow())
    }
    fn save(&mut self, st: &StoredStamps) -> crate::Result<()> {
        *self.0.borrow_mut() = *st;
        Ok(())
    }
}

struct Phone {
    link: Link,
    key: Zeroizing<[u8; 32]>,
    radio_link: [u8; 32],
    conn: ConnId,
    tr: Transport,
    rx: Deframer<MTU>,
    stamps: PhoneStamps,
    /// Messages from the radio, `[type][body]`.
    got: Vec<Vec<u8>>,
    /// Every packet the phone sent.
    sent: Vec<Vec<u8>>,
}

impl Phone {
    fn new(done: &PhonePaired, conn: ConnId, tr: Transport) -> Self {
        Self::with(
            done.radio_link_key.private_key(),
            done.radio_link_public,
            conn,
            tr,
            WALL,
            PhoneStamps::default(),
        )
    }

    fn with(
        key: &[u8; 32],
        radio_link: [u8; 32],
        conn: ConnId,
        tr: Transport,
        wall: Duration,
        stamps: PhoneStamps,
    ) -> Self {
        let id = Identity::from_private_bytes(key).unwrap();
        let link = phone_link(
            &id,
            radio_link,
            MTU,
            Box::new(OsEntropy),
            wall,
            Box::new(stamps.clone()),
        )
        .unwrap();
        Self {
            link,
            key: Zeroizing::new(*key),
            radio_link,
            conn,
            tr,
            rx: Deframer::new(),
            stamps,
            got: vec![],
            sent: vec![],
        }
    }

    /// The same phone after its connection dropped: a new link object
    /// (sessions gone), same key and saved timestamps.
    fn reconnected(&self, conn: ConnId) -> Self {
        Self::with(
            &self.key,
            self.radio_link,
            conn,
            self.tr,
            WALL,
            self.stamps.clone(),
        )
    }

    fn wire(&self, p: &[u8]) -> Vec<u8> {
        match self.tr {
            Transport::Ble => frame(p).unwrap(),
            Transport::Usb => p.to_vec(),
        }
    }

    /// Bytes from the radio; returns what the phone sends back.
    fn recv(&mut self, t: f64, bytes: &[u8]) -> Vec<Vec<u8>> {
        let mut pk = vec![];
        match self.tr {
            Transport::Ble => self.rx.push(bytes, |p| pk.push(p.to_vec())).unwrap(),
            Transport::Usb => pk.push(bytes.to_vec()),
        }
        let mut back = vec![];
        for p in pk {
            for e in self.link.handle_packet(s(t), &p) {
                match e {
                    Event::Send { packet, .. } => back.push(packet),
                    Event::Deliver(b) => self.got.push(b),
                    _ => {}
                }
            }
        }
        back
    }

    fn held(&self) -> Option<u16> {
        self.got
            .iter()
            .rev()
            .find(|m| m[0] == MSG_HELD)
            .map(|m| u16::from_be_bytes([m[1], m[2]]))
    }

    /// `RECEIVED` messages: hold number and packet.
    fn received(&self) -> Vec<(u32, Vec<u8>)> {
        self.got
            .iter()
            .filter(|m| m[0] == MSG_RECEIVED)
            .map(|m| {
                (
                    u32::from_be_bytes(m[1..5].try_into().unwrap()),
                    m[7..].to_vec(),
                )
            })
            .collect()
    }
}

// ---- the bench ----

const RADIO_NAME: &str = "keel-1";

struct Bench {
    n: N,
    flash: Rc<RefCell<Flash>>,
    label: LabelCode,
    pairing_private: Zeroizing<[u8; 32]>,
    entropy: TestEntropy,
    /// Every action so far.
    log: Vec<NodeAction>,
}

impl Bench {
    fn boot(usb: bool) -> Self {
        let id = Identity::generate().unwrap();
        let label = LabelCode::new(*id.public_key()).unwrap();
        let pairing_private = Zeroizing::new(*id.private_key());
        let flash = Rc::new(RefCell::new(Flash::default()));
        let entropy = TestEntropy::default();
        let mut log = vec![];
        let n = N::boot(
            RadioKeys::new(id, &label).unwrap(),
            Name::new(RADIO_NAME).unwrap(),
            MemStore(flash.clone()),
            entropy.clone(),
            TestFormat,
            s(0.0),
            usb,
            &mut |a| log.push(a),
        );
        Self {
            n,
            flash,
            label,
            pairing_private,
            entropy,
            log,
        }
    }

    /// Power comes back: the same flash, a new radio (nothing in memory).
    fn reboot(&mut self, t: f64, usb: bool) -> Vec<NodeAction> {
        {
            let mut f = self.flash.borrow_mut();
            f.dead = false;
            f.crash_at = None;
        }
        let id = Identity::from_private_bytes(&self.pairing_private[..]).unwrap();
        let mut v = vec![];
        self.n = N::boot(
            RadioKeys::new(id, &self.label).unwrap(),
            Name::new(RADIO_NAME).unwrap(),
            MemStore(self.flash.clone()),
            self.entropy.clone(),
            TestFormat,
            s(t),
            usb,
            &mut |a| v.push(a),
        );
        self.log.extend(v.iter().cloned());
        v
    }

    fn go(&mut self, f: impl FnOnce(&mut N, &mut dyn FnMut(NodeAction))) -> Vec<NodeAction> {
        let mut v = vec![];
        {
            let mut sink = |a| v.push(a);
            f(&mut self.n, &mut sink);
        }
        self.log.extend(v.iter().cloned());
        v
    }

    fn poll(&mut self, t: f64) -> Vec<NodeAction> {
        self.go(|n, mut o| n.poll(s(t), &mut o))
    }
    fn reset(&mut self, t: f64) -> Vec<NodeAction> {
        self.go(|n, mut o| n.pinhole_reset(s(t), &mut o))
    }
    fn open(&mut self, t: f64, tr: Transport, conn: ConnId) -> Vec<NodeAction> {
        self.go(|n, mut o| n.link_opened(s(t), tr, conn, &mut o))
    }
    fn close(&mut self, t: f64, conn: ConnId) -> Vec<NodeAction> {
        self.go(|n, mut o| n.link_closed(s(t), conn, &mut o))
    }
    fn bytes(&mut self, t: f64, conn: ConnId, b: &[u8]) -> Vec<NodeAction> {
        self.go(|n, mut o| n.link_bytes(s(t), conn, b, &mut o))
    }
    fn air(&mut self, t: f64, p: &[u8]) -> Vec<NodeAction> {
        self.go(|n, mut o| n.air_received(s(t), p, Signal(-90), &mut o))
    }

    fn link_stats(&self) -> crate::link::Stats {
        self.n.link_stats().cloned().unwrap_or_default()
    }

    fn dropped(&self, r: DropReason) -> u64 {
        self.link_stats().dropped(r)
    }

    fn transmits(&self) -> usize {
        self.log
            .iter()
            .filter(|a| matches!(a, NodeAction::Transmit { .. }))
            .count()
    }

    /// Pair a phone over a pairing channel in the open window.
    fn pair(
        &mut self,
        t: f64,
        tr: Transport,
        ch: ChannelId,
        code: PairWith<'_>,
        name: &str,
    ) -> PhonePaired {
        self.go(|n, mut o| n.pairing_channel_opened(s(t), tr, ch, &mut o));
        let (p, m1) = PhonePairing::start(code, name, &mut OsEntropy).unwrap();
        let v = self.go(|n, mut o| n.pairing_message(s(t), ch, &m1, &mut o));
        let m2 = msg2_in(&v, ch).expect("message 2");
        let done = p.finish(&m2).unwrap();
        let v = self.go(|n, mut o| n.pairing_message(s(t), ch, &done.msg3, &mut o));
        assert!(
            v.iter()
                .any(|a| matches!(a, NodeAction::Pairing(Action::Paired { .. }))),
            "not paired"
        );
        done
    }

    /// Booted on USB, window at 2 s, paired over USB at 3 s.
    fn paired() -> (Self, PhonePaired) {
        let mut b = Self::boot(true);
        b.poll(2.0);
        let label = b.label.clone();
        let done = b.pair(3.0, Transport::Usb, 1, PairWith::Label(&label), "owner");
        (b, done)
    }

    /// Paired, and the phone connected on BLE connection 10 at 4 s.
    fn connected() -> (Self, Phone) {
        let (mut b, done) = Self::paired();
        let mut p = Phone::new(&done, 10, Transport::Ble);
        b.connect(4.0, &mut p);
        assert!(b.n.connected(), "the owner did not connect");
        (b, p)
    }

    /// Send the phone's packets and run until nothing more flows.
    fn pump(&mut self, t: f64, p: &mut Phone, mut to_radio: Vec<Vec<u8>>) -> Vec<NodeAction> {
        let mut all = vec![];
        for _ in 0..20 {
            if to_radio.is_empty() {
                break;
            }
            let mut back = vec![];
            for pkt in std::mem::take(&mut to_radio) {
                p.sent.push(pkt.clone());
                let w = p.wire(&pkt);
                let acts = self.bytes(t, p.conn, &w);
                back.extend(sends_to(&acts, p.conn));
                all.extend(acts);
            }
            for b in back {
                to_radio.extend(p.recv(t, &b));
            }
        }
        all
    }

    fn connect(&mut self, t: f64, p: &mut Phone) -> Vec<NodeAction> {
        let mut v = self.open(t, p.tr, p.conn);
        let hs = packets(&p.link.start_handshake(s(t)).unwrap());
        v.extend(self.pump(t, p, hs));
        v
    }

    /// The phone sends one message `[type][body]`.
    fn say(&mut self, t: f64, p: &mut Phone, plain: &[u8]) -> Vec<NodeAction> {
        let pkt = p.link.send(s(t), plain).unwrap();
        self.pump(t, p, vec![pkt])
    }

    /// Run both sides' timers at `t`.
    fn tick_both(&mut self, t: f64, p: &mut Phone) -> Vec<NodeAction> {
        let acts = self.poll(t);
        let mut back = vec![];
        for b in sends_to(&acts, p.conn) {
            back.extend(p.recv(t, &b));
        }
        back.extend(packets(&p.link.poll_timers(s(t))));
        let mut all = acts;
        all.extend(self.pump(t, p, back));
        all
    }
}

fn msg2_in(v: &[NodeAction], ch: ChannelId) -> Option<Vec<u8>> {
    v.iter().find_map(|a| match a {
        NodeAction::Pairing(Action::Send { channel, msg2 }) if *channel == ch => {
            Some(msg2.as_bytes().to_vec())
        }
        _ => None,
    })
}

fn sends_to(v: &[NodeAction], conn: ConnId) -> Vec<Vec<u8>> {
    v.iter()
        .filter_map(|a| match a {
            NodeAction::LinkSend { conn: c, bytes } if *c == conn => Some(bytes.clone()),
            _ => None,
        })
        .collect()
}

fn closed(v: &[NodeAction], conn: ConnId) -> Option<LinkCloseReason> {
    v.iter().find_map(|a| match a {
        NodeAction::LinkClose { conn: c, why } if *c == conn => Some(*why),
        _ => None,
    })
}

fn has(v: &[NodeAction], f: impl Fn(&NodeAction) -> bool) -> bool {
    v.iter().any(f)
}

fn random_secret() -> [u8; 32] {
    let mut k = [0u8; 32];
    getrandom::fill(&mut k).unwrap();
    k
}

// ---- section 3: the session ----

#[test]
fn the_owner_connects_and_is_told_what_is_held() {
    let (b, p) = Bench::connected();
    assert_eq!(p.held(), Some(0));
    assert_eq!(b.link_stats().handshakes_accepted, 1);
    assert!(b.n.connected());
}

#[test]
fn the_session_runs_the_same_on_usb_datagrams() {
    let (mut b, done) = Bench::paired();
    let mut p = Phone::new(&done, 20, Transport::Usb);
    b.connect(4.0, &mut p);
    assert!(b.n.connected());
    b.say(5.0, &mut p, &send_msg(1));
    assert_eq!(b.transmits(), 1);
}

#[test]
fn link_settings_are_the_specs() {
    let c = link_config(MTU);
    assert_eq!(c.keepalive, None);
    assert_eq!(c.rekey_after, Duration::from_secs(3600));
    assert_eq!(c.rekey_after_packets, 1 << 32);
    assert_eq!(c.reject_after, Duration::from_secs(5400));
    assert_eq!(c.max_future, None);
    assert!(c.validate().is_ok());
}

#[test]
fn case_01_an_unpaired_phone_is_refused() {
    let (mut b, done) = Bench::connected_pair();
    let before = b.transmits();
    // A stranger who knows the radio's link public key: untrusted_peer.
    let stranger = Identity::generate().unwrap();
    let mut s1 = Phone::with(
        stranger.private_key(),
        done.radio_link_public,
        30,
        Transport::Ble,
        WALL,
        PhoneStamps::default(),
    );
    let v = b.connect(10.0, &mut s1);
    assert!(sends_to(&v, 30).is_empty(), "the stranger got a reply");
    assert_eq!(b.dropped(DropReason::UntrustedPeer), 1);
    // One who does not: it can only aim at the pairing key (from the
    // label): bad_header.
    let mut s2 = Phone::with(
        stranger.private_key(),
        *b.label.pairing_public(),
        31,
        Transport::Ble,
        WALL,
        PhoneStamps::default(),
    );
    let v = b.connect(11.0, &mut s2);
    assert!(sends_to(&v, 31).is_empty());
    assert_eq!(b.dropped(DropReason::BadHeader), 1);
    // Its commands, as data packets with made-up indexes: unknown_index.
    for i in 0..4u16 {
        let v = b.bytes(11.5, 31, &frame(&data_pkt(i, 1, 60)).unwrap());
        assert!(sends_to(&v, 31).is_empty());
    }
    assert_eq!(b.dropped(DropReason::UnknownIndex), 4);
    assert_eq!(b.transmits(), before, "a stranger's command was done");
    // Neither stranger's connection completes: closed at 5 s.
    let v = b.poll(17.0);
    assert_eq!(closed(&v, 30), Some(LinkCloseReason::NoHandshake));
    assert_eq!(closed(&v, 31), Some(LinkCloseReason::NoHandshake));
}

impl Bench {
    /// Paired and connected, also returning the pairing result.
    fn connected_pair() -> (Self, PhonePaired) {
        let (mut b, done) = Self::paired();
        let mut p = Phone::new(&done, 10, Transport::Ble);
        b.connect(4.0, &mut p);
        (b, done)
    }
}

#[test]
fn case_01_an_unpaired_radio_answers_nobody() {
    let mut b = Bench::boot(false);
    let stranger = Identity::generate().unwrap();
    let mut p = Phone::with(
        stranger.private_key(),
        *Identity::generate().unwrap().public_key(),
        5,
        Transport::Ble,
        WALL,
        PhoneStamps::default(),
    );
    let v = b.connect(1.0, &mut p);
    assert!(sends_to(&v, 5).is_empty());
    assert_eq!(b.n.stats().no_peer, 1);
    assert!(b.n.link_stats().is_none());
}

#[test]
fn case_02_a_replayed_send_is_dropped_everywhere() {
    let (mut b, mut p) = Bench::connected();
    let rec = p.link.send(s(5.0), &send_msg(1)).unwrap();
    let w = p.wire(&rec);
    b.bytes(5.0, 10, &w);
    assert_eq!(b.transmits(), 1);
    // In the same session.
    let v = b.bytes(5.5, 10, &w);
    assert!(sends_to(&v, 10).is_empty());
    assert_eq!(b.dropped(DropReason::Replay), 1);
    // After a rekey, during the old session's grace.
    let t = 3600.0 + 4.0;
    b.tick_both(t, &mut p);
    assert!(p.link.stats().handshakes_completed >= 2, "no rekey");
    b.say(t + 1.0, &mut p, &send_msg(2));
    assert_eq!(b.transmits(), 2);
    b.bytes(t + 2.0, 10, &w);
    assert_eq!(b.transmits(), 2);
    // After the grace: the old session is gone.
    b.tick_both(t + 30.0, &mut p);
    let unknown = b.dropped(DropReason::UnknownIndex);
    b.bytes(t + 31.0, 10, &w);
    assert_eq!(b.dropped(DropReason::UnknownIndex), unknown + 1);
    // After a reconnect.
    b.close(t + 40.0, 10);
    let mut p2 = p.reconnected(11);
    b.connect(t + 41.0, &mut p2);
    assert!(b.n.connected());
    let v = b.bytes(t + 42.0, 11, &w);
    assert!(sends_to(&v, 11).is_empty());
    assert_eq!(b.transmits(), 2, "a replayed SEND went on the air");
}

#[test]
fn reordered_commands_each_count_once() {
    let (mut b, mut p) = Bench::connected();
    let pk: Vec<Vec<u8>> = (0..5)
        .map(|i| {
            let k = p.link.send(s(5.0), &send_msg(i)).unwrap();
            p.wire(&k)
        })
        .collect();
    for i in [4usize, 0, 3, 1, 2, 2, 4, 0] {
        b.bytes(6.0, 10, &pk[i]);
    }
    assert_eq!(b.transmits(), 5);
    assert_eq!(b.dropped(DropReason::Replay), 3);
}

#[test]
fn case_06_the_owner_who_lost_the_race_gets_no_link_handshake() {
    let mut b = Bench::boot(true);
    b.poll(2.0);
    let label = b.label.clone();
    // The owner reaches message 2 first; a stranger with the label
    // completes first.
    b.go(|n, mut o| n.pairing_channel_opened(s(3.0), Transport::Usb, 1, &mut o));
    let (owner, m1) =
        PhonePairing::start(PairWith::Label(&label), "owner", &mut OsEntropy).unwrap();
    let v = b.go(|n, mut o| n.pairing_message(s(3.0), 1, &m1, &mut o));
    let owner = owner.finish(&msg2_in(&v, 1).unwrap()).unwrap();
    b.pair(3.5, Transport::Usb, 2, PairWith::Label(&label), "stranger");
    let v = b.go(|n, mut o| n.pairing_message(s(4.0), 1, &owner.msg3, &mut o));
    assert!(!has(&v, |a| matches!(
        a,
        NodeAction::Pairing(Action::Paired { .. })
    )));
    // The owner's confirmation never comes.
    let mut p = Phone::new(&owner, 10, Transport::Ble);
    let v = b.connect(5.0, &mut p);
    assert!(sends_to(&v, 10).is_empty());
    assert!(!b.n.connected());
    assert_eq!(b.dropped(DropReason::BadHeader), 1);
}

#[test]
fn case_16_the_link_uses_the_link_key_from_message_2_never_the_pairing_key() {
    let (mut b, done) = Bench::paired();
    assert_ne!(&done.radio_link_public, b.label.pairing_public());
    // The owner's own radio-link key, aimed at the pairing key: dropped.
    let mut wrong = Phone::with(
        done.radio_link_key.private_key(),
        *b.label.pairing_public(),
        9,
        Transport::Ble,
        WALL,
        PhoneStamps::default(),
    );
    let v = b.connect(4.0, &mut wrong);
    assert!(sends_to(&v, 9).is_empty());
    assert_eq!(b.dropped(DropReason::BadHeader), 1);
    // To the link key: accepted.
    let mut p = Phone::new(&done, 10, Transport::Ble);
    b.connect(5.0, &mut p);
    assert!(b.n.connected());
}

#[test]
fn case_16_after_a_reset_and_a_new_pairing_old_handshakes_are_dropped() {
    let (mut b, mut old) = Bench::connected();
    let recorded = old.sent[0].clone();
    b.reset(10.0);
    b.usb_replug(11.0);
    let label = b.label.clone();
    let new = b.pair(30.0, Transport::Usb, 2, PairWith::Label(&label), "new");
    assert_ne!(new.radio_link_public, old.radio_link);
    // The old phone and its recorded handshake: nothing.
    b.open(31.0, Transport::Ble, 12);
    let v = b.bytes(31.0, 12, &frame(&recorded).unwrap());
    assert!(sends_to(&v, 12).is_empty());
    let mut again = old.reconnected(13);
    let v = b.connect(32.0, &mut again);
    assert!(sends_to(&v, 13).is_empty());
    assert!(b.dropped(DropReason::BadHeader) >= 2);
    // The new phone works.
    let mut p = Phone::new(&new, 14, Transport::Ble);
    b.connect(33.0, &mut p);
    assert!(b.n.connected());
    let _ = &mut old;
}

impl Bench {
    /// Unplug, wait, plug back in: a USB window opens 2 s later (the
    /// radio must be unpaired).
    fn usb_replug(&mut self, t: f64) {
        self.go(|n, mut o| n.usb_power(s(t), false, &mut o));
        self.go(|n, mut o| n.usb_power(s(t + 11.0), true, &mut o));
        let v = self.poll(t + 13.0);
        assert!(
            has(&v, |a| matches!(
                a,
                NodeAction::Pairing(Action::WindowOpened { .. })
            )) || self.n.status(s(t + 13.0)).window.is_some(),
            "no window"
        );
    }
}

#[test]
fn case_17_a_changed_bit_in_any_command_is_dropped() {
    let (mut b, mut p) = Bench::connected();
    let pkt = p.link.send(s(5.0), &send_msg(1)).unwrap();
    for i in 0..pkt.len() {
        for bit in [0u8, 3, 7] {
            let mut m = pkt.clone();
            m[i] ^= 1 << bit;
            let v = b.bytes(6.0, 10, &frame(&m).unwrap());
            assert!(sends_to(&v, 10).is_empty(), "byte {i} bit {bit}: a reply");
        }
    }
    assert_eq!(b.transmits(), 0, "a changed command was done");
    assert_eq!(b.link_stats().total_dropped(), 3 * pkt.len() as u64);
    // The original still works: the session survived the junk.
    b.bytes(7.0, 10, &frame(&pkt).unwrap());
    assert_eq!(b.transmits(), 1);
}

#[test]
fn case_18_idle_and_flooding_connections_do_not_keep_the_owner_out() {
    let (mut b, done) = Bench::paired();
    // Three idle connections take every slot.
    for c in 100..103 {
        b.open(4.0, Transport::Ble, c);
    }
    // The owner still gets in: the oldest idle one is displaced.
    let mut p = Phone::new(&done, 10, Transport::Ble);
    let v = b.connect(4.5, &mut p);
    assert_eq!(closed(&v, 100), Some(LinkCloseReason::Displaced));
    assert!(b.n.connected());
    // A flood of new connections never displaces the completed owner.
    for c in 200..260 {
        let v = b.open(5.0 + f64::from(c - 200) * 0.01, Transport::Ble, c);
        assert_ne!(closed(&v, 10), Some(LinkCloseReason::Displaced));
    }
    b.say(6.0, &mut p, &send_msg(1));
    assert_eq!(b.transmits(), 1);
    // A slow connection that never completes is closed at 5 s; the owner
    // is never closed by the timer.
    let v = b.poll(20.0);
    assert!(closed(&v, 10).is_none());
    assert!(b.n.connected());
}

#[test]
fn case_18_every_slot_completed_refuses_a_new_connection() {
    let (mut b, done) = Bench::paired();
    let mut ps: Vec<Phone> = (10..13)
        .map(|c| Phone::new(&done, c, Transport::Ble))
        .collect();
    for (k, p) in ps.iter_mut().enumerate() {
        b.connect(4.0 + 1.1 * k as f64, p);
    }
    let v = b.open(9.0, Transport::Ble, 50);
    assert_eq!(closed(&v, 50), Some(LinkCloseReason::SlotsFull));
    for c in 10..13 {
        assert!(closed(&v, c).is_none());
    }
}

#[test]
fn case_18_a_connection_opened_in_a_window_gets_its_5_s_after_the_window() {
    let mut b = Bench::boot(true);
    b.poll(2.0);
    b.open(3.0, Transport::Ble, 7);
    // Inside the window it is not closed by the link's 5 s rule.
    assert!(closed(&b.poll(60.0), 7).is_none());
    // The window closes at 122 s; then 5 s.
    assert!(
        b.poll(122.0)
            .iter()
            .any(|a| matches!(a, NodeAction::Pairing(Action::WindowExpired { .. })))
    );
    assert!(closed(&b.poll(126.9), 7).is_none());
    assert_eq!(
        closed(&b.poll(127.1), 7),
        Some(LinkCloseReason::NoHandshake)
    );
}

#[test]
fn a_session_ends_with_its_connection_and_the_phone_handshakes_again() {
    let (mut b, p) = Bench::connected();
    b.close(10.0, 10);
    assert!(!b.n.connected());
    let mut p2 = p.reconnected(11);
    b.connect(11.0, &mut p2);
    assert!(b.n.connected());
    assert_eq!(p2.held(), Some(0));
}

#[test]
fn a_frame_over_the_mtu_or_empty_closes_the_connection() {
    let (mut b, _p) = Bench::connected();
    let mut over = ((MTU + 1) as u16).to_be_bytes().to_vec();
    over.extend(vec![0u8; MTU + 1]);
    let v = b.bytes(5.0, 10, &over);
    assert_eq!(closed(&v, 10), Some(LinkCloseReason::TooLong));
    assert!(!b.n.connected(), "the session outlived its connection");
    b.open(6.0, Transport::Ble, 11);
    assert_eq!(
        closed(&b.bytes(6.0, 11, &[0, 0]), 11),
        Some(LinkCloseReason::BadFrame)
    );
    b.open(6.0, Transport::Usb, 12);
    assert_eq!(
        closed(&b.bytes(6.0, 12, &vec![0u8; MTU + 1]), 12),
        Some(LinkCloseReason::TooLong)
    );
    // A packet exactly at the MTU is only dropped by the link.
    b.open(6.0, Transport::Usb, 13);
    assert!(closed(&b.bytes(6.0, 13, &vec![0x31u8; MTU]), 13).is_none());
}

#[test]
fn truncated_packets_are_dropped_without_a_reply() {
    let (mut b, mut p) = Bench::connected();
    let pkt = p.link.send(s(5.0), &send_msg(1)).unwrap();
    for n in 1..pkt.len() {
        let v = b.bytes(6.0, 10, &frame(&pkt[..n]).unwrap());
        assert!(sends_to(&v, 10).is_empty());
    }
    assert_eq!(b.transmits(), 0);
}

#[test]
fn case_19_the_radio_starts_a_handshake_by_the_stale_rule() {
    let (mut b, mut p) = Bench::connected();
    b.say(5.0, &mut p, &filters_msg(&[Filter::Index(7)]));
    // The radio sends a RECEIVED; the phone's answers are lost from here.
    b.air(6.0, &data_pkt(7, 1, 60));
    assert_eq!(p.received().len(), 0);
    let mut started = false;
    for k in 0..40 {
        let v = b.poll(6.0 + f64::from(k));
        if sends_to(&v, 10)
            .iter()
            .any(|x| x.len() == 2 + crate::link::HANDSHAKE1_LEN)
        {
            started = true;
            break;
        }
    }
    assert!(started, "the radio never started a handshake");
}

#[test]
fn case_19_the_radio_rekeys_late_when_the_phone_does_not() {
    let (mut b, mut p) = Bench::connected();
    // The phone answers the radio's HELD, then never rekeys (its timers
    // stop).
    b.tick_both(20.0, &mut p);
    let mut started = None;
    let mut t = 3600.0;
    while t < 5400.0 {
        if sends_to(&b.poll(t), 10)
            .iter()
            .any(|x| x.len() == 2 + crate::link::HANDSHAKE1_LEN)
        {
            started = Some(t);
            break;
        }
        t += 10.0;
    }
    let t = started.expect("no late rekey");
    assert!(t > 3604.0 && t < 4.0 + 5400.0, "late rekey at {t}");
}

#[test]
fn case_19_a_recorded_handshake_replayed_after_a_power_cycle_is_dropped() {
    let (mut b, p) = Bench::connected();
    let recorded = p.sent[0].clone();
    // Recorded from the radio too: its handshake 2.
    b.reboot(20.0, true);
    b.open(21.0, Transport::Ble, 40);
    let v = b.bytes(21.0, 40, &frame(&recorded).unwrap());
    assert!(
        sends_to(&v, 40).is_empty(),
        "a recorded handshake was answered"
    );
    assert_eq!(b.dropped(DropReason::StaleHandshake), 1);
    // The phone, reconnecting, still gets in.
    let mut p2 = p.reconnected(41);
    b.connect(22.0, &mut p2);
    assert!(b.n.connected());
}

#[test]
fn case_19_a_recorded_radio_handshake_is_dropped_by_the_phone() {
    let (mut b, mut p) = Bench::connected();
    b.say(5.0, &mut p, &filters_msg(&[Filter::Index(7)]));
    b.air(6.0, &data_pkt(7, 1, 60));
    // Let the radio start a handshake by the stale rule; record it.
    let mut rec = None;
    for k in 0..40 {
        let v = b.poll(6.0 + f64::from(k));
        if let Some(x) = sends_to(&v, 10)
            .into_iter()
            .find(|x| x.len() == 2 + crate::link::HANDSHAKE1_LEN)
        {
            rec = Some(x);
            break;
        }
    }
    let rec = rec.expect("no radio handshake");
    // The phone takes it once...
    let back = p.recv(50.0, &rec);
    assert_eq!(back.len(), 1);
    // ...and a replay after a power cycle of either side is dropped.
    let mut p2 = p.reconnected(10);
    let back = p2.recv(60.0, &rec);
    assert!(back.is_empty());
    assert_eq!(p2.link.stats().dropped(DropReason::StaleHandshake), 1);
}

#[test]
fn case_20_a_phone_with_a_lost_timestamp_and_an_earlier_clock_waits_for_a_reset() {
    let (mut b, done) = Bench::paired();
    let mut p = Phone::new(&done, 10, Transport::Ble);
    b.connect(4.0, &mut p);
    b.close(5.0, 10);
    // The phone lost its saved timestamps and its clock is a day earlier.
    let earlier = WALL - Duration::from_secs(86_400);
    let mut lost = Phone::with(
        done.radio_link_key.private_key(),
        done.radio_link_public,
        11,
        Transport::Ble,
        earlier,
        PhoneStamps::default(),
    );
    let v = b.connect(6.0, &mut lost);
    assert!(sends_to(&v, 11).is_empty());
    assert_eq!(b.dropped(DropReason::StaleHandshake), 1);
    // A reset and a new pairing: new keys, fresh timestamps.
    b.reset(10.0);
    b.usb_replug(11.0);
    let label = b.label.clone();
    let new = b.pair(30.0, Transport::Usb, 3, PairWith::Label(&label), "owner");
    let mut p = Phone::with(
        new.radio_link_key.private_key(),
        new.radio_link_public,
        12,
        Transport::Ble,
        earlier,
        PhoneStamps::default(),
    );
    b.connect(31.0, &mut p);
    assert!(b.n.connected());
}

#[test]
fn case_24_control_messages_change_nothing() {
    let (mut b, mut p) = Bench::connected();
    for body in [&[0x10u8, 0, 1][..], &[0x20, 0, 2, 9, 9], &[0x30, 1]] {
        let pkt = p.link.send_control(s(5.0), body).unwrap();
        let v = b.pump(5.0, &mut p, vec![pkt]);
        assert!(
            sends_to(&v, 10).is_empty(),
            "a control message was answered"
        );
        assert!(!has(&v, |a| !matches!(a, NodeAction::LinkSend { .. })));
    }
    assert_eq!(b.n.stats().control_refused, 3);
    assert_eq!(b.transmits(), 0);
    assert!(b.n.connected());
    // The radio has no way to send one: the firmware may send SENT and
    // STATUS only.
    for ty in [0x00, MSG_HELD, MSG_RECEIVED, MSG_SEND, MSG_PAIR_OPEN, 0x30] {
        let r = b.n.send_to_phone(s(6.0), ty, &[1], &mut |_| {});
        assert_eq!(r, Err(PhoneSendError::NotAllowed));
    }
    assert_eq!(
        b.n.send_to_phone(s(6.0), MSG_STATUS, &[1], &mut |_| {}),
        Ok(())
    );
}

#[test]
fn messages_the_radio_does_not_take_are_dropped_and_counted() {
    let (mut b, mut p) = Bench::connected();
    let bad: Vec<Vec<u8>> = vec![
        vec![MSG_SENT, 1],
        vec![MSG_RECEIVED],
        vec![MSG_HELD, 0, 0],
        vec![MSG_STATUS],
        vec![0x0C],
        vec![0xFF, 1, 2],
        vec![MSG_PAIR_OPEN, 1, 2, 3],
        vec![MSG_FILTERS, 9],
        vec![MSG_FETCH, 1],
        vec![MSG_FETCH_ACK, 1, 2, 3],
    ];
    for m in &bad {
        let v = b.say(5.0, &mut p, m);
        assert!(!has(&v, |a| matches!(
            a,
            NodeAction::Transmit { .. } | NodeAction::StatusWanted | NodeAction::Pairing(_)
        )));
    }
    assert_eq!(b.n.stats().messages_dropped, bad.len() as u64);
    assert_eq!(b.n.status(s(5.0)).window, None);
}

#[test]
fn settings_and_updates_go_to_the_firmware_as_sent() {
    let (mut b, mut p) = Bench::connected();
    let v = b.say(5.0, &mut p, &[MSG_SETTINGS, 1, 2]);
    assert!(has(
        &v,
        |a| matches!(a, NodeAction::Settings { body } if body == &[1, 2])
    ));
    let v = b.say(5.0, &mut p, &[MSG_UPDATE, 3]);
    assert!(has(
        &v,
        |a| matches!(a, NodeAction::Update { body } if body == &[3])
    ));
    let v = b.say(5.0, &mut p, &send_msg(4));
    assert!(has(
        &v,
        |a| matches!(a, NodeAction::Transmit { body } if body[0] == 4)
    ));
}

#[test]
fn case_26_captures_of_the_phone_link_hold_no_plaintext() {
    let (mut b, mut p) = Bench::connected();
    let secret = random_secret();
    let mut po = vec![MSG_PAIR_OPEN];
    po.extend(secret);
    b.say(5.0, &mut p, &filters_msg(&[Filter::Index(7)]));
    b.say(6.0, &mut p, &send_msg(1));
    let mut held = data_pkt(7, 1, 60);
    held.extend_from_slice(MARK);
    b.air(7.0, &held);
    b.say(8.0, &mut p, &po);
    b.n.send_to_phone(s(9.0), MSG_STATUS, MARK, &mut |a| b.log.push(a))
        .unwrap();
    // Everything that crossed the link, both ways.
    let mut capture: Vec<Vec<u8>> = p.sent.clone();
    for a in &b.log {
        if let NodeAction::LinkSend { bytes, .. } = a {
            capture.push(bytes.clone());
        }
    }
    let find = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
    for (i, c) in capture.iter().enumerate() {
        // Name the capture, never print it.
        assert!(!find(c, b"test-plaintext"), "capture {i} shows plaintext");
        assert!(!find(c, &secret[..8]), "capture {i} shows the secret");
    }
    assert!(capture.len() > 6);
}

#[test]
fn case_27_with_no_phone_the_radio_transmits_nothing_of_its_own() {
    let (mut b, mut p) = Bench::connected();
    b.say(
        5.0,
        &mut p,
        &filters_msg(&[Filter::Index(7), Filter::Group(9)]),
    );
    b.close(6.0, 10);
    let start = b.transmits();
    let log_start = b.log.len();
    for k in 0..360 {
        let t = 10.0 + 10.0 * f64::from(k);
        b.air(t, &data_pkt(7, k as u8, 60));
        b.air(t, &group_pkt(9, k as u8));
        b.air(t, &data_pkt(8, k as u8, 60));
        b.poll(t + 5.0);
    }
    assert_eq!(b.transmits(), start, "the radio transmitted on its own");
    assert!(b.n.stats().wakes > 0);
    // Nothing was sent anywhere: no connection is open.
    assert!(
        !b.log[log_start..]
            .iter()
            .any(|a| matches!(a, NodeAction::LinkSend { .. }))
    );
}

// ---- section 4: PAIR_OPEN through the session, and replace (case 13) ----

#[test]
fn case_13_pair_open_through_the_session_opens_a_replace_window() {
    let (mut b, mut p) = Bench::connected();
    let rc = ReplaceCode::new(*b.label.pairing_public()).unwrap();
    let v = b.say(5.0, &mut p, rc.pair_open_body().as_bytes());
    assert!(has(&v, |a| matches!(a, NodeAction::StatusWanted)));
    assert_eq!(b.n.status(s(5.0)).window, Some(WindowKind::Replace));
    // Refused while a window is open, still answered with STATUS.
    let rc2 = ReplaceCode::new(*b.label.pairing_public()).unwrap();
    let v = b.say(6.0, &mut p, rc2.pair_open_body().as_bytes());
    assert!(has(&v, |a| matches!(a, NodeAction::StatusWanted)));
    assert_eq!(b.n.stats().pair_open_refused, 1);
    // The old phone keeps working during the window.
    b.say(7.0, &mut p, &send_msg(1));
    assert_eq!(b.transmits(), 1);
}

#[test]
fn case_13_pair_open_with_a_zero_or_label_secret_is_refused() {
    let (mut b, mut p) = Bench::connected();
    let mut zero = vec![MSG_PAIR_OPEN];
    zero.extend([0u8; 32]);
    b.say(5.0, &mut p, &zero);
    let mut label = vec![MSG_PAIR_OPEN];
    label.extend(b.label.secret());
    b.say(6.0, &mut p, &label);
    assert_eq!(b.n.stats().pair_open_refused, 2);
    assert_eq!(b.n.status(s(6.0)).window, None);
}

#[test]
fn case_13_an_unauthenticated_request_for_a_window_is_refused() {
    let (mut b, _p) = Bench::connected();
    let rc = ReplaceCode::new(*b.label.pairing_public()).unwrap();
    // The bare message on a link connection, unsealed, and as a data packet.
    b.open(5.0, Transport::Ble, 30);
    b.bytes(5.0, 30, &frame(rc.pair_open_body().as_bytes()).unwrap());
    let mut d = data_pkt(1, 1, 21);
    d.extend(rc.pair_open_body().as_bytes());
    b.bytes(5.0, 30, &frame(&d).unwrap());
    b.open(5.0, Transport::Usb, 31);
    b.bytes(5.0, 31, rc.pair_open_body().as_bytes());
    assert_eq!(b.n.status(s(5.0)).window, None);
    assert!(!b.log.iter().any(|a| matches!(a, NodeAction::StatusWanted)));
}

#[test]
fn case_13_a_replace_ends_the_old_phone_and_erases_its_state() {
    let (mut b, mut old) = Bench::connected();
    b.say(5.0, &mut old, &filters_msg(&[Filter::Index(7)]));
    // Sent at once while connected; a FETCH would not repeat it.
    let v = b.air(6.0, &data_pkt(7, 1, 60));
    for x in sends_to(&v, 10) {
        old.recv(6.0, &x);
    }
    // The old phone acknowledges...
    let holds: Vec<u32> = old.received().iter().map(|r| r.0).collect();
    assert_eq!(holds.len(), 1);
    b.say(8.0, &mut old, &ack_msg(&holds));
    assert_eq!(b.n.held(), 0);
    // ...then opens the window; a packet arrives after the ack.
    let rc = ReplaceCode::new(*b.label.pairing_public()).unwrap();
    b.say(9.0, &mut old, rc.pair_open_body().as_bytes());
    b.air(10.0, &data_pkt(7, 2, 60));
    assert_eq!(b.n.held(), 1);
    assert!(!b.flash.borrow().stamps.is_empty());
    // The new phone pairs over BLE.
    let v_before = b.log.len();
    let new = b.pair(11.0, Transport::Ble, 5, PairWith::Replace(&rc), "new");
    let v = b.log[v_before..].to_vec();
    assert_eq!(closed(&v, 10), Some(LinkCloseReason::SessionsEnded));
    assert!(!b.n.connected());
    assert_eq!(b.n.held(), 0, "a held packet reached the new phone");
    {
        let f = b.flash.borrow();
        assert!(f.filters.is_none(), "filters survived");
        assert!(f.stamps.is_empty(), "timestamps survived");
    }
    // The old phone is refused at once.
    let mut again = old.reconnected(12);
    let v = b.connect(12.0, &mut again);
    assert!(sends_to(&v, 12).is_empty());
    // The new phone connects and is told nothing is held.
    let mut p = Phone::new(&new, 13, Transport::Ble);
    b.connect(13.0, &mut p);
    assert!(b.n.connected());
    assert_eq!(p.held(), Some(0));
    b.air(14.0, &data_pkt(7, 3, 60));
    assert_eq!(b.n.held(), 0, "the old filters still work");
}

// ---- section 2.8 through the session: reset (case 14), faults (case 30) ----

#[test]
fn case_14_a_pinhole_reset_ends_the_session_at_once_and_erases_the_owner() {
    let (mut b, mut p) = Bench::connected();
    b.say(5.0, &mut p, &filters_msg(&[Filter::Index(7)]));
    b.air(6.0, &data_pkt(7, 1, 60));
    b.close(6.5, 10);
    b.air(7.0, &data_pkt(7, 2, 60));
    assert_eq!(b.n.held(), 2);
    let mut p2 = p.reconnected(11);
    b.connect(8.0, &mut p2);
    let v = b.reset(9.0);
    assert_eq!(closed(&v, 11), Some(LinkCloseReason::SessionsEnded));
    assert!(!b.n.connected());
    assert_eq!(b.n.held(), 0);
    {
        let f = b.flash.borrow();
        assert!(f.filters.is_none() && f.stamps.is_empty() && f.trust.is_none());
    }
    // The old phone is refused: the radio has no peer.
    let mut p3 = p.reconnected(12);
    let v = b.connect(10.0, &mut p3);
    assert!(sends_to(&v, 12).is_empty());
    assert_eq!(b.n.stats().no_peer, 1);
    // Packets are no longer held for anyone.
    b.air(11.0, &data_pkt(7, 3, 60));
    assert_eq!(b.n.held(), 0);
}

#[test]
fn case_30_a_timestamp_write_error_when_answering_fails_closed() {
    let (mut b, done) = Bench::paired();
    // The next write (the timestamp before the radio answers) fails.
    {
        let mut f = b.flash.borrow_mut();
        f.error_at = Some(f.ops);
    }
    let mut p = Phone::new(&done, 10, Transport::Ble);
    let v = b.connect(4.0, &mut p);
    assert!(
        sends_to(&v, 10).is_empty(),
        "answered with an unsaved timestamp"
    );
    assert!(has(&v, |a| matches!(
        a,
        NodeAction::Pairing(Action::StoreFailed)
    )));
    assert!(b.n.status(s(4.0)).faulted);
    // Refused while faulted.
    let mut p2 = p.reconnected(11);
    let v = b.connect(5.0, &mut p2);
    assert!(sends_to(&v, 11).is_empty());
    // The pinhole works while faulted.
    b.reset(6.0);
    assert!(!b.n.status(s(6.0)).faulted);
    assert!(b.flash.borrow().trust.is_none());
}

#[test]
fn case_30_a_timestamp_write_error_when_the_radio_starts_a_handshake_fails_closed() {
    let (mut b, mut p) = Bench::connected();
    b.say(5.0, &mut p, &filters_msg(&[Filter::Index(7)]));
    b.air(6.0, &data_pkt(7, 1, 60));
    {
        let mut f = b.flash.borrow_mut();
        f.error_at = Some(f.ops);
    }
    let mut faulted = false;
    for k in 0..40 {
        let v = b.poll(6.0 + f64::from(k));
        assert!(
            !sends_to(&v, 10)
                .iter()
                .any(|x| x.len() == 2 + crate::link::HANDSHAKE1_LEN),
            "a handshake left with an unsaved timestamp"
        );
        if b.n.status(s(6.0 + f64::from(k))).faulted {
            faulted = true;
            break;
        }
    }
    assert!(faulted);
    assert!(!b.n.connected());
}

#[test]
fn case_30_a_filter_write_error_fails_closed() {
    let (mut b, mut p) = Bench::connected();
    {
        let mut f = b.flash.borrow_mut();
        f.error_at = Some(f.ops);
    }
    let v = b.say(5.0, &mut p, &filters_msg(&[Filter::Index(7)]));
    assert!(has(&v, |a| matches!(
        a,
        NodeAction::Pairing(Action::StoreFailed)
    )));
    assert_eq!(closed(&v, 10), Some(LinkCloseReason::SessionsEnded));
    assert!(!b.n.connected());
    b.air(6.0, &data_pkt(7, 1, 60));
    assert_eq!(b.n.held(), 0);
}

#[test]
fn case_30_a_read_error_at_boot_or_reconnect_fails_closed() {
    let (mut b, p) = Bench::connected();
    b.flash.borrow_mut().reads_fail = true;
    // A new connection reads the trust state again.
    let v = b.open(5.0, Transport::Ble, 20);
    assert!(has(&v, |a| matches!(
        a,
        NodeAction::Pairing(Action::StoreFailed)
    )));
    assert!(!b.n.connected());
    b.reboot(6.0, false);
    assert!(b.n.status(s(6.0)).faulted);
    let mut p2 = p.reconnected(21);
    let v = b.connect(7.0, &mut p2);
    assert!(sends_to(&v, 21).is_empty());
    b.flash.borrow_mut().reads_fail = false;
    b.reboot(8.0, false);
    let mut p3 = p.reconnected(22);
    b.connect(9.0, &mut p3);
    assert!(b.n.connected(), "a sound flash should come back paired");
}

#[test]
fn a_power_loss_while_saving_a_timestamp_sends_nothing_and_comes_back() {
    let (mut b, done) = Bench::paired();
    {
        let mut f = b.flash.borrow_mut();
        f.crash_at = Some(f.ops);
    }
    let mut p = Phone::new(&done, 10, Transport::Ble);
    let v = b.connect(4.0, &mut p);
    assert!(sends_to(&v, 10).is_empty());
    b.reboot(5.0, true);
    let mut p2 = p.reconnected(11);
    b.connect(6.0, &mut p2);
    assert!(b.n.connected());
}

// ---- section 5: held packets (cases 21, 22) ----

#[test]
fn case_21_held_packets_are_delivered_once_and_deleted_only_on_fetch_ack() {
    let (mut b, mut p) = Bench::connected();
    b.say(
        5.0,
        &mut p,
        &filters_msg(&[Filter::Index(7), Filter::Group(9)]),
    );
    b.close(6.0, 10);
    b.air(7.0, &data_pkt(7, 1, 60));
    b.air(7.1, &group_pkt(9, 2));
    b.air(7.2, &data_pkt(8, 3, 60)); // no filter: not held
    assert_eq!(b.n.held(), 2);
    assert!(b.log.iter().any(|a| matches!(a, NodeAction::Wake)));
    // A new session is told how many, and FETCH hands each over once.
    let mut p = p.reconnected(11);
    b.connect(10.0, &mut p);
    assert_eq!(p.held(), Some(2));
    b.say(11.0, &mut p, &[MSG_FETCH]);
    b.say(12.0, &mut p, &[MSG_FETCH]);
    let r = p.received();
    assert_eq!(r.len(), 2, "delivered more than once");
    assert_eq!(r[0].1, data_pkt(7, 1, 60));
    assert_eq!(r[1].1, group_pkt(9, 2));
    // Nothing is deleted without FETCH_ACK, and only what it names.
    assert_eq!(b.n.held(), 2);
    b.say(13.0, &mut p, &ack_msg(&[r[0].0, 999_999]));
    assert_eq!(b.n.held(), 1);
    // The next session gets the rest again.
    b.close(14.0, 11);
    let mut p = p.reconnected(12);
    b.connect(15.0, &mut p);
    assert_eq!(p.held(), Some(1));
    b.say(16.0, &mut p, &[MSG_FETCH]);
    assert_eq!(p.received().len(), 1);
    assert_eq!(p.received()[0].0, r[1].0);
}

#[test]
fn case_21_a_packet_arriving_during_a_session_goes_straight_to_the_phone() {
    let (mut b, mut p) = Bench::connected();
    b.say(5.0, &mut p, &filters_msg(&[Filter::Index(7)]));
    let acts = b.air(6.0, &data_pkt(7, 1, 60));
    for x in sends_to(&acts, 10) {
        p.recv(6.0, &x);
    }
    assert_eq!(p.received().len(), 1);
    assert!(!acts.iter().any(|a| matches!(a, NodeAction::Wake)));
    // Held until acknowledged; a FETCH in the same session does not repeat it.
    assert_eq!(b.n.held(), 1);
    b.say(7.0, &mut p, &[MSG_FETCH]);
    assert_eq!(p.received().len(), 1);
    let h = p.received()[0].0;
    b.say(8.0, &mut p, &ack_msg(&[h]));
    assert_eq!(b.n.held(), 0);
}

#[test]
fn case_21_an_ack_for_a_number_not_handed_over_in_this_session_deletes_nothing() {
    let (mut b, mut p) = Bench::connected();
    b.say(5.0, &mut p, &filters_msg(&[Filter::Index(7)]));
    b.close(6.0, 10);
    b.air(7.0, &data_pkt(7, 1, 60));
    let mut p = p.reconnected(11);
    b.connect(8.0, &mut p);
    // Hold numbers start at 1: ack it without fetching.
    b.say(9.0, &mut p, &ack_msg(&[1, 2, 3]));
    assert_eq!(b.n.held(), 1);
}

#[test]
fn case_21_nothing_held_survives_a_power_cycle_but_the_filters_do() {
    let (mut b, mut p) = Bench::connected();
    b.say(5.0, &mut p, &filters_msg(&[Filter::Index(7)]));
    b.air(6.0, &data_pkt(7, 1, 60));
    assert_eq!(b.n.held(), 1);
    b.reboot(10.0, true);
    assert_eq!(b.n.held(), 0);
    b.air(11.0, &data_pkt(7, 2, 60));
    assert_eq!(b.n.held(), 1, "the filters in flash were lost");
}

#[test]
fn case_21_packets_expire_after_24_hours() {
    let (mut b, mut p) = Bench::connected();
    b.say(5.0, &mut p, &filters_msg(&[Filter::Index(7)]));
    b.close(5.5, 10);
    b.air(6.0, &data_pkt(7, 1, 60));
    b.poll(6.0 + HOLD_FOR.as_secs_f64() - 1.0);
    assert_eq!(b.n.held(), 1);
    b.poll(6.0 + HOLD_FOR.as_secs_f64());
    assert_eq!(b.n.held(), 0);
}

#[test]
fn case_21_the_store_limits_hold() {
    let mut f = Filters::none();
    let mut h = HoldStore::new();
    // Rotate filters so old shares become orphans and fill the store.
    for k in 0..10u16 {
        f = Filters::new(&[Filter::Index(k)]).unwrap();
        for j in 0..40u8 {
            let p = data_pkt(k, j, 256);
            h.offer(s(f64::from(k)), &p, Signal(0), &f);
            assert!(h.len() <= HOLD_PACKETS && h.bytes() <= HOLD_BYTES);
        }
    }
    assert_eq!(h.len(), HOLD_PACKETS);
    // The current filter keeps its whole share: the newest 21.
    let mut fetched = vec![];
    h.fetch(1, |_, _, p| {
        fetched.push(p.to_vec());
        true
    });
    let current: Vec<_> = fetched.iter().filter(|p| p[2] == 9).collect();
    assert_eq!(current.len(), 21);
    assert!(current.iter().all(|p| p[4] >= 19), "not the newest");
    // Too large to hold.
    assert!(
        h.offer(s(20.0), &data_pkt(9, 1, 257), Signal(0), &f)
            .is_none()
    );
    let _ = f;
}

#[test]
fn case_22_a_flood_on_one_filter_leaves_the_others_and_wakes_stay_limited() {
    let messaging = Identity::generate().unwrap();
    let (mut b, mut p) = Bench::connected();
    b.say(
        5.0,
        &mut p,
        &filters_msg(&[
            Filter::Index(1),
            Filter::Index(2),
            Filter::Group(3),
            Filter::Handshake(handshake_filter(messaging.public_key())),
        ]),
    );
    b.close(6.0, 10);
    let real = [
        data_pkt(2, 0xEE, 60),
        group_pkt(3, 0xEE),
        hs_pkt(messaging.public_key()),
    ];
    for (i, r) in real.iter().enumerate() {
        b.air(7.0 + i as f64 * 0.1, r);
    }
    assert_eq!(b.n.held(), 3, "a real packet was not held");
    // A handshake to anyone else does not match the handshake filter.
    b.air(7.5, &hs_pkt(Identity::generate().unwrap().public_key()));
    assert_eq!(b.n.held(), 3);
    // Ten minutes of flood on index 1, no phone.
    let wakes0 = b.n.stats().wakes;
    let mut t = 8.0;
    while t < 608.0 {
        b.air(t, &data_pkt(1, (t as u32 % 251) as u8, 200));
        t += 0.25;
    }
    let wakes = b.n.stats().wakes - wakes0;
    assert!(wakes <= 60, "{wakes} wakes in 10 minutes");
    assert!(wakes <= 8, "{wakes} wakes: no backing off");
    // The other filters' packets are all still there.
    let mut p = p.reconnected(11);
    b.connect(610.0, &mut p);
    b.say(611.0, &mut p, &[MSG_FETCH]);
    let got: Vec<Vec<u8>> = p.received().into_iter().map(|r| r.1).collect();
    for r in &real {
        assert!(
            got.contains(r),
            "the flood pushed out another filter's packet"
        );
    }
    assert!(got.iter().filter(|g| g[2] == 1).count() <= HOLD_PACKETS / 3 / 2);
}

#[test]
fn wakes_reset_after_a_real_ack() {
    let mut w = WakeLimit::new();
    let mut fired = vec![];
    for k in 0..200u64 {
        w.held();
        if w.poll(Duration::from_secs(k)) {
            fired.push(k);
        }
    }
    // 0, 10, 30, 70, 150: doubling.
    assert_eq!(fired, vec![0, 10, 30, 70, 150]);
    w.real_ack();
    w.held();
    assert!(w.poll(Duration::from_secs(470)));
    w.real_ack();
    w.held();
    assert!(!w.poll(Duration::from_secs(479)));
    assert!(w.poll(Duration::from_secs(480)));
}

#[test]
fn filters_refuse_too_many_or_duplicates() {
    let many: Vec<Filter> = (0..9).map(Filter::Index).collect();
    assert!(Filters::new(&many).is_none());
    assert!(Filters::new(&many[..8]).is_some());
    assert!(Filters::new(&[Filter::Group(1), Filter::Group(1)]).is_none());
    assert!(Filters::new(&[Filter::Handshake([1; 32]), Filter::Handshake([2; 32])]).is_none());
    let shown = format!("{:?}", Filter::Handshake([0xAB; 32]));
    assert!(!shown.contains("171"));
}

#[test]
fn a_refused_filter_list_keeps_the_old_one() {
    let (mut b, mut p) = Bench::connected();
    b.say(5.0, &mut p, &filters_msg(&[Filter::Index(7)]));
    let many: Vec<Filter> = (0..9).map(Filter::Index).collect();
    b.say(6.0, &mut p, &filters_msg(&many));
    assert_eq!(b.n.stats().messages_dropped, 1);
    b.close(7.0, 10);
    b.air(8.0, &data_pkt(7, 1, 60));
    assert_eq!(b.n.held(), 1);
}

#[test]
fn debug_output_shows_no_secret() {
    let (mut b, mut p) = Bench::connected();
    let rc = ReplaceCode::new(*b.label.pairing_public()).unwrap();
    let body = rc.pair_open_body();
    b.say(5.0, &mut p, body.as_bytes());
    let link_private = b.flash.borrow().trust.as_ref().unwrap().2;
    let mut shown: Vec<String> = b.log.iter().map(|a| format!("{a:?}")).collect();
    shown.push(format!("{:?}", b.n));
    let secrets = [*body.secret(), link_private, *b.label.secret()];
    for (i, text) in shown.iter().enumerate() {
        for k in &secrets {
            let hex = data_encoding::HEXLOWER.encode(&k[..8]);
            let dec = format!("{}, {}, {}, {}", k[0], k[1], k[2], k[3]);
            // Name the output, never print it.
            assert!(
                !text.contains(&hex) && !text.contains(&dec),
                "output {i} shows a secret"
            );
        }
    }
}

#[test]
fn a_valid_packet_on_another_connection_does_not_move_the_session() {
    let (mut b, mut p) = Bench::connected();
    b.open(5.0, Transport::Ble, 30);
    // Someone copies the owner's next packet onto their own connection.
    let pkt = p.link.send(s(5.0), &send_msg(1)).unwrap();
    let v = b.bytes(5.0, 30, &frame(&pkt).unwrap());
    assert!(sends_to(&v, 30).is_empty());
    assert_eq!(b.transmits(), 1);
    // The owner's copy is a replay; replies still go to the owner.
    b.bytes(5.1, 10, &frame(&pkt).unwrap());
    assert_eq!(b.transmits(), 1);
    let v = b.go(|n, mut o| n.send_to_phone(s(6.0), MSG_STATUS, &[1], &mut o).unwrap());
    assert_eq!(sends_to(&v, 10).len(), 1);
    // The other connection never completed: closed at 5 s.
    assert_eq!(
        closed(&b.poll(10.5), 30),
        Some(LinkCloseReason::NoHandshake)
    );
    assert!(b.n.connected());
}

#[test]
fn a_faulted_radio_holds_nothing() {
    let (mut b, mut p) = Bench::connected();
    b.say(5.0, &mut p, &filters_msg(&[Filter::Index(7)]));
    b.flash.borrow_mut().reads_fail = true;
    b.open(6.0, Transport::Ble, 20);
    assert!(b.n.status(s(6.0)).faulted);
    b.air(7.0, &data_pkt(7, 1, 60));
    assert_eq!(
        b.n.held(),
        0,
        "a faulted radio held a packet nobody can fetch"
    );
    assert!(!b.log.iter().any(|a| matches!(a, NodeAction::Wake)));
}
