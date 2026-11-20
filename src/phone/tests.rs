//! Phone pairing in simulated time: one or more tests per case of spec
//! section 8 that this part covers (named `case_NN_...`), the power-loss
//! tests of section 2.8, and the refusals.
//!
//! The radio runs against [`MemStore`], a flash that can lose power before
//! any write, and a reboot reads the same flash back.

use std::cell::RefCell;
use std::rc::Rc;
use std::result::Result;
use std::time::Duration;

use zeroize::Zeroizing;

use super::handshake::{radio_open_msg1, radio_write_msg2};
use super::*;
use crate::identity::Identity;
use crate::link::{Entropy, EntropyFailed};

// ---- the simulated flash ----

#[derive(Default)]
struct Flash {
    marker: Option<Marker>,
    /// Whose timestamps, wake filters and settings are in flash, if any.
    owner_state: Option<[u8; 32]>,
    /// The trust state: phone key, name, the radio's link private key.
    trust: Option<([u8; 32], String, [u8; 32])>,
    /// Every link private key ever written to flash.
    written_links: Vec<[u8; 32]>,
    /// Writes and erases done so far.
    ops: usize,
    /// The persisted rate-limit count.
    rate_count: u8,
    /// Power is lost instead of doing operation number `n` (0-based).
    crash_at: Option<usize>,
    dead: bool,
    /// Operation number `n` fails with a write error (the flash stays
    /// powered and later operations work).
    error_at: Option<usize>,
    /// Every read fails (a broken flash).
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
        self.0.borrow_mut().owner_state = None;
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
        let mut f = self.0.borrow_mut();
        f.trust = t.map(|t| (t.phone_public, t.name.as_str().to_string(), *t.link_private));
        if let Some(t) = t {
            f.written_links.push(*t.link_private);
        }
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

/// The operating system's random source, unless the test says it has
/// failed.
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

// ---- the bench ----

type R = Radio<MemStore, TestEntropy, 3, 2>;

const RADIO_NAME: &str = "keel-1";

fn s(secs: f64) -> Duration {
    Duration::from_secs_f64(secs)
}

struct Bench {
    r: R,
    flash: Rc<RefCell<Flash>>,
    label: LabelCode,
    pairing_private: Zeroizing<[u8; 32]>,
    entropy: TestEntropy,
}

impl Bench {
    /// A new radio, unpaired, started from no power at 0 s.
    fn boot(usb: bool) -> Self {
        let id = Identity::generate().unwrap();
        let label = LabelCode::new(*id.public_key()).unwrap();
        let pairing_private = Zeroizing::new(*id.private_key());
        let flash = Rc::new(RefCell::new(Flash::default()));
        let keys = RadioKeys::new(id, &label).unwrap();
        let entropy = TestEntropy::default();
        let r = R::boot(
            keys,
            Name::new(RADIO_NAME).unwrap(),
            MemStore(flash.clone()),
            entropy.clone(),
            s(0.0),
            usb,
            &mut |_| {},
        );
        Self {
            r,
            flash,
            label,
            pairing_private,
            entropy,
        }
    }

    /// Power comes back after a loss: the same flash, a new radio.
    fn reboot(&mut self, t: f64, usb: bool) -> Vec<Action> {
        {
            let mut f = self.flash.borrow_mut();
            f.dead = false;
            f.crash_at = None;
        }
        self.boot_again(t, usb)
    }

    /// A new radio on the same flash, as it is (a crash setting stays).
    fn boot_again(&mut self, t: f64, usb: bool) -> Vec<Action> {
        let id = Identity::from_private_bytes(&self.pairing_private[..]).unwrap();
        let keys = RadioKeys::new(id, &self.label).unwrap();
        let mut v = vec![];
        self.r = R::boot(
            keys,
            Name::new(RADIO_NAME).unwrap(),
            MemStore(self.flash.clone()),
            self.entropy.clone(),
            s(t),
            usb,
            &mut |a| v.push(a),
        );
        v
    }

    fn link_peer(&mut self) -> Option<[u8; 32]> {
        self.r.link_peer(&mut |_| {}).map(|p| p.phone_public)
    }

    /// Started on USB power at 0 s: a USB window opens at 2 s, with no
    /// host enumerated (BLE opens at 12 s).
    fn window() -> Self {
        let mut b = Self::boot(true);
        let v = b.poll(2.0);
        assert!(opened(&v, WindowKind::Usb));
        b
    }

    /// Paired over USB at 3 s with a phone named "old", which then set its
    /// filters and settings (owner state). The window is closed.
    fn paired() -> (Self, PhonePaired) {
        let mut b = Self::window();
        let label = b.label.clone();
        let old = b.pair(3.0, Transport::Usb, 1, PairWith::Label(&label), "old");
        b.flash.borrow_mut().owner_state = Some(*old.radio_link_key.public_key());
        (b, old)
    }

    fn crash_after(&self, n: usize) {
        let mut f = self.flash.borrow_mut();
        f.crash_at = Some(f.ops + n);
    }

    fn poll(&mut self, t: f64) -> Vec<Action> {
        let mut v = vec![];
        self.r.poll(s(t), &mut |a| v.push(a));
        v
    }
    fn usb(&mut self, t: f64, on: bool) -> Vec<Action> {
        let mut v = vec![];
        self.r.usb_power(s(t), on, &mut |a| v.push(a));
        v
    }
    fn enumerated(&mut self, t: f64) -> Vec<Action> {
        let mut v = vec![];
        self.r.usb_enumerated(s(t), &mut |a| v.push(a));
        v
    }
    fn open(&mut self, t: f64, tr: Transport, conn: ChannelId) -> Vec<Action> {
        let mut v = vec![];
        self.r
            .pairing_channel_opened(s(t), tr, conn, &mut |a| v.push(a));
        v
    }
    fn lost(&mut self, t: f64, conn: ChannelId) -> Vec<Action> {
        let mut v = vec![];
        self.r
            .pairing_channel_closed(s(t), conn, &mut |a| v.push(a));
        v
    }
    fn msg(&mut self, t: f64, conn: ChannelId, m: &[u8]) -> Vec<Action> {
        let mut v = vec![];
        self.r.message(s(t), conn, m, &mut |a| v.push(a));
        v
    }
    fn reset(&mut self, t: f64) -> Vec<Action> {
        let mut v = vec![];
        self.r.pinhole_reset(s(t), &mut |a| v.push(a));
        v
    }
    fn pair_open(
        &mut self,
        t: f64,
        from: &[u8; 32],
        secret: &[u8; 32],
    ) -> (Result<(), PairOpenRefused>, Vec<Action>) {
        let mut v = vec![];
        let r = self.r.pair_open(s(t), from, secret, &mut |a| v.push(a));
        (r, v)
    }

    /// Connect, send message 1, return the phone and message 2.
    fn reach_msg2(
        &mut self,
        t: f64,
        tr: Transport,
        conn: ChannelId,
        code: PairWith<'_>,
        name: &str,
    ) -> (PhonePairing, Vec<u8>) {
        self.open(t, tr, conn);
        let (p, m1) = phone(code, name);
        let v = self.msg(t, conn, &m1);
        let m2 = msg2_for(&v, conn).unwrap_or_else(|| panic!("no message 2: {v:?}"));
        (p, m2)
    }

    /// A whole pairing on one connection at time `t`.
    fn pair(
        &mut self,
        t: f64,
        tr: Transport,
        conn: ChannelId,
        code: PairWith<'_>,
        name: &str,
    ) -> PhonePaired {
        let (p, m2) = self.reach_msg2(t, tr, conn, code, name);
        let done = p.finish(&m2).unwrap();
        let v = self.msg(t, conn, &done.msg3);
        let (c, k, _) = paired_in(&v).unwrap_or_else(|| panic!("not paired: {v:?}"));
        assert_eq!(c, conn);
        assert_eq!(&k, done.radio_link_key.public_key());
        done
    }

    fn trust_phone(&self) -> Option<[u8; 32]> {
        self.flash.borrow().trust.as_ref().map(|t| t.0)
    }
}

fn phone(code: PairWith<'_>, name: &str) -> (PhonePairing, Vec<u8>) {
    PhonePairing::start(code, name, &mut TestEntropy::default()).unwrap()
}

fn msg2_for(v: &[Action], conn: ChannelId) -> Option<Vec<u8>> {
    v.iter().find_map(|a| match a {
        Action::Send { channel: c, msg2 } if *c == conn => Some(msg2.as_bytes().to_vec()),
        _ => None,
    })
}

fn close_of(v: &[Action], conn: ChannelId) -> Option<CloseReason> {
    v.iter().find_map(|a| match a {
        Action::Close { channel: c, why } if *c == conn => Some(*why),
        _ => None,
    })
}

fn no_reply(v: &[Action], conn: ChannelId) -> bool {
    v.iter()
        .any(|a| matches!(a, Action::NoReply { channel: c, .. } if *c == conn))
        && msg2_for(v, conn).is_none()
}

fn paired_in(v: &[Action]) -> Option<(ChannelId, [u8; 32], bool)> {
    v.iter().find_map(|a| match a {
        Action::Paired {
            channel,
            phone_public,
            replaced,
        } => Some((*channel, *phone_public, *replaced)),
        _ => None,
    })
}

fn opened(v: &[Action], kind: WindowKind) -> bool {
    v.iter()
        .any(|a| matches!(a, Action::WindowOpened { kind: k } if *k == kind))
}

fn expired(v: &[Action]) -> bool {
    v.iter().any(|a| matches!(a, Action::WindowExpired { .. }))
}

fn has(v: &[Action], f: impl Fn(&Action) -> bool) -> bool {
    v.iter().any(f)
}

fn random_secret() -> [u8; 32] {
    let mut k = [0u8; 32];
    getrandom::fill(&mut k).unwrap();
    k
}

fn public_of(private: &[u8; 32]) -> [u8; 32] {
    *Identity::from_private_bytes(private).unwrap().public_key()
}

/// Message 1 with a small-order phone key: `snow` with a test-only
/// resolver whose static key claims a small-order public key and whose DH
/// with it gives the all-zero result the radio computes for such a key.
fn small_order_msg1(radio: &[u8; 32], secret: &[u8; 32], point: [u8; 32]) -> Vec<u8> {
    use snow::params::{CipherChoice, DHChoice, HashChoice};
    use snow::resolvers::{CryptoResolver, DefaultResolver};
    use snow::types::{Cipher, Dh, Hash, Random};

    const MAGIC: [u8; 32] = [0x5A; 32];
    struct EvilDh {
        inner: Box<dyn Dh>,
        small: Option<[u8; 32]>,
        point: [u8; 32],
    }
    impl Dh for EvilDh {
        fn name(&self) -> &'static str {
            self.inner.name()
        }
        fn pub_len(&self) -> usize {
            32
        }
        fn priv_len(&self) -> usize {
            32
        }
        fn set(&mut self, k: &[u8]) {
            if k == MAGIC {
                self.small = Some(self.point);
            } else {
                self.inner.set(k)
            }
        }
        fn generate(&mut self, rng: &mut dyn Random) -> Result<(), snow::Error> {
            self.inner.generate(rng)
        }
        fn pubkey(&self) -> &[u8] {
            match &self.small {
                Some(p) => p,
                None => self.inner.pubkey(),
            }
        }
        fn privkey(&self) -> &[u8] {
            match &self.small {
                Some(_) => &MAGIC,
                None => self.inner.privkey(),
            }
        }
        fn dh(&self, pk: &[u8], out: &mut [u8]) -> Result<(), snow::Error> {
            match self.small {
                Some(_) => {
                    out[..32].fill(0);
                    Ok(())
                }
                None => self.inner.dh(pk, out),
            }
        }
    }
    struct Evil([u8; 32]);
    impl CryptoResolver for Evil {
        fn resolve_rng(&self) -> Option<Box<dyn Random>> {
            DefaultResolver.resolve_rng()
        }
        fn resolve_dh(&self, c: &DHChoice) -> Option<Box<dyn Dh>> {
            Some(Box::new(EvilDh {
                inner: DefaultResolver.resolve_dh(c)?,
                small: None,
                point: self.0,
            }))
        }
        fn resolve_hash(&self, c: &HashChoice) -> Option<Box<dyn Hash>> {
            DefaultResolver.resolve_hash(c)
        }
        fn resolve_cipher(&self, c: &CipherChoice) -> Option<Box<dyn Cipher>> {
            DefaultResolver.resolve_cipher(c)
        }
    }
    let mut hs =
        snow::Builder::with_resolver(crate::PAIRING_NOISE.parse().unwrap(), Box::new(Evil(point)))
            .local_private_key(&MAGIC)
            .unwrap()
            .remote_public_key(radio)
            .unwrap()
            .psk(1, secret)
            .unwrap()
            .prologue(crate::PHONE_PAIRING_PROLOGUE)
            .unwrap()
            .build_initiator()
            .unwrap();
    let mut out = vec![0u8; 200];
    let n = hs
        .write_message(&[0x01, 3, b'b', b'a', b'd'], &mut out)
        .unwrap();
    out.truncate(n);
    out
}

fn small_order_points() -> Vec<[u8; 32]> {
    let mut eight = [0u8; 32];
    data_encoding::HEXLOWER
        .decode_mut(
            b"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            &mut eight,
        )
        .unwrap();
    let mut one = [0u8; 32];
    one[0] = 1;
    vec![[0u8; 32], one, eight]
}

// ---- the handshake on its own ----

#[test]
fn a_pairing_gives_both_sides_the_same_link_key() {
    let mut b = Bench::window();
    let label = b.label.clone();
    let done = b.pair(3.0, Transport::Usb, 7, PairWith::Label(&label), "pixel-9");
    assert_eq!(done.radio_name.as_str(), RADIO_NAME);
    assert_eq!(&done.radio_pairing_public, label.pairing_public());
    let f = b.flash.borrow();
    let (phone_key, name, link_private) = f.trust.clone().unwrap();
    assert_eq!(&phone_key, done.radio_link_key.public_key());
    assert_eq!(name, "pixel-9");
    // The link key from message 2 is the one the radio saved, and it is not
    // the pairing key.
    assert_eq!(public_of(&link_private), done.radio_link_public);
    assert_ne!(&done.radio_link_public, label.pairing_public());
    drop(f);
    let st = b.r.status(s(3.0));
    assert!(st.paired && st.window.is_none());
}

#[test]
fn message_sizes_are_the_spec_sizes() {
    assert_eq!(MAX_MSG1, 130);
    assert_eq!(MIN_MSG1, 99);
    assert_eq!(MAX_MSG2, 115);
    assert_eq!(MIN_MSG2, 84);
    assert_eq!(MSG3_LEN, 17);
    let id = Identity::generate().unwrap();
    let label = LabelCode::new(*id.public_key()).unwrap();
    for name in ["a", &"n".repeat(32)] {
        let (_, m1) = phone(PairWith::Label(&label), name);
        assert!((MIN_MSG1..=MAX_MSG1).contains(&m1.len()));
    }
}

#[test]
fn a_drone_pairing_message_1_is_refused_by_the_radio() {
    // Same pattern and secret, R-SEC1's prologue: the prologues keep the two
    // kinds of pairing apart.
    let mut b = Bench::window();
    let me = Identity::generate().unwrap();
    let mut hs = snow::Builder::new(crate::PAIRING_NOISE.parse().unwrap())
        .local_private_key(me.private_key())
        .unwrap()
        .remote_public_key(b.label.pairing_public())
        .unwrap()
        .psk(1, b.label.secret())
        .unwrap()
        .prologue(crate::PAIRING_PROLOGUE)
        .unwrap()
        .build_initiator()
        .unwrap();
    let mut m1 = vec![0u8; 200];
    let n = hs
        .write_message(&[0x01, 3, b'g', b'c', b's'], &mut m1)
        .unwrap();
    m1.truncate(n);
    b.open(3.0, Transport::Usb, 1);
    let v = b.msg(3.0, 1, &m1);
    assert_eq!(close_of(&v, 1), Some(CloseReason::Msg1Failed));
    assert!(msg2_for(&v, 1).is_none());
}

#[test]
fn radio_keys_refuse_a_label_for_another_radio() {
    let id = Identity::generate().unwrap();
    let other = LabelCode::new(*Identity::generate().unwrap().public_key()).unwrap();
    assert!(RadioKeys::new(id, &other).is_err());
}

// ---- section 8 cases ----

#[test]
fn case_04_wrong_secret_gets_no_reply_in_and_out_of_a_window() {
    let mut b = Bench::window();
    let pk = *b.label.pairing_public();
    // A random secret in a USB window.
    let wrong = LabelCode::with_secret(pk, random_secret());
    b.open(3.0, Transport::Usb, 1);
    let (_, m1) = phone(PairWith::Label(&wrong), "x");
    let v = b.msg(3.0, 1, &m1);
    assert_eq!(close_of(&v, 1), Some(CloseReason::Msg1Failed));
    assert!(msg2_for(&v, 1).is_none());
    // A replace code's secret in a USB window.
    let rc = ReplaceCode::new(pk).unwrap();
    b.open(3.5, Transport::Usb, 2);
    let (_, m1) = phone(PairWith::Replace(&rc), "x");
    let v = b.msg(3.5, 2, &m1);
    assert_eq!(close_of(&v, 2), Some(CloseReason::Msg1Failed));
    // No lockout: the window stays open and the right secret still pairs.
    assert_eq!(b.r.status(s(4.0)).window, Some(WindowKind::Usb));
    let label = b.label.clone();
    b.pair(4.0, Transport::Usb, 3, PairWith::Label(&label), "owner");
    // Out of a window (now paired): the right label, no reply at all.
    b.open(5.0, Transport::Usb, 4);
    let (_, m1) = phone(PairWith::Label(&label), "x");
    let v = b.msg(5.0, 4, &m1);
    assert!(no_reply(&v, 4));
}

#[test]
fn case_04_label_secret_in_a_replace_window_gets_no_reply() {
    let (mut b, old) = Bench::paired();
    let secret = random_secret();
    let (r, _) = b.pair_open(10.0, old.radio_link_key.public_key(), &secret);
    r.unwrap();
    let label = b.label.clone();
    for (i, tr) in [Transport::Ble, Transport::Usb].into_iter().enumerate() {
        let c = 10 + i as ChannelId;
        b.open(11.0, tr, c);
        let (_, m1) = phone(PairWith::Label(&label), "x");
        let v = b.msg(11.0, c, &m1);
        assert_eq!(close_of(&v, c), Some(CloseReason::Msg1Failed));
    }
    // A random replace secret: also nothing.
    let other = ReplaceCode::new(*label.pairing_public()).unwrap();
    b.open(12.0, Transport::Ble, 20);
    let (_, m1) = phone(PairWith::Replace(&other), "x");
    assert_eq!(
        close_of(&b.msg(12.0, 20, &m1), 20),
        Some(CloseReason::Msg1Failed)
    );
}

#[test]
fn case_04_replace_secret_after_its_window_closed_gets_no_reply() {
    let (mut b, old) = Bench::paired();
    let first = random_secret();
    let old_pub = *old.radio_link_key.public_key();
    b.pair_open(10.0, &old_pub, &first).0.unwrap();
    let v = b.poll(130.0);
    assert!(expired(&v));
    let rc = ReplaceCode::from_secret(*b.label.pairing_public(), &first).unwrap();
    // No window: no reply.
    b.open(131.0, Transport::Ble, 1);
    let (_, m1) = phone(PairWith::Replace(&rc), "x");
    assert!(no_reply(&b.msg(131.0, 1, &m1), 1));
    // A new replace window with a new secret: the old one still fails.
    b.pair_open(140.0, &old_pub, &random_secret()).0.unwrap();
    b.open(141.0, Transport::Ble, 2);
    let (_, m1) = phone(PairWith::Replace(&rc), "x");
    assert_eq!(
        close_of(&b.msg(141.0, 2, &m1), 2),
        Some(CloseReason::Msg1Failed)
    );
    assert_eq!(b.trust_phone(), Some(old_pub));
}

#[test]
fn case_05_small_order_phone_key_with_the_right_secret_gets_no_reply() {
    let mut b = Bench::window();
    let pk = *b.label.pairing_public();
    let secret = *b.label.secret();
    for (i, point) in small_order_points().into_iter().enumerate() {
        let c = i as ChannelId + 1;
        let m1 = small_order_msg1(&pk, &secret, point);
        b.open(3.0, Transport::Usb, c);
        let v = b.msg(3.0, c, &m1);
        assert!(msg2_for(&v, c).is_none(), "point {i}");
        assert_eq!(close_of(&v, c), Some(CloseReason::Msg1Refused), "point {i}");
    }
    // Nothing saved, the window stays open, and the owner still pairs (on
    // USB: the refused message 1s pre-empted nothing).
    assert!(b.trust_phone().is_none());
    assert_eq!(b.r.status(s(4.0)).window, Some(WindowKind::Usb));
    let label = b.label.clone();
    b.pair(13.0, Transport::Ble, 9, PairWith::Label(&label), "owner");
}

#[test]
fn case_06_a_second_phone_with_the_label_completes_first() {
    let mut b = Bench::window();
    let label = b.label.clone();
    let (owner, m2_owner) = b.reach_msg2(13.0, Transport::Ble, 1, PairWith::Label(&label), "owner");
    let (stranger, m2_s) =
        b.reach_msg2(13.5, Transport::Ble, 2, PairWith::Label(&label), "stranger");
    let s_done = stranger.finish(&m2_s).unwrap();
    let v = b.msg(14.0, 2, &s_done.msg3);
    assert!(paired_in(&v).is_some());
    // The window closes; the owner's attempt is closed with no reply.
    assert_eq!(close_of(&v, 1), Some(CloseReason::OtherCompleted));
    assert!(b.r.status(s(14.0)).window.is_none());
    // The owner's message 3 then gets nothing, and the owner is not saved.
    let o_done = owner.finish(&m2_owner).unwrap();
    assert!(no_reply(&b.msg(14.5, 1, &o_done.msg3), 1));
    assert_eq!(b.trust_phone(), Some(*s_done.radio_link_key.public_key()));
    // Not covered here: the owner's link handshake getting no answer and
    // the app's "not confirmed" (later parts).
}

#[test]
fn case_07_several_proved_phones_each_get_message_2_and_the_first_message_3_completes() {
    let mut b = Bench::window();
    let label = b.label.clone();
    let mut phones = vec![];
    for c in 1..=3 {
        let (p, m2) = b.reach_msg2(13.0, Transport::Ble, c, PairWith::Label(&label), "p");
        phones.push((c, p.finish(&m2).unwrap()));
    }
    // The second phone's message 3 arrives first.
    let v = b.msg(14.0, 2, &phones[1].1.msg3);
    assert_eq!(paired_in(&v).map(|p| p.0), Some(2));
    assert_eq!(close_of(&v, 1), Some(CloseReason::OtherCompleted));
    assert_eq!(close_of(&v, 3), Some(CloseReason::OtherCompleted));
    for (c, p) in [&phones[0], &phones[2]] {
        assert!(no_reply(&b.msg(14.1, *c, &p.msg3), *c));
    }
    assert_eq!(
        b.trust_phone(),
        Some(*phones[1].1.radio_link_key.public_key())
    );
}

#[test]
fn case_07_a_phone_that_never_sends_message_3_blocks_nobody() {
    let mut b = Bench::window();
    let label = b.label.clone();
    let (_silent, _) = b.reach_msg2(13.0, Transport::Ble, 1, PairWith::Label(&label), "silent");
    // Another phone completes while it is pending...
    let done = b.pair(14.0, Transport::Ble, 2, PairWith::Label(&label), "owner");
    assert_eq!(b.trust_phone(), Some(*done.radio_link_key.public_key()));

    // ...and in another window, after it has timed out on its own.
    let mut b = Bench::window();
    let (_silent, _) = b.reach_msg2(13.0, Transport::Ble, 1, PairWith::Label(&label_of(&b)), "s");
    let v = b.poll(19.0);
    assert_eq!(close_of(&v, 1), Some(CloseReason::Msg3Timeout));
    let label = b.label.clone();
    b.pair(20.0, Transport::Ble, 2, PairWith::Label(&label), "owner");
}

fn label_of(b: &Bench) -> LabelCode {
    b.label.clone()
}

#[test]
fn case_07_a_dropped_message_3_while_the_window_is_open_pairs_again() {
    let mut b = Bench::window();
    let label = b.label.clone();
    let (p, m2) = b.reach_msg2(13.0, Transport::Ble, 1, PairWith::Label(&label), "owner");
    let _lost = p.finish(&m2).unwrap(); // its message 3 never arrives
    b.lost(14.0, 1);
    // The window is still open; the app pairs again on a new connection.
    assert_eq!(b.r.status(s(15.0)).window, Some(WindowKind::Usb));
    let done = b.pair(15.0, Transport::Ble, 2, PairWith::Label(&label), "owner");
    assert_eq!(b.trust_phone(), Some(*done.radio_link_key.public_key()));
}

#[test]
fn case_07_a_dropped_message_3_then_another_completion_leaves_the_owner_out() {
    let mut b = Bench::window();
    let label = b.label.clone();
    let (p, m2) = b.reach_msg2(13.0, Transport::Ble, 1, PairWith::Label(&label), "owner");
    let lost = p.finish(&m2).unwrap();
    let other = b.pair(13.5, Transport::Ble, 2, PairWith::Label(&label), "other");
    // The owner's late message 3 gets nothing, and its retry finds no window.
    assert!(no_reply(&b.msg(14.0, 1, &lost.msg3), 1));
    b.open(15.0, Transport::Ble, 3);
    let (_, m1) = phone(PairWith::Label(&label), "owner");
    assert!(no_reply(&b.msg(15.0, 3, &m1), 3));
    assert_eq!(b.trust_phone(), Some(*other.radio_link_key.public_key()));
}

#[test]
fn case_08_full_slots_of_proved_attempts_refuse_a_new_connection() {
    let mut b = Bench::window();
    let label = b.label.clone();
    // Both USB slots hold proved attempts.
    let (p1, m21) = b.reach_msg2(3.0, Transport::Usb, 1, PairWith::Label(&label), "a");
    let (_p2, _) = b.reach_msg2(3.1, Transport::Usb, 2, PairWith::Label(&label), "b");
    let v = b.open(3.2, Transport::Usb, 3);
    assert_eq!(close_of(&v, 3), Some(CloseReason::SlotsFull));
    assert!(close_of(&v, 1).is_none() && close_of(&v, 2).is_none());
    // Its message gets no reply, and the proved attempts still complete.
    let (_, m1) = phone(PairWith::Label(&label), "c");
    assert!(no_reply(&b.msg(3.3, 3, &m1), 3));
    let d1 = p1.finish(&m21).unwrap();
    assert!(paired_in(&b.msg(3.4, 1, &d1.msg3)).is_some());
}

#[test]
fn case_08_a_full_transport_replaces_only_an_unproved_attempt() {
    let mut b = Bench::window();
    let label = b.label.clone();
    // USB: a proved attempt (older) and an idle one (newer).
    let (p1, m21) = b.reach_msg2(3.0, Transport::Usb, 1, PairWith::Label(&label), "a");
    b.open(3.5, Transport::Usb, 2);
    let v = b.open(4.0, Transport::Usb, 3);
    assert_eq!(close_of(&v, 2), Some(CloseReason::Displaced));
    assert!(close_of(&v, 1).is_none());
    // Among unproved attempts the oldest goes.
    let v = b.open(4.5, Transport::Usb, 4);
    assert_eq!(close_of(&v, 3), Some(CloseReason::Displaced));
    let d1 = p1.finish(&m21).unwrap();
    assert!(paired_in(&b.msg(5.0, 1, &d1.msg3)).is_some());
}

#[test]
fn case_08_ble_and_usb_slots_are_counted_separately() {
    let mut b = Bench::window();
    // Fill all 3 BLE slots with idle connections once BLE is open.
    for c in 1..=3 {
        assert!(b.open(12.0, Transport::Ble, c).is_empty());
    }
    // USB still has both its slots.
    assert!(b.open(12.1, Transport::Usb, 10).is_empty());
    assert!(b.open(12.1, Transport::Usb, 11).is_empty());
    // A fourth BLE connection displaces a BLE attempt, never a USB one.
    let v = b.open(12.2, Transport::Ble, 4);
    assert_eq!(close_of(&v, 1), Some(CloseReason::Displaced));
    assert!(close_of(&v, 10).is_none() && close_of(&v, 11).is_none());
    // A third USB connection displaces a USB attempt, never a BLE one.
    let v = b.open(12.3, Transport::Usb, 12);
    assert_eq!(close_of(&v, 10), Some(CloseReason::Displaced));
    assert!(v.len() == 1);
}

#[test]
fn case_08_a_second_message_1_or_a_failed_one_closes_the_connection() {
    let mut b = Bench::window();
    let label = b.label.clone();
    let (_p, _) = b.reach_msg2(3.0, Transport::Usb, 1, PairWith::Label(&label), "a");
    let (_, again) = phone(PairWith::Label(&label), "a");
    let v = b.msg(3.1, 1, &again);
    assert_eq!(close_of(&v, 1), Some(CloseReason::BadMsg3));
    assert!(msg2_for(&v, 1).is_none());
    // A failed message 1 closes it; nothing more is read on it.
    let wrong = LabelCode::with_secret(*label.pairing_public(), random_secret());
    b.open(3.2, Transport::Usb, 2);
    let (_, bad) = phone(PairWith::Label(&wrong), "a");
    assert_eq!(
        close_of(&b.msg(3.2, 2, &bad), 2),
        Some(CloseReason::Msg1Failed)
    );
    let (_, good) = phone(PairWith::Label(&label), "a");
    assert!(no_reply(&b.msg(3.3, 2, &good), 2));
}

#[test]
fn case_08_every_usb_window_that_closes_without_a_pairing_counts() {
    // Review C-2/C-3: no window is spared, however its proved attempts
    // ended (lost, pre-empted by USB, timed out). Two such windows, then
    // the limit.
    for how in ["lost", "preempted", "timeout"] {
        let mut b = Bench::boot(false);
        let label = b.label.clone();
        let mut t = 10.0;
        for round in 0..2 {
            b.usb(t, true);
            assert!(opened(&b.poll(t + 2.0), WindowKind::Usb), "{how} {round}");
            let c = 100 + 2 * round;
            match how {
                "lost" => {
                    let (_p, _) =
                        b.reach_msg2(t + 3.0, Transport::Usb, c, PairWith::Label(&label), "o");
                    b.lost(t + 4.0, c);
                }
                "preempted" => {
                    let (_p, _) =
                        b.reach_msg2(t + 13.0, Transport::Ble, c, PairWith::Label(&label), "o");
                    let (_u, _) = b.reach_msg2(
                        t + 14.0,
                        Transport::Usb,
                        c + 1,
                        PairWith::Label(&label),
                        "u",
                    );
                }
                _ => {
                    let (_p, _) =
                        b.reach_msg2(t + 3.0, Transport::Usb, c, PairWith::Label(&label), "o");
                    assert_eq!(
                        close_of(&b.poll(t + 9.5), c),
                        Some(CloseReason::Msg3Timeout)
                    );
                }
            }
            assert!(expired(&b.poll(t + 122.0)));
            assert_eq!(b.flash.borrow().rate_count, round as u8 + 1, "{how}");
            b.usb(t + 125.0, false);
            t += 140.0;
        }
        assert!(b.r.status(s(t)).rate_limited, "{how}");
        b.usb(t, true);
        assert!(!opened(&b.poll(t + 3.0), WindowKind::Usb), "{how}");
    }
}

#[test]
fn case_11_the_rate_limit_survives_a_reboot() {
    // Review C-2: the count is kept in the store, so a reboot (a flat
    // battery on a pulsing source, a watchdog) does not forget it.
    let mut b = Bench::boot(false);
    for on_at in [10.0, 150.0] {
        b.usb(on_at, true);
        assert!(opened(&b.poll(on_at + 2.0), WindowKind::Usb));
        assert!(expired(&b.poll(on_at + 122.0)));
        b.usb(on_at + 130.0, false);
    }
    assert_eq!(b.flash.borrow().rate_count, 2);
    // A boot on USB power: no window (the 30 minutes count from the boot).
    b.reboot(0.0, true);
    assert!(b.r.status(s(1.0)).rate_limited);
    assert!(b.poll(5.0).is_empty());
    // Still none before 30 minutes from the boot, even on a new edge.
    b.usb(100.0, false);
    b.usb(200.0, true);
    assert!(b.poll(205.0).is_empty());
    // A new edge after the 30 minutes: a window.
    b.usb(1800.0, false);
    b.usb(1811.0, true);
    assert!(opened(&b.poll(1813.0), WindowKind::Usb));
    // A completed pairing clears it in the store.
    let label = b.label.clone();
    b.pair(1814.0, Transport::Usb, 1, PairWith::Label(&label), "owner");
    assert_eq!(b.flash.borrow().rate_count, 0);
    b.reboot(0.0, false);
    assert!(!b.r.status(s(0.0)).rate_limited);
}

#[test]
fn case_11_a_count_below_the_limit_survives_a_reboot_too() {
    let mut b = Bench::boot(false);
    b.usb(10.0, true);
    assert!(opened(&b.poll(12.0), WindowKind::Usb));
    assert!(expired(&b.poll(132.0)));
    // Reboot on USB: one window (the second of two)...
    b.reboot(0.0, true);
    assert!(opened(&b.poll(2.0), WindowKind::Usb));
    assert!(expired(&b.poll(122.0)));
    // ...and then the limit, across another reboot.
    b.reboot(0.0, true);
    assert!(b.poll(5.0).is_empty());
    assert!(b.r.status(s(5.0)).rate_limited);
}

#[test]
fn case_09_a_recorded_message_1_in_the_same_window_gets_no_reply() {
    let mut b = Bench::window();
    let label = b.label.clone();
    b.open(3.0, Transport::Usb, 1);
    let (_p, m1) = phone(PairWith::Label(&label), "owner");
    assert!(msg2_for(&b.msg(3.0, 1, &m1), 1).is_some());
    b.lost(3.5, 1);
    for (c, tr) in [(2, Transport::Usb), (3, Transport::Usb)] {
        b.open(4.0, tr, c);
        let v = b.msg(4.0, c, &m1);
        assert_eq!(close_of(&v, c), Some(CloseReason::Msg1Replay));
        assert!(msg2_for(&v, c).is_none());
    }
    assert!(b.trust_phone().is_none());
}

#[test]
fn case_09_a_message_1_from_an_earlier_window_gets_message_2_and_never_completes() {
    let mut b = Bench::window();
    let label = b.label.clone();
    // Recorded in the first window: message 1 and the phone's message 3.
    let (p, m2) = {
        b.open(3.0, Transport::Usb, 1);
        let (p, m1) = phone(PairWith::Label(&label), "owner");
        let v = b.msg(3.0, 1, &m1);
        (p, (m1, msg2_for(&v, 1).unwrap()))
    };
    let (rec_m1, m2) = m2;
    let rec_m3 = p.finish(&m2).unwrap().msg3;
    b.lost(3.5, 1);
    assert!(expired(&b.poll(122.0)));
    // A second window.
    b.usb(125.0, false);
    b.usb(140.0, true);
    assert!(opened(&b.poll(142.0), WindowKind::Usb));
    b.open(143.0, Transport::Usb, 2);
    let v = b.msg(143.0, 2, &rec_m1);
    assert!(msg2_for(&v, 2).is_some(), "it proves the secret again");
    let v = b.msg(143.5, 2, &rec_m3);
    assert_eq!(close_of(&v, 2), Some(CloseReason::BadMsg3));
    assert!(paired_in(&v).is_none());
    assert!(b.trust_phone().is_none());
}

#[test]
fn case_09_a_message_1_forgotten_from_a_full_record_gets_message_2_and_never_completes() {
    let mut b = Bench::window();
    let label = b.label.clone();
    b.open(3.0, Transport::Usb, 1);
    let (p0, first) = phone(PairWith::Label(&label), "owner");
    let m2 = msg2_for(&b.msg(3.0, 1, &first), 1).unwrap();
    let old_m3 = p0.finish(&m2).unwrap().msg3;
    b.lost(3.1, 1);
    // 15 more proving message 1s: the record (16) still holds the first.
    let mut t = 4.0;
    let send_fresh = |b: &mut Bench, c: ChannelId, t: f64| {
        b.open(t, Transport::Usb, c);
        let (_, m) = phone(PairWith::Label(&label), "x");
        assert!(msg2_for(&b.msg(t, c, &m), c).is_some());
        b.lost(t, c);
    };
    for c in 0..15 {
        send_fresh(&mut b, 10 + c, t);
        t += 0.1;
    }
    b.open(t, Transport::Usb, 50);
    assert_eq!(
        close_of(&b.msg(t, 50, &first), 50),
        Some(CloseReason::Msg1Replay)
    );
    // That replay did not enter the record twice. One more fresh one
    // makes 17 proving message 1s: the first is forgotten.
    send_fresh(&mut b, 60, t + 0.1);
    b.open(t + 0.2, Transport::Usb, 51);
    let v = b.msg(t + 0.2, 51, &first);
    assert!(msg2_for(&v, 51).is_some());
    // It still cannot complete, and holds its slot for at most 6 s.
    assert_eq!(
        close_of(&b.msg(t + 0.3, 51, &old_m3), 51),
        Some(CloseReason::BadMsg3)
    );
    b.open(t + 0.4, Transport::Usb, 52);
    assert!(msg2_for(&b.msg(t + 0.4, 52, &first), 52).is_none());
    assert_eq!(
        close_of(&b.poll(t + 0.4 + 6.0), 52),
        None,
        "the repeat was refused, not held"
    );
    assert!(b.trust_phone().is_none());
}

#[test]
fn case_09_a_forgotten_replay_holds_its_slot_for_at_most_6_s() {
    let mut b = Bench::window();
    let label = b.label.clone();
    b.open(3.0, Transport::Usb, 1);
    let (_p, first) = phone(PairWith::Label(&label), "owner");
    b.msg(3.0, 1, &first);
    b.lost(3.0, 1);
    for c in 0..16 {
        b.open(4.0, Transport::Usb, 10 + c);
        let (_, m) = phone(PairWith::Label(&label), "x");
        b.msg(4.0, 10 + c, &m);
        b.lost(4.0, 10 + c);
    }
    b.open(5.0, Transport::Usb, 2);
    assert!(msg2_for(&b.msg(5.0, 2, &first), 2).is_some());
    assert!(close_of(&b.poll(10.9), 2).is_none());
    assert_eq!(close_of(&b.poll(11.0), 2), Some(CloseReason::Msg3Timeout));
}

#[test]
fn case_10_no_window_on_battery_start_or_on_usb_power_when_paired() {
    let mut b = Bench::boot(false);
    let v = b.poll(300.0);
    assert!(v.is_empty());
    assert!(b.r.status(s(300.0)).window.is_none());
    let (mut b, _) = Bench::paired();
    b.usb(10.0, false);
    b.usb(30.0, true);
    assert!(b.poll(40.0).is_empty());
    assert!(b.r.status(s(40.0)).window.is_none());
}

#[test]
fn case_10_a_window_opens_only_after_10_s_absent_and_2_s_present() {
    let mut b = Bench::boot(false);
    b.usb(20.0, true);
    b.usb(21.9, false); // present 1.9 s
    b.usb(25.0, true); // absent 3.1 s
    assert!(b.poll(40.0).is_empty());
    b.usb(40.0, false);
    b.usb(49.9, true); // absent 9.9 s
    assert!(b.poll(60.0).is_empty());
    b.usb(60.0, false);
    b.usb(70.0, true); // absent 10 s
    assert!(b.poll(71.99).is_empty());
    assert!(opened(&b.poll(72.0), WindowKind::Usb));
}

#[test]
fn case_10_a_window_closes_after_2_minutes_and_at_the_first_completion() {
    let mut b = Bench::window();
    assert!(b.poll(121.99).is_empty());
    let v = b.poll(122.0);
    assert!(expired(&v));
    assert!(b.r.status(s(122.0)).window.is_none());

    let mut b = Bench::window();
    let label = b.label.clone();
    b.pair(3.0, Transport::Usb, 1, PairWith::Label(&label), "owner");
    assert!(b.r.status(s(3.0)).window.is_none());
    // One chance per window: a second phone cannot complete in it.
    b.open(3.1, Transport::Usb, 2);
    let (_, m1) = phone(PairWith::Label(&label), "second");
    assert!(no_reply(&b.msg(3.1, 2, &m1), 2));
}

#[test]
fn case_10_a_pairing_message_outside_a_window_gets_no_reply() {
    let mut b = Bench::boot(false);
    let label = b.label.clone();
    for tr in [Transport::Ble, Transport::Usb] {
        b.open(1.0, tr, 1);
        let (_, m1) = phone(PairWith::Label(&label), "x");
        assert!(no_reply(&b.msg(1.0, 1, &m1), 1));
        b.lost(1.0, 1);
    }
    // A connection made before a window opens is not an attempt either.
    b.open(5.0, Transport::Usb, 2);
    b.usb(10.0, true);
    assert!(opened(&b.poll(12.0), WindowKind::Usb));
    let (_, m1) = phone(PairWith::Label(&label), "x");
    assert!(no_reply(&b.msg(12.5, 2, &m1), 2));
}

#[test]
fn case_11_power_toggled_faster_than_the_debounce_opens_nothing() {
    let mut b = Bench::boot(false);
    let mut t = 20.0;
    let mut on = true;
    while t < 200.0 {
        b.usb(t, on);
        on = !on;
        t += 1.5;
    }
    assert!(!has(&b.poll(t), |a| matches!(
        a,
        Action::WindowOpened { .. }
    )));
    assert!(b.r.status(s(t)).window.is_none());
}

#[test]
fn case_11_an_edge_during_a_window_restarts_nothing() {
    let mut b = Bench::window(); // opened at 2 s, no host: BLE at 12 s
    let label = b.label.clone();
    b.open(13.0, Transport::Ble, 1);
    let (_p, m1) = phone(PairWith::Label(&label), "owner");
    assert!(msg2_for(&b.msg(13.0, 1, &m1), 1).is_some());
    b.lost(13.0, 1);
    // A full debounced edge inside the window (absent 11 s, present 2 s).
    b.usb(14.0, false);
    b.usb(25.0, true);
    let v = b.poll(27.5);
    assert!(!has(&v, |a| matches!(a, Action::WindowOpened { .. })));
    // The BLE rule did not restart (it would shut BLE until 37 s).
    assert!(b.r.status(s(27.5)).ble_open);
    // The record of message 1s is kept.
    b.open(28.0, Transport::Ble, 2);
    assert_eq!(
        close_of(&b.msg(28.0, 2, &m1), 2),
        Some(CloseReason::Msg1Replay)
    );
    // The 2 minutes run from the first opening.
    assert!(b.poll(121.9).is_empty());
    assert!(expired(&b.poll(122.0)));
}

#[test]
fn case_11_a_pulsing_source_opens_two_windows_then_one_each_30_minutes() {
    let mut b = Bench::boot(false);
    let mut opens = vec![];
    let cycle = |b: &mut Bench, on_at: f64| -> bool {
        b.usb(on_at, true);
        let o = opened(&b.poll(on_at + 2.0), WindowKind::Usb);
        if o {
            assert!(expired(&b.poll(on_at + 2.0 + 120.0)));
        }
        b.usb(on_at + 130.0, false);
        o
    };
    // Windows 1 and 2 close with no pairing.
    opens.push(cycle(&mut b, 10.0)); // closes at 132
    opens.push(cycle(&mut b, 150.0)); // closes at 272
    assert_eq!(opens, [true, true]);
    assert!(b.r.status(s(281.0)).rate_limited);
    // An edge before 30 minutes after the last close: nothing.
    assert!(!cycle(&mut b, 290.0));
    // Left on power past the 30 minutes: nothing by itself.
    b.usb(500.0, true);
    assert!(b.poll(272.0 + 1800.0 + 60.0).is_empty());
    assert!(b.r.status(s(2200.0)).rate_limited);
    b.usb(2200.0, false);
    // A new edge after the 30 minutes: one window.
    assert!(cycle(&mut b, 2215.0)); // closes at 2337
    // And the next needs another 30 minutes and a new edge.
    assert!(!cycle(&mut b, 2360.0));
    assert!(cycle(&mut b, 2337.0 + 1800.0 + 5.0));
}

#[test]
fn case_11_a_reset_lifts_the_limit_and_its_window_is_the_first_of_a_new_two() {
    let mut b = Bench::boot(false);
    for on_at in [10.0, 150.0] {
        b.usb(on_at, true);
        assert!(opened(&b.poll(on_at + 2.0), WindowKind::Usb));
        assert!(expired(&b.poll(on_at + 122.0)));
        b.usb(on_at + 130.0, false);
    }
    assert!(b.r.status(s(300.0)).rate_limited);
    // Plugged in (the edge is refused), then the pin.
    b.usb(300.0, true);
    assert!(b.poll(303.0).is_empty());
    b.reset(310.0);
    assert!(!b.r.status(s(310.0)).rate_limited);
    assert!(opened(&b.poll(312.0), WindowKind::Usb)); // window 1 of 2
    assert!(expired(&b.poll(432.0)));
    b.usb(440.0, false);
    b.usb(450.0, true);
    assert!(opened(&b.poll(452.0), WindowKind::Usb)); // window 2 of 2
    assert!(expired(&b.poll(572.0)));
    b.usb(580.0, false);
    b.usb(590.0, true);
    assert!(b.poll(593.0).is_empty()); // limited again
}

#[test]
fn case_12_with_no_host_ble_is_refused_until_10_s() {
    let mut b = Bench::window(); // opened at 2 s
    let label = b.label.clone();
    assert!(!b.r.status(s(11.9)).ble_open);
    assert!(b.open(11.9, Transport::Ble, 1).is_empty());
    let (_, m1) = phone(PairWith::Label(&label), "x");
    assert!(no_reply(&b.msg(11.95, 1, &m1), 1));
    assert!(b.r.status(s(12.0)).ble_open);
    b.pair(12.0, Transport::Ble, 2, PairWith::Label(&label), "owner");
}

#[test]
fn case_12_a_host_enumerated_by_10_s_keeps_ble_shut_until_20_s() {
    let mut b = Bench::boot(true);
    b.enumerated(1.0); // during the debounce, before the window opens
    assert!(opened(&b.poll(2.0), WindowKind::Usb));
    let label = b.label.clone();
    b.open(12.5, Transport::Ble, 1);
    let (_, m1) = phone(PairWith::Label(&label), "x");
    assert!(no_reply(&b.msg(12.5, 1, &m1), 1));
    assert!(!b.r.status(s(21.9)).ble_open);
    b.pair(22.0, Transport::Ble, 2, PairWith::Label(&label), "owner");

    // A host that enumerates inside the first 10 s, then is unplugged.
    let mut b = Bench::window();
    b.enumerated(8.0);
    b.usb(9.0, false);
    assert!(!b.r.status(s(15.0)).ble_open);
    assert!(b.r.status(s(22.0)).ble_open);

    // A host that enumerates after 10 s does not shut BLE again.
    let mut b = Bench::window();
    b.enumerated(12.5);
    assert!(b.r.status(s(13.0)).ble_open);
}

#[test]
fn case_12_a_proving_usb_message_1_shuts_ble_for_the_whole_window() {
    let mut b = Bench::boot(true);
    b.enumerated(1.0);
    assert!(opened(&b.poll(2.0), WindowKind::Usb));
    let label = b.label.clone();
    let (_p, _) = b.reach_msg2(5.0, Transport::Usb, 1, PairWith::Label(&label), "cable");
    b.lost(6.0, 1);
    for t in [22.0, 60.0, 121.0] {
        assert!(!b.r.status(s(t)).ble_open, "{t}");
        let c = t as ChannelId;
        assert!(b.open(t, Transport::Ble, c).is_empty());
        let (_, m1) = phone(PairWith::Label(&label), "ble");
        assert!(no_reply(&b.msg(t, c, &m1), c));
    }
}

#[test]
fn case_12_a_proving_usb_message_1_ends_every_ble_attempt_not_completed() {
    let mut b = Bench::window();
    let label = b.label.clone();
    let (ble_p, ble_m2) = b.reach_msg2(13.0, Transport::Ble, 1, PairWith::Label(&label), "ble");
    b.open(13.5, Transport::Ble, 2); // an idle one too
    b.open(14.0, Transport::Usb, 10);
    let (usb_p, m1) = phone(PairWith::Label(&label), "cable");
    let v = b.msg(14.0, 10, &m1);
    assert_eq!(close_of(&v, 1), Some(CloseReason::PreemptedByUsb));
    assert_eq!(close_of(&v, 2), Some(CloseReason::PreemptedByUsb));
    let usb_m2 = msg2_for(&v, 10).unwrap();
    // The BLE phone that had its message 2 gets nothing for its message 3.
    let ble_done = ble_p.finish(&ble_m2).unwrap();
    assert!(no_reply(&b.msg(14.5, 1, &ble_done.msg3), 1));
    let usb_done = usb_p.finish(&usb_m2).unwrap();
    assert!(paired_in(&b.msg(15.0, 10, &usb_done.msg3)).is_some());
    assert_eq!(b.trust_phone(), Some(*usb_done.radio_link_key.public_key()));
}

#[test]
fn case_12_a_ble_message_3_that_arrived_first_still_completes() {
    let mut b = Bench::window();
    let label = b.label.clone();
    b.open(13.0, Transport::Usb, 10); // the cable phone has connected...
    let ble = b.pair(14.0, Transport::Ble, 1, PairWith::Label(&label), "ble");
    // ...but its message 1 comes after the BLE completion.
    let (_, m1) = phone(PairWith::Label(&label), "cable");
    assert!(no_reply(&b.msg(14.5, 10, &m1), 10));
    assert_eq!(b.trust_phone(), Some(*ble.radio_link_key.public_key()));
}

#[test]
fn case_12_a_usb_and_a_ble_message_3_together_save_exactly_one_phone() {
    // In a USB window a proving USB message 1 ends the BLE attempts, so a
    // live BLE message 3 next to a USB one can only happen in a replace
    // window (no USB rules). Both orders, there.
    for usb_first in [true, false] {
        let (mut b, old) = Bench::paired();
        let secret = random_secret();
        b.pair_open(10.0, old.radio_link_key.public_key(), &secret)
            .0
            .unwrap();
        let rc = ReplaceCode::from_secret(*b.label.pairing_public(), &secret).unwrap();
        let (pb, mb) = b.reach_msg2(11.0, Transport::Ble, 1, PairWith::Replace(&rc), "ble");
        let (pu, mu) = b.reach_msg2(11.0, Transport::Usb, 2, PairWith::Replace(&rc), "usb");
        let (db, du) = (pb.finish(&mb).unwrap(), pu.finish(&mu).unwrap());
        let order = if usb_first {
            [(2, &du), (1, &db)]
        } else {
            [(1, &db), (2, &du)]
        };
        let first = b.msg(12.0, order[0].0, &order[0].1.msg3);
        let second = b.msg(12.0, order[1].0, &order[1].1.msg3);
        assert!(paired_in(&first).is_some());
        assert!(paired_in(&second).is_none());
        assert!(no_reply(&second, order[1].0));
        assert_eq!(
            b.trust_phone(),
            Some(*order[0].1.radio_link_key.public_key())
        );
        assert_eq!(b.flash.borrow().written_links.len(), 2); // old + this one
    }
    // In a USB window: the BLE attempt is already gone when the USB
    // message 1 lands.
    let mut b = Bench::window();
    let label = b.label.clone();
    let (pb, mb) = b.reach_msg2(13.0, Transport::Ble, 1, PairWith::Label(&label), "ble");
    let (pu, mu) = b.reach_msg2(13.0, Transport::Usb, 2, PairWith::Label(&label), "usb");
    let (db, du) = (pb.finish(&mb).unwrap(), pu.finish(&mu).unwrap());
    assert!(no_reply(&b.msg(14.0, 1, &db.msg3), 1));
    assert!(paired_in(&b.msg(14.0, 2, &du.msg3)).is_some());
    assert_eq!(b.flash.borrow().written_links.len(), 1);
}

#[test]
fn case_13_pair_open_opens_a_window_keyed_with_its_secret_only() {
    let (mut b, old) = Bench::paired();
    let old_pub = *old.radio_link_key.public_key();
    let secret = random_secret();
    let (r, v) = b.pair_open(10.0, &old_pub, &secret);
    r.unwrap();
    assert!(opened(&v, WindowKind::Replace));
    // A replace window has no USB rules: BLE is open at once.
    assert!(b.r.status(s(10.0)).ble_open);
    // The old phone stays paired during the window, and nothing of its
    // state has been touched yet.
    assert_eq!(b.link_peer(), Some(old_pub));
    assert!(!has(&v, |a| matches!(a, Action::EndAllSessions)));
    assert_eq!(b.flash.borrow().owner_state, Some(old_pub));
    let rc = ReplaceCode::from_secret(*b.label.pairing_public(), &secret).unwrap();
    // A label in it fails (case 4); the replace code pairs.
    let label = b.label.clone();
    b.open(11.0, Transport::Ble, 5);
    let (_, m1) = phone(PairWith::Label(&label), "x");
    assert_eq!(
        close_of(&b.msg(11.0, 5, &m1), 5),
        Some(CloseReason::Msg1Failed)
    );
    b.open(12.0, Transport::Ble, 6);
    let (p, m1) = phone(PairWith::Replace(&rc), "new");
    let v = b.msg(12.0, 6, &m1);
    let new = p.finish(&msg2_for(&v, 6).unwrap()).unwrap();
    let v = b.msg(12.5, 6, &new.msg3);
    let new_pub = *new.radio_link_key.public_key();
    assert_eq!(paired_in(&v), Some((6, new_pub, true)));
    // At completion: old out, new in, owner state erased, sessions end,
    // held packets wiped, a new Bluetooth address.
    assert!(has(&v, |a| matches!(a, Action::EndAllSessions)));
    assert!(has(&v, |a| matches!(a, Action::WipeHeldPackets)));
    assert!(has(&v, |a| matches!(a, Action::NewBluetoothAddress)));
    let f = b.flash.borrow();
    assert_eq!(f.trust.as_ref().map(|t| t.0), Some(new_pub));
    assert_eq!(f.owner_state, None);
    assert_eq!(f.marker, None);
    drop(f);
    // The old phone is refused at once.
    assert_eq!(
        b.pair_open(13.0, &old_pub, &random_secret()).0,
        Err(PairOpenRefused::NotThePairedPhone)
    );
    assert_eq!(b.link_peer(), Some(new_pub));
}

#[test]
fn case_13_an_all_zero_secret_is_refused() {
    let (mut b, old) = Bench::paired();
    let (r, v) = b.pair_open(10.0, old.radio_link_key.public_key(), &[0u8; 32]);
    assert_eq!(r, Err(PairOpenRefused::ZeroSecret));
    assert!(v.is_empty());
    assert!(b.r.status(s(10.0)).window.is_none());
}

#[test]
fn case_13_with_no_completion_nothing_changes_and_the_secret_is_gone() {
    let (mut b, old) = Bench::paired();
    let old_pub = *old.radio_link_key.public_key();
    let secret = random_secret();
    b.pair_open(10.0, &old_pub, &secret).0.unwrap();
    let rc = ReplaceCode::from_secret(*b.label.pairing_public(), &secret).unwrap();
    // An attempt that never completes.
    let (_p, _) = b.reach_msg2(11.0, Transport::Ble, 1, PairWith::Replace(&rc), "new");
    let v = b.poll(130.0);
    assert!(expired(&v));
    assert!(!has(&v, |a| matches!(a, Action::EndAllSessions)));
    let f = b.flash.borrow();
    assert_eq!(f.trust.as_ref().map(|t| t.0), Some(old_pub));
    assert_eq!(f.owner_state, Some(old_pub));
    drop(f);
    assert_eq!(b.link_peer(), Some(old_pub));
    // The radio's copy of the secret is gone with the window: the code
    // finds no window, and a new window with another secret refuses it.
    b.open(131.0, Transport::Ble, 2);
    let (_, m1) = phone(PairWith::Replace(&rc), "new");
    assert!(no_reply(&b.msg(131.0, 2, &m1), 2));
    // An old phone that died during the window: the radio stays paired to
    // it until a reset.
    assert!(b.r.status(s(500.0)).paired);
    b.reset(500.0);
    assert!(!b.r.status(s(500.0)).paired);
}

#[test]
fn case_13_pair_open_from_anyone_else_or_during_a_window_is_refused() {
    let (mut b, old) = Bench::paired();
    let old_pub = *old.radio_link_key.public_key();
    let stranger = *Identity::generate().unwrap().public_key();
    assert_eq!(
        b.pair_open(10.0, &stranger, &random_secret()).0,
        Err(PairOpenRefused::NotThePairedPhone)
    );
    b.pair_open(11.0, &old_pub, &random_secret()).0.unwrap();
    assert_eq!(
        b.pair_open(12.0, &old_pub, &random_secret()).0,
        Err(PairOpenRefused::WindowOpen)
    );
    // An unpaired radio has nobody to accept it from.
    let mut u = Bench::boot(false);
    assert_eq!(
        u.pair_open(1.0, &stranger, &random_secret()).0,
        Err(PairOpenRefused::NotThePairedPhone)
    );
    assert!(u.r.status(s(1.0)).window.is_none());
    // And in a USB window, PAIR_OPEN from the phone that is pairing is not
    // possible: it is not the paired phone.
    let mut w = Bench::window();
    assert_eq!(
        w.pair_open(3.0, &stranger, &random_secret()).0,
        Err(PairOpenRefused::NotThePairedPhone)
    );
}

#[test]
fn case_14_a_pinhole_reset_erases_the_owner_and_keeps_the_label() {
    let (mut b, old) = Bench::paired();
    let old_pub = *old.radio_link_key.public_key();
    b.usb(9.0, false); // on battery
    let v = b.reset(10.0);
    assert!(has(&v, |a| matches!(a, Action::EndAllSessions)));
    assert!(has(&v, |a| matches!(a, Action::WipeHeldPackets)));
    assert!(has(&v, |a| matches!(a, Action::NewBluetoothAddress)));
    assert!(has(&v, |a| matches!(a, Action::ResetDone)));
    let f = b.flash.borrow();
    assert!(f.trust.is_none());
    assert!(f.owner_state.is_none());
    assert!(f.marker.is_none());
    drop(f);
    assert!(b.link_peer().is_none());
    // The old phone is refused at once.
    assert_eq!(
        b.pair_open(11.0, &old_pub, &random_secret()).0,
        Err(PairOpenRefused::NotThePairedPhone)
    );
    // On battery: no window until a debounced USB edge.
    assert!(b.poll(30.0).is_empty());
    b.usb(30.0, true);
    assert!(opened(&b.poll(32.0), WindowKind::Usb));
    // The same label pairs again (pairing key and secret kept).
    let label = b.label.clone();
    b.pair(33.0, Transport::Usb, 3, PairWith::Label(&label), "again");
}

#[test]
fn case_14_a_reset_closes_a_replace_window() {
    let (mut b, old) = Bench::paired();
    let secret = random_secret();
    b.pair_open(10.0, old.radio_link_key.public_key(), &secret)
        .0
        .unwrap();
    let rc = ReplaceCode::from_secret(*b.label.pairing_public(), &secret).unwrap();
    let (p, m2) = b.reach_msg2(11.0, Transport::Ble, 1, PairWith::Replace(&rc), "new");
    b.usb(11.5, false);
    let v = b.reset(12.0);
    assert_eq!(close_of(&v, 1), Some(CloseReason::Reset));
    assert!(b.r.status(s(12.0)).window.is_none());
    let done = p.finish(&m2).unwrap();
    assert!(no_reply(&b.msg(12.5, 1, &done.msg3), 1));
    assert!(b.trust_phone().is_none());
}

#[test]
fn case_14_a_reset_on_usb_power_opens_a_window_2_s_later() {
    let (mut b, _) = Bench::paired(); // USB present since boot
    b.reset(10.0);
    assert!(b.poll(11.99).is_empty());
    assert!(opened(&b.poll(12.0), WindowKind::Usb));
    // Unplugged during the 2 s: no window from the reset.
    let (mut b, _) = Bench::paired();
    b.reset(10.0);
    b.usb(11.0, false);
    assert!(b.poll(20.0).is_empty());
    // Unplugged and plugged back within the 2 s: the reset's window is
    // gone, and the short absence is no debounced edge either.
    let (mut b, _) = Bench::paired();
    b.reset(10.0);
    b.usb(10.5, false);
    b.usb(11.0, true);
    assert!(b.poll(20.0).is_empty());
}

#[test]
fn case_14_a_reset_after_closing_a_window_and_writing_the_peer_leaves_it_unpaired() {
    // The state machine closes the window and writes the peer in one step,
    // so a reset comes after the write and erases it.
    let mut b = Bench::window();
    let label = b.label.clone();
    b.pair(3.0, Transport::Usb, 1, PairWith::Label(&label), "owner");
    b.usb(3.0, false);
    b.reset(3.0);
    assert!(b.trust_phone().is_none());
    assert!(!b.r.status(s(3.0)).paired);
    // A reset while the trust write is torn (power lost during it): the
    // boot finds no new peer.
    let mut b = Bench::window();
    let (p, m2) = b.reach_msg2(3.0, Transport::Usb, 1, PairWith::Label(&label_of(&b)), "o");
    let done = p.finish(&m2).unwrap();
    b.crash_after(0);
    let v = b.msg(3.1, 1, &done.msg3);
    assert!(has(&v, |a| matches!(a, Action::StoreFailed)));
    assert!(paired_in(&v).is_none());
    b.reboot(5.0, false);
    assert!(b.trust_phone().is_none());
}

/// After any reboot: never a phone with another phone's owner state.
fn assert_invariant(b: &Bench) {
    let f = b.flash.borrow();
    assert!(f.marker.is_none(), "boot clears the marker");
    if let (Some(t), Some(o)) = (&f.trust, &f.owner_state) {
        assert_eq!(&t.0, o, "a phone with another phone's state");
    }
}

#[test]
fn case_15_power_lost_at_each_step_of_a_first_pairing() {
    for k in 0..=1 {
        let mut b = Bench::window();
        let label = b.label.clone();
        let (p, m2) = b.reach_msg2(3.0, Transport::Usb, 1, PairWith::Label(&label), "new");
        let done = p.finish(&m2).unwrap();
        b.crash_after(k);
        let v = b.msg(3.1, 1, &done.msg3);
        b.reboot(10.0, false);
        assert_invariant(&b);
        if k == 0 {
            assert!(has(&v, |a| matches!(a, Action::StoreFailed)));
            assert!(b.trust_phone().is_none());
            assert!(!b.r.status(s(10.0)).paired);
        } else {
            assert_eq!(b.trust_phone(), Some(*done.radio_link_key.public_key()));
            assert!(b.r.status(s(10.0)).paired);
        }
    }
}

#[test]
fn case_15_power_lost_at_each_step_of_a_replace() {
    // The replace writes: marker, erase, trust, clear marker.
    for k in 0..=4 {
        let (mut b, old) = Bench::paired();
        let old_pub = *old.radio_link_key.public_key();
        let secret = random_secret();
        b.pair_open(10.0, &old_pub, &secret).0.unwrap();
        let rc = ReplaceCode::from_secret(*b.label.pairing_public(), &secret).unwrap();
        let (p, m2) = b.reach_msg2(11.0, Transport::Ble, 1, PairWith::Replace(&rc), "new");
        let new = p.finish(&m2).unwrap();
        let new_pub = *new.radio_link_key.public_key();
        b.crash_after(k);
        let v = b.msg(11.5, 1, &new.msg3);
        assert_eq!(
            has(&v, |a| matches!(a, Action::StoreFailed)),
            k < 4,
            "k={k}"
        );
        b.reboot(20.0, false);
        assert_invariant(&b);
        let f = b.flash.borrow();
        let phone = f.trust.as_ref().map(|t| t.0);
        match k {
            // Power lost before the marker landed: the replace never began.
            0 => {
                assert_eq!(phone, Some(old_pub));
                assert_eq!(f.owner_state, Some(old_pub));
            }
            // Torn before the trust change: the old phone, its state gone.
            1 | 2 => {
                assert_eq!(phone, Some(old_pub));
                assert_eq!(f.owner_state, None);
            }
            // Torn after it, or not torn: complete.
            _ => {
                assert_eq!(phone, Some(new_pub));
                assert_eq!(f.owner_state, None);
            }
        }
        drop(f);
        assert_eq!(b.link_peer(), phone);
    }
}

#[test]
fn case_15_power_lost_at_each_step_of_a_reset() {
    // The reset writes: marker, erase, trust (none), clear marker.
    for k in 0..=4 {
        let (mut b, old) = Bench::paired();
        let old_pub = *old.radio_link_key.public_key();
        b.crash_after(k);
        b.reset(10.0);
        b.reboot(20.0, false);
        assert_invariant(&b);
        let f = b.flash.borrow();
        if k == 0 {
            // Power lost before the marker landed: no reset happened.
            assert_eq!(f.trust.as_ref().map(|t| t.0), Some(old_pub));
            assert_eq!(f.owner_state, Some(old_pub));
        } else {
            assert!(f.trust.is_none(), "k={k}");
            assert!(f.owner_state.is_none(), "k={k}");
        }
    }
}

#[test]
fn case_15_power_lost_during_the_boot_that_finishes_an_erase() {
    for marker in [Marker::Reset, Marker::Replace] {
        for k in 0..=2 {
            let (mut b, old) = Bench::paired();
            let old_pub = *old.radio_link_key.public_key();
            b.flash.borrow_mut().marker = Some(marker);
            // The first boot loses power at step k of its own work.
            {
                let mut f = b.flash.borrow_mut();
                f.crash_at = Some(f.ops + k);
            }
            let v = b.boot_again(30.0, false);
            let finished = !b.r.status(s(30.0)).faulted;
            assert_eq!(has(&v, |a| matches!(a, Action::StoreFailed)), !finished);
            if !finished {
                // Fail closed: no link peer from a faulted boot.
                assert!(b.link_peer().is_none());
            }
            // The next boot finishes it.
            b.reboot(40.0, false);
            assert_invariant(&b);
            let f = b.flash.borrow();
            assert!(f.owner_state.is_none(), "{marker:?} k={k} ok={finished}");
            match marker {
                Marker::Reset => assert!(f.trust.is_none()),
                Marker::Replace => assert_eq!(f.trust.as_ref().map(|t| t.0), Some(old_pub)),
            }
        }
    }
}

#[test]
fn case_16_a_small_order_link_key_in_message_2_is_refused_by_the_phone() {
    let radio = Identity::generate().unwrap();
    let label = LabelCode::new(*radio.public_key()).unwrap();
    for point in small_order_points() {
        let (p, m1) = phone(PairWith::Label(&label), "phone");
        let o = radio_open_msg1(&radio, label.secret(), &m1).unwrap();
        let mut buf = [0u8; MAX_MSG2];
        let (_, n) = radio_write_msg2(o.hs, &Name::new("evil").unwrap(), &point, &mut buf).unwrap();
        assert!(matches!(
            p.finish(&buf[..n]),
            Err(crate::Error::SmallOrderKey)
        ));
    }
}

#[test]
fn case_16_two_pairings_give_different_link_keys_and_phone_keys() {
    let (mut b, first) = Bench::paired();
    b.reset(10.0); // USB present: a window at 12 s
    assert!(opened(&b.poll(12.0), WindowKind::Usb));
    let label = b.label.clone();
    let second = b.pair(13.0, Transport::Usb, 2, PairWith::Label(&label), "old");
    assert_ne!(first.radio_link_public, second.radio_link_public);
    assert_ne!(
        first.radio_link_key.public_key(),
        second.radio_link_key.public_key()
    );
    assert_ne!(&second.radio_link_public, label.pairing_public());
}

#[test]
fn case_16_only_the_completing_attempts_link_key_is_ever_written() {
    let mut b = Bench::window();
    let label = b.label.clone();
    let mut not_written = vec![];
    let link_of = |p: PhonePairing, m2: &[u8]| p.finish(m2).unwrap().radio_link_public;
    // Times out by itself.
    let (p, m2) = b.reach_msg2(13.0, Transport::Ble, 1, PairWith::Label(&label), "a");
    not_written.push(link_of(p, &m2));
    b.poll(19.0);
    // Its connection is lost.
    let (p, m2) = b.reach_msg2(20.0, Transport::Ble, 2, PairWith::Label(&label), "b");
    not_written.push(link_of(p, &m2));
    b.lost(21.0, 2);
    // Closed for a bad message 3.
    let (p, m2) = b.reach_msg2(22.0, Transport::Ble, 3, PairWith::Label(&label), "c");
    not_written.push(link_of(p, &m2));
    b.msg(22.5, 3, &[0u8; MSG3_LEN]);
    // Pre-empted by USB.
    let (p, m2) = b.reach_msg2(23.0, Transport::Ble, 4, PairWith::Label(&label), "d");
    not_written.push(link_of(p, &m2));
    let (pu, mu) = b.reach_msg2(24.0, Transport::Usb, 10, PairWith::Label(&label), "usb");
    // Ended by another's completion.
    let (p, m2) = b.reach_msg2(24.5, Transport::Usb, 11, PairWith::Label(&label), "e");
    not_written.push(link_of(p, &m2));
    let done = pu.finish(&mu).unwrap();
    assert!(paired_in(&b.msg(25.0, 10, &done.msg3)).is_some());
    // The window closing on a pending attempt.
    let mut w = Bench::window();
    let label2 = w.label.clone();
    let (p, m2) = w.reach_msg2(118.0, Transport::Usb, 1, PairWith::Label(&label2), "f");
    let pending = link_of(p, &m2);
    assert_eq!(close_of(&w.poll(122.0), 1), Some(CloseReason::WindowClosed));
    assert!(w.flash.borrow().written_links.is_empty());
    // The first window wrote exactly one link key: the completer's.
    let written = b.flash.borrow().written_links.clone();
    assert_eq!(written.len(), 1);
    assert_eq!(public_of(&written[0]), done.radio_link_public);
    for k in not_written.iter().chain([&pending]) {
        assert_ne!(k, &done.radio_link_public);
    }
}

#[test]
fn case_18_idle_connections_do_not_keep_a_phone_with_the_code_out() {
    // Covered here for the window only: idle connections on every slot of
    // both transports, renewed all the time, and the owner still pairs.
    let mut b = Bench::window();
    let label = b.label.clone();
    let mut c = 100;
    for t in [12.0, 12.5, 13.0, 13.5] {
        for tr in [Transport::Ble, Transport::Usb, Transport::Ble] {
            b.open(t, tr, c);
            c += 1;
        }
    }
    b.pair(14.0, Transport::Ble, 1, PairWith::Label(&label), "owner");
    // Slow: an attempt that never sends message 1 is closed after 3 s.
    let mut b = Bench::window();
    b.open(3.0, Transport::Usb, 1);
    assert!(close_of(&b.poll(5.99), 1).is_none());
    assert_eq!(close_of(&b.poll(6.0), 1), Some(CloseReason::Msg1Timeout));
}

// ---- refusals, hostile input, secrets ----

#[test]
fn messages_of_the_wrong_size_or_junk_are_refused_without_panicking() {
    let mut b = Bench::window();
    let mut c = 1;
    for len in [0usize, 1, 31, 32, 98, 99, 100, 130, 131, 500] {
        for fill in [0u8, 0xFF] {
            b.open(3.0, Transport::Usb, c);
            let v = b.msg(3.0, c, &vec![fill; len]);
            assert_eq!(close_of(&v, c), Some(CloseReason::Msg1Failed), "len {len}");
            assert!(msg2_for(&v, c).is_none());
            c += 1;
        }
    }
    // Message 3 of the wrong size, or right-sized junk.
    let label = b.label.clone();
    for junk in [vec![], vec![3u8], vec![0u8; MSG3_LEN], vec![0u8; 200]] {
        let (_p, _) = b.reach_msg2(4.0, Transport::Usb, c, PairWith::Label(&label), "x");
        assert_eq!(
            close_of(&b.msg(4.0, c, &junk), c),
            Some(CloseReason::BadMsg3)
        );
        c += 1;
    }
    assert!(b.trust_phone().is_none());
}

#[test]
fn the_phone_refuses_a_bad_message_2() {
    let radio = Identity::generate().unwrap();
    let label = LabelCode::new(*radio.public_key()).unwrap();
    for junk in [
        vec![],
        vec![0u8; MIN_MSG2],
        vec![0u8; MAX_MSG2 + 1],
        vec![7u8; 100],
    ] {
        let (p, _) = phone(PairWith::Label(&label), "phone");
        assert!(p.finish(&junk).is_err());
    }
    // A message 2 with no link key field (an R-SEC1 drone's hello only).
    let (p, m1) = phone(PairWith::Label(&label), "phone");
    let mut o = radio_open_msg1(&radio, label.secret(), &m1).unwrap();
    let mut buf = [0u8; 200];
    let n =
        o.hs.write_message(&[0x01, 2, b'd', b'r', 0, 0], &mut buf)
            .unwrap();
    assert!(p.finish(&buf[..n]).is_err());
}

#[test]
fn a_store_failure_stops_the_radio_until_it_boots() {
    let mut b = Bench::window();
    let label = b.label.clone();
    let (p, m2) = b.reach_msg2(3.0, Transport::Usb, 1, PairWith::Label(&label), "o");
    let done = p.finish(&m2).unwrap();
    b.crash_after(0);
    b.msg(3.1, 1, &done.msg3);
    assert!(b.r.status(s(3.1)).faulted);
    b.open(4.0, Transport::Usb, 2);
    let v = b.msg(4.0, 2, &[0u8; 100]);
    assert!(has(&v, |a| matches!(
        a,
        Action::NoReply {
            why: NoReplyReason::Faulted,
            ..
        }
    )));
    assert_eq!(
        b.pair_open(5.0, done.radio_link_key.public_key(), &random_secret())
            .0,
        Err(PairOpenRefused::Faulted)
    );
    b.usb(6.0, false);
    b.usb(20.0, true);
    assert!(b.poll(30.0).is_empty());
}

#[test]
fn debug_output_shows_no_secret() {
    let (mut b, old) = Bench::paired();
    let label_text = b.label.encode();
    let secret_b32 = &label_text[7 + 53..7 + 100];
    let secret = random_secret();
    b.pair_open(10.0, old.radio_link_key.public_key(), &secret)
        .0
        .unwrap();
    let rc = ReplaceCode::from_secret(*b.label.pairing_public(), &secret).unwrap();
    let (p, m2) = b.reach_msg2(11.0, Transport::Ble, 1, PairWith::Replace(&rc), "n");
    let shown_pairing = format!("{p:?}");
    let done = p.finish(&m2).unwrap();
    let saved = b.flash.borrow().trust.clone().unwrap();
    let shown = [
        format!("{:?}", b.r),
        format!("{rc:?}"),
        format!("{done:?}"),
        shown_pairing,
        format!(
            "{:?}",
            SavedPhone {
                phone_public: saved.0,
                name: Name::new(&saved.1).unwrap(),
                link_private: Zeroizing::new(saved.2),
            }
        ),
        format!("{:?}", b.msg(12.0, 1, &done.msg3)),
    ];
    let hexes = [
        data_encoding::HEXLOWER.encode(&secret),
        data_encoding::HEXLOWER.encode(&saved.2),
        data_encoding::HEXLOWER.encode(b.label.secret()),
        data_encoding::HEXLOWER.encode(done.radio_link_key.private_key()),
    ];
    // On failure, name which output leaked, never the output itself (it
    // would print the secret).
    for (i, text) in shown.iter().enumerate() {
        assert!(!text.contains(secret_b32), "output {i} shows the label");
        for h in &hexes {
            assert!(!text.contains(&h[..16]), "output {i} shows a secret");
        }
        // Debug of a byte array prints decimals: look for the first bytes.
        for k in [secret, saved.2, *b.label.secret()] {
            let dec = format!("{}, {}, {}, {}", k[0], k[1], k[2], k[3]);
            assert!(!text.contains(&dec), "output {i} shows a secret");
        }
    }
}

#[test]
fn next_wakeup_names_the_earliest_timer() {
    let mut b = Bench::boot(true);
    assert_eq!(b.r.next_wakeup(), Some(s(2.0)));
    b.poll(2.0);
    assert_eq!(b.r.next_wakeup(), Some(s(122.0)));
    b.open(3.0, Transport::Usb, 1);
    assert_eq!(b.r.next_wakeup(), Some(s(6.0)));
}

// ---- review findings (docs/security-review-t-msg1-phone-pairing-code.md) ----

/// Run `f` on a radio, with a write error (not a power loss) at store
/// operation `k` from now; return the actions.
fn with_write_error(
    b: &mut Bench,
    k: usize,
    f: impl FnOnce(&mut Bench) -> Vec<Action>,
) -> Vec<Action> {
    {
        let mut fl = b.flash.borrow_mut();
        fl.error_at = Some(fl.ops + k);
    }
    let v = f(b);
    b.flash.borrow_mut().error_at = None;
    v
}

/// A faulted radio refuses every link session and every pairing.
fn assert_fails_closed(b: &mut Bench, t: f64) {
    assert!(b.r.status(s(t)).faulted);
    assert!(!b.r.status(s(t)).paired);
    assert!(b.link_peer().is_none(), "no link session while faulted");
    let label = b.label.clone();
    b.open(t, Transport::Usb, 900);
    let (_, m1) = phone(PairWith::Label(&label), "x");
    let v = b.msg(t, 900, &m1);
    assert!(has(&v, |a| matches!(
        a,
        Action::NoReply {
            why: NoReplyReason::Faulted,
            ..
        }
    )));
    assert!(b.r.next_wakeup().is_none());
}

#[test]
fn c1_a_write_error_at_each_step_of_a_reset_fails_closed_and_the_pin_retries() {
    // Reset writes: marker, erase, trust (none), clear marker.
    for k in 0..4 {
        let (mut b, old) = Bench::paired();
        let old_pub = *old.radio_link_key.public_key();
        let v = with_write_error(&mut b, k, |b| b.reset(10.0));
        assert!(has(&v, |a| matches!(a, Action::StoreFailed)), "k={k}");
        assert!(has(&v, |a| matches!(a, Action::EndAllSessions)));
        assert!(!has(&v, |a| matches!(a, Action::ResetDone)));
        // The flash may still hold the old phone (k < 3); the link gets
        // nothing either way.
        assert_fails_closed(&mut b, 11.0);
        // The pinhole keeps working: a retry finishes the reset.
        let v = b.reset(12.0);
        assert!(has(&v, |a| matches!(a, Action::ResetDone)), "k={k}");
        assert!(!b.r.status(s(12.0)).faulted);
        assert!(b.link_peer().is_none());
        assert!(b.trust_phone().is_none());
        assert!(b.flash.borrow().owner_state.is_none());
        // On USB power, its window opens 2 s later.
        assert!(opened(&b.poll(14.0), WindowKind::Usb));
        // The old phone is refused.
        assert_eq!(
            b.pair_open(15.0, &old_pub, &random_secret()).0,
            Err(PairOpenRefused::NotThePairedPhone)
        );
    }
}

#[test]
fn c1_a_write_error_during_a_reset_then_a_boot_without_the_pin() {
    // If the owner does not retry, the boot follows the flash: before the
    // marker landed nothing began (the old phone stays, spec question 2);
    // after it, the boot finishes the reset.
    for k in 0..4 {
        let (mut b, old) = Bench::paired();
        let old_pub = *old.radio_link_key.public_key();
        with_write_error(&mut b, k, |b| b.reset(10.0));
        b.reboot(0.0, false);
        assert_invariant(&b);
        if k == 0 {
            assert_eq!(b.link_peer(), Some(old_pub));
        } else {
            assert!(b.link_peer().is_none(), "k={k}");
            assert!(b.flash.borrow().owner_state.is_none());
        }
    }
}

#[test]
fn c1_a_write_error_at_each_step_of_a_replace_fails_closed() {
    // Replace writes: marker, erase, trust, clear marker.
    for k in 0..4 {
        let (mut b, old) = Bench::paired();
        let old_pub = *old.radio_link_key.public_key();
        let secret = random_secret();
        b.pair_open(10.0, &old_pub, &secret).0.unwrap();
        let rc = ReplaceCode::from_secret(*b.label.pairing_public(), &secret).unwrap();
        let (p, m2) = b.reach_msg2(11.0, Transport::Ble, 1, PairWith::Replace(&rc), "new");
        let new = p.finish(&m2).unwrap();
        let v = with_write_error(&mut b, k, |b| b.msg(11.5, 1, &new.msg3));
        assert!(has(&v, |a| matches!(a, Action::StoreFailed)), "k={k}");
        assert!(paired_in(&v).is_none());
        // Neither the old phone (perhaps still in flash) nor the new one
        // gets a link session.
        assert_fails_closed(&mut b, 12.0);
        assert_eq!(
            b.pair_open(12.5, &old_pub, &random_secret()).0,
            Err(PairOpenRefused::Faulted)
        );
        // The pin clears it: unpaired and empty.
        assert!(has(&b.reset(13.0), |a| matches!(a, Action::ResetDone)));
        assert!(b.link_peer().is_none());
        assert!(b.trust_phone().is_none());
        assert!(b.flash.borrow().owner_state.is_none());
        assert_invariant(&b);
    }
}

#[test]
fn c1_a_write_error_in_a_first_pairing_fails_closed() {
    // A first pairing writes the trust state, then clears a non-zero count.
    for k in 0..2 {
        let mut b = Bench::boot(false);
        // One window closed with no pairing, so the count is 1 and the
        // pairing has a second write to make.
        b.usb(10.0, true);
        assert!(opened(&b.poll(12.0), WindowKind::Usb));
        assert!(expired(&b.poll(132.0)));
        b.usb(140.0, false);
        b.usb(150.0, true);
        assert!(opened(&b.poll(152.0), WindowKind::Usb));
        let label = b.label.clone();
        let (p, m2) = b.reach_msg2(153.0, Transport::Usb, 1, PairWith::Label(&label), "o");
        let done = p.finish(&m2).unwrap();
        let v = with_write_error(&mut b, k, |b| b.msg(153.5, 1, &done.msg3));
        assert!(has(&v, |a| matches!(a, Action::StoreFailed)), "k={k}");
        assert!(paired_in(&v).is_none());
        assert_fails_closed(&mut b, 154.0);
        assert!(has(&b.reset(155.0), |a| matches!(a, Action::ResetDone)));
        assert!(b.trust_phone().is_none());
        assert_eq!(b.flash.borrow().rate_count, 0);
        assert!(opened(&b.poll(157.0), WindowKind::Usb));
    }
}

#[test]
fn c1_a_failed_reset_retry_stays_faulted_and_a_read_error_faults_too() {
    let (mut b, _) = Bench::paired();
    with_write_error(&mut b, 0, |b| b.reset(10.0));
    let v = with_write_error(&mut b, 1, |b| b.reset(11.0));
    assert!(has(&v, |a| matches!(a, Action::StoreFailed)));
    assert_fails_closed(&mut b, 12.0);
    assert!(has(&b.reset(13.0), |a| matches!(a, Action::ResetDone)));

    // A trust read that fails when the link asks: fail closed.
    let (mut b, _) = Bench::paired();
    b.flash.borrow_mut().reads_fail = true;
    let mut v = vec![];
    assert!(b.r.link_peer(&mut |a| v.push(a)).is_none());
    assert!(has(&v, |a| matches!(a, Action::StoreFailed)));
    b.flash.borrow_mut().reads_fail = false;
    assert!(b.link_peer().is_none(), "still faulted");
    // A boot whose reads fail starts faulted.
    b.flash.borrow_mut().reads_fail = true;
    let v = b.boot_again(0.0, true);
    assert!(has(&v, |a| matches!(a, Action::StoreFailed)));
    b.flash.borrow_mut().reads_fail = false;
    assert_fails_closed(&mut b, 3.0);
}

#[test]
fn c4_a_usb_host_replaying_a_recorded_message_1_shuts_ble_for_that_window_only() {
    let mut b = Bench::window();
    let label = b.label.clone();
    // Recorded over BLE in the first window.
    b.open(13.0, Transport::Ble, 1);
    let (_p, rec) = phone(PairWith::Label(&label), "owner");
    assert!(msg2_for(&b.msg(13.0, 1, &rec), 1).is_some());
    assert!(expired(&b.poll(122.0)));
    // A second window: a hostile USB host replays it at once.
    b.usb(125.0, false);
    b.usb(140.0, true);
    assert!(opened(&b.poll(142.0), WindowKind::Usb));
    b.open(143.0, Transport::Usb, 2);
    assert!(msg2_for(&b.msg(143.0, 2, &rec), 2).is_some());
    for t in [152.0, 162.0, 200.0, 261.0] {
        assert!(!b.r.status(s(t)).ble_open, "{t}");
    }
    assert!(expired(&b.poll(262.0)));
    // The next window (a reset on USB) has its normal BLE rule.
    b.reset(270.0);
    assert!(opened(&b.poll(272.0), WindowKind::Usb));
    assert!(!b.r.status(s(281.9)).ble_open);
    assert!(b.r.status(s(282.0)).ble_open);
    b.pair(282.0, Transport::Ble, 3, PairWith::Label(&label), "owner");
}

#[test]
fn c5_a_flood_between_connect_and_message_1_is_bounded_and_the_owner_retries() {
    let mut b = Bench::window();
    let label = b.label.clone();
    // The owner opens a USB pairing channel; a flood follows before its
    // message 1 is sent.
    b.open(3.0, Transport::Usb, 1);
    let mut displaced = 0;
    let mut c = 100;
    for i in 0..20 {
        let v = b.open(3.0 + 0.01 * i as f64, Transport::Usb, c);
        displaced += v
            .iter()
            .filter(|a| {
                matches!(
                    a,
                    Action::Close {
                        why: CloseReason::Displaced,
                        ..
                    }
                )
            })
            .count();
        assert!(v.len() <= 1, "one channel in, at most one out");
        c += 1;
    }
    // Bounded: at most 2 live attempts (the slots), so 19 of the 21 went.
    assert_eq!(displaced, 19);
    // The owner's message 1 on its displaced channel gets nothing...
    let (_, m1) = phone(PairWith::Label(&label), "owner");
    assert!(no_reply(&b.msg(3.3, 1, &m1), 1));
    // ...and its retry, message 1 at once on a new channel, proves the
    // secret before the next flood channel; the flood then cannot end it.
    b.open(3.4, Transport::Usb, 2);
    let (p, m1) = phone(PairWith::Label(&label), "owner");
    let m2 = msg2_for(&b.msg(3.4, 2, &m1), 2).unwrap();
    for i in 0..20 {
        let v = b.open(3.5 + 0.01 * i as f64, Transport::Usb, c);
        assert!(close_of(&v, 2).is_none());
        c += 1;
    }
    let done = p.finish(&m2).unwrap();
    assert!(paired_in(&b.msg(4.0, 2, &done.msg3)).is_some());
}

#[test]
fn c6_radio_keys_refuse_an_all_zero_label_secret() {
    let id = Identity::generate().unwrap();
    let zero = LabelCode::with_secret(*id.public_key(), [0u8; 32]);
    assert!(RadioKeys::new(id, &zero).is_err());
}

#[test]
fn c7_pair_open_with_the_label_secret_is_refused() {
    let (mut b, old) = Bench::paired();
    let label_secret = *b.label.secret();
    let (r, v) = b.pair_open(10.0, old.radio_link_key.public_key(), &label_secret);
    assert_eq!(r, Err(PairOpenRefused::LabelSecret));
    assert!(v.is_empty());
    assert!(b.r.status(s(10.0)).window.is_none());
    // One bit off is a different secret, and accepted.
    let mut near = label_secret;
    near[31] ^= 1;
    b.pair_open(11.0, old.radio_link_key.public_key(), &near)
        .0
        .unwrap();
}

#[test]
fn c8_pairing_channels_in_a_replace_window_never_touch_the_old_phones_link() {
    let (mut b, old) = Bench::paired();
    let old_pub = *old.radio_link_key.public_key();
    b.pair_open(10.0, &old_pub, &random_secret()).0.unwrap();
    // A flood of pairing channels, idle, displaced and timing out: the old
    // phone's link (not a pairing channel, never seen here) stays.
    for c in 0..30 {
        let v = b.open(10.0 + 0.1 * c as f64, Transport::Ble, 500 + c);
        assert!(!has(&v, |a| matches!(a, Action::EndAllSessions)));
    }
    b.poll(20.0);
    assert_eq!(b.link_peer(), Some(old_pub));
    assert!(b.r.status(s(20.0)).paired);
}

#[test]
fn c9_message_3_must_be_exactly_the_confirm_byte() {
    for payload in [&[0x04u8][..], &[0x03, 0x00][..], &[][..]] {
        let mut b = Bench::window();
        let label = b.label.clone();
        let (p, m2) = b.reach_msg2(3.0, Transport::Usb, 1, PairWith::Label(&label), "o");
        let bad = p.finish_with_payload(&m2, payload).unwrap();
        let v = b.msg(3.5, 1, &bad.msg3);
        assert_eq!(close_of(&v, 1), Some(CloseReason::BadMsg3), "{payload:?}");
        assert!(paired_in(&v).is_none());
        assert!(b.trust_phone().is_none());
    }
}

#[test]
fn c9_the_phone_requires_the_link_key_tag() {
    let radio = Identity::generate().unwrap();
    let label = LabelCode::new(*radio.public_key()).unwrap();
    let link = *Identity::generate().unwrap().public_key();
    for tag in [0x05u8, 0x07, 0x00] {
        let (p, m1) = phone(PairWith::Label(&label), "phone");
        let mut o = radio_open_msg1(&radio, label.secret(), &m1).unwrap();
        let mut payload = vec![0x01, 2, b'r', b'1', tag];
        payload.extend_from_slice(&link);
        let mut buf = [0u8; 200];
        let n = o.hs.write_message(&payload, &mut buf).unwrap();
        assert!(p.finish(&buf[..n]).is_err(), "tag {tag:#x}");
    }
}

/// A message 1 from a real initiator with any hello payload.
fn msg1_with_payload(label: &LabelCode, payload: &[u8]) -> Vec<u8> {
    let me = Identity::generate().unwrap();
    let mut hs = snow::Builder::new(crate::PAIRING_NOISE.parse().unwrap())
        .local_private_key(me.private_key())
        .unwrap()
        .remote_public_key(label.pairing_public())
        .unwrap()
        .psk(1, label.secret())
        .unwrap()
        .prologue(crate::PHONE_PAIRING_PROLOGUE)
        .unwrap()
        .build_initiator()
        .unwrap();
    let mut out = vec![0u8; 400];
    let n = hs.write_message(payload, &mut out).unwrap();
    out.truncate(n);
    out
}

#[test]
fn c9_message_1_size_limits_are_checked_before_decrypting() {
    let mut b = Bench::window();
    let label = b.label.clone();
    // Too long (a 40-byte hello) and too short (no hello): each would
    // decrypt, so only the size check gives Msg1Failed.
    let mut long = vec![0x01, 40];
    long.extend_from_slice(&[b'a'; 40]);
    let too_long = msg1_with_payload(&label, &long);
    assert!(too_long.len() > MAX_MSG1);
    let too_short = msg1_with_payload(&label, &[]);
    assert!(too_short.len() < MIN_MSG1);
    for (c, m) in [(1, too_long), (2, too_short)] {
        b.open(3.0, Transport::Usb, c);
        let v = b.msg(3.0, c, &m);
        assert_eq!(close_of(&v, c), Some(CloseReason::Msg1Failed));
        assert!(msg2_for(&v, c).is_none());
    }
}

#[test]
fn c9_a_reset_on_battery_opens_no_window_of_its_own() {
    // Plugged in 1 s after a reset on battery: the window comes from the
    // debounce (2 s after the plug), not from the reset (2 s after it).
    let (mut b, _) = Bench::paired();
    b.usb(5.0, false);
    b.reset(20.0);
    b.usb(21.0, true);
    assert!(b.poll(22.5).is_empty());
    assert!(opened(&b.poll(23.0), WindowKind::Usb));
}

#[test]
fn c11_time_going_backwards_or_near_the_end_never_panics() {
    let mut b = Bench::window(); // opened at 2 s
    let label = b.label.clone();
    // An earlier time is no progress: nothing re-opens, nothing expires.
    assert!(b.poll(1.0).is_empty());
    assert!(b.usb(0.5, false).is_empty());
    assert!(b.r.status(s(0.0)).window.is_some());
    b.open(1.0, Transport::Usb, 1);
    let (_, m1) = phone(PairWith::Label(&label), "o");
    assert!(msg2_for(&b.msg(0.0, 1, &m1), 1).is_some());
    // Message 3's 6 s run from the latest time seen (2 s), not from 0.
    assert!(close_of(&b.poll(7.9), 1).is_none());
    assert_eq!(close_of(&b.poll(8.0), 1), Some(CloseReason::Msg3Timeout));
    // Times at the end of the range saturate.
    let mut v = vec![];
    b.r.poll(Duration::MAX, &mut |a| v.push(a));
    assert!(expired(&v));
    b.r.usb_power(Duration::MAX, true, &mut |_| {});
    b.r.pinhole_reset(Duration::MAX, &mut |_| {});
    b.r.poll(Duration::MAX, &mut |_| {});
    let _ = b.r.next_wakeup();
    let _ = b.r.status(Duration::MAX);
}

#[test]
fn c13_waking_from_storage_by_usb_counts_as_absent_long_enough() {
    let mut b = Bench::boot(true);
    assert!(opened(&b.poll(2.0), WindowKind::Usb));
    assert!(expired(&b.poll(122.0)));
    // In storage mode a short unplug and plug opens a window.
    b.r.enter_storage(s(130.0), &mut |_| {});
    b.usb(130.0, false);
    b.usb(131.0, true);
    assert!(opened(&b.poll(133.0), WindowKind::Usb));
    // Without storage mode the same short gap opens nothing.
    assert!(expired(&b.poll(253.0)));
    b.usb(260.0, false);
    b.usb(261.0, true);
    assert!(b.poll(270.0).is_empty());
}

#[test]
fn c13_a_battery_boot_counts_usb_absence_from_the_boot() {
    let mut b = Bench::boot(false);
    b.usb(5.0, true); // 5 s after the boot: not an edge
    assert!(b.poll(20.0).is_empty());
    b.usb(20.0, false);
    b.usb(30.0, true); // 10 s absent
    assert!(b.poll(31.9).is_empty());
    assert!(opened(&b.poll(32.0), WindowKind::Usb));
}

#[test]
fn a_failed_random_source_pairs_nobody() {
    let mut b = Bench::window();
    let label = b.label.clone();
    b.entropy.0.set(true);
    b.open(3.0, Transport::Usb, 1);
    let (_, m1) = phone(PairWith::Label(&label), "o");
    let v = b.msg(3.0, 1, &m1);
    assert_eq!(close_of(&v, 1), Some(CloseReason::EntropyFailed));
    assert!(msg2_for(&v, 1).is_none());
    // The phone side refuses to start too.
    let failed = TestEntropy::default();
    failed.0.set(true);
    assert!(PhonePairing::start(PairWith::Label(&label), "o", &mut failed.clone()).is_err());
    // Once the source works again, pairing does.
    b.entropy.0.set(false);
    b.pair(4.0, Transport::Usb, 2, PairWith::Label(&label), "o");
}

#[test]
fn c12_the_pair_open_body_from_a_replace_code_opens_its_window() {
    let (mut b, old) = Bench::paired();
    let rc = ReplaceCode::new(*b.label.pairing_public()).unwrap();
    let body = rc.pair_open_body();
    b.pair_open(10.0, old.radio_link_key.public_key(), body.secret())
        .0
        .unwrap();
    let new = b.pair(11.0, Transport::Ble, 1, PairWith::Replace(&rc), "new");
    assert_eq!(b.link_peer(), Some(*new.radio_link_key.public_key()));
}
