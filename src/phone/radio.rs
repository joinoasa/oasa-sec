//! The radio's side of phone pairing: a sans-IO, deterministic state machine
//! (spec sections 2.3 to 2.8).
//!
//! Every input carries the time `now`, a monotonic [`Duration`] since any
//! fixed start that never goes backwards. The machine reads no clock, opens
//! no socket, starts no thread and prints nothing. What it does goes out
//! through a sink (`FnMut(Action)`), and what it keeps goes into a
//! [`RadioStore`] the firmware implements.
//!
//! **Allocation.** The machine itself keeps fixed arrays: one per transport
//! for attempts (`BLE` and `USB` slots, const parameters), 16 entries for the
//! record of message 1s, names in fixed buffers, message 2 in a fixed buffer.
//! The one place it allocates is inside `snow`: each attempt's
//! `HandshakeState` and `TransportState` live on `snow`'s heap. A `no_std`
//! build would need `alloc` for `snow`, or a different Noise library, which
//! is a crypto dependency change and needs owner approval (AGENTS.md).
//!
//! **Randomness.** Link keys come from the [`Entropy`] passed in. `snow`
//! draws each Noise ephemeral key from its own resolver (the operating
//! system), exactly as the link does; so the machine is deterministic in
//! everything but those ephemeral keys.

use std::time::Duration;

use snow::TransportState;
use zeroize::Zeroizing;

use super::handshake::{
    MAX_MSG2, new_key, radio_check_msg1, radio_open_msg1, radio_read_msg3, radio_write_msg2,
};
use super::{
    BLE_AFTER_HOST, BLE_AFTER_NO_HOST, LabelCode, MSG1_WITHIN, MSG3_WITHIN, Name, RATE_LIMIT_WAIT,
    RATE_LIMIT_WINDOWS, RESET_WINDOW_DELAY, SEEN_RECORD, USB_ABSENT, USB_PRESENT, WINDOW, all_zero,
};
use crate::identity::Identity;
use crate::link::Entropy;
use crate::{Error, Result};

/// A transport connection, named by the transport layer. It must be unique
/// among open connections.
pub type ConnId = u32;

/// The two transports (spec section 2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Ble,
    Usb,
}

/// The kind of an open pairing window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowKind {
    /// Opened by USB power while unpaired, or by a reset on USB power. Its
    /// psk is the label secret.
    Usb,
    /// Opened by `PAIR_OPEN` from the paired phone. Its psk is that
    /// message's one-time secret, and only that.
    Replace,
}

/// Why the radio ended a pairing attempt. In every case the attempt gets no
/// reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    /// A new connection needed the slot and this attempt had not proved the
    /// secret.
    Displaced,
    /// Every slot on the transport holds a proved attempt: the new
    /// connection is refused.
    SlotsFull,
    /// No message 1 within 3 s of connecting.
    Msg1Timeout,
    /// No message 3 within 6 s of message 2.
    Msg3Timeout,
    /// Message 1 failed: wrong secret, wrong size, or it did not decrypt.
    Msg1Failed,
    /// Message 1 proved the secret, but its ephemeral key is in the record
    /// of this window (a replay).
    Msg1Replay,
    /// Message 1 proved the secret, but its hello or the phone's key is bad
    /// (for example a small-order key).
    Msg1Refused,
    /// A message after message 2 that is not a valid message 3 (including a
    /// second message 1).
    BadMsg3,
    /// A proving message 1 arrived on USB: BLE attempts end (section 2.5).
    PreemptedByUsb,
    /// Another attempt completed.
    OtherCompleted,
    /// The window closed (2 minutes).
    WindowClosed,
    /// Pinhole reset.
    Reset,
    /// The store failed; the radio stops until it boots again.
    StoreFailed,
}

/// Why a pairing message got no reply and made no attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoReplyReason {
    /// The connection is not a pairing attempt: no window was open when it
    /// connected, BLE was not open yet, or its attempt already ended.
    NotAnAttempt,
    /// The radio's store failed; it ignores everything until it boots.
    Faulted,
}

/// A message 2, in a fixed buffer.
#[derive(Clone)]
pub struct Msg2 {
    buf: [u8; MAX_MSG2],
    len: usize,
}

impl Msg2 {
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl std::fmt::Debug for Msg2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Msg2({} bytes)", self.len)
    }
}

/// What the radio does, handed to the sink in order.
#[derive(Debug, Clone)]
pub enum Action {
    /// Send message 2 on this connection.
    Send { conn: ConnId, msg2: Msg2 },
    /// End the pairing attempt on this connection, with no reply. On USB
    /// that is closing the TCP connection to the pairing port. On BLE the
    /// firmware ends the attempt, and closes the connection unless it has
    /// completed a link handshake (that is the link layer's, spec section 3).
    Close { conn: ConnId, why: CloseReason },
    /// A pairing message got no reply and was counted as a drop.
    NoReply { conn: ConnId, why: NoReplyReason },
    /// A window opened.
    WindowOpened { kind: WindowKind },
    /// A window closed with no pairing (2 minutes passed).
    WindowExpired { kind: WindowKind },
    /// A phone completed and is saved as the radio's one peer. Its link
    /// session may start on `conn`.
    Paired {
        conn: ConnId,
        phone_public: [u8; 32],
        replaced: bool,
    },
    /// End every link session at once (reset, replace).
    EndAllSessions,
    /// Wipe every held packet in memory (reset, replace).
    WipeHeldPackets,
    /// Pick a new Bluetooth address (reset, replace; spec section 7).
    NewBluetoothAddress,
    /// The pinhole reset is done (in memory and in the store).
    ResetDone,
    /// A store write failed. The radio has stopped: it ignores every input
    /// until it boots again, and the boot finishes the work (section 2.8).
    StoreFailed,
}

/// The operation a marker says is running (spec section 2.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Marker {
    Reset,
    Replace,
}

/// The radio's one paired phone, as stored: its radio-link public key and
/// name, and the radio's link key for it. The link private key is wiped
/// when dropped and never shown by `Debug`.
pub struct SavedPhone {
    pub phone_public: [u8; 32],
    pub name: Name,
    pub link_private: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for SavedPhone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SavedPhone")
            .field("phone", &crate::identity::fingerprint(&self.phone_public))
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// A store operation failed (for example the power went).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreFailed;

/// The radio's flash, as the pairing logic sees it. The firmware implements
/// it; tests implement it with one that can lose power at any step.
///
/// Requirements on an implementation (spec section 2.8):
///
/// - [`write_trust`](Self::write_trust) is **one atomic change**: after a
///   power loss the store holds either the old trust state or the new one.
/// - "Erase" means **gone from flash**: after [`erase_owner_state`]
///   (Self::erase_owner_state) and `write_trust`, no readable copy of the
///   erased items remains anywhere (page erase, or forced clean-up of a
///   log-structured store), before the call returns.
/// - The marker survives power loss once `set_marker` returns.
/// - The pairing key and the pairing secret are never touched by any of
///   these.
pub trait RadioStore {
    /// The marker, if a reset or replace was running.
    fn marker(&mut self) -> std::result::Result<Option<Marker>, StoreFailed>;
    fn set_marker(&mut self, m: Marker) -> std::result::Result<(), StoreFailed>;
    fn clear_marker(&mut self) -> std::result::Result<(), StoreFailed>;
    /// Erase the owner state **other than the trust state**: every saved
    /// handshake timestamp, the wake filters and owner-set settings (and any
    /// other owner state a later part adds).
    fn erase_owner_state(&mut self) -> std::result::Result<(), StoreFailed>;
    /// The trust state: the one paired phone and the radio's link key, or
    /// none.
    fn trust(&mut self) -> std::result::Result<Option<SavedPhone>, StoreFailed>;
    /// Replace the trust state in one atomic change; `None` erases it.
    fn write_trust(&mut self, t: Option<&SavedPhone>) -> std::result::Result<(), StoreFailed>;
}

/// The radio's own keys: the pairing key and the label secret. Both are
/// kept for the radio's whole life; the secret is wiped from memory when
/// dropped and never shown by `Debug`.
pub struct RadioKeys {
    pairing: Identity,
    label_secret: Zeroizing<[u8; 32]>,
}

impl RadioKeys {
    /// The radio's pairing key and the label made for it. Refuses a label
    /// for a different key.
    pub fn new(pairing: Identity, label: &LabelCode) -> Result<Self> {
        if label.pairing_public() != pairing.public_key() {
            return Err(Error::Protocol("the label was made for a different radio"));
        }
        Ok(Self {
            pairing,
            label_secret: Zeroizing::new(*label.secret()),
        })
    }

    pub fn pairing_public(&self) -> &[u8; 32] {
        self.pairing.public_key()
    }
}

impl std::fmt::Debug for RadioKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RadioKeys")
            .field("pairing", &self.pairing.fingerprint())
            .finish_non_exhaustive()
    }
}

/// What the radio shows (the light and `STATUS` are built from this).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Status {
    pub paired: bool,
    pub window: Option<WindowKind>,
    /// In a window: whether a new BLE connection becomes a pairing attempt.
    pub ble_open: bool,
    /// Unpaired, no window, and the next USB window needs 30 minutes and a
    /// new USB edge (or a reset).
    pub rate_limited: bool,
    /// A store write failed and the radio waits for a boot.
    pub faulted: bool,
}

struct Window {
    kind: WindowKind,
    opened: Duration,
    /// The psk: the label secret (USB window) or the replace secret.
    psk: Zeroizing<[u8; 32]>,
    /// A USB host had enumerated the radio by 10 s into the window.
    host_by_10s: bool,
    /// A proving message 1 arrived on USB: BLE is shut for the window.
    usb_proved: bool,
    /// An attempt proved the secret and then ended by something other than
    /// its own 6 s timeout: the window does not count toward the rate limit.
    spared: bool,
}

impl Window {
    fn ble_open(&self, now: Duration) -> bool {
        match self.kind {
            // A replace window has no USB rules.
            WindowKind::Replace => true,
            WindowKind::Usb => {
                !self.usb_proved
                    && (now >= self.opened + BLE_AFTER_HOST
                        || (now >= self.opened + BLE_AFTER_NO_HOST && !self.host_by_10s))
            }
        }
    }
}

// Each slot holds its attempt's whole state in place, so the fixed array of
// slots needs no allocation of its own; the unused size of an idle slot is
// the price (the spec bounds an attempt at under 1 kB).
#[allow(clippy::large_enum_variant)]
enum Stage {
    AwaitMsg1,
    AwaitMsg3 {
        due: Duration,
        transport: TransportState,
        /// This attempt's link key, in memory only; wiped on drop.
        link_key: Identity,
        phone_public: [u8; 32],
        phone_name: Name,
    },
}

struct Attempt {
    conn: ConnId,
    opened: Duration,
    stage: Stage,
}

impl Attempt {
    fn proved(&self) -> bool {
        matches!(self.stage, Stage::AwaitMsg3 { .. })
    }
    fn due(&self) -> Duration {
        match &self.stage {
            Stage::AwaitMsg1 => self.opened + MSG1_WITHIN,
            Stage::AwaitMsg3 { due, .. } => *due,
        }
    }
}

/// The ephemeral keys of the last [`SEEN_RECORD`] message 1s that proved
/// the secret in this window, oldest forgotten first.
struct Seen {
    keys: [[u8; 32]; SEEN_RECORD],
    len: usize,
    next: usize,
}

impl Seen {
    const fn new() -> Self {
        Self {
            keys: [[0u8; 32]; SEEN_RECORD],
            len: 0,
            next: 0,
        }
    }
    fn contains(&self, k: &[u8; 32]) -> bool {
        self.keys[..self.len].iter().any(|s| s == k)
    }
    fn insert(&mut self, k: [u8; 32]) {
        self.keys[self.next] = k;
        self.next = (self.next + 1) % SEEN_RECORD;
        self.len = (self.len + 1).min(SEEN_RECORD);
    }
    fn clear(&mut self) {
        *self = Self::new();
    }
}

/// USB power as the debounce sees it.
struct Usb {
    present: bool,
    /// When `present` last changed.
    since: Duration,
    /// The current presence followed an absence of at least 10 s (or a
    /// start from no power, or storage mode) and has not fired yet.
    armed: bool,
    /// The radio was put in storage mode: the next presence is armed.
    storage: bool,
    /// A USB host has configured the radio during the current presence.
    enumerated: bool,
}

struct Rate {
    /// USB windows in a row that closed with no pairing and counted.
    failed: u8,
    last_close: Option<Duration>,
}

/// The radio's pairing logic. `BLE` and `USB` are the pairing slot counts
/// (`BLE_PAIRING_SLOTS`, `USB_PAIRING_SLOTS`; the firmware card fixes them).
pub struct Radio<S: RadioStore, E: Entropy, const BLE: usize, const USB: usize> {
    keys: RadioKeys,
    name: Name,
    store: S,
    entropy: E,
    /// The paired phone's radio-link public key (the trust state's).
    paired: Option<[u8; 32]>,
    usb: Usb,
    window: Option<Window>,
    ble: [Option<Attempt>; BLE],
    usb_slots: [Option<Attempt>; USB],
    seen: Seen,
    rate: Rate,
    /// A reset on USB power opens a USB window at this time.
    reset_window_at: Option<Duration>,
    faulted: bool,
}

impl<S: RadioStore, E: Entropy, const BLE: usize, const USB: usize> Radio<S, E, BLE, USB> {
    /// Start the radio from no power. If the store holds a marker, the boot
    /// first finishes the erase it names (spec section 2.8): after a reset
    /// marker the radio is unpaired and empty; after a replace marker the
    /// owner state is erased and whatever peer the trust state holds stays.
    /// `usb_present`: USB power at start (a start from no power counts as
    /// USB having been absent).
    pub fn boot(
        keys: RadioKeys,
        name: Name,
        mut store: S,
        entropy: E,
        now: Duration,
        usb_present: bool,
    ) -> std::result::Result<Self, StoreFailed> {
        assert!(
            BLE > 0 && USB > 0,
            "each transport needs at least one pairing slot"
        );
        if let Some(m) = store.marker()? {
            store.erase_owner_state()?;
            if m == Marker::Reset {
                store.write_trust(None)?;
            }
            store.clear_marker()?;
        }
        let paired = store.trust()?.map(|t| t.phone_public);
        Ok(Self {
            keys,
            name,
            store,
            entropy,
            paired,
            usb: Usb {
                present: usb_present,
                since: now,
                armed: usb_present,
                storage: false,
                enumerated: false,
            },
            window: None,
            ble: std::array::from_fn(|_| None),
            usb_slots: std::array::from_fn(|_| None),
            seen: Seen::new(),
            rate: Rate {
                failed: 0,
                last_close: None,
            },
            reset_window_at: None,
            faulted: false,
        })
    }

    /// The store, for tests and for the firmware's link layer to read the
    /// trust state.
    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn status(&self, now: Duration) -> Status {
        Status {
            paired: self.paired.is_some(),
            window: self.window.as_ref().map(|w| w.kind),
            ble_open: self.window.as_ref().is_some_and(|w| w.ble_open(now)),
            rate_limited: self.paired.is_none()
                && self.window.is_none()
                && self.rate.failed >= RATE_LIMIT_WINDOWS,
            faulted: self.faulted,
        }
    }

    /// The paired phone's radio-link public key, if any.
    pub fn paired_phone(&self) -> Option<&[u8; 32]> {
        self.paired.as_ref()
    }

    /// When [`poll`](Self::poll) next has something to do, if ever.
    pub fn next_wakeup(&self) -> Option<Duration> {
        self.next_due().map(|(t, _)| t)
    }

    /// Run the timers due by `now`. Every other input does this first.
    pub fn poll(&mut self, now: Duration, out: &mut impl FnMut(Action)) {
        if self.faulted {
            return;
        }
        while let Some((t, what)) = self.next_due() {
            if t > now {
                break;
            }
            match what {
                Due::UsbEdge => {
                    self.usb.armed = false;
                    self.usb.storage = false;
                    self.on_usb_edge(t, out);
                }
                Due::ResetWindow => {
                    self.reset_window_at = None;
                    if self.usb.present && self.paired.is_none() && self.window.is_none() {
                        self.open_window(t, WindowKind::Usb, None, out);
                    }
                }
                Due::Attempt(transport, i) => {
                    let why = if self.slots(transport)[i]
                        .as_ref()
                        .is_some_and(|a| a.proved())
                    {
                        CloseReason::Msg3Timeout
                    } else {
                        CloseReason::Msg1Timeout
                    };
                    self.end_attempt(transport, i, why, out);
                }
                Due::WindowEnd => self.window_expired(t, out),
            }
        }
    }

    /// USB power appeared (`true`) or went (`false`).
    pub fn usb_power(&mut self, now: Duration, present: bool, out: &mut impl FnMut(Action)) {
        self.poll(now, out);
        if self.faulted || present == self.usb.present {
            return;
        }
        if present {
            self.usb.armed = self.usb.storage || now >= self.usb.since + USB_ABSENT;
        } else {
            self.usb.armed = false;
            self.usb.enumerated = false;
            // A reset's window needs USB power to stay.
            self.reset_window_at = None;
        }
        self.usb.present = present;
        self.usb.since = now;
    }

    /// The radio is going into storage mode: the next USB power wakes it and
    /// counts as appearing (spec section 2.3).
    pub fn enter_storage(&mut self, now: Duration, out: &mut impl FnMut(Action)) {
        self.poll(now, out);
        self.usb.storage = true;
    }

    /// A USB host configured the radio (the USB "set configuration" step).
    pub fn usb_enumerated(&mut self, now: Duration, out: &mut impl FnMut(Action)) {
        self.poll(now, out);
        if self.faulted || !self.usb.present {
            return;
        }
        self.usb.enumerated = true;
        if let Some(w) = self.window.as_mut()
            && w.kind == WindowKind::Usb
            && now <= w.opened + BLE_AFTER_NO_HOST
        {
            w.host_by_10s = true;
        }
    }

    /// A connection was made: on BLE the connection itself, on USB the
    /// radio accepting a TCP connection to its pairing port. In an open
    /// window where the transport is open for pairing, it becomes an
    /// attempt (spec section 2.4); otherwise it is not one, and any pairing
    /// message on it gets no reply.
    pub fn connection_opened(
        &mut self,
        now: Duration,
        transport: Transport,
        conn: ConnId,
        out: &mut impl FnMut(Action),
    ) {
        self.poll(now, out);
        if self.faulted || self.find(conn).is_some() {
            return;
        }
        let Some(w) = self.window.as_ref() else {
            return;
        };
        if transport == Transport::Ble && !w.ble_open(now) {
            return;
        }
        let new = Attempt {
            conn,
            opened: now,
            stage: Stage::AwaitMsg1,
        };
        let slots = self.slots(transport);
        if let Some(i) = slots.iter().position(Option::is_none) {
            self.slots_mut(transport)[i] = Some(new);
            return;
        }
        // Full: replace the oldest attempt that has not proved the secret.
        // A proved attempt is never closed to make room.
        let oldest = slots
            .iter()
            .enumerate()
            .filter_map(|(i, a)| a.as_ref().map(|a| (i, a)))
            .filter(|(_, a)| !a.proved())
            .min_by_key(|(_, a)| a.opened)
            .map(|(i, _)| i);
        match oldest {
            Some(i) => {
                self.end_attempt(transport, i, CloseReason::Displaced, out);
                self.slots_mut(transport)[i] = Some(new);
            }
            None => out(Action::Close {
                conn,
                why: CloseReason::SlotsFull,
            }),
        }
    }

    /// The transport lost or closed the connection.
    pub fn connection_closed(&mut self, now: Duration, conn: ConnId, out: &mut impl FnMut(Action)) {
        self.poll(now, out);
        if let Some((t, i)) = self.find(conn) {
            let a = self.slots_mut(t)[i].take().expect("found");
            self.spare_if_proved(&a);
        }
    }

    /// One pairing message arrived on a connection (already deframed).
    pub fn message(
        &mut self,
        now: Duration,
        conn: ConnId,
        msg: &[u8],
        out: &mut impl FnMut(Action),
    ) {
        self.poll(now, out);
        if self.faulted {
            out(Action::NoReply {
                conn,
                why: NoReplyReason::Faulted,
            });
            return;
        }
        let Some((transport, i)) = self.find(conn) else {
            out(Action::NoReply {
                conn,
                why: NoReplyReason::NotAnAttempt,
            });
            return;
        };
        let proved = self.slots(transport)[i].as_ref().expect("found").proved();
        if proved {
            self.on_msg3(transport, i, msg, out);
        } else {
            self.on_msg1(now, transport, i, msg, out);
        }
    }

    /// `PAIR_OPEN` arrived inside a link session from the phone whose
    /// radio-link public key is `from` (the session layer authenticates it).
    /// Opens a replace window keyed with `secret` only.
    pub fn pair_open(
        &mut self,
        now: Duration,
        from: &[u8; 32],
        secret: &[u8; 32],
        out: &mut impl FnMut(Action),
    ) -> std::result::Result<(), PairOpenRefused> {
        self.poll(now, out);
        if self.faulted {
            return Err(PairOpenRefused::Faulted);
        }
        if self.paired.as_ref() != Some(from) {
            return Err(PairOpenRefused::NotThePairedPhone);
        }
        if self.window.is_some() {
            return Err(PairOpenRefused::WindowOpen);
        }
        if all_zero(secret) {
            return Err(PairOpenRefused::ZeroSecret);
        }
        self.open_window(now, WindowKind::Replace, Some(secret), out);
        Ok(())
    }

    /// The pinhole was held for 5 s (spec section 2.8).
    pub fn pinhole_reset(&mut self, now: Duration, out: &mut impl FnMut(Action)) {
        self.poll(now, out);
        if self.faulted {
            return;
        }
        // In memory first: no window, no attempt, no record, no limit.
        self.close_window(CloseReason::Reset, out);
        self.rate = Rate {
            failed: 0,
            last_close: None,
        };
        self.paired = None;
        out(Action::EndAllSessions);
        out(Action::WipeHeldPackets);
        out(Action::NewBluetoothAddress);
        // Then flash, in the power-safe order.
        let r = (|| {
            self.store.set_marker(Marker::Reset)?;
            self.store.erase_owner_state()?;
            self.store.write_trust(None)?;
            self.store.clear_marker()
        })();
        if r.is_err() {
            self.fault(out);
            return;
        }
        self.reset_window_at = self.usb.present.then_some(now + RESET_WINDOW_DELAY);
        out(Action::ResetDone);
    }

    // ---- inside ----

    fn on_usb_edge(&mut self, t: Duration, out: &mut impl FnMut(Action)) {
        // An edge during a window changes nothing; a paired radio opens no
        // window on USB power.
        if self.window.is_some() || self.paired.is_some() {
            return;
        }
        if self.rate.failed >= RATE_LIMIT_WINDOWS {
            let waited = self
                .rate
                .last_close
                .is_none_or(|c| t >= c + RATE_LIMIT_WAIT);
            if !waited {
                return; // this edge is spent; the next must come after the wait
            }
        }
        self.open_window(t, WindowKind::Usb, None, out);
    }

    fn open_window(
        &mut self,
        t: Duration,
        kind: WindowKind,
        secret: Option<&[u8; 32]>,
        out: &mut impl FnMut(Action),
    ) {
        let psk = Zeroizing::new(match secret {
            Some(s) => *s,
            None => *self.keys.label_secret,
        });
        self.seen.clear();
        self.window = Some(Window {
            kind,
            opened: t,
            psk,
            host_by_10s: kind == WindowKind::Usb && self.usb.enumerated,
            usb_proved: false,
            spared: false,
        });
        out(Action::WindowOpened { kind });
    }

    /// Close the window (if any) and every attempt, and clear the record.
    /// Returns the window that closed.
    fn close_window(&mut self, why: CloseReason, out: &mut impl FnMut(Action)) -> Option<Window> {
        for t in [Transport::Ble, Transport::Usb] {
            for i in 0..self.slots(t).len() {
                if self.slots(t)[i].is_some() {
                    self.end_attempt(t, i, why, out);
                }
            }
        }
        self.seen.clear();
        self.window.take()
    }

    fn window_expired(&mut self, t: Duration, out: &mut impl FnMut(Action)) {
        let Some(w) = self.close_window(CloseReason::WindowClosed, out) else {
            return;
        };
        if w.kind == WindowKind::Usb {
            if !w.spared {
                self.rate.failed = self.rate.failed.saturating_add(1);
            }
            // The wait runs from the last USB window that closed with no
            // pairing, counted or not.
            self.rate.last_close = Some(t);
        }
        out(Action::WindowExpired { kind: w.kind });
    }

    fn on_msg1(
        &mut self,
        now: Duration,
        transport: Transport,
        i: usize,
        msg: &[u8],
        out: &mut impl FnMut(Action),
    ) {
        let w = self
            .window
            .as_ref()
            .expect("attempts exist only in a window");
        let opened = match radio_open_msg1(&self.keys.pairing, &w.psk, msg) {
            Ok(o) => o,
            Err(_) => return self.end_attempt(transport, i, CloseReason::Msg1Failed, out),
        };
        if self.seen.contains(&opened.ephemeral) {
            return self.end_attempt(transport, i, CloseReason::Msg1Replay, out);
        }
        self.seen.insert(opened.ephemeral);
        let (phone_public, phone_name) = match radio_check_msg1(&opened) {
            Ok(x) => x,
            Err(_) => return self.end_attempt(transport, i, CloseReason::Msg1Refused, out),
        };
        let usb_window = w.kind == WindowKind::Usb;
        let link_key = match new_key(&mut self.entropy) {
            Ok(k) => k,
            Err(_) => return self.end_attempt(transport, i, CloseReason::Msg1Refused, out),
        };
        let mut msg2 = Msg2 {
            buf: [0u8; MAX_MSG2],
            len: 0,
        };
        let (t, len) =
            match radio_write_msg2(opened.hs, &self.name, link_key.public_key(), &mut msg2.buf) {
                Ok(x) => x,
                Err(_) => return self.end_attempt(transport, i, CloseReason::Msg1Refused, out),
            };
        msg2.len = len;
        // USB first: a proving message 1 on USB ends every BLE attempt and
        // shuts BLE for the rest of the window (spec section 2.5).
        if usb_window && transport == Transport::Usb {
            self.window.as_mut().expect("open").usb_proved = true;
            for j in 0..BLE {
                if self.ble[j].is_some() {
                    self.end_attempt(Transport::Ble, j, CloseReason::PreemptedByUsb, out);
                }
            }
        }
        let a = self.slots_mut(transport)[i].as_mut().expect("found");
        a.stage = Stage::AwaitMsg3 {
            due: now + MSG3_WITHIN,
            transport: t,
            link_key,
            phone_public,
            phone_name,
        };
        let conn = a.conn;
        out(Action::Send { conn, msg2 });
    }

    fn on_msg3(
        &mut self,
        transport: Transport,
        i: usize,
        msg: &[u8],
        out: &mut impl FnMut(Action),
    ) {
        let a = self.slots_mut(transport)[i].as_mut().expect("found");
        let Stage::AwaitMsg3 { transport: t, .. } = &mut a.stage else {
            unreachable!("proved");
        };
        if radio_read_msg3(t, msg).is_err() {
            return self.end_attempt(transport, i, CloseReason::BadMsg3, out);
        }
        // Completion. Close the window in memory first, so nothing else can
        // complete during the write.
        let a = self.slots_mut(transport)[i].take().expect("found");
        let Stage::AwaitMsg3 {
            link_key,
            phone_public,
            phone_name,
            ..
        } = a.stage
        else {
            unreachable!("proved");
        };
        let w = self
            .close_window(CloseReason::OtherCompleted, out)
            .expect("attempts exist only in a window");
        self.rate = Rate {
            failed: 0,
            last_close: None,
        };
        let saved = SavedPhone {
            phone_public,
            name: phone_name,
            link_private: Zeroizing::new(*link_key.private_key()),
        };
        drop(link_key);
        let replaced = w.kind == WindowKind::Replace;
        // A USB window opens only while unpaired, so a peer exists here only
        // in a replace window. Should one ever exist otherwise, the same
        // power-safe order still runs, so no state of it reaches the new phone.
        let r = if replaced || self.paired.is_some() {
            // The old phone's sessions end now; nothing of its state may
            // reach the new phone.
            self.paired = None;
            out(Action::EndAllSessions);
            out(Action::WipeHeldPackets);
            out(Action::NewBluetoothAddress);
            (|| {
                self.store.set_marker(Marker::Replace)?;
                self.store.erase_owner_state()?;
                self.store.write_trust(Some(&saved))?;
                self.store.clear_marker()
            })()
        } else {
            self.store.write_trust(Some(&saved))
        };
        if r.is_err() {
            self.fault(out);
            return;
        }
        self.paired = Some(phone_public);
        out(Action::Paired {
            conn: a.conn,
            phone_public,
            replaced,
        });
    }

    /// End attempt `i` on `transport` with a `Close` (and wipe its keys).
    fn end_attempt(
        &mut self,
        transport: Transport,
        i: usize,
        why: CloseReason,
        out: &mut impl FnMut(Action),
    ) {
        let Some(a) = self.slots_mut(transport)[i].take() else {
            return;
        };
        if why != CloseReason::Msg3Timeout {
            self.spare_if_proved(&a);
        }
        out(Action::Close { conn: a.conn, why });
        // Dropping `a` wipes its link key (`Identity` zeroizes on drop).
    }

    fn spare_if_proved(&mut self, a: &Attempt) {
        if a.proved()
            && let Some(w) = self.window.as_mut()
        {
            w.spared = true;
        }
    }

    fn fault(&mut self, out: &mut impl FnMut(Action)) {
        self.close_window(CloseReason::StoreFailed, out);
        self.reset_window_at = None;
        self.faulted = true;
        out(Action::StoreFailed);
    }

    fn find(&self, conn: ConnId) -> Option<(Transport, usize)> {
        for t in [Transport::Ble, Transport::Usb] {
            if let Some(i) = self
                .slots(t)
                .iter()
                .position(|a| a.as_ref().is_some_and(|a| a.conn == conn))
            {
                return Some((t, i));
            }
        }
        None
    }

    fn slots(&self, t: Transport) -> &[Option<Attempt>] {
        match t {
            Transport::Ble => &self.ble,
            Transport::Usb => &self.usb_slots,
        }
    }

    fn slots_mut(&mut self, t: Transport) -> &mut [Option<Attempt>] {
        match t {
            Transport::Ble => &mut self.ble,
            Transport::Usb => &mut self.usb_slots,
        }
    }

    /// The earliest timer, with what it is. Ties go in this order: the USB
    /// edge, the reset window, attempts, the window's end.
    fn next_due(&self) -> Option<(Duration, Due)> {
        let mut best: Option<(Duration, Due)> = None;
        let mut consider = |t: Duration, d: Due| {
            if best.as_ref().is_none_or(|(b, _)| t < *b) {
                best = Some((t, d));
            }
        };
        if self.usb.present && self.usb.armed {
            consider(self.usb.since + USB_PRESENT, Due::UsbEdge);
        }
        if let Some(t) = self.reset_window_at {
            consider(t, Due::ResetWindow);
        }
        for tr in [Transport::Ble, Transport::Usb] {
            for (i, a) in self.slots(tr).iter().enumerate() {
                if let Some(a) = a {
                    consider(a.due(), Due::Attempt(tr, i));
                }
            }
        }
        if let Some(w) = &self.window {
            consider(w.opened + WINDOW, Due::WindowEnd);
        }
        best
    }
}

#[derive(Clone, Copy)]
enum Due {
    UsbEdge,
    ResetWindow,
    Attempt(Transport, usize),
    WindowEnd,
}

/// Why `PAIR_OPEN` was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairOpenRefused {
    /// Not from the radio's paired phone (or the radio is unpaired).
    NotThePairedPhone,
    /// A window is already open.
    WindowOpen,
    /// The secret is all zero.
    ZeroSecret,
    /// The radio's store failed; it waits for a boot.
    Faulted,
}

impl<S: RadioStore, E: Entropy, const BLE: usize, const USB: usize> std::fmt::Debug
    for Radio<S, E, BLE, USB>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No secrets: the label secret, window psk and link keys stay out.
        f.debug_struct("Radio")
            .field("keys", &self.keys)
            .field("name", &self.name)
            .field(
                "paired",
                &self.paired.map(|p| crate::identity::fingerprint(&p)),
            )
            .field("window", &self.window.as_ref().map(|w| w.kind))
            .field("faulted", &self.faulted)
            .finish_non_exhaustive()
    }
}
