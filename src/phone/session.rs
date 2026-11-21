//! The radio's side of the phone link after pairing (spec sections 3 to 5):
//! the link session with its one phone, the connections it runs on, the
//! messages inside it, and what the radio does while the phone is away.
//!
//! [`RadioNode`] wraps the pairing machine ([`Radio`]) and adds:
//!
//! - **The session.** The R-COM2 link, wire version 1, **unchanged**
//!   ([`crate::link::Link`]). The radio's static key is the **link key** it
//!   made at pairing, never the pairing key; its one trusted peer is the
//!   phone's radio-link key. Both come only from [`Radio::link_peer`], read
//!   from the store: nothing while unpaired or faulted. Settings
//!   ([`link_config`]): keepalives off, rekey after an hour or 2³² packets,
//!   reject after 90 minutes, no `max_future` (the radio has no clock; its
//!   timestamps count on from the saved value). Handshake timestamps are
//!   saved per phone through [`PhoneStateStore`]; a failed save faults the
//!   radio (fail closed).
//! - **Connections.** Link packets arrive on numbered connections (a BLE
//!   connection, or the USB network link). On BLE they are framed
//!   ([`super::frame`]); on USB each datagram is one packet. A packet longer
//!   than the MTU closes the connection. Outside a pairing window, a
//!   connection that has not completed a link handshake within 5 s is
//!   closed; when every connection slot is taken, a new connection replaces
//!   the oldest one that has not completed, and a completed one is never
//!   displaced. A session belongs to the connection it last authenticated
//!   on: when that connection closes the session ends and the phone
//!   handshakes again.
//! - **Messages** (spec section 4, [`super::msg`]). `PAIR_OPEN` goes to
//!   [`Radio::pair_open`] with the session's own peer as the sender, and is
//!   answered with `STATUS`. Control messages (`0x01`) carry no rights here
//!   and are dropped. Radio-to-phone types from the phone, unknown types and
//!   refused bodies are dropped and counted.
//! - **Held packets** (spec section 5, [`super::hold`]): wake filters kept
//!   in flash, the hold store in memory, wakes limited.
//!
//! The radio never originates anything on the air: the only transmit
//! action, [`NodeAction::Transmit`], carries a `SEND` from the phone.
//!
//! **Allocation.** The link allocates (it always has); so do the events and
//! the packets handed to the firmware. The hold store, the filters and the
//! deframers are fixed arrays.

use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use zeroize::Zeroize;

use super::Name;
use super::frame::{Deframer, FrameError, frame};
use super::hold::{Filters, HoldNumber, HoldStore, Signal, WakeLimit};
use super::msg::{
    BodyFormat, FromPhone, MAX_ACK, MSG_HELD, MSG_RECEIVED, firmware_may_send, parse_from_phone,
};
use super::radio::{
    Action, ChannelId, Radio, RadioKeys, RadioStore, Status, StoreFailed, Transport,
};
use crate::identity::Identity;
use crate::link::{Config, Dest, Entropy, Event, Link, Stats, StoredStamps, TimestampStore};
use crate::{Error, Result};

/// The link's rekey time on the phone link (spec section 3).
pub const REKEY_AFTER: Duration = Duration::from_secs(60 * 60);
/// ...or this many packets.
pub const REKEY_AFTER_PACKETS: u64 = 1 << 32;
/// Nobody sends or accepts on a session after this long.
pub const REJECT_AFTER: Duration = Duration::from_secs(90 * 60);
/// Outside a window, a connection must complete a link handshake within
/// this long (spec section 3).
pub const LINK_CONNECT_WITHIN: Duration = Duration::from_secs(5);

/// The link settings of the phone link, for both sides (spec section 3):
/// keepalive off, rekey once an hour or at 2³² packets, reject after 90
/// minutes, `max_future` off. Everything else is the link's default.
pub fn link_config(mtu: usize) -> Config {
    Config {
        mtu,
        keepalive: None,
        rekey_after: REKEY_AFTER,
        rekey_after_packets: REKEY_AFTER_PACKETS,
        reject_after: REJECT_AFTER,
        max_future: None,
        ..Config::default()
    }
}

/// The phone's side of the session: the link to the radio's link key, with
/// this phone's radio-link key from the pairing and the phone link's
/// settings. The first completed handshake is the pairing's confirmation
/// (spec section 2.4).
pub fn phone_link(
    radio_link_key: &Identity,
    radio_link_public: [u8; 32],
    mtu: usize,
    entropy: Box<dyn Entropy>,
    wall_base: Duration,
    store: Box<dyn TimestampStore>,
) -> Result<Link> {
    Link::new(
        radio_link_key,
        radio_link_public,
        link_config(mtu),
        entropy,
        wall_base,
        store,
    )
}

/// The radio's flash beyond the trust state: the handshake timestamps of
/// the session and the wake filters. Both are **owner state**: an
/// implementation must erase them in [`RadioStore::erase_owner_state`]
/// ("gone from flash", spec section 2.8). Every write is durable before it
/// returns `Ok`; any error faults the radio.
pub trait PhoneStateStore {
    /// The timestamps saved for this phone (none if never saved).
    fn stamps(&mut self, phone: &[u8; 32]) -> std::result::Result<StoredStamps, StoreFailed>;
    fn write_stamps(
        &mut self,
        phone: &[u8; 32],
        stamps: &StoredStamps,
    ) -> std::result::Result<(), StoreFailed>;
    /// The wake filters (none if never saved).
    fn filters(&mut self) -> std::result::Result<Filters, StoreFailed>;
    fn write_filters(&mut self, filters: &Filters) -> std::result::Result<(), StoreFailed>;
}

/// The link's timestamp store over [`PhoneStateStore`], remembering a
/// failure so the radio can fail closed.
struct Stamps<S> {
    store: S,
    phone: [u8; 32],
    failed: Rc<Cell<bool>>,
}

impl<S: PhoneStateStore> TimestampStore for Stamps<S> {
    fn load(&mut self) -> Result<StoredStamps> {
        self.store.stamps(&self.phone).map_err(|_| {
            self.failed.set(true);
            Error::Link("the radio's store failed")
        })
    }
    fn save(&mut self, stamps: &StoredStamps) -> Result<()> {
        self.store.write_stamps(&self.phone, stamps).map_err(|_| {
            self.failed.set(true);
            Error::Link("the radio's store failed")
        })
    }
}

/// Names one link connection (a BLE connection, or the USB network link),
/// unique among open ones. Separate from pairing channels.
pub type ConnId = u32;

/// Why the radio closed a link connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkCloseReason {
    /// Outside a window, no link handshake completed within 5 s.
    NoHandshake,
    /// A new connection needed the slot and this one had not completed.
    Displaced,
    /// Every slot holds a completed connection: the new one is refused.
    SlotsFull,
    /// A packet longer than the MTU.
    TooLong,
    /// A frame of length zero.
    BadFrame,
    /// Every session ended (reset, replace, a store fault).
    SessionsEnded,
}

/// Why [`RadioNode::send_to_phone`] sent nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhoneSendError {
    /// The firmware may send only `SENT` and `STATUS` this way.
    NotAllowed,
    /// No session with the phone.
    NoSession,
    /// The link refused it (too large for the MTU).
    TooLarge,
}

/// What the radio's phone side does, handed to the sink in order.
#[derive(Clone)]
pub enum NodeAction {
    /// An action of the pairing machine, after the node has done its part
    /// (ended sessions, wiped held packets).
    Pairing(Action),
    /// Send these bytes on this link connection (already framed for BLE).
    LinkSend { conn: ConnId, bytes: Vec<u8> },
    /// Close this link connection.
    LinkClose { conn: ConnId, why: LinkCloseReason },
    /// A `SEND` from the phone (its body as sent). The firmware decodes it,
    /// checks it against its built-in frequency, power and airtime limits,
    /// transmits or refuses, and answers `SENT` ([`RadioNode::send_to_phone`]).
    Transmit { body: Vec<u8> },
    /// A `SETTINGS` from the phone, for the firmware to check against its
    /// built-in limits.
    Settings { body: Vec<u8> },
    /// An `UPDATE_*` piece, for the firmware's signed-update checks.
    Update { body: Vec<u8> },
    /// Answer with `STATUS` (after a `PAIR_OPEN`).
    StatusWanted,
    /// Wake the phone: a bare BLE notification with nothing in it.
    Wake,
}

impl std::fmt::Debug for NodeAction {
    // Never prints packet bytes or bodies.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeAction::Pairing(a) => write!(f, "Pairing({a:?})"),
            NodeAction::LinkSend { conn, bytes } => {
                write!(f, "LinkSend(conn {conn}, {} bytes)", bytes.len())
            }
            NodeAction::LinkClose { conn, why } => write!(f, "LinkClose(conn {conn}, {why:?})"),
            NodeAction::Transmit { body } => write!(f, "Transmit({} bytes)", body.len()),
            NodeAction::Settings { body } => write!(f, "Settings({} bytes)", body.len()),
            NodeAction::Update { body } => write!(f, "Update({} bytes)", body.len()),
            NodeAction::StatusWanted => f.write_str("StatusWanted"),
            NodeAction::Wake => f.write_str("Wake"),
        }
    }
}

/// Counters of the phone side (the link's own are in [`RadioNode::link_stats`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeStats {
    /// Link packets dropped because the radio has no peer (unpaired or
    /// faulted).
    pub no_peer: u64,
    /// Control messages (`0x01`) dropped: they carry no rights here.
    pub control_refused: u64,
    /// Application messages dropped: unknown type, wrong direction, bad body.
    pub messages_dropped: u64,
    /// `PAIR_OPEN`s that [`Radio::pair_open`] refused.
    pub pair_open_refused: u64,
    /// Wakes sent.
    pub wakes: u64,
    /// Packets the link wanted to send with no connection to send on.
    pub not_sent: u64,
}

struct Conn<const MTU: usize> {
    id: ConnId,
    transport: Transport,
    /// When it opened, or when its session ended (it must handshake again).
    since: Duration,
    /// A link packet from it authenticated.
    completed: bool,
    deframer: Deframer<MTU>,
}

struct Session {
    link: Link,
    phone: [u8; 32],
    store_failed: Rc<Cell<bool>>,
    /// The connection the session last authenticated on.
    bound: Option<ConnId>,
}

/// The radio's phone side. `BLE` and `USB` are the pairing slots (as
/// [`Radio`]), `LINKS` the link connection slots, `MTU` the phone link's
/// largest packet (at least 128; spec section 3: it must fit the largest air
/// packet plus the `SEND` or `RECEIVED` fields plus the link's 22 bytes).
pub struct RadioNode<
    S,
    E,
    F,
    const BLE: usize,
    const USB: usize,
    const LINKS: usize,
    const MTU: usize,
> where
    S: RadioStore + PhoneStateStore + Clone + 'static,
    E: Entropy + Clone + 'static,
    F: BodyFormat,
{
    radio: Radio<S, E, BLE, USB>,
    store: S,
    entropy: E,
    format: F,
    session: Option<Session>,
    /// Counts sessions; held packets remember which one they went out in.
    session_no: u32,
    conns: [Option<Conn<MTU>>; LINKS],
    window_open: bool,
    window_closed_at: Duration,
    hold: HoldStore,
    filters: Filters,
    wake: WakeLimit,
    stats: NodeStats,
    clock: Duration,
}

impl<S, E, F, const BLE: usize, const USB: usize, const LINKS: usize, const MTU: usize>
    RadioNode<S, E, F, BLE, USB, LINKS, MTU>
where
    S: RadioStore + PhoneStateStore + Clone + 'static,
    E: Entropy + Clone + 'static,
    F: BodyFormat,
{
    /// Start the radio from no power ([`Radio::boot`]), then load the wake
    /// filters and, if paired, the session's link. Held packets start empty
    /// (memory only).
    #[allow(clippy::too_many_arguments)]
    pub fn boot(
        keys: RadioKeys,
        name: Name,
        store: S,
        entropy: E,
        format: F,
        now: Duration,
        usb_present: bool,
        out: &mut impl FnMut(NodeAction),
    ) -> Self {
        assert!(LINKS > 0, "at least one link connection slot");
        assert!(
            link_config(MTU).validate().is_ok(),
            "the MTU must be 128 to 65535 bytes"
        );
        let mut acts = Vec::new();
        let radio = Radio::boot(
            keys,
            name,
            store.clone(),
            entropy.clone(),
            now,
            usb_present,
            &mut |a| acts.push(a),
        );
        let mut n = Self {
            radio,
            store,
            entropy,
            format,
            session: None,
            session_no: 0,
            conns: std::array::from_fn(|_| None),
            window_open: false,
            window_closed_at: now,
            hold: HoldStore::new(),
            filters: Filters::none(),
            wake: WakeLimit::new(),
            stats: NodeStats::default(),
            clock: now,
        };
        n.after_radio(now, acts, out);
        if !n.radio.status(now).faulted {
            match n.store.filters() {
                Ok(f) => n.filters = f,
                Err(StoreFailed) => n.fault(now, out),
            }
        }
        n.rebuild(now, out);
        n
    }

    /// The pairing machine, for what the node does not wrap.
    pub fn radio(&self) -> &Radio<S, E, BLE, USB> {
        &self.radio
    }

    pub fn status(&self, now: Duration) -> Status {
        self.radio.status(now)
    }

    pub fn stats(&self) -> &NodeStats {
        &self.stats
    }

    /// The link's counters (drops by reason), while a session link exists.
    pub fn link_stats(&self) -> Option<&Stats> {
        self.session.as_ref().map(|s| s.link.stats())
    }

    /// Packets held now.
    pub fn held(&self) -> usize {
        self.hold.len()
    }

    /// Bytes held now.
    pub fn held_bytes(&self) -> usize {
        self.hold.bytes()
    }

    /// Whether a session can carry messages now.
    pub fn connected(&self) -> bool {
        self.live()
    }

    /// When the node's own timers next need [`poll`](Self::poll). While a
    /// session link exists, also call `poll` every few hundred milliseconds
    /// for the link's timers (as [`Link::poll_timers`] asks).
    pub fn next_wakeup(&self) -> Option<Duration> {
        let mut t = self.radio.next_wakeup();
        let mut consider = |d: Duration| t = Some(t.map_or(d, |x| x.min(d)));
        if !self.window_open {
            for c in self.conns.iter().flatten().filter(|c| !c.completed) {
                consider(self.conn_due(c));
            }
        }
        if let Some(d) = self.hold.next_expiry() {
            consider(d);
        }
        if !self.live()
            && let Some(d) = self.wake.due()
        {
            consider(d);
        }
        t
    }

    // ---- inputs: the pairing machine's, passed through ----

    /// Run every timer due by `now`.
    pub fn poll(&mut self, now: Duration, out: &mut impl FnMut(NodeAction)) {
        let now = self.tick(now);
        let mut acts = Vec::new();
        self.radio.poll(now, &mut |a| acts.push(a));
        self.after_radio(now, acts, out);
        self.poll_inner(now, out);
    }

    pub fn usb_power(&mut self, now: Duration, present: bool, out: &mut impl FnMut(NodeAction)) {
        let now = self.tick(now);
        let mut acts = Vec::new();
        self.radio.usb_power(now, present, &mut |a| acts.push(a));
        self.after_radio(now, acts, out);
        self.poll_inner(now, out);
    }

    pub fn usb_enumerated(&mut self, now: Duration, out: &mut impl FnMut(NodeAction)) {
        let now = self.tick(now);
        let mut acts = Vec::new();
        self.radio.usb_enumerated(now, &mut |a| acts.push(a));
        self.after_radio(now, acts, out);
        self.poll_inner(now, out);
    }

    /// See [`Radio::enter_storage`]: a local, physical action only.
    pub fn enter_storage(&mut self, now: Duration, out: &mut impl FnMut(NodeAction)) {
        let now = self.tick(now);
        let mut acts = Vec::new();
        self.radio.enter_storage(now, &mut |a| acts.push(a));
        self.after_radio(now, acts, out);
        self.poll_inner(now, out);
    }

    pub fn pairing_channel_opened(
        &mut self,
        now: Duration,
        transport: Transport,
        channel: ChannelId,
        out: &mut impl FnMut(NodeAction),
    ) {
        let now = self.tick(now);
        let mut acts = Vec::new();
        self.radio
            .pairing_channel_opened(now, transport, channel, &mut |a| acts.push(a));
        self.after_radio(now, acts, out);
        self.poll_inner(now, out);
    }

    pub fn pairing_channel_closed(
        &mut self,
        now: Duration,
        channel: ChannelId,
        out: &mut impl FnMut(NodeAction),
    ) {
        let now = self.tick(now);
        let mut acts = Vec::new();
        self.radio
            .pairing_channel_closed(now, channel, &mut |a| acts.push(a));
        self.after_radio(now, acts, out);
        self.poll_inner(now, out);
    }

    pub fn pairing_message(
        &mut self,
        now: Duration,
        channel: ChannelId,
        msg: &[u8],
        out: &mut impl FnMut(NodeAction),
    ) {
        let now = self.tick(now);
        let mut acts = Vec::new();
        self.radio.message(now, channel, msg, &mut |a| acts.push(a));
        self.after_radio(now, acts, out);
        self.poll_inner(now, out);
    }

    /// The pinhole was held for 5 s ([`Radio::pinhole_reset`]): every
    /// session ends, every connection closes, held packets and filters go.
    pub fn pinhole_reset(&mut self, now: Duration, out: &mut impl FnMut(NodeAction)) {
        let now = self.tick(now);
        let mut acts = Vec::new();
        self.radio.pinhole_reset(now, &mut |a| acts.push(a));
        self.after_radio(now, acts, out);
        self.poll_inner(now, out);
    }

    // ---- inputs: link connections ----

    /// A link connection opened (a BLE connection, or the USB network link
    /// came up). It must complete a link handshake (outside a window,
    /// within 5 s).
    pub fn link_opened(
        &mut self,
        now: Duration,
        transport: Transport,
        conn: ConnId,
        out: &mut impl FnMut(NodeAction),
    ) {
        let now = self.tick(now);
        self.poll_inner(now, out);
        if self.find(conn).is_some() {
            return;
        }
        // The flash is the only source of who is paired: check it again.
        self.check_trust(now, out);
        let new = Conn {
            id: conn,
            transport,
            since: now,
            completed: false,
            deframer: Deframer::new(),
        };
        if let Some(i) = self.conns.iter().position(Option::is_none) {
            self.conns[i] = Some(new);
            return;
        }
        let oldest = self
            .conns
            .iter()
            .enumerate()
            .filter_map(|(i, c)| c.as_ref().map(|c| (i, c)))
            .filter(|(_, c)| !c.completed)
            .min_by_key(|(_, c)| c.since)
            .map(|(i, _)| i);
        match oldest {
            Some(i) => {
                self.close_conn(now, i, LinkCloseReason::Displaced, out);
                self.conns[i] = Some(new);
            }
            None => out(NodeAction::LinkClose {
                conn,
                why: LinkCloseReason::SlotsFull,
            }),
        }
    }

    /// The transport lost or closed a link connection.
    pub fn link_closed(&mut self, now: Duration, conn: ConnId, out: &mut impl FnMut(NodeAction)) {
        let now = self.tick(now);
        if let Some(i) = self.find(conn) {
            self.conns[i] = None;
            self.conn_gone(now, conn, out);
        }
        self.poll_inner(now, out);
    }

    /// Bytes arrived on a link connection: part of the stream on BLE, one
    /// datagram on USB.
    pub fn link_bytes(
        &mut self,
        now: Duration,
        conn: ConnId,
        bytes: &[u8],
        out: &mut impl FnMut(NodeAction),
    ) {
        let now = self.tick(now);
        self.poll_inner(now, out);
        let Some(i) = self.find(conn) else {
            return;
        };
        let c = self.conns[i].as_mut().expect("found");
        let mut packets: Vec<Vec<u8>> = Vec::new();
        let r = match c.transport {
            Transport::Ble => c.deframer.push(bytes, |p| packets.push(p.to_vec())),
            Transport::Usb if bytes.is_empty() => Err(FrameError::Empty),
            Transport::Usb if bytes.len() > MTU => Err(FrameError::TooLong),
            Transport::Usb => {
                packets.push(bytes.to_vec());
                Ok(())
            }
        };
        if let Err(e) = r {
            // Nothing from a stream that broke the framing is used.
            let why = match e {
                FrameError::TooLong => LinkCloseReason::TooLong,
                FrameError::Empty => LinkCloseReason::BadFrame,
            };
            self.close_conn(now, i, why, out);
            return;
        }
        for p in packets {
            if self.find(conn).is_none() {
                break;
            }
            self.packet(now, conn, &p, out);
        }
    }

    // ---- inputs: the air and the firmware ----

    /// A packet from the air. If it matches a wake filter it is held, and
    /// sent to the phone at once if a session is up, or the phone is woken
    /// (within the wake limit). Relaying is the firmware's and is not
    /// decided here.
    pub fn air_received(
        &mut self,
        now: Duration,
        packet: &[u8],
        signal: Signal,
        out: &mut impl FnMut(NodeAction),
    ) {
        let now = self.tick(now);
        self.poll_inner(now, out);
        let st = self.radio.status(now);
        if st.faulted || !st.paired {
            return;
        }
        let Some(hold) = self.hold.offer(now, packet, signal, &self.filters) else {
            return;
        };
        if self.live() && self.send_received(now, hold, signal, packet, out) {
            self.hold.mark_delivered(self.session_no, hold);
        } else {
            self.wake.held();
        }
        self.poll_inner(now, out);
    }

    /// Send a message the firmware built (`SENT` or `STATUS`) to the phone.
    pub fn send_to_phone(
        &mut self,
        now: Duration,
        ty: u8,
        body: &[u8],
        out: &mut impl FnMut(NodeAction),
    ) -> std::result::Result<(), PhoneSendError> {
        let now = self.tick(now);
        if !firmware_may_send(ty) {
            return Err(PhoneSendError::NotAllowed);
        }
        let mut plain = Vec::with_capacity(1 + body.len());
        plain.push(ty);
        plain.extend_from_slice(body);
        self.send_app(now, &plain, out)
    }

    // ---- inside ----

    fn tick(&mut self, now: Duration) -> Duration {
        self.clock = self.clock.max(now);
        self.clock
    }

    fn live(&self) -> bool {
        self.session
            .as_ref()
            .is_some_and(|s| s.bound.is_some() && s.link.can_send())
    }

    fn find(&self, conn: ConnId) -> Option<usize> {
        self.conns
            .iter()
            .position(|c| c.as_ref().is_some_and(|c| c.id == conn))
    }

    fn conn_due(&self, c: &Conn<MTU>) -> Duration {
        c.since
            .max(self.window_closed_at)
            .saturating_add(LINK_CONNECT_WITHIN)
    }

    /// Handle what the pairing machine did, then pass it on.
    fn after_radio(&mut self, now: Duration, acts: Vec<Action>, out: &mut impl FnMut(NodeAction)) {
        let mut rebuild = false;
        for a in acts {
            match &a {
                Action::EndAllSessions => self.end_sessions(now, out),
                Action::WipeHeldPackets => {
                    self.hold.clear();
                    self.filters = Filters::none();
                    self.wake = WakeLimit::new();
                }
                Action::Paired { .. } | Action::ResetDone => rebuild = true,
                _ => {}
            }
            out(NodeAction::Pairing(a));
        }
        if rebuild {
            self.rebuild(now, out);
        }
        self.track_window(now);
    }

    fn track_window(&mut self, now: Duration) {
        let open = self.radio.status(now).window.is_some();
        if self.window_open && !open {
            self.window_closed_at = now;
        }
        self.window_open = open;
    }

    /// End the session and close every link connection.
    fn end_sessions(&mut self, now: Duration, out: &mut impl FnMut(NodeAction)) {
        self.session = None;
        for i in 0..LINKS {
            if self.conns[i].is_some() {
                self.close_conn(now, i, LinkCloseReason::SessionsEnded, out);
            }
        }
    }

    /// Close connection slot `i` (and end the session if it was bound there).
    fn close_conn(
        &mut self,
        now: Duration,
        i: usize,
        why: LinkCloseReason,
        out: &mut impl FnMut(NodeAction),
    ) {
        if let Some(c) = self.conns[i].take() {
            out(NodeAction::LinkClose { conn: c.id, why });
            self.conn_gone(now, c.id, out);
        }
    }

    /// A connection is gone: if the session was bound to it, the session
    /// ends (a new link from the store, with no sessions), and every other
    /// connection must handshake again.
    fn conn_gone(&mut self, now: Duration, conn: ConnId, out: &mut impl FnMut(NodeAction)) {
        if self.session.as_ref().is_some_and(|s| s.bound == Some(conn)) {
            for c in self.conns.iter_mut().flatten() {
                c.completed = false;
                c.since = now;
            }
            self.rebuild(now, out);
        }
    }

    /// Read the trust state; end the session if it no longer matches.
    fn check_trust(&mut self, now: Duration, out: &mut impl FnMut(NodeAction)) {
        let mut acts = Vec::new();
        let peer = self
            .radio
            .link_peer(&mut |a| acts.push(a))
            .map(|p| p.phone_public);
        self.after_radio(now, acts, out);
        let have = self.session.as_ref().map(|s| s.phone);
        if peer != have {
            self.end_sessions(now, out);
            self.rebuild(now, out);
        }
    }

    /// A new session link from the store's trust state (none if unpaired or
    /// faulted). Any session before it is gone.
    fn rebuild(&mut self, now: Duration, out: &mut impl FnMut(NodeAction)) {
        self.session = None;
        let mut acts = Vec::new();
        let saved = self.radio.link_peer(&mut |a| acts.push(a));
        self.after_radio(now, acts, out);
        let Some(saved) = saved else {
            return;
        };
        let store_failed = Rc::new(Cell::new(false));
        let stamps = Stamps {
            store: self.store.clone(),
            phone: saved.phone_public,
            failed: store_failed.clone(),
        };
        let built = Identity::from_private_bytes(&saved.link_private[..]).and_then(|id| {
            Link::new(
                &id,
                saved.phone_public,
                link_config(MTU),
                Box::new(self.entropy.clone()),
                Duration::ZERO,
                Box::new(stamps),
            )
        });
        match built {
            Ok(link) => {
                self.session_no = self.session_no.wrapping_add(1).max(1);
                self.session = Some(Session {
                    link,
                    phone: saved.phone_public,
                    store_failed,
                    bound: None,
                });
            }
            // A store that cannot be read, or a trust state the link
            // refuses: fail closed.
            Err(_) => self.fault(now, out),
        }
    }

    fn fault(&mut self, now: Duration, out: &mut impl FnMut(NodeAction)) {
        let mut acts = Vec::new();
        self.radio.store_failed(now, &mut |a| acts.push(a));
        self.after_radio(now, acts, out);
        self.session = None;
    }

    fn poll_inner(&mut self, now: Duration, out: &mut impl FnMut(NodeAction)) {
        if let Some(s) = self.session.as_mut() {
            let evs = s.link.poll_timers(now);
            self.route(now, None, evs, out);
        }
        self.track_window(now);
        if !self.window_open {
            for i in 0..LINKS {
                let due = self.conns[i]
                    .as_ref()
                    .filter(|c| !c.completed)
                    .map(|c| self.conn_due(c));
                if due.is_some_and(|d| now >= d) {
                    self.close_conn(now, i, LinkCloseReason::NoHandshake, out);
                }
            }
        }
        self.hold.expire(now);
        if self.live() {
            self.wake.connected();
        } else if self.wake.poll(now) {
            self.stats.wakes += 1;
            out(NodeAction::Wake);
        }
    }

    fn packet(&mut self, now: Duration, conn: ConnId, p: &[u8], out: &mut impl FnMut(NodeAction)) {
        let Some(s) = self.session.as_mut() else {
            self.stats.no_peer += 1;
            return;
        };
        let evs = s.link.handle_packet(now, p);
        self.route(now, Some(conn), evs, out);
    }

    /// Act on the link's events. `from`: the connection of the packet that
    /// caused them (none for timers).
    fn route(
        &mut self,
        now: Duration,
        from: Option<ConnId>,
        evs: Vec<Event>,
        out: &mut impl FnMut(NodeAction),
    ) {
        let mut delivered = Vec::new();
        let mut established = false;
        let mut failed = false;
        for e in evs {
            match e {
                Event::Authenticated | Event::SessionEstablished { .. } => {
                    let new_session = matches!(e, Event::SessionEstablished { .. });
                    established |= new_session;
                    // A session belongs to the connection it was made on.
                    // A packet that authenticates on another connection is
                    // still the phone's (the link checked it), but does not
                    // move the session there or make that connection
                    // complete: only a new session does.
                    // SPEC-GAP: the spec says a session belongs to one
                    // connection, not what a valid packet of it on another
                    // connection means; it is used, and moves nothing.
                    if let (Some(c), Some(s)) = (from, self.session.as_mut())
                        && (new_session || s.bound.is_none() || s.bound == Some(c))
                    {
                        s.bound = Some(c);
                        if let Some(i) = self.find(c) {
                            self.conns[i].as_mut().expect("found").completed = true;
                        }
                    }
                }
                Event::Send { packet, to } => {
                    let bound = self.session.as_ref().and_then(|s| s.bound);
                    let dest = match to {
                        Dest::Source => from,
                        Dest::Remote => bound.or(from),
                    };
                    match dest.and_then(|c| self.wire(c, &packet).map(|b| (c, b))) {
                        Some((conn, bytes)) => out(NodeAction::LinkSend { conn, bytes }),
                        None => self.stats.not_sent += 1,
                    }
                }
                Event::Deliver(body) => delivered.push(body),
                Event::Control(_) => self.stats.control_refused += 1,
                Event::Failure(_) => {
                    failed |= self.session.as_ref().is_some_and(|s| s.store_failed.get());
                }
                Event::Dropped(_) | Event::HandshakeSent { .. } => {}
            }
        }
        if failed {
            for mut b in delivered {
                b.zeroize();
            }
            self.fault(now, out);
            return;
        }
        if established {
            self.wake.connected();
            self.send_held(now, out);
        }
        for mut body in delivered {
            self.message(now, &body, out);
            // Bodies can carry a replace secret: wipe them.
            body.zeroize();
        }
    }

    /// The bytes to send on connection `conn` for one link packet.
    fn wire(&self, conn: ConnId, packet: &[u8]) -> Option<Vec<u8>> {
        let c = self.conns[self.find(conn)?].as_ref()?;
        match c.transport {
            Transport::Ble => frame(packet),
            Transport::Usb => Some(packet.to_vec()),
        }
    }

    /// One message from the phone, authenticated by the session.
    fn message(&mut self, now: Duration, plain: &[u8], out: &mut impl FnMut(NodeAction)) {
        let Some(phone) = self.session.as_ref().map(|s| s.phone) else {
            return;
        };
        let m = match parse_from_phone(plain) {
            Ok(m) => m,
            Err(_) => {
                self.stats.messages_dropped += 1;
                return;
            }
        };
        match m {
            FromPhone::Send(b) => out(NodeAction::Transmit { body: b.to_vec() }),
            FromPhone::Settings(b) => out(NodeAction::Settings { body: b.to_vec() }),
            FromPhone::Update(b) => out(NodeAction::Update { body: b.to_vec() }),
            FromPhone::Filters(b) => match self.format.decode_filters(b) {
                None => self.stats.messages_dropped += 1,
                Some(f) => {
                    if self.store.write_filters(&f).is_err() {
                        self.fault(now, out);
                        return;
                    }
                    self.filters = f;
                }
            },
            FromPhone::Fetch(b) => {
                if !self.format.decode_fetch(b) {
                    self.stats.messages_dropped += 1;
                    return;
                }
                self.fetch(now, out);
            }
            FromPhone::FetchAck(b) => {
                let mut holds = [HoldNumber(0); MAX_ACK];
                match self.format.decode_fetch_ack(b, &mut holds) {
                    Some(n) if n <= MAX_ACK => {
                        if self.hold.ack(self.session_no, &holds[..n]) > 0 {
                            self.wake.real_ack();
                        }
                    }
                    _ => self.stats.messages_dropped += 1,
                }
            }
            FromPhone::PairOpen(secret) => {
                let mut acts = Vec::new();
                let r = self
                    .radio
                    .pair_open(now, &phone, secret, &mut |a| acts.push(a));
                self.after_radio(now, acts, out);
                if r.is_err() {
                    self.stats.pair_open_refused += 1;
                }
                out(NodeAction::StatusWanted);
            }
        }
    }

    /// `FETCH`: every held packet not yet handed over in this session, as
    /// `RECEIVED` with its hold number. Nothing is deleted.
    fn fetch(&mut self, now: Duration, out: &mut impl FnMut(NodeAction)) {
        let session_no = self.session_no;
        let mut sent: Vec<(HoldNumber, Signal, Vec<u8>)> = Vec::new();
        // Collect first (the link needs `self`), then send in order; a
        // packet that cannot be sent stays unmarked.
        self.hold.fetch(session_no, |h, sig, p| {
            sent.push((h, sig, p.to_vec()));
            true
        });
        let mut failed_from = None;
        for (k, (h, sig, p)) in sent.iter().enumerate() {
            if !self.send_received(now, *h, *sig, p, out) {
                failed_from = Some(k);
                break;
            }
        }
        if let Some(k) = failed_from {
            // Not handed over: unmark so the next FETCH offers them again.
            for (h, _, _) in &sent[k..] {
                self.hold.mark_delivered(0, *h);
            }
        }
    }

    fn send_received(
        &mut self,
        now: Duration,
        hold: HoldNumber,
        signal: Signal,
        packet: &[u8],
        out: &mut impl FnMut(NodeAction),
    ) -> bool {
        let mut plain = vec![MSG_RECEIVED];
        self.format
            .encode_received(hold, signal, packet, &mut plain);
        self.send_app(now, &plain, out).is_ok()
    }

    fn send_held(&mut self, now: Duration, out: &mut impl FnMut(NodeAction)) {
        let mut plain = vec![MSG_HELD];
        self.format.encode_held(self.hold.len(), &mut plain);
        let _ = self.send_app(now, &plain, out);
    }

    fn send_app(
        &mut self,
        now: Duration,
        plain: &[u8],
        out: &mut impl FnMut(NodeAction),
    ) -> std::result::Result<(), PhoneSendError> {
        let Some(s) = self.session.as_mut() else {
            return Err(PhoneSendError::NoSession);
        };
        let Some(conn) = s.bound else {
            return Err(PhoneSendError::NoSession);
        };
        let packet = s.link.send(now, plain).map_err(|e| match e {
            crate::link::SendError::TooLarge => PhoneSendError::TooLarge,
            _ => PhoneSendError::NoSession,
        })?;
        match self.wire(conn, &packet) {
            Some(bytes) => {
                out(NodeAction::LinkSend { conn, bytes });
                Ok(())
            }
            None => Err(PhoneSendError::NoSession),
        }
    }
}

impl<S, E, F, const BLE: usize, const USB: usize, const LINKS: usize, const MTU: usize>
    std::fmt::Debug for RadioNode<S, E, F, BLE, USB, LINKS, MTU>
where
    S: RadioStore + PhoneStateStore + Clone + 'static,
    E: Entropy + Clone + 'static,
    F: BodyFormat,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No secrets: the link holds the link key and is not shown.
        f.debug_struct("RadioNode")
            .field("radio", &self.radio)
            .field("session", &self.session.as_ref().map(|s| s.bound))
            .field("connections", &self.conns.iter().flatten().count())
            .field("held", &self.hold)
            .field("filters", &self.filters)
            .finish_non_exhaustive()
    }
}
