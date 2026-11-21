//! What the radio does without the phone (spec section 5): the wake
//! filters, the hold store and the wake limit.
//!
//! The radio cannot read packets. It holds a packet from the air only if it
//! matches a filter the phone set, by fields that are public on the air:
//!
//! - a **link receiver index**: a link data packet or handshake 2 whose
//!   receiver index is in the list;
//! - a **group id**: a group packet (header type 4) with that group id;
//! - the **handshake filter**: a link handshake 1 whose `mac1` checks under
//!   the filter, which is the `mac1` key of the phone's messaging identity
//!   (link spec section 2; the existing `mac1` check, no new crypto).
//!
//! The store is **in memory only** and uses fixed arrays (no allocation):
//! [`HOLD_PACKETS`] slots of [`MAX_HELD_PACKET`] bytes. A packet is
//! deleted only by a `FETCH_ACK` that names it, by the limits (oldest first
//! within its own share), after [`HOLD_FOR`], or by a wipe (reset, replace,
//! power loss).

use std::time::Duration;

use zeroize::Zeroize;

use crate::link::{Packet, VERSION, mac1_key, mac1_ok, parse};

/// At most this many packets are held (spec section 5).
pub const HOLD_PACKETS: usize = 64;
/// ...and at most this many bytes.
pub const HOLD_BYTES: usize = 16 * 1024;
/// Each packet is held at most this long.
pub const HOLD_FOR: Duration = Duration::from_secs(24 * 60 * 60);
/// The largest packet the radio holds. Larger ones are not held.
// SPEC-GAP: the spec does not give the largest air packet. 256 bytes covers
// a LoRa payload (255) and makes 64 slots exactly the 16 kB limit.
pub const MAX_HELD_PACKET: usize = HOLD_BYTES / HOLD_PACKETS;
/// Most index filters, and most group filters, in one `FILTERS`.
// SPEC-GAP: the spec sets no number. A list with more is refused whole.
pub const MAX_FILTERS_PER_KIND: usize = 8;
/// Wakes: at most one this often (spec section 5)...
pub const WAKE_EVERY: Duration = Duration::from_secs(10);
/// ...backing off, doubling each wake the phone fetched nothing real since
/// the last one, up to this.
// SPEC-GAP: the spec says "backing off" with no curve or ceiling.
pub const WAKE_MAX: Duration = Duration::from_secs(640);

/// Each kind of filter has its own third of the store (spec section 5).
const KIND_PACKETS: usize = HOLD_PACKETS / 3;
const KIND_BYTES: usize = HOLD_BYTES / 3;

/// The radio's number for one held packet. Not reused while this boot
/// holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HoldNumber(pub u32);

/// The signal level of a received packet, as the radio's receiver reports
/// it (carried to the phone in `RECEIVED`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signal(pub i16);

/// One wake filter.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Filter {
    /// A link receiver index (2 bytes, public on the air).
    Index(u16),
    /// A group id (2 bytes, public on the air).
    Group(u16),
    /// The handshake filter: the `mac1` key for the phone's messaging
    /// identity. Not a secret, but it ties the radio to its owner for
    /// anyone who knows the owner's messaging key, so `Debug` hides it.
    Handshake([u8; 32]),
}

impl std::fmt::Debug for Filter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Filter::Index(i) => write!(f, "Index({i})"),
            Filter::Group(g) => write!(f, "Group({g})"),
            Filter::Handshake(_) => f.write_str("Handshake(..)"),
        }
    }
}

/// The handshake filter for a messaging identity: its `mac1` key (link
/// spec section 2), which the phone sends in `FILTERS`. A hash of a public
/// key, not a secret.
pub fn handshake_filter(messaging_public: &[u8; 32]) -> [u8; 32] {
    mac1_key(messaging_public)
}

/// Which share of the store a packet belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Share {
    Index(u16),
    Group(u16),
    Handshake,
}

/// The wake filters (`FILTERS` replaces the whole list). Fixed size.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Filters {
    index: [u16; MAX_FILTERS_PER_KIND],
    n_index: usize,
    group: [u16; MAX_FILTERS_PER_KIND],
    n_group: usize,
    handshake: Option<[u8; 32]>,
}

impl std::fmt::Debug for Filters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Filters")
            .field("index", &&self.index[..self.n_index])
            .field("group", &&self.group[..self.n_group])
            .field("handshake", &self.handshake.is_some())
            .finish()
    }
}

impl Filters {
    /// No filters: nothing is held.
    pub fn none() -> Self {
        Self::default()
    }

    /// A whole list. Refused (`None`) if it has more than
    /// [`MAX_FILTERS_PER_KIND`] indexes or groups, more than one handshake
    /// filter, or the same filter twice.
    // SPEC-GAP: the spec does not say what a list with duplicates or too
    // many entries means; it is refused whole, and the old list stays.
    pub fn new(list: &[Filter]) -> Option<Self> {
        let mut f = Self::default();
        for item in list {
            match *item {
                Filter::Index(i) => {
                    if f.index[..f.n_index].contains(&i) || f.n_index == MAX_FILTERS_PER_KIND {
                        return None;
                    }
                    f.index[f.n_index] = i;
                    f.n_index += 1;
                }
                Filter::Group(g) => {
                    if f.group[..f.n_group].contains(&g) || f.n_group == MAX_FILTERS_PER_KIND {
                        return None;
                    }
                    f.group[f.n_group] = g;
                    f.n_group += 1;
                }
                Filter::Handshake(k) => {
                    if f.handshake.is_some() {
                        return None;
                    }
                    f.handshake = Some(k);
                }
            }
        }
        Some(f)
    }

    /// The filters as a list (for the store to save).
    pub fn list(&self) -> impl Iterator<Item = Filter> + '_ {
        self.index[..self.n_index]
            .iter()
            .map(|i| Filter::Index(*i))
            .chain(self.group[..self.n_group].iter().map(|g| Filter::Group(*g)))
            .chain(self.handshake.map(Filter::Handshake))
    }

    pub fn is_empty(&self) -> bool {
        self.n_index == 0 && self.n_group == 0 && self.handshake.is_none()
    }

    /// The share a packet from the air falls in, if it matches a filter.
    /// Only the packet's public header is looked at.
    fn matches(&self, packet: &[u8]) -> Option<Share> {
        if packet.is_empty() || packet.len() > MAX_HELD_PACKET {
            return None;
        }
        if let Some(g) = group_id(packet) {
            return self.group[..self.n_group]
                .contains(&g)
                .then_some(Share::Group(g));
        }
        match parse(packet, MAX_HELD_PACKET).ok()? {
            Packet::Data { receiver, .. } | Packet::Handshake2 { receiver, .. } => self.index
                [..self.n_index]
                .contains(&receiver)
                .then_some(Share::Index(receiver)),
            Packet::Handshake1 { signed, mac1, .. } => {
                let key = self.handshake.as_ref()?;
                mac1_ok(key, signed, mac1).then_some(Share::Handshake)
            }
        }
    }

    /// The packet and byte limit of a share under these filters; `None` if
    /// no current filter owns it (its filter was removed).
    fn quota(&self, share: Share) -> Option<(usize, usize)> {
        let (owned, n) = match share {
            Share::Index(i) => (self.index[..self.n_index].contains(&i), self.n_index),
            Share::Group(g) => (self.group[..self.n_group].contains(&g), self.n_group),
            Share::Handshake => (self.handshake.is_some(), 1),
        };
        // Each kind has a third; each index and each group its own equal
        // part of its kind's third.
        // SPEC-GAP: the spec says "its own share" without sizes; equal
        // thirds and equal parts are the plain reading.
        owned.then(|| (KIND_PACKETS / n, KIND_BYTES / n))
    }
}

/// Group packet header (group spec): type 4, bit 3 zero, the link version,
/// then the 2-byte group id; at least 27 bytes.
fn group_id(packet: &[u8]) -> Option<u16> {
    const GROUP_HEADER: u8 = (4 << 4) | VERSION;
    const GROUP_MIN: usize = 27;
    (packet.len() >= GROUP_MIN && packet[0] == GROUP_HEADER)
        .then(|| u16::from_be_bytes([packet[1], packet[2]]))
}

struct Entry {
    hold: HoldNumber,
    share: Share,
    /// Insertion order: oldest first.
    seq: u64,
    arrived: Duration,
    signal: Signal,
    len: usize,
    buf: [u8; MAX_HELD_PACKET],
    /// The session number it was last handed over in (0: never).
    delivered_in: u32,
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

/// The hold store: fixed slots in memory.
pub struct HoldStore {
    slots: [Option<Entry>; HOLD_PACKETS],
    bytes: usize,
    seq: u64,
    next_hold: u32,
}

impl Default for HoldStore {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for HoldStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HoldStore")
            .field("packets", &self.len())
            .field("bytes", &self.bytes)
            .finish()
    }
}

impl HoldStore {
    pub fn new() -> Self {
        Self {
            slots: std::array::from_fn(|_| None),
            bytes: 0,
            seq: 0,
            next_hold: 1,
        }
    }

    /// Packets held.
    pub fn len(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Bytes held.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Whether a packet with this number is held.
    pub fn holds(&self, hold: HoldNumber) -> bool {
        self.slots.iter().flatten().any(|e| e.hold == hold)
    }

    /// A packet from the air. Held if it matches `filters`, making room in
    /// its own share (oldest first), never in another's. Returns its hold
    /// number, or `None` if it was not held.
    pub fn offer(
        &mut self,
        now: Duration,
        packet: &[u8],
        signal: Signal,
        filters: &Filters,
    ) -> Option<HoldNumber> {
        let share = filters.matches(packet)?;
        let (q_packets, q_bytes) = filters.quota(share)?;
        let len = packet.len();
        if q_packets == 0 || len > q_bytes {
            return None;
        }
        // Room in its own share.
        loop {
            let (n, b) = self.usage(share);
            if n < q_packets && b + len <= q_bytes {
                break;
            }
            if !self.remove_oldest(|e| e.share == share) {
                return None;
            }
        }
        // Room in the whole store: the shares of current filters add up to
        // less than the limits, so only packets whose filter was removed can
        // be in the way; the oldest of those goes first.
        while self.len() >= HOLD_PACKETS || self.bytes + len > HOLD_BYTES {
            let orphan = |e: &Entry| filters.quota(e.share).is_none();
            if !self.remove_oldest(orphan) && !self.remove_oldest(|e| e.share == share) {
                return None;
            }
        }
        let hold = self.new_hold_number();
        let slot = self.slots.iter().position(Option::is_none)?;
        let mut buf = [0u8; MAX_HELD_PACKET];
        buf[..len].copy_from_slice(packet);
        self.seq += 1;
        self.bytes += len;
        self.slots[slot] = Some(Entry {
            hold,
            share,
            seq: self.seq,
            arrived: now,
            signal,
            len,
            buf,
            delivered_in: 0,
        });
        Some(hold)
    }

    /// Forget packets held longer than [`HOLD_FOR`].
    pub fn expire(&mut self, now: Duration) {
        for slot in self.slots.iter_mut() {
            if slot
                .as_ref()
                .is_some_and(|e| now >= e.arrived.saturating_add(HOLD_FOR))
            {
                self.bytes -= slot.as_ref().map_or(0, |e| e.len);
                *slot = None;
            }
        }
    }

    /// When the next packet expires.
    pub fn next_expiry(&self) -> Option<Duration> {
        self.slots
            .iter()
            .flatten()
            .map(|e| e.arrived.saturating_add(HOLD_FOR))
            .min()
    }

    /// Hand over, oldest first, every packet not yet handed over in
    /// `session`, and mark each one handed over. Nothing is deleted.
    /// `give` returns false if it could not pass the packet on; that packet
    /// stays unmarked.
    pub fn fetch(&mut self, session: u32, mut give: impl FnMut(HoldNumber, Signal, &[u8]) -> bool) {
        // Each pass marks one packet, so this ends after at most every slot;
        // the bound keeps it so even if that ever stopped being true.
        for _ in 0..HOLD_PACKETS {
            let next = self
                .slots
                .iter_mut()
                .flatten()
                .filter(|e| e.delivered_in != session)
                .min_by_key(|e| e.seq);
            let Some(e) = next else { break };
            // Mark first, so a packet `give` refuses is not offered again in
            // this call; unmark it after.
            let before = e.delivered_in;
            e.delivered_in = session;
            if !give(e.hold, e.signal, &e.buf[..e.len]) {
                e.delivered_in = before;
                break;
            }
        }
    }

    /// Mark one packet handed over in `session` (sent at once while the
    /// phone is connected).
    pub fn mark_delivered(&mut self, session: u32, hold: HoldNumber) {
        if let Some(e) = self.slots.iter_mut().flatten().find(|e| e.hold == hold) {
            e.delivered_in = session;
        }
    }

    /// `FETCH_ACK`: delete the named packets that were handed over in
    /// `session`, and no others. Returns how many were deleted.
    // SPEC-GAP: the spec says the radio deletes the acknowledged packets
    // "and no others". A number that was not handed over in this session
    // (from an older session, a reboot's reused number, or an app bug) is
    // ignored rather than deleted.
    pub fn ack(&mut self, session: u32, holds: &[HoldNumber]) -> usize {
        let mut n = 0;
        for slot in self.slots.iter_mut() {
            if slot
                .as_ref()
                .is_some_and(|e| e.delivered_in == session && holds.contains(&e.hold))
            {
                self.bytes -= slot.as_ref().map_or(0, |e| e.len);
                *slot = None;
                n += 1;
            }
        }
        n
    }

    /// Wipe everything (reset, replace).
    pub fn clear(&mut self) {
        for slot in self.slots.iter_mut() {
            *slot = None;
        }
        self.bytes = 0;
    }

    fn usage(&self, share: Share) -> (usize, usize) {
        self.slots
            .iter()
            .flatten()
            .filter(|e| e.share == share)
            .fold((0, 0), |(n, b), e| (n + 1, b + e.len))
    }

    /// Remove the oldest entry that `pick` accepts. False if none.
    fn remove_oldest(&mut self, pick: impl Fn(&Entry) -> bool) -> bool {
        let oldest = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.as_ref().map(|e| (i, e)))
            .filter(|(_, e)| pick(e))
            .min_by_key(|(_, e)| e.seq)
            .map(|(i, _)| i);
        match oldest {
            Some(i) => {
                self.bytes -= self.slots[i].as_ref().map_or(0, |e| e.len);
                self.slots[i] = None;
                true
            }
            None => false,
        }
    }

    fn new_hold_number(&mut self) -> HoldNumber {
        loop {
            let h = HoldNumber(self.next_hold);
            self.next_hold = self.next_hold.wrapping_add(1).max(1);
            if !self.holds(h) {
                return h;
            }
        }
    }
}

/// The wake limit (spec section 5): at most one wake every
/// [`WAKE_EVERY`], doubling up to [`WAKE_MAX`] after each wake that was not
/// followed by a `FETCH_ACK` naming at least one packet.
#[derive(Debug, Clone)]
pub struct WakeLimit {
    /// Something was held since the last wake.
    pending: bool,
    /// A `FETCH_ACK` named a held packet since the last wake.
    paid: bool,
    interval: Duration,
    next_allowed: Option<Duration>,
}

impl Default for WakeLimit {
    fn default() -> Self {
        Self::new()
    }
}

impl WakeLimit {
    pub fn new() -> Self {
        Self {
            pending: false,
            paid: false,
            interval: WAKE_EVERY,
            next_allowed: None,
        }
    }

    /// A packet was held while the phone was not connected.
    pub fn held(&mut self) {
        self.pending = true;
    }

    /// The phone connected: it is told what is held (`HELD`), so nothing
    /// earlier is waiting for a wake.
    pub fn connected(&mut self) {
        self.pending = false;
    }

    /// A `FETCH_ACK` named at least one held packet: the wakes were real.
    pub fn real_ack(&mut self) {
        self.paid = true;
        self.interval = WAKE_EVERY;
    }

    /// When a wake is next due, if one is waiting.
    pub fn due(&self) -> Option<Duration> {
        self.pending
            .then(|| self.next_allowed.unwrap_or(Duration::ZERO))
    }

    /// Wake now if one is waiting and allowed. Returns true if it woke.
    pub fn poll(&mut self, now: Duration) -> bool {
        if !self.pending || self.next_allowed.is_some_and(|t| now < t) {
            return false;
        }
        if self.next_allowed.is_some() && !self.paid {
            self.interval = self.interval.saturating_mul(2).min(WAKE_MAX);
        }
        self.pending = false;
        self.paid = false;
        self.next_allowed = Some(now.saturating_add(self.interval));
        true
    }
}
