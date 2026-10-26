//! The OASA-SEC encrypted link, wire version 1 (tech tree node R-COM2). Spec:
//! `docs/oasa-sec-v0-link.md`.
//!
//! This module is **sans-IO**: it never opens a socket, starts a thread or
//! reads a clock. You pass in bytes and the time; it hands back events (bytes
//! to send, plaintext to deliver, drops to log). The same code runs on a
//! laptop, a companion computer, and later a microcontroller, and tests drive
//! it through a simulated channel.
//!
//! - [`Link`]: one encrypted link to one trusted peer. Start here.
//! - [`Endpoint`]: the same for several trusted peers at once (one ground
//!   station serving several drones). It decrypts handshake 1 to learn who is
//!   calling, checks the list, and routes everything by index.
//!   [`Link`] is a thin wrapper around an `Endpoint` with one peer.
//!
//! Time is a monotonic [`Duration`] since any fixed start, passed to every
//! call. Wall-clock time is only needed for the handshake timestamp and is
//! given once, as the wall time at monotonic zero (`wall_base`).
//!
//! Every invalid, untrusted or replayed packet is dropped without any reply.
//! Drops are counted by reason in [`Stats`].

mod counter;
mod endpoint;
mod packet;
mod session;
mod source;
mod stamp;
#[cfg(test)]
mod tests;
mod timing;

use std::fmt;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::identity::Identity;
use crate::{Error, Result};

pub use counter::{ReplayWindow, WINDOW_SIZE, rebuild_counter};
pub use endpoint::{Endpoint, PeerId};
pub use packet::{
    CounterLen, HANDSHAKE1_LEN, HANDSHAKE2_LEN, Packet, TAG_LEN, VERSION, data_overhead,
    keepalive_len, parse,
};
pub use source::{SourceLimiter, looks_like_handshake1};
pub use stamp::{
    FileTimestampStore, MemoryTimestampStore, StoredStamps, Timestamp, TimestampStore,
};
#[cfg(test)]
pub(crate) use timing::lora_airtime;
pub use timing::{RadioProfile, jittered};

/// The Noise protocol used for the link.
pub const LINK_NOISE: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// Prologue mixed into every link handshake.
pub const LINK_PROLOGUE: &[u8] = b"OASA-SEC v1 link";

/// Content type byte at the start of every non-empty data plaintext: an
/// application packet (spec section 3).
pub const CONTENT_APP: u8 = 0x00;
/// Content type byte: a control message (see [`crate::control`]).
pub const CONTENT_CONTROL: u8 = 0x01;

/// Smallest packet size (MTU) the link supports, in bytes.
pub const MIN_MTU: usize = 128;

/// Settings. [`Config::default`] has the spec section 5 values.
#[derive(Debug, Clone)]
pub struct Config {
    /// Counter length on data packets we send. We accept both on receive.
    pub counter_len: CounterLen,
    /// Largest packet we send or accept, in bytes (at least [`MIN_MTU`]).
    pub mtu: usize,
    /// The initiator starts a new handshake after this long...
    pub rekey_after: Duration,
    /// ...or after this many packets sent.
    pub rekey_after_packets: u64,
    /// Nobody sends or accepts on a session after this long...
    pub reject_after: Duration,
    /// ...or after this many packets (at most 2^60).
    pub reject_after_packets: u64,
    /// First handshake retry delay. Doubles each try.
    pub retry_initial: Duration,
    /// Longest handshake retry delay.
    pub retry_max: Duration,
    /// Send a keepalive when nothing was sent for this long. `None` is off.
    pub keepalive: Option<Duration>,
    /// A side that has sent payload packets on its session but heard nothing
    /// authenticated for this long starts a new handshake (WireGuard's rule:
    /// keepalive time plus retry time). Applies with keepalives off too. The
    /// peer answers payload it receives with a keepalive after half of this,
    /// so a healthy one-way link does not trip it.
    pub stale_after: Duration,
    /// How long a replaced session stays readable (for packets still in the
    /// air), counted from the last packet that arrived on it.
    pub previous_grace: Duration,
    /// Handshake 1 packets processed per second, in total.
    pub handshakes_per_second: u32,
    /// Shortest gap between accepted handshakes from one peer.
    pub peer_handshake_gap: Duration,
    /// Only for devices with a trusted clock. A handshake 1 whose timestamp
    /// is more than this far ahead of the wall clock is refused and not
    /// recorded. `None` (the default) is off: a device with a slow or unset
    /// clock must not refuse every handshake. The wall clock is read at
    /// each check from the clock given to `set_wall_clock`.
    pub max_future: Option<Duration>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            counter_len: CounterLen::Short,
            mtu: MIN_MTU,
            rekey_after: Duration::from_secs(10 * 60),
            rekey_after_packets: 1 << 32,
            reject_after: Duration::from_secs(15 * 60),
            reject_after_packets: 1 << 60,
            retry_initial: Duration::from_secs(5),
            retry_max: Duration::from_secs(60),
            keepalive: Some(Duration::from_secs(25)),
            stale_after: Duration::from_secs(30),
            previous_grace: Duration::from_secs(10),
            handshakes_per_second: 20,
            peer_handshake_gap: Duration::from_secs(1),
            max_future: None,
        }
    }
}

impl Config {
    /// Refuse settings that would break the protocol's safety rules.
    pub fn validate(&self) -> Result<()> {
        let bad = |why: &'static str| Err(Error::Link(why));
        if self.mtu < MIN_MTU {
            return bad("mtu is below 128 bytes");
        }
        if self.mtu > 65_535 {
            return bad("mtu is above 65535 bytes");
        }
        if self.reject_after_packets == 0 || self.reject_after_packets > 1 << 60 {
            return bad("reject_after_packets must be 1 to 2^60");
        }
        if self.rekey_after_packets >= self.reject_after_packets {
            return bad("rekey_after_packets must be below reject_after_packets");
        }
        if self.rekey_after.is_zero() || self.rekey_after >= self.reject_after {
            return bad("rekey_after must be above zero and below reject_after");
        }
        if self.retry_initial.is_zero() || self.retry_max < self.retry_initial {
            return bad("retry_initial must be above zero and not above retry_max");
        }
        if self.handshakes_per_second == 0 || self.handshakes_per_second > 100_000 {
            return bad("handshakes_per_second must be 1 to 100000");
        }
        if self.stale_after.is_zero() {
            return bad("stale_after must be above zero");
        }
        // Timers that must fit together on a slow radio (spec section 5).
        if self.stale_after < self.retry_initial.saturating_mul(2) {
            return bad("stale_after must be at least twice retry_initial");
        }
        if self.peer_handshake_gap > self.retry_initial {
            return bad("peer_handshake_gap must not be above retry_initial");
        }
        // A slow retry with a short rekey time would be rekeying all the time.
        // (Fast timers keep any rekey time: short ones are used in tests.)
        if self.retry_initial > Config::default().retry_initial
            && self.rekey_after < self.retry_initial.saturating_mul(4)
        {
            return bad("rekey_after must be at least 4 times retry_initial");
        }
        if self.reject_after.saturating_sub(self.rekey_after) < self.retry_initial {
            return bad("reject_after must be at least retry_initial above rekey_after");
        }
        // Time arithmetic never overflows if every setting stays under ten years.
        let cap = Duration::from_secs(10 * 365 * 86_400);
        if [
            self.reject_after,
            self.retry_max,
            self.stale_after,
            self.previous_grace,
            self.peer_handshake_gap,
            self.max_future.unwrap_or_default(),
            self.keepalive.unwrap_or_default(),
        ]
        .iter()
        .any(|d| *d > cap)
        {
            return bad("a time setting is over ten years");
        }
        if self.keepalive.is_some_and(|k| k.is_zero()) {
            return bad("keepalive must be above zero (use None for off)");
        }
        Ok(())
    }
}

/// The current Unix time (since 1970), read when asked. For the
/// `max_future` check only; the caller says how to read its clock. Any
/// `FnMut() -> Duration` works.
pub trait WallClock {
    fn now(&mut self) -> Duration;
}

impl<F: FnMut() -> Duration> WallClock for F {
    fn now(&mut self) -> Duration {
        self()
    }
}

/// Source of random bytes (session indexes). Handshake keys come from
/// `snow`, which uses the operating system directly, so those are not
/// affected by this. Tests pass a seeded generator here.
pub trait Entropy {
    fn fill(&mut self, dst: &mut [u8]);
}

/// The operating system's random source. If it fails, this panics: carrying
/// on with weak randomness would be worse.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsEntropy;

impl Entropy for OsEntropy {
    fn fill(&mut self, dst: &mut [u8]) {
        getrandom::fill(dst).expect("operating system random source failed");
    }
}

/// Why a received packet was dropped. Names are the ones in spec section 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DropReason {
    BadHeader,
    UnknownIndex,
    TooOld,
    BadTag,
    Replay,
    UntrustedPeer,
    StaleHandshake,
    RateLimited,
    /// Authenticated, but the content type byte is unknown (or there is
    /// nothing after it).
    BadContent,
}

impl DropReason {
    pub const ALL: [DropReason; 9] = [
        DropReason::BadHeader,
        DropReason::UnknownIndex,
        DropReason::TooOld,
        DropReason::BadTag,
        DropReason::Replay,
        DropReason::UntrustedPeer,
        DropReason::StaleHandshake,
        DropReason::RateLimited,
        DropReason::BadContent,
    ];

    /// The name used in logs and stats.
    pub fn as_str(self) -> &'static str {
        match self {
            DropReason::BadHeader => "bad_header",
            DropReason::UnknownIndex => "unknown_index",
            DropReason::TooOld => "too_old",
            DropReason::BadTag => "bad_tag",
            DropReason::Replay => "replay",
            DropReason::UntrustedPeer => "untrusted_peer",
            DropReason::StaleHandshake => "stale_handshake",
            DropReason::RateLimited => "rate_limited",
            DropReason::BadContent => "bad_content",
        }
    }

    fn slot(self) -> usize {
        self as usize
    }
}

impl fmt::Display for DropReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why [`Link::send`] could not make a packet. Nothing was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    /// Empty plaintext is reserved for keepalives.
    Empty,
    /// The packet would be larger than the MTU.
    TooLarge,
    /// No usable session yet (or it expired).
    NoSession,
    /// No such peer.
    UnknownPeer,
}

impl SendError {
    pub fn as_str(self) -> &'static str {
        match self {
            SendError::Empty => "empty",
            SendError::TooLarge => "too_large",
            SendError::NoSession => "no_session",
            SendError::UnknownPeer => "unknown_peer",
        }
    }
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SendError::Empty => "empty packets are reserved for keepalives",
            SendError::TooLarge => "packet is larger than the MTU allows",
            SendError::NoSession => "no usable session",
            SendError::UnknownPeer => "no such peer",
        })
    }
}

impl std::error::Error for SendError {}

/// Counters. Never contains packet contents.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    /// Data packets with a payload that we sent (not keepalives).
    pub sent: u64,
    /// Data packets with a payload that passed every check.
    pub received: u64,
    /// Plaintexts handed to the caller. Equals `received`.
    pub delivered: u64,
    /// Control messages sent (they are not counted in `sent`).
    pub control_sent: u64,
    /// Control messages that passed every check (not counted in `received`).
    pub control_received: u64,
    pub keepalives_sent: u64,
    pub keepalives_received: u64,
    pub handshakes_sent: u64,
    /// Handshake 1 packets that were accepted and answered.
    pub handshakes_accepted: u64,
    /// Handshake 2 packets accepted (we were the initiator).
    pub handshakes_completed: u64,
    drops: [u64; 9],
}

impl Stats {
    /// How many packets were dropped for `reason`.
    pub fn dropped(&self, reason: DropReason) -> u64 {
        self.drops[reason.slot()]
    }

    /// All drop counts, in spec order, zeros included.
    pub fn drops(&self) -> impl Iterator<Item = (DropReason, u64)> + '_ {
        DropReason::ALL.iter().map(|r| (*r, self.dropped(*r)))
    }

    pub fn total_dropped(&self) -> u64 {
        self.drops.iter().sum()
    }

    pub(crate) fn count_drop(&mut self, reason: DropReason) {
        self.drops[reason.slot()] += 1;
    }
}

/// Where a packet the link wants sent should go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dest {
    /// The peer's known address (configured, or learned from the last packet
    /// that authenticated).
    Remote,
    /// The address the packet being handled came from. Used only for
    /// handshake 2, which is the one reply to a peer we have no data from.
    Source,
}

/// Something the link wants the caller to do or log.
#[derive(Clone, PartialEq, Eq)]
pub enum Event {
    /// Transmit this packet.
    Send { packet: Vec<u8>, to: Dest },
    /// An application packet arrived, authenticated and not replayed. The
    /// content type byte is already removed.
    Deliver(Vec<u8>),
    /// A control message arrived, authenticated and not replayed: its bytes
    /// (type, request id, body) without the content type byte. Never goes to
    /// the application side; hand it to [`crate::control::Control`].
    Control(Zeroizing<Vec<u8>>),
    /// A data packet (or keepalive) passed every check. The caller may
    /// update the peer's address to where it came from. Always comes before
    /// the `Send` and `Deliver` it causes.
    Authenticated,
    /// A handshake 1 was made. `retry`: no answer came to the last one.
    /// `rekey`: a session already exists.
    HandshakeSent { retry: bool, rekey: bool },
    /// A session is now the one we send on. `rekey`: it replaced another.
    SessionEstablished { initiator: bool, rekey: bool },
    /// A received packet was dropped (and not answered).
    Dropped(DropReason),
    /// Something local failed (for example saving the handshake timestamp).
    /// The link stays safe: it did not send what it could not make safe.
    Failure(&'static str),
}

impl fmt::Debug for Event {
    // Never prints packet contents.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Event::Send { packet, to } => write!(f, "Send({} bytes, {to:?})", packet.len()),
            Event::Deliver(p) => write!(f, "Deliver({} bytes)", p.len()),
            Event::Control(p) => write!(f, "Control({} bytes)", p.len()),
            Event::Authenticated => f.write_str("Authenticated"),
            Event::HandshakeSent { retry, rekey } => {
                write!(f, "HandshakeSent(retry={retry}, rekey={rekey})")
            }
            Event::SessionEstablished { initiator, rekey } => {
                write!(
                    f,
                    "SessionEstablished(initiator={initiator}, rekey={rekey})"
                )
            }
            Event::Dropped(r) => write!(f, "Dropped({r})"),
            Event::Failure(why) => write!(f, "Failure({why})"),
        }
    }
}

/// One encrypted link to one trusted peer.
pub struct Link {
    ep: Endpoint,
    id: PeerId,
}

impl fmt::Debug for Link {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Link").finish_non_exhaustive()
    }
}

impl Link {
    /// Make a link from our identity to `peer_public`.
    ///
    /// `wall_base` is the Unix time (since 1970) at monotonic zero, or
    /// `Duration::ZERO` if the device has no trusted clock. The handshake
    /// timestamp is then `max(clock, last sent + 1 ns)` and survives reboots
    /// through `store`.
    pub fn new(
        identity: &Identity,
        peer_public: [u8; 32],
        config: Config,
        entropy: Box<dyn Entropy>,
        wall_base: Duration,
        store: Box<dyn TimestampStore>,
    ) -> Result<Self> {
        let mut ep = Endpoint::new(identity, config, entropy, wall_base)?;
        let id = ep.add_peer(peer_public, store)?;
        Ok(Self { ep, id })
    }

    /// Start a handshake as the initiator. Returns the packet to send and
    /// the events that go with it. Calling it again restarts the attempt.
    pub fn start_handshake(&mut self, now: Duration) -> Result<Vec<Event>> {
        self.ep.start_handshake(self.id, now)
    }

    /// Give the clock that `Config::max_future` is checked against. Without
    /// one, the check uses `wall_base` plus the monotonic time.
    pub fn set_wall_clock(&mut self, clock: Box<dyn WallClock>) {
        self.ep.set_wall_clock(clock);
    }

    /// Process one received packet.
    pub fn handle_packet(&mut self, now: Duration, packet: &[u8]) -> Vec<Event> {
        self.ep
            .handle_packet(now, packet)
            .into_iter()
            .map(|(_, e)| e)
            .collect()
    }

    /// Encrypt an application packet on the current session (the link adds
    /// the content type byte). Returns the packet.
    pub fn send(
        &mut self,
        now: Duration,
        plaintext: &[u8],
    ) -> std::result::Result<Vec<u8>, SendError> {
        self.ep.send(self.id, now, plaintext)
    }

    /// Encrypt a control message (`[type][request id][body]`) on the current
    /// session. Returns the packet.
    pub fn send_control(
        &mut self,
        now: Duration,
        message: &[u8],
    ) -> std::result::Result<Vec<u8>, SendError> {
        self.ep.send_control(self.id, now, message)
    }

    /// Run timers: expiry, rekey, handshake retries, keepalives. Call at
    /// least every few hundred milliseconds, and after anything that takes
    /// time.
    pub fn poll_timers(&mut self, now: Duration) -> Vec<Event> {
        self.ep
            .poll_timers(now)
            .into_iter()
            .map(|(_, e)| e)
            .collect()
    }

    pub fn stats(&self) -> &Stats {
        self.ep.stats()
    }

    /// Whether a session exists that we can send on.
    pub fn can_send(&self) -> bool {
        self.ep.can_send(self.id)
    }
}

/// Copy the private key out of an identity so the link can build handshakes.
/// Wiped when dropped.
pub(crate) fn private_copy(id: &Identity) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(*id.private_key())
}
