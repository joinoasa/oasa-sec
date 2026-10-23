//! The link state machine for one or more trusted peers.
//!
//! # Design
//!
//! An [`Endpoint`] owns our identity, the settings, the random source, the
//! counters and one [`PeerLink`] per trusted peer. Everything arrives through
//! [`Endpoint::handle_packet`] and comes out as events.
//!
//! Routing:
//! - **Data and handshake 2** carry our own random 16-bit index, so they go
//!   straight to the right peer without trying any keys.
//! - **Handshake 1** carries no way to tell who sent it, because in Noise IK
//!   the initiator's key is encrypted. So the endpoint runs the (one) X25519
//!   handshake read, takes the initiator's static key out of it, and looks it
//!   up in the trusted list. Not in the list: dropped, no reply. In the list:
//!   the finished read is handed to that peer's `PeerLink`. Nothing is
//!   decrypted twice.
//!
//! Each peer has up to four slots:
//! - `hs`: our handshake 1 waiting for an answer (we are the initiator);
//! - `current`: the session we send on;
//! - `previous`: the session just replaced, readable for a short grace;
//! - `pending`: a session we answered as the responder but that has not yet
//!   carried a valid data packet. It is readable but never sent on. The first
//!   valid data packet promotes it to `current` (spec section 5).

use std::time::Duration;

use snow::params::NoiseParams;
use zeroize::Zeroizing;

use super::packet::{self, CounterLen, Packet};
use super::session::Session;
use super::stamp::{StoredStamps, Timestamp, TimestampStore};
use super::{
    Config, Dest, DropReason, Entropy, Event, LINK_NOISE, LINK_PROLOGUE, SendError, Stats,
    private_copy,
};
use crate::identity::Identity;
use crate::{Error, Result};

/// Names a peer inside an [`Endpoint`]. Stays valid until the peer is removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerId(pub usize);

/// Events from an [`Endpoint`], with the peer they belong to (`None` when it
/// was dropped before we could tell who it was for).
pub type PeerEvents = Vec<(Option<PeerId>, Event)>;

struct Shared {
    private: Zeroizing<[u8; 32]>,
    public: [u8; 32],
    /// Key for checking `mac1` on handshake 1 packets sent to us.
    mac1_key: [u8; 32],
    cfg: Config,
    rng: Box<dyn Entropy>,
    wall_base: Duration,
    limiter: Bucket,
    stats: Stats,
}

/// Token bucket in thousandths of a token.
struct Bucket {
    milli: u64,
    cap: u64,
    per_ms: u64,
    last: Duration,
}

impl Bucket {
    fn new(per_second: u32) -> Self {
        let cap = u64::from(per_second) * 1000;
        Self {
            milli: cap,
            cap,
            per_ms: u64::from(per_second),
            last: Duration::ZERO,
        }
    }

    fn allow(&mut self, now: Duration) -> bool {
        let ms = now.saturating_sub(self.last).as_millis().min(1 << 40) as u64;
        if now > self.last {
            self.last = now;
        }
        self.milli = (self.milli + ms * self.per_ms).min(self.cap);
        if self.milli >= 1000 {
            self.milli -= 1000;
            true
        } else {
            false
        }
    }
}

struct InFlight {
    state: snow::HandshakeState,
    local_index: u16,
    next_retry: Duration,
    attempt: u32,
}

struct PeerLink {
    public: [u8; 32],
    store: Box<dyn TimestampStore>,
    stamps: StoredStamps,
    last_accept: Option<Duration>,
    /// We have started handshakes with this peer, so we also restart them
    /// (rekey, retry, after expiry).
    initiator_role: bool,
    /// Do not try to start a handshake before this (after a local failure).
    hold_until: Duration,
    /// Handshakes started because our newest session was never confirmed.
    /// Slows the retries down (backoff); reset when a session is confirmed.
    unconfirmed_rounds: u32,
    /// When we first sent a payload packet after the last authenticated
    /// packet we received (None: nothing is waiting for an answer).
    awaiting_since: Option<Duration>,
    /// When we first received payload after the last packet we sent (we owe
    /// the peer a sign of life).
    owe_ack_since: Option<Duration>,
    /// We tried to send with no session: start a handshake ourselves.
    wants_session: Option<Duration>,
    hs: Option<InFlight>,
    current: Option<Session>,
    /// A replaced session and when it last carried a valid packet.
    previous: Option<(Session, Duration)>,
    pending: Option<Session>,
}

/// Several trusted peers behind one identity and one address.
pub struct Endpoint {
    sh: Shared,
    peers: Vec<Option<PeerLink>>,
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Endpoint").finish_non_exhaustive()
    }
}

/// How far ahead of our clock a handshake 1 timestamp may be (10 minutes).
const MAX_FUTURE_SECS: u64 = 600;

fn noise_params() -> NoiseParams {
    LINK_NOISE.parse().expect("valid Noise name")
}

impl Endpoint {
    /// See [`super::Link::new`] for `wall_base`.
    pub fn new(
        identity: &Identity,
        config: Config,
        entropy: Box<dyn Entropy>,
        wall_base: Duration,
    ) -> Result<Self> {
        config.validate()?;
        let limiter = Bucket::new(config.handshakes_per_second);
        Ok(Self {
            sh: Shared {
                private: private_copy(identity),
                public: *identity.public_key(),
                mac1_key: packet::mac1_key(identity.public_key()),
                cfg: config,
                rng: entropy,
                wall_base,
                limiter,
                stats: Stats::default(),
            },
            peers: Vec::new(),
        })
    }

    /// Trust `public`: it may open sessions with us, and we may open them
    /// with it. Refuses our own key and keys already added.
    pub fn add_peer(
        &mut self,
        public: [u8; 32],
        mut store: Box<dyn TimestampStore>,
    ) -> Result<PeerId> {
        crate::identity::check_peer_public(&public)?;
        if public == self.sh.public {
            return Err(Error::Link("a device cannot be its own peer"));
        }
        if self.peers.iter().flatten().any(|p| p.public == public) {
            return Err(Error::Link("peer already added"));
        }
        let stamps = store.load()?;
        self.peers.push(Some(PeerLink {
            public,
            store,
            stamps,
            last_accept: None,
            initiator_role: false,
            hold_until: Duration::ZERO,
            unconfirmed_rounds: 0,
            awaiting_since: None,
            owe_ack_since: None,
            wants_session: None,
            hs: None,
            current: None,
            previous: None,
            pending: None,
        }));
        Ok(PeerId(self.peers.len() - 1))
    }

    /// Stop trusting a peer and wipe its sessions (spec section 6).
    pub fn remove_peer(&mut self, id: PeerId) {
        if let Some(slot) = self.peers.get_mut(id.0) {
            *slot = None;
        }
    }

    pub fn stats(&self) -> &Stats {
        &self.sh.stats
    }

    /// Whether a session exists that we can send on.
    pub fn can_send(&self, id: PeerId) -> bool {
        self.peer(id).is_some_and(|p| p.current.is_some())
    }

    fn peer(&self, id: PeerId) -> Option<&PeerLink> {
        self.peers.get(id.0).and_then(Option::as_ref)
    }

    pub(crate) fn live_indexes(&self) -> Vec<u16> {
        let mut v = Vec::new();
        for p in self.peers.iter().flatten() {
            v.extend(p.hs.iter().map(|h| h.local_index));
            v.extend(p.current.iter().map(|s| s.local_index));
            v.extend(p.previous.iter().map(|(s, _)| s.local_index));
            v.extend(p.pending.iter().map(|s| s.local_index));
        }
        v
    }

    fn drop_packet(&mut self, reason: DropReason, out: &mut PeerEvents) {
        self.sh.stats.count_drop(reason);
        out.push((None, Event::Dropped(reason)));
    }

    /// Start a handshake with `id` as the initiator. Returns the events
    /// (the packet to send). Fails, sending nothing, if the timestamp could
    /// not be saved.
    pub fn start_handshake(&mut self, id: PeerId, now: Duration) -> Result<Vec<Event>> {
        let taken = self.live_indexes();
        let Some(Some(peer)) = self.peers.get_mut(id.0) else {
            return Err(Error::Link("no such peer"));
        };
        peer.initiator_role = true;
        let mut out = Vec::new();
        peer.begin_handshake(&mut self.sh, &taken, now, 0, &mut out)?;
        Ok(out)
    }

    /// Process one received packet. Invalid packets produce only a
    /// `Dropped` event, never a reply.
    pub fn handle_packet(&mut self, now: Duration, buf: &[u8]) -> PeerEvents {
        let mut out = PeerEvents::new();
        let parsed = match packet::parse(buf, self.sh.cfg.mtu) {
            Ok(p) => p,
            Err(r) => {
                self.drop_packet(r, &mut out);
                return out;
            }
        };
        match parsed {
            Packet::Handshake1 {
                signed,
                noise,
                mac1,
            } => self.on_handshake1(now, signed, mac1, noise, &mut out),
            Packet::Handshake2 { receiver, noise } => {
                let found = self.peers.iter().position(|p| {
                    p.as_ref()
                        .is_some_and(|p| p.hs.as_ref().is_some_and(|h| h.local_index == receiver))
                });
                match found {
                    Some(i) => {
                        let mut ev = Vec::new();
                        let peer = self.peers[i].as_mut().expect("found above");
                        peer.on_handshake2(&mut self.sh, now, noise, &mut ev);
                        out.extend(ev.into_iter().map(|e| (Some(PeerId(i)), e)));
                    }
                    None => self.drop_packet(DropReason::UnknownIndex, &mut out),
                }
            }
            Packet::Data {
                receiver,
                counter_len,
                low,
                ciphertext,
            } => {
                let found = self
                    .peers
                    .iter()
                    .position(|p| p.as_ref().is_some_and(|p| p.has_session_index(receiver)));
                match found {
                    Some(i) => {
                        let mut ev = Vec::new();
                        let peer = self.peers[i].as_mut().expect("found above");
                        peer.on_data(
                            &mut self.sh,
                            now,
                            receiver,
                            counter_len,
                            low,
                            ciphertext,
                            &mut ev,
                        );
                        out.extend(ev.into_iter().map(|e| (Some(PeerId(i)), e)));
                    }
                    None => self.drop_packet(DropReason::UnknownIndex, &mut out),
                }
            }
        }
        out
    }

    fn on_handshake1(
        &mut self,
        now: Duration,
        signed: &[u8],
        mac1: &[u8],
        noise: &[u8],
        out: &mut PeerEvents,
    ) {
        // Cheapest check first: random junk must not use up the handshake
        // budget, so mac1 comes before the global limit.
        if !packet::mac1_ok(&self.sh.mac1_key, signed, mac1) {
            self.drop_packet(DropReason::BadHeader, out);
            return;
        }
        // Next, the only expensive step is the X25519 read, so the global
        // limit comes before it.
        if !self.sh.limiter.allow(now) {
            self.drop_packet(DropReason::RateLimited, out);
            return;
        }
        let built = snow::Builder::new(noise_params())
            .local_private_key(&self.sh.private[..])
            .and_then(|b| b.prologue(LINK_PROLOGUE))
            .and_then(|b| b.build_responder());
        let mut hs = match built {
            Ok(h) => h,
            Err(_) => {
                out.push((None, Event::Failure("could not start a handshake")));
                return;
            }
        };
        let mut payload = [0u8; 64];
        let n = match hs.read_message(noise, &mut payload) {
            Ok(n) => n,
            Err(_) => {
                self.drop_packet(DropReason::BadTag, out);
                return;
            }
        };
        let remote: Option<[u8; 32]> = hs.get_remote_static().and_then(|s| s.try_into().ok());
        let Some(remote) = remote else {
            self.drop_packet(DropReason::BadTag, out);
            return;
        };
        let found = self
            .peers
            .iter()
            .position(|p| p.as_ref().is_some_and(|p| p.public == remote));
        let Some(i) = found else {
            // Not trusted: no reply, not even an error.
            self.drop_packet(DropReason::UntrustedPeer, out);
            return;
        };
        // Payload: 12-byte timestamp, then the initiator's index.
        let parsed = (n == Timestamp::LEN + 2)
            .then(|| Timestamp::from_bytes(&payload[..Timestamp::LEN]))
            .flatten();
        let Some(ts) = parsed else {
            self.drop_packet(DropReason::BadHeader, out);
            return;
        };
        let sender = u16::from_be_bytes([payload[Timestamp::LEN], payload[Timestamp::LEN + 1]]);
        let taken = self.live_indexes();
        let mut ev = Vec::new();
        let peer = self.peers[i].as_mut().expect("found above");
        peer.accept_initiation(&mut self.sh, &taken, now, hs, sender, ts, &mut ev);
        out.extend(ev.into_iter().map(|e| (Some(PeerId(i)), e)));
    }

    /// Encrypt `plaintext` for `id` on its current session.
    pub fn send(
        &mut self,
        id: PeerId,
        now: Duration,
        plaintext: &[u8],
    ) -> std::result::Result<Vec<u8>, SendError> {
        if plaintext.is_empty() {
            return Err(SendError::Empty);
        }
        let Some(Some(peer)) = self.peers.get_mut(id.0) else {
            return Err(SendError::UnknownPeer);
        };
        let Some(cur) = peer.current.as_mut() else {
            peer.wants_session.get_or_insert(now);
            return Err(SendError::NoSession);
        };
        let packet = match cur.encrypt(now, &self.sh.cfg, plaintext) {
            Ok(p) => p,
            Err(e) => {
                if e == SendError::NoSession {
                    peer.wants_session.get_or_insert(now);
                }
                return Err(e);
            }
        };
        peer.awaiting_since.get_or_insert(now);
        peer.owe_ack_since = None;
        self.sh.stats.sent += 1;
        Ok(packet)
    }

    /// Run timers for every peer.
    pub fn poll_timers(&mut self, now: Duration) -> PeerEvents {
        let mut out = PeerEvents::new();
        for i in 0..self.peers.len() {
            let taken = self.live_indexes();
            let Some(peer) = self.peers[i].as_mut() else {
                continue;
            };
            let mut ev = Vec::new();
            peer.poll(&mut self.sh, &taken, now, &mut ev);
            out.extend(ev.into_iter().map(|e| (Some(PeerId(i)), e)));
        }
        out
    }
}

/// A random index that no live session or handshake uses.
fn pick_index(rng: &mut dyn Entropy, taken: &[u16]) -> Option<u16> {
    for _ in 0..64 {
        let mut b = [0u8; 2];
        rng.fill(&mut b);
        let i = u16::from_be_bytes(b);
        if !taken.contains(&i) {
            return Some(i);
        }
    }
    // Nearly full (not expected): take the first free one after a random start.
    let mut b = [0u8; 2];
    rng.fill(&mut b);
    let start = u16::from_be_bytes(b);
    (0..=u16::MAX)
        .map(|k| start.wrapping_add(k))
        .find(|i| !taken.contains(i))
}

fn backoff(cfg: &Config, attempt: u32) -> Duration {
    let mult = 1u32 << attempt.min(16);
    cfg.retry_initial
        .checked_mul(mult)
        .unwrap_or(cfg.retry_max)
        .min(cfg.retry_max)
}

impl PeerLink {
    fn has_session_index(&self, i: u16) -> bool {
        self.current.as_ref().is_some_and(|s| s.local_index == i)
            || self
                .previous
                .as_ref()
                .is_some_and(|(s, _)| s.local_index == i)
            || self.pending.as_ref().is_some_and(|s| s.local_index == i)
    }

    /// Make and send handshake 1. Saves the timestamp first.
    fn begin_handshake(
        &mut self,
        sh: &mut Shared,
        taken: &[u16],
        now: Duration,
        attempt: u32,
        out: &mut Vec<Event>,
    ) -> Result<()> {
        let wall = Timestamp::from_duration(sh.wall_base + now);
        let ts = match self.stamps.sent {
            Some(last) if last >= wall => last.next(),
            _ => wall,
        };
        let Some(index) = pick_index(&mut *sh.rng, taken) else {
            return Err(Error::Link("no free session index"));
        };
        let mut hs = snow::Builder::new(noise_params())
            .local_private_key(&sh.private[..])
            .and_then(|b| b.remote_public_key(&self.public))
            .and_then(|b| b.prologue(LINK_PROLOGUE))
            .and_then(|b| b.build_initiator())
            .map_err(Error::from)?;
        let mut buf = [0u8; 128];
        let mut payload = [0u8; Timestamp::LEN + 2];
        payload[..Timestamp::LEN].copy_from_slice(&ts.to_bytes());
        payload[Timestamp::LEN..].copy_from_slice(&index.to_be_bytes());
        let n = hs.write_message(&payload, &mut buf)?;
        // Save before the packet can leave: a crash must never let us send
        // an older timestamp later.
        let mut next = self.stamps;
        next.sent = Some(ts);
        self.store.save(&next)?;
        self.stamps = next;
        let packet = packet::encode_handshake1(&self.public, &buf[..n]);
        self.hs = Some(InFlight {
            state: hs,
            local_index: index,
            next_retry: now + backoff(&sh.cfg, attempt),
            attempt,
        });
        sh.stats.handshakes_sent += 1;
        out.push(Event::HandshakeSent {
            retry: attempt > 0,
            rekey: self.current.is_some(),
        });
        out.push(Event::Send {
            packet,
            to: Dest::Remote,
        });
        Ok(())
    }

    /// Handshake 1 from this peer, already read and authenticated by Noise.
    #[allow(clippy::too_many_arguments)]
    fn accept_initiation(
        &mut self,
        sh: &mut Shared,
        taken: &[u16],
        now: Duration,
        mut hs: snow::HandshakeState,
        remote_index: u16,
        ts: Timestamp,
        out: &mut Vec<Event>,
    ) {
        let mut drop_with = |r: DropReason| {
            sh.stats.count_drop(r);
            out.push(Event::Dropped(r));
        };
        // With a real clock, a timestamp far in the future is refused. It
        // would otherwise lock the peer out until that time (one forged by
        // nobody, but sent by a peer whose clock was wrong): spec section 6.
        if !sh.wall_base.is_zero() {
            let now_wall = (sh.wall_base + now).as_secs();
            if ts.secs > now_wall.saturating_add(MAX_FUTURE_SECS) {
                drop_with(DropReason::StaleHandshake);
                return;
            }
        }
        // A recorded handshake 1 is never newer than what we have seen.
        if self.stamps.seen.is_some_and(|seen| ts <= seen) {
            drop_with(DropReason::StaleHandshake);
            return;
        }
        // Only fresh, authenticated handshakes count against the peer's rate.
        if self
            .last_accept
            .is_some_and(|t| now.saturating_sub(t) < sh.cfg.peer_handshake_gap)
        {
            drop_with(DropReason::RateLimited);
            return;
        }
        let Some(index) = pick_index(&mut *sh.rng, taken) else {
            out.push(Event::Failure("no free session index"));
            return;
        };
        let mut buf = [0u8; 64];
        let mut payload = [0u8; 4];
        payload[..2].copy_from_slice(&index.to_be_bytes());
        payload[2..].copy_from_slice(&remote_index.to_be_bytes());
        let n = match hs.write_message(&payload, &mut buf) {
            Ok(n) => n,
            Err(_) => {
                out.push(Event::Failure("could not answer a handshake"));
                return;
            }
        };
        let transport = match hs.into_stateless_transport_mode() {
            Ok(t) => t,
            Err(_) => {
                out.push(Event::Failure("could not finish a handshake"));
                return;
            }
        };
        // Save before answering: after a reboot the same message must still
        // be refused.
        let mut next = self.stamps;
        next.seen = Some(ts);
        if self.store.save(&next).is_err() {
            out.push(Event::Failure("could not save the handshake timestamp"));
            return;
        }
        self.stamps = next;
        self.last_accept = Some(now);
        sh.stats.handshakes_accepted += 1;
        // Replaces an older unconfirmed session, if any.
        self.pending = Some(Session::new(transport, index, remote_index, false, now));
        out.push(Event::Send {
            packet: packet::encode_handshake2(remote_index, &buf[..n]),
            to: Dest::Source,
        });
    }

    fn on_handshake2(
        &mut self,
        sh: &mut Shared,
        now: Duration,
        noise: &[u8],
        out: &mut Vec<Event>,
    ) {
        let Some(mut f) = self.hs.take() else {
            sh.stats.count_drop(DropReason::UnknownIndex);
            out.push(Event::Dropped(DropReason::UnknownIndex));
            return;
        };
        let mut payload = [0u8; 32];
        match f.state.read_message(noise, &mut payload) {
            // Payload: the responder's index, then ours. The receiver index
            // in the clear header only found this handshake; it must be the
            // same one inside.
            Ok(4)
                if f.state.is_handshake_finished()
                    && u16::from_be_bytes([payload[2], payload[3]]) == f.local_index => {}
            Ok(_) => {
                // Authentic Noise but a payload that is not what the spec says
                // (cannot come from a correct peer). snow has used up this
                // handshake, so the retry timer starts a new one.
                self.hs = Some(f);
                sh.stats.count_drop(DropReason::BadHeader);
                out.push(Event::Dropped(DropReason::BadHeader));
                return;
            }
            Err(_) => {
                // snow restores its state on a failed read, so a forged
                // handshake 2 does not spoil the real one.
                self.hs = Some(f);
                sh.stats.count_drop(DropReason::BadTag);
                out.push(Event::Dropped(DropReason::BadTag));
                return;
            }
        }
        let transport = match f.state.into_stateless_transport_mode() {
            Ok(t) => t,
            Err(_) => {
                out.push(Event::Failure("could not finish a handshake"));
                return;
            }
        };
        sh.stats.handshakes_completed += 1;
        let remote_index = u16::from_be_bytes([payload[0], payload[1]]);
        let session = Session::new(transport, f.local_index, remote_index, true, now);
        let rekey = self.install_current(session, now, true);
        out.push(Event::SessionEstablished {
            initiator: true,
            rekey,
        });
        // Tell the responder the session works (it only switches after a
        // valid data packet on it).
        self.send_keepalive(sh, now, out);
    }

    /// Make `session` the one we send on; the old one stays readable.
    ///
    /// `from_handshake_2`: we made it ourselves. Then a session we made
    /// earlier that the peer never confirmed does not push out the older,
    /// working one that is still readable. (When the peer has just proved
    /// itself with a valid packet, the old session always stays readable.)
    fn install_current(&mut self, session: Session, now: Duration, from_handshake_2: bool) -> bool {
        let rekey = self.current.is_some();
        self.awaiting_since = None;
        self.wants_session = None;
        if let Some(old) = self.current.take()
            && (old.confirmed || self.previous.is_none() || !from_handshake_2)
        {
            self.previous = Some((old, now));
        }
        self.current = Some(session);
        rekey
    }

    fn send_keepalive(&mut self, sh: &mut Shared, now: Duration, out: &mut Vec<Event>) {
        if let Some(cur) = self.current.as_mut()
            && let Ok(packet) = cur.encrypt(now, &sh.cfg, &[])
        {
            sh.stats.keepalives_sent += 1;
            self.owe_ack_since = None;
            out.push(Event::Send {
                packet,
                to: Dest::Remote,
            });
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn on_data(
        &mut self,
        sh: &mut Shared,
        now: Duration,
        receiver: u16,
        counter_len: CounterLen,
        low: u64,
        ciphertext: &[u8],
        out: &mut Vec<Event>,
    ) {
        enum Slot {
            Current,
            Previous,
            Pending,
        }
        let (slot, session) = if self
            .current
            .as_ref()
            .is_some_and(|s| s.local_index == receiver)
        {
            (Slot::Current, self.current.as_mut())
        } else if self
            .previous
            .as_ref()
            .is_some_and(|(s, _)| s.local_index == receiver)
        {
            (Slot::Previous, self.previous.as_mut().map(|(s, _)| s))
        } else if self
            .pending
            .as_ref()
            .is_some_and(|s| s.local_index == receiver)
        {
            (Slot::Pending, self.pending.as_mut())
        } else {
            (Slot::Pending, None)
        };
        let Some(session) = session else {
            sh.stats.count_drop(DropReason::UnknownIndex);
            out.push(Event::Dropped(DropReason::UnknownIndex));
            return;
        };
        let plain = match session.decrypt(now, &sh.cfg, counter_len, low, ciphertext) {
            Ok(p) => p,
            Err(r) => {
                sh.stats.count_drop(r);
                out.push(Event::Dropped(r));
                return;
            }
        };
        let session_is_initiator = session.initiator;
        session.confirmed = true;
        self.awaiting_since = None;
        if !plain.is_empty() {
            self.owe_ack_since.get_or_insert(now);
        }
        out.push(Event::Authenticated);
        match slot {
            Slot::Current => {
                // Valid data on the session we made: the peer has it, so the
                // one it replaced can go.
                if session_is_initiator {
                    self.previous = None;
                    self.unconfirmed_rounds = 0;
                }
            }
            Slot::Previous => {
                if let Some((_, used)) = self.previous.as_mut() {
                    *used = now;
                }
            }
            Slot::Pending => {
                // First valid data on the new session: switch to it.
                let new = self.pending.take().expect("matched above");
                let rekey = self.install_current(new, now, false);
                out.push(Event::SessionEstablished {
                    initiator: false,
                    rekey,
                });
                self.send_keepalive(sh, now, out);
            }
        }
        if plain.is_empty() {
            sh.stats.keepalives_received += 1;
        } else {
            sh.stats.received += 1;
            sh.stats.delivered += 1;
            out.push(Event::Deliver(plain));
        }
    }

    fn poll(&mut self, sh: &mut Shared, taken: &[u16], now: Duration, out: &mut Vec<Event>) {
        // Expiry: wipe what may no longer be used.
        if self
            .current
            .as_ref()
            .is_some_and(|s| s.expired(now, &sh.cfg))
        {
            self.current = None;
        }
        if self.previous.as_ref().is_some_and(|(s, used)| {
            s.expired(now, &sh.cfg) || now.saturating_sub(*used) >= sh.cfg.previous_grace
        }) {
            self.previous = None;
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|s| s.expired(now, &sh.cfg))
        {
            self.pending = None;
        }

        // Handshake: retry with backoff, or (initiator only) start / rekey.
        let mut start: Option<u32> = None;
        if let Some(f) = &self.hs {
            if now >= f.next_retry {
                start = Some(f.attempt.saturating_add(1));
            }
        } else if now >= self.hold_until {
            // Sent payload, heard nothing for too long: the peer may have
            // restarted, or the counters may have drifted apart (a long
            // one-way loss). Either side may start over.
            let stale = self
                .awaiting_since
                .is_some_and(|t| now.saturating_sub(t) >= sh.cfg.stale_after);
            // Whoever made the current session renews it; a side with no
            // session starts one if it is the dialing side or has data to send.
            match &self.current {
                None if self.initiator_role => start = Some(0),
                // Data to send and no session: start one, after giving the
                // dialing side a moment to do it first.
                None if self
                    .wants_session
                    .is_some_and(|t| now.saturating_sub(t) >= sh.cfg.retry_initial) =>
                {
                    start = Some(0)
                }
                None => {}
                Some(c) if c.initiator && c.wants_rekey(now, &sh.cfg) => start = Some(0),
                // We made this session and the peer has not sent a single valid
                // packet on it: ask again, slowing down each time.
                Some(c)
                    if c.initiator
                        && !c.confirmed
                        && now.saturating_sub(c.created)
                            >= backoff(&sh.cfg, self.unconfirmed_rounds) =>
                {
                    self.unconfirmed_rounds = self.unconfirmed_rounds.saturating_add(1);
                    start = Some(self.unconfirmed_rounds);
                }
                Some(_) if stale => start = Some(0),
                Some(_) => {}
            }
        }
        if start.is_some() {
            self.wants_session = None;
        }
        if let Some(attempt) = start
            && self.begin_handshake(sh, taken, now, attempt, out).is_err()
        {
            self.hold_until = now + sh.cfg.retry_initial;
            if let Some(f) = self.hs.as_mut() {
                f.next_retry = self.hold_until;
            }
            out.push(Event::Failure("could not start a handshake"));
        }

        // Keepalive.
        if let (Some(every), Some(cur)) = (sh.cfg.keepalive, self.current.as_ref())
            && now.saturating_sub(cur.last_sent) >= every
        {
            self.send_keepalive(sh, now, out);
        }
        // We received payload and have sent nothing since: say we are alive,
        // before the peer decides we are not.
        if self.current.is_some()
            && self
                .owe_ack_since
                .is_some_and(|t| now.saturating_sub(t) >= sh.cfg.stale_after / 2)
        {
            self.send_keepalive(sh, now, out);
        }
    }
}
