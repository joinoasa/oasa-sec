//! Control messages (spec R-SEC2 section 2): the messages that travel inside
//! an established link session, next to the application packets, to remove
//! devices across a fleet (and, in phase B, to hand over signing keys).
//!
//! They need no new crypto: every one arrives inside a link session, which
//! already proves who sent it. What each peer may send is decided here by the
//! peer's **role on this device**, read fresh from the files at each message.
//!
//! [`Control`] is a state machine in the style of the link: it takes bytes
//! and the time in, and returns [`Action`]s (messages to send, drops to
//! count, notes to log). It opens no sockets and reads no clock; its only
//! outside effect is the device folder (through [`crate::removal`]). The
//! program (`oasa-link`) wraps messages with `Link::send_control`, hands
//! `Event::Control` to [`Control::handle`], and calls [`Control::poll`] with
//! the timers.
//!
//! A control message is `[type: 1][request id: 4][body]`, all integers
//! big-endian:
//!
//! | Type | Name | From → to | Body |
//! |---|---|---|---|
//! | `0x01` | `ACK` | any | acked type (1); the request id is the acked message's |
//! | `0x10` | `SIGNING_KEY_NEXT` | drone → its operators | generation (4), key (32) |
//! | `0x11` | `SIGNING_KEY_COMMIT` | drone → its operators | generation (4) |
//! | `0x20` | `REMOVE_HEAD` | admin → device | log id (4), highest seq (4) |
//! | `0x21` | `REMOVE_HAVE` | device → admin | highest seq held in a row (4) |
//! | `0x22` | `REMOVE_ENTRY` | admin → device | log id (4), seq (4), removed key (32), time (8) |
//! | `0x23` | `NOT_ADMIN` | device → sender of `REMOVE_HEAD` | none |
//!
//! `REMOVE_HAVE` and `NOT_ADMIN` echo the request id of the `REMOVE_HEAD`
//! they answer; a message whose id matches nothing we sent is ignored, so a
//! stale answer from an earlier session does nothing. Phase A parses and
//! role-checks the signing-key messages and does nothing with them.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::identity::{check_peer_public, fingerprint};
use crate::link::{Entropy, jittered};
use crate::removal::{self, Applied, Entry, LogId};
use crate::rotation::{self, CommitOutcome, NextOutcome};
use crate::signing::{AUTOPILOT_KEY_FILE, peer_key_path};
use crate::store::{self, Role};

pub const ACK: u8 = 0x01;
pub const SIGNING_KEY_NEXT: u8 = 0x10;
pub const SIGNING_KEY_COMMIT: u8 = 0x11;
pub const REMOVE_HEAD: u8 = 0x20;
pub const REMOVE_HAVE: u8 = 0x21;
pub const REMOVE_ENTRY: u8 = 0x22;
pub const NOT_ADMIN: u8 = 0x23;

/// First resend of an unacked message, and the delay before each next one
/// doubles, up to [`RETRY_MAX`]. Resends go on for the life of the session.
pub const RETRY_INITIAL: Duration = Duration::from_secs(2);
pub const RETRY_MAX: Duration = Duration::from_secs(60);

/// Most new removals (or votes) one link session may add. A long log
/// arrives over several sessions (every rekey starts one); a stolen admin
/// cannot flood the files in one.
pub const SESSION_NEW_REMOVALS: u32 = 64;

/// Most `REMOVE_ENTRY` messages waiting for an ack at once. Keeps a long log
/// from filling a slow radio; the rest follow as acks come in.
pub const ENTRY_WINDOW: usize = 8;

/// A request id: random, per message.
pub type RequestId = [u8; 4];

/// A signing key in transit. Wiped when dropped; never printed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(..)")
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        // Constant time: no early exit on the first different byte.
        self.0
            .iter()
            .zip(&other.0)
            .fold(0u8, |d, (a, b)| d | (a ^ b))
            == 0
    }
}

impl Eq for SecretKey {}

/// One control message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Ack {
        id: RequestId,
        acked: u8,
    },
    SigningKeyNext {
        id: RequestId,
        generation: u32,
        key: SecretKey,
    },
    SigningKeyCommit {
        id: RequestId,
        generation: u32,
    },
    RemoveHead {
        id: RequestId,
        log_id: LogId,
        highest: u32,
    },
    RemoveHave {
        id: RequestId,
        held: u32,
    },
    RemoveEntry {
        id: RequestId,
        log_id: LogId,
        seq: u32,
        key: [u8; 32],
        time: u64,
    },
    NotAdmin {
        id: RequestId,
    },
}

/// Why bytes are not a control message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    Empty,
    UnknownType(u8),
    /// The length is not the one this type has.
    BadLength,
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes(b.try_into().expect("4 bytes"))
}

impl Message {
    /// Read one message. Strict: the length must be exactly right, so a
    /// truncated or padded message is refused, never half-read.
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let (&kind, rest) = bytes.split_first().ok_or(ParseError::Empty)?;
        let want = match kind {
            ACK => 5,
            SIGNING_KEY_NEXT => 40,
            SIGNING_KEY_COMMIT => 8,
            REMOVE_HEAD => 12,
            REMOVE_HAVE => 8,
            REMOVE_ENTRY => 52,
            NOT_ADMIN => 4,
            other => return Err(ParseError::UnknownType(other)),
        };
        if rest.len() != want {
            return Err(ParseError::BadLength);
        }
        let id: RequestId = rest[..4].try_into().expect("4 bytes");
        let body = &rest[4..];
        Ok(match kind {
            ACK => Message::Ack { id, acked: body[0] },
            SIGNING_KEY_NEXT => Message::SigningKeyNext {
                id,
                generation: be32(&body[..4]),
                key: SecretKey(body[4..36].try_into().expect("32 bytes")),
            },
            SIGNING_KEY_COMMIT => Message::SigningKeyCommit {
                id,
                generation: be32(body),
            },
            REMOVE_HEAD => Message::RemoveHead {
                id,
                log_id: body[..4].try_into().expect("4 bytes"),
                highest: be32(&body[4..]),
            },
            REMOVE_HAVE => Message::RemoveHave {
                id,
                held: be32(body),
            },
            REMOVE_ENTRY => Message::RemoveEntry {
                id,
                log_id: body[..4].try_into().expect("4 bytes"),
                seq: be32(&body[4..8]),
                key: body[8..40].try_into().expect("32 bytes"),
                time: u64::from_be_bytes(body[40..48].try_into().expect("8 bytes")),
            },
            NOT_ADMIN => Message::NotAdmin { id },
            _ => unreachable!("checked above"),
        })
    }

    /// The bytes to hand to `Link::send_control`. Wiped when dropped, because
    /// a `SIGNING_KEY_NEXT` holds a key.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut v = Zeroizing::new(Vec::with_capacity(53));
        match self {
            Message::Ack { id, acked } => {
                v.push(ACK);
                v.extend_from_slice(id);
                v.push(*acked);
            }
            Message::SigningKeyNext {
                id,
                generation,
                key,
            } => {
                v.push(SIGNING_KEY_NEXT);
                v.extend_from_slice(id);
                v.extend_from_slice(&generation.to_be_bytes());
                v.extend_from_slice(key.as_bytes());
            }
            Message::SigningKeyCommit { id, generation } => {
                v.push(SIGNING_KEY_COMMIT);
                v.extend_from_slice(id);
                v.extend_from_slice(&generation.to_be_bytes());
            }
            Message::RemoveHead {
                id,
                log_id,
                highest,
            } => {
                v.push(REMOVE_HEAD);
                v.extend_from_slice(id);
                v.extend_from_slice(log_id);
                v.extend_from_slice(&highest.to_be_bytes());
            }
            Message::RemoveHave { id, held } => {
                v.push(REMOVE_HAVE);
                v.extend_from_slice(id);
                v.extend_from_slice(&held.to_be_bytes());
            }
            Message::RemoveEntry {
                id,
                log_id,
                seq,
                key,
                time,
            } => {
                v.push(REMOVE_ENTRY);
                v.extend_from_slice(id);
                v.extend_from_slice(log_id);
                v.extend_from_slice(&seq.to_be_bytes());
                v.extend_from_slice(key);
                v.extend_from_slice(&time.to_be_bytes());
            }
            Message::NotAdmin { id } => {
                v.push(NOT_ADMIN);
                v.extend_from_slice(id);
            }
        }
        v
    }

    pub fn id(&self) -> RequestId {
        match self {
            Message::Ack { id, .. }
            | Message::SigningKeyNext { id, .. }
            | Message::SigningKeyCommit { id, .. }
            | Message::RemoveHead { id, .. }
            | Message::RemoveHave { id, .. }
            | Message::RemoveEntry { id, .. }
            | Message::NotAdmin { id } => *id,
        }
    }

    pub fn type_byte(&self) -> u8 {
        match self {
            Message::Ack { .. } => ACK,
            Message::SigningKeyNext { .. } => SIGNING_KEY_NEXT,
            Message::SigningKeyCommit { .. } => SIGNING_KEY_COMMIT,
            Message::RemoveHead { .. } => REMOVE_HEAD,
            Message::RemoveHave { .. } => REMOVE_HAVE,
            Message::RemoveEntry { .. } => REMOVE_ENTRY,
            Message::NotAdmin { .. } => NOT_ADMIN,
        }
    }
}

/// Something worth a log line. Never contains a key, only fingerprints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    pub what: &'static str,
    /// Fingerprint of the device the note is about.
    pub key: Option<String>,
    pub seq: Option<u32>,
    pub detail: Option<&'static str>,
}

impl Note {
    fn new(what: &'static str) -> Self {
        Self {
            what,
            key: None,
            seq: None,
            detail: None,
        }
    }
}

/// What the program should do after a call.
#[derive(Clone, PartialEq, Eq)]
pub enum Action {
    /// Send this control message with `Link::send_control`. If the link has
    /// no session right now, forget it: a resend is already scheduled.
    Send(Zeroizing<Vec<u8>>),
    /// A message was dropped. Count it under this name: `bad_control` (not a
    /// message), `bad_role` (the peer may not send this) or `peer_removed`.
    Drop(&'static str),
    /// A line for the log.
    Note(Note),
}

impl fmt::Debug for Action {
    // A sent message can hold a key (phase B), so only its size is shown.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Action::Send(m) => write!(f, "Send({} bytes)", m.len()),
            Action::Drop(r) => write!(f, "Drop({r})"),
            Action::Note(n) => write!(f, "Note({n:?})"),
        }
    }
}

/// A message waiting for an answer or an ack.
struct Outgoing {
    id: RequestId,
    /// Wiped when dropped: a `SIGNING_KEY_NEXT` holds a key.
    bytes: Zeroizing<Vec<u8>>,
    next_try: Duration,
    backoff: Duration,
    /// How many times it was sent again.
    resends: u32,
}

/// What our one signing-key message in flight is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SigningKind {
    Next(u32),
    Commit(u32),
}

/// A commit that stays unacked this many resends makes the drone start over
/// with the current key's `SIGNING_KEY_NEXT`: the operator may have lost or
/// replaced its pending key, and a commit alone would never be understood.
const COMMIT_RESENDS_BEFORE_RESTART: u32 = 4;

/// What belongs to one link session; forgotten when the next one starts.
#[derive(Default)]
struct SessionState {
    active: bool,
    /// Our `REMOVE_HEAD`, until the peer answers it.
    head: Option<Outgoing>,
    /// The log id our head named.
    head_log: Option<LogId>,
    /// The peer said `NOT_ADMIN`: it does not list us, so we stop.
    not_admin: bool,
    /// `REMOVE_ENTRY` messages in flight, by seq.
    entries: BTreeMap<u32, Outgoing>,
    /// Entries the peer acked this session.
    acked: BTreeSet<u32>,
    /// The peer's last `REMOVE_HAVE`.
    held: Option<u32>,
    /// New removals and votes applied this session (see [`SESSION_NEW_REMOVALS`]).
    new_removals: u32,
    /// A `SIGNING_KEY_NEXT` or `_COMMIT` waiting for its ack (drone side).
    signing: Option<(Outgoing, SigningKind)>,
}

/// The control layer for one peer (one `oasa-link` process).
pub struct Control {
    dir: PathBuf,
    own: [u8; 32],
    peer: [u8; 32],
    peer_fp: String,
    rng: Box<dyn Entropy>,
    retry_initial: Duration,
    retry_max: Duration,
    session: SessionState,
    peer_gone: bool,
}

impl fmt::Debug for Control {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Control").finish_non_exhaustive()
    }
}

impl Control {
    /// `dir` is the device folder, `own` this device's public key and `peer`
    /// the public key of the device at the other end of the link.
    pub fn new(dir: &Path, own: [u8; 32], peer: [u8; 32], rng: Box<dyn Entropy>) -> Self {
        Self {
            dir: dir.to_path_buf(),
            own,
            peer,
            peer_fp: fingerprint(&peer),
            rng,
            retry_initial: RETRY_INITIAL,
            retry_max: RETRY_MAX,
            session: SessionState::default(),
            peer_gone: false,
        }
    }

    /// Resend timing for a slow radio: the first resend after `initial`
    /// (at least [`RETRY_INITIAL`]), doubling up to `max` (at least
    /// `initial`). Give it the link's `retry_initial` and `retry_max` when
    /// the link is scaled to the radio's airtime: a message and its ack must
    /// be able to cross the air before the first resend. Every wait is
    /// spread by up to 20% so resends do not line up with other traffic.
    pub fn with_retry(mut self, initial: Duration, max: Duration) -> Self {
        self.retry_initial = initial.max(RETRY_INITIAL);
        self.retry_max = max.max(self.retry_initial);
        self
    }

    fn new_id(&mut self) -> RequestId {
        loop {
            let mut id = [0u8; 4];
            self.rng.fill(&mut id);
            let in_use = self.session.head.as_ref().is_some_and(|h| h.id == id)
                || self.session.entries.values().any(|e| e.id == id);
            if !in_use {
                return id;
            }
        }
    }

    fn outgoing(&mut self, now: Duration, msg: Message) -> (Outgoing, Action) {
        let bytes = msg.encode();
        let send = Action::Send(bytes.clone());
        let out = Outgoing {
            id: msg.id(),
            bytes,
            next_try: now + jittered(self.retry_initial, &mut *self.rng),
            backoff: self.retry_initial,
            resends: 0,
        };
        (out, send)
    }

    /// The peer's role here, fresh from the files. `None`: not trusted.
    fn peer_role(&self) -> crate::Result<Option<Role>> {
        Ok(store::snapshot(&self.dir)?.get(&self.peer).map(|p| p.role))
    }

    /// A new link session started (including a rekey). Everything unfinished
    /// starts over: an admin with a removal log sends its `REMOVE_HEAD`.
    pub fn session_started(&mut self, now: Duration) -> Vec<Action> {
        self.session = SessionState {
            active: true,
            ..SessionState::default()
        };
        if self.peer_gone {
            return Vec::new();
        }
        let mut out = self.send_head(now);
        out.extend(self.send_signing(now));
        out
    }

    /// The drone's signing-key files changed (a rotation began, finished or
    /// was dropped): send what this operator is now owed.
    pub fn signing_changed(&mut self, now: Duration) -> Vec<Action> {
        if !self.session.active || self.peer_gone {
            return Vec::new();
        }
        self.send_signing(now)
    }

    /// Drone side: what does our operator still need? A pending key goes out
    /// at once; the commit only after the autopilot took the key. Nothing for
    /// anyone who is not an operator here (read fresh from the files, so a
    /// removed operator is never sent a key) or if we are not a drone.
    fn send_signing(&mut self, now: Duration) -> Vec<Action> {
        if self.session.signing.is_some() {
            return Vec::new(); // one at a time; the ack brings the next
        }
        match self.peer_role() {
            Ok(Some(Role::Operator)) => {}
            Ok(_) => return Vec::new(),
            Err(_) => return vec![Action::Note(Note::new("control_error"))],
        }
        let (keys, acked) = match (
            rotation::load_drone_keys(&self.dir),
            rotation::read_acked(&self.dir, &self.peer_fp),
        ) {
            (Ok(Some(k)), Ok(a)) => (k, a),
            (Ok(None), _) => return Vec::new(), // not a drone
            _ => return vec![Action::Note(Note::new("control_error"))],
        };
        let (msg, kind) = match rotation::owed(&keys, acked) {
            rotation::Owed::Nothing => return Vec::new(),
            rotation::Owed::Next(g) => {
                let key = if keys.next.as_ref().is_some_and(|n| n.0 == g) {
                    keys.next.as_ref().map(|n| n.1.as_bytes())
                } else {
                    Some(keys.current.as_bytes())
                };
                let Some(key) = key else { return Vec::new() };
                let id = self.new_id();
                (
                    Message::SigningKeyNext {
                        id,
                        generation: g,
                        key: SecretKey::new(*key),
                    },
                    SigningKind::Next(g),
                )
            }
            rotation::Owed::Commit(g) => {
                let id = self.new_id();
                (
                    Message::SigningKeyCommit { id, generation: g },
                    SigningKind::Commit(g),
                )
            }
        };
        let (o, send) = self.outgoing(now, msg);
        self.session.signing = Some((o, kind));
        vec![send]
    }

    /// The removal log may have grown (an admin ran `revoke` while the link
    /// was up): announce it again, unless the peer already said it does not
    /// list us.
    pub fn log_changed(&mut self, now: Duration) -> Vec<Action> {
        if !self.session.active || self.session.not_admin || self.peer_gone {
            return Vec::new();
        }
        self.send_head(now)
    }

    /// Our peer was removed: forget everything unsent and answer nothing.
    pub fn peer_removed(&mut self) {
        self.peer_gone = true;
        self.session = SessionState::default();
    }

    fn send_head(&mut self, now: Duration) -> Vec<Action> {
        let log = match removal::load_log(&self.dir) {
            Ok(Some(l)) if l.highest() > 0 => l,
            Ok(_) => return Vec::new(),
            Err(_) => return vec![Action::Note(Note::new("control_error"))],
        };
        let id = self.new_id();
        let (head, send) = self.outgoing(
            now,
            Message::RemoveHead {
                id,
                log_id: log.id,
                highest: log.highest(),
            },
        );
        self.session.head = Some(head);
        self.session.head_log = Some(log.id);
        vec![send]
    }

    /// Timers: resend what is unanswered, 2 s then doubling to 60 s.
    pub fn poll(&mut self, now: Duration) -> Vec<Action> {
        if self.peer_gone || !self.session.active {
            return Vec::new();
        }
        let mut out = Vec::new();
        fn due(
            o: &mut Outgoing,
            now: Duration,
            rng: &mut dyn Entropy,
            retry_max: Duration,
        ) -> Option<Action> {
            if now < o.next_try {
                return None;
            }
            o.backoff = o.backoff.saturating_mul(2).min(retry_max);
            o.next_try = now + jittered(o.backoff, rng);
            Some(Action::Send(o.bytes.clone()))
        }
        let retry_max = self.retry_max;
        if let Some(a) = self
            .session
            .head
            .as_mut()
            .and_then(|o| due(o, now, &mut *self.rng, retry_max))
        {
            out.push(a);
        }
        let mut restart = false;
        if let Some((o, kind)) = self.session.signing.as_mut()
            && let Some(a) = due(o, now, &mut *self.rng, retry_max)
        {
            o.resends += 1;
            if matches!(kind, SigningKind::Commit(_)) && o.resends >= COMMIT_RESENDS_BEFORE_RESTART
            {
                restart = true;
            } else {
                out.push(a);
            }
        }
        if restart {
            // Forget that the operator took the pending key; it is sent again.
            self.session.signing = None;
            match rotation::update_acked(&self.dir, &self.peer_fp, |a| a.next = 0) {
                Ok(_) => out.extend(self.send_signing(now)),
                Err(_) => out.push(Action::Note(Note::new("control_error"))),
            }
        }
        for o in self.session.entries.values_mut() {
            if let Some(a) = due(o, now, &mut *self.rng, retry_max) {
                out.push(a);
            }
        }
        out
    }

    /// One control message arrived on the link (the bytes of
    /// `Event::Control`). `unix` is the wall clock, for the records only.
    pub fn handle(&mut self, now: Duration, unix: u64, bytes: &[u8]) -> Vec<Action> {
        if self.peer_gone {
            return vec![Action::Drop("peer_removed")];
        }
        let msg = match Message::parse(bytes) {
            Ok(m) => m,
            Err(_) => return vec![Action::Drop("bad_control")],
        };
        // The role is read now, not remembered: a removal that landed a
        // moment ago must count for the very next message.
        let role = match self.peer_role() {
            Ok(Some(r)) => r,
            Ok(None) => return vec![Action::Drop("peer_removed")],
            Err(_) => return vec![Action::Note(Note::new("control_error"))],
        };
        match msg {
            Message::Ack { id, acked } => self.on_ack(now, id, acked),
            Message::RemoveHead {
                id,
                log_id,
                highest,
            } => self.on_head(role, id, log_id, highest),
            Message::RemoveHave { id, held } => self.on_have(now, id, held),
            Message::NotAdmin { id } => self.on_not_admin(id),
            Message::RemoveEntry {
                id,
                log_id,
                seq,
                key,
                time,
            } => self.on_entry(
                role,
                unix,
                id,
                &Entry {
                    log_id,
                    seq,
                    target: key,
                    time,
                },
            ),
            Message::SigningKeyNext {
                id,
                generation,
                key,
            } => self.on_signing_next(id, generation, &key),
            Message::SigningKeyCommit { id, generation } => self.on_signing_commit(id, generation),
        }
    }

    fn ack(&self, id: RequestId, acked: u8) -> Action {
        Action::Send(Message::Ack { id, acked }.encode())
    }

    fn on_head(&mut self, role: Role, id: RequestId, log_id: LogId, highest: u32) -> Vec<Action> {
        if role != Role::Admin {
            // We don't list this device as admin: tell it, so it stops.
            return vec![Action::Send(Message::NotAdmin { id }.encode())];
        }
        match removal::on_head(&self.dir, &self.peer_fp, &log_id, highest) {
            Ok(held) => vec![Action::Send(Message::RemoveHave { id, held }.encode())],
            Err(_) => vec![Action::Note(Note::new("control_error"))],
        }
    }

    fn on_entry(&mut self, role: Role, unix: u64, id: RequestId, entry: &Entry) -> Vec<Action> {
        if role != Role::Admin {
            return vec![Action::Drop("bad_role")];
        }
        if entry.seq == 0 || check_peer_public(&entry.target).is_err() {
            return vec![Action::Drop("bad_control")];
        }
        let target_fp = fingerprint(&entry.target);
        let allow_new = self.session.new_removals < SESSION_NEW_REMOVALS;
        match removal::apply_entry_limited(&self.dir, &self.own, &self.peer, entry, unix, allow_new)
        {
            Ok(Applied::NotAdmin) => vec![Action::Drop("bad_role")],
            // Over a limit: logged, not applied and not acked, so a stolen
            // admin cannot fill the files and a real one just waits.
            Ok(Applied::Limit) => vec![Action::Note(Note {
                what: "removal_refused",
                key: Some(target_fp),
                seq: Some(entry.seq),
                detail: Some(if allow_new {
                    "admin_limit"
                } else {
                    "session_limit"
                }),
            })],
            Ok(applied) => {
                if applied == Applied::Removed || applied == Applied::Voted {
                    self.session.new_removals += 1;
                }
                let detail = match applied {
                    Applied::Removed => "removed",
                    Applied::Voted => "voted",
                    Applied::Known => "known",
                    Applied::OwnKey => "own_key",
                    Applied::SelfRevoke => "self_revoke",
                    Applied::NotAdmin | Applied::Limit => unreachable!("handled above"),
                };
                vec![
                    Action::Note(Note {
                        what: "removal_entry",
                        key: Some(target_fp),
                        seq: Some(entry.seq),
                        detail: Some(detail),
                    }),
                    self.ack(id, REMOVE_ENTRY),
                ]
            }
            // Not saved, so not acked: the admin will send it again.
            Err(_) => vec![Action::Note(Note::new("control_error"))],
        }
    }

    fn on_have(&mut self, now: Duration, id: RequestId, held: u32) -> Vec<Action> {
        if self.session.head.as_ref().map(|h| h.id) != Some(id) {
            return Vec::new(); // not an answer to anything we asked
        }
        self.session.head = None;
        self.session.held = Some(held);
        self.send_entries(now)
    }

    fn on_not_admin(&mut self, id: RequestId) -> Vec<Action> {
        if self.session.head.as_ref().map(|h| h.id) != Some(id) {
            return Vec::new();
        }
        self.session.head = None;
        self.session.not_admin = true;
        vec![Action::Note(Note::new("not_admin_here"))]
    }

    fn on_ack(&mut self, now: Duration, id: RequestId, acked: u8) -> Vec<Action> {
        if acked == SIGNING_KEY_NEXT || acked == SIGNING_KEY_COMMIT {
            return self.on_signing_ack(now, id, acked);
        }
        if acked != REMOVE_ENTRY {
            return Vec::new();
        }
        let Some(seq) = self
            .session
            .entries
            .iter()
            .find(|(_, e)| e.id == id)
            .map(|(s, _)| *s)
        else {
            return Vec::new();
        };
        self.session.entries.remove(&seq);
        self.session.acked.insert(seq);
        self.send_entries(now)
    }

    /// Send the entries the peer is missing, a few at a time.
    fn send_entries(&mut self, now: Duration) -> Vec<Action> {
        let Some(held) = self.session.held else {
            return Vec::new();
        };
        let log = match removal::load_log(&self.dir) {
            Ok(Some(l)) => l,
            Ok(None) => return Vec::new(),
            Err(_) => return vec![Action::Note(Note::new("control_error"))],
        };
        if Some(log.id) != self.session.head_log {
            // The log was replaced while the link was up: ask again.
            return self.send_head(now);
        }
        // Whatever the peer holds in a row needs no more waiting.
        self.session.entries.retain(|seq, _| *seq > held);
        let mut out = Vec::new();
        let mut seq = held;
        while self.session.entries.len() < ENTRY_WINDOW && seq < log.highest() {
            seq += 1;
            if self.session.entries.contains_key(&seq) || self.session.acked.contains(&seq) {
                continue;
            }
            let Some(e) = log.entry(seq) else { break };
            let id = self.new_id();
            let (o, send) = self.outgoing(
                now,
                Message::RemoveEntry {
                    id,
                    log_id: log.id,
                    seq,
                    key: e.key,
                    time: e.time,
                },
            );
            self.session.entries.insert(seq, o);
            out.push(send);
        }
        out
    }

    /// The drone's signing messages are accepted from a drone this ground
    /// station holds a signing key for, and from no one else. A device that
    /// is itself a drone (holds an autopilot key) never takes them.
    fn sender_is_a_known_drone(&self) -> bool {
        peer_key_path(&self.dir, &self.peer_fp).exists()
            && !self.dir.join(AUTOPILOT_KEY_FILE).exists()
    }

    /// `SIGNING_KEY_NEXT`: keep the key as pending. Acked once it is saved (or
    /// was already, or is old news), so the drone can stop; never switched
    /// before the commit. The same generation with another key is refused.
    fn on_signing_next(&mut self, id: RequestId, generation: u32, key: &SecretKey) -> Vec<Action> {
        if !self.sender_is_a_known_drone() {
            return vec![Action::Drop("bad_role")];
        }
        if key.as_bytes() == &[0u8; 32] {
            // All zeros means "signing off" in MAVLink; never a real key.
            return vec![Action::Drop("bad_control")];
        }
        match rotation::operator_on_next(&self.dir, &self.peer_fp, generation, key.as_bytes()) {
            Ok(NextOutcome::Conflict) => vec![Action::Drop("bad_control")],
            Ok(outcome) => {
                let mut note = Note::new("signing_key_next");
                note.seq = Some(generation);
                note.detail = Some(match outcome {
                    NextOutcome::Stored => "stored",
                    NextOutcome::Known => "known",
                    _ => "old",
                });
                vec![Action::Note(note), self.ack(id, SIGNING_KEY_NEXT)]
            }
            Err(_) => vec![Action::Note(Note::new("control_error"))],
        }
    }

    /// `SIGNING_KEY_COMMIT`: switch to the pending key of that generation. A
    /// commit for a generation we hold no key for is not acked.
    fn on_signing_commit(&mut self, id: RequestId, generation: u32) -> Vec<Action> {
        if !self.sender_is_a_known_drone() {
            return vec![Action::Drop("bad_role")];
        }
        match rotation::operator_on_commit(&self.dir, &self.peer_fp, generation) {
            Ok(CommitOutcome::NoPending) => {
                let mut note = Note::new("signing_key_commit_unknown");
                note.seq = Some(generation);
                vec![Action::Note(note)]
            }
            Ok(outcome) => {
                let mut note = Note::new("signing_key_commit");
                note.seq = Some(generation);
                note.detail = Some(if outcome == CommitOutcome::Switched {
                    "switched"
                } else {
                    "already"
                });
                vec![Action::Note(note), self.ack(id, SIGNING_KEY_COMMIT)]
            }
            Err(_) => vec![Action::Note(Note::new("control_error"))],
        }
    }

    /// Drone side: the operator acked our `NEXT` or `COMMIT`.
    fn on_signing_ack(&mut self, now: Duration, id: RequestId, acked: u8) -> Vec<Action> {
        let Some((o, kind)) = self.session.signing.as_ref() else {
            return Vec::new();
        };
        let want = match kind {
            SigningKind::Next(_) => SIGNING_KEY_NEXT,
            SigningKind::Commit(_) => SIGNING_KEY_COMMIT,
        };
        if o.id != id || acked != want {
            return Vec::new();
        }
        let kind = *kind;
        self.session.signing = None;
        let done = rotation::update_acked(&self.dir, &self.peer_fp, |a| match kind {
            SigningKind::Next(g) => a.next = g,
            SigningKind::Commit(g) => a.commit = g,
        });
        if done.is_err() {
            return vec![Action::Note(Note::new("control_error"))];
        }
        let mut out = vec![Action::Note({
            let mut n = Note::new("signing_key_acked");
            n.seq = Some(match kind {
                SigningKind::Next(g) | SigningKind::Commit(g) => g,
            });
            n.detail = Some(match kind {
                SigningKind::Next(_) => "next",
                SigningKind::Commit(_) => "commit",
            });
            n
        })];
        out.extend(self.send_signing(now));
        out
    }
}

#[cfg(test)]
mod tests;
