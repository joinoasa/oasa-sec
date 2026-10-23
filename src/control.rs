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
use crate::link::Entropy;
use crate::removal::{self, Applied, Entry, LogId};
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
    Send(Vec<u8>),
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
    bytes: Vec<u8>,
    next_try: Duration,
    backoff: Duration,
}

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
}

/// The control layer for one peer (one `oasa-link` process).
pub struct Control {
    dir: PathBuf,
    own: [u8; 32],
    peer: [u8; 32],
    peer_fp: String,
    rng: Box<dyn Entropy>,
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
            session: SessionState::default(),
            peer_gone: false,
        }
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
        let bytes = msg.encode().to_vec();
        let out = Outgoing {
            id: msg.id(),
            bytes: bytes.clone(),
            next_try: now + RETRY_INITIAL,
            backoff: RETRY_INITIAL,
        };
        (out, Action::Send(bytes))
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
        self.send_head(now)
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
        let due = |o: &mut Outgoing| {
            if now < o.next_try {
                return None;
            }
            o.backoff = (o.backoff * 2).min(RETRY_MAX);
            o.next_try = now + o.backoff;
            Some(Action::Send(o.bytes.clone()))
        };
        if let Some(a) = self.session.head.as_mut().and_then(due) {
            out.push(a);
        }
        for o in self.session.entries.values_mut() {
            if let Some(a) = due(o) {
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
            Message::SigningKeyNext { generation, .. } => self.on_signing_key(generation),
            Message::SigningKeyCommit { generation, .. } => self.on_signing_key(generation),
        }
    }

    fn ack(&self, id: RequestId, acked: u8) -> Action {
        Action::Send(Message::Ack { id, acked }.encode().to_vec())
    }

    fn on_head(&mut self, role: Role, id: RequestId, log_id: LogId, highest: u32) -> Vec<Action> {
        if role != Role::Admin {
            // We don't list this device as admin: tell it, so it stops.
            return vec![Action::Send(Message::NotAdmin { id }.encode().to_vec())];
        }
        match removal::on_head(&self.dir, &self.peer_fp, &log_id, highest) {
            Ok(held) => vec![Action::Send(
                Message::RemoveHave { id, held }.encode().to_vec(),
            )],
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
        match removal::apply_entry(&self.dir, &self.own, &self.peer, entry, unix) {
            Ok(Applied::NotAdmin) => vec![Action::Drop("bad_role")],
            Ok(applied) => {
                let detail = match applied {
                    Applied::Removed => "removed",
                    Applied::Voted => "voted",
                    Applied::Known => "known",
                    Applied::OwnKey => "own_key",
                    Applied::SelfRevoke => "self_revoke",
                    Applied::NotAdmin => unreachable!("handled above"),
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

    /// `SIGNING_KEY_NEXT` and `_COMMIT`: phase A only checks who sent them.
    /// They are accepted from a drone this ground station holds a signing
    /// key for, and from no one else. Nothing is done with them yet, and they
    /// are not acked, so a sender is never told they were stored.
    fn on_signing_key(&mut self, generation: u32) -> Vec<Action> {
        let from_known_drone = peer_key_path(&self.dir, &self.peer_fp).exists()
            && !self.dir.join(AUTOPILOT_KEY_FILE).exists();
        if !from_known_drone {
            return vec![Action::Drop("bad_role")];
        }
        let mut note = Note::new("signing_key_message_ignored");
        note.seq = Some(generation);
        note.detail = Some("signing-key rotation is not built yet");
        vec![Action::Note(note)]
    }
}

#[cfg(test)]
mod tests;
