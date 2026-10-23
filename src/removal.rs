//! Removing a device (spec R-SEC2 section 3): tombstones, the removal log an
//! admin keeps, and the state a device keeps about the logs it has received.
//!
//! Files in the device folder (all owner-only, replaced by atomic rename,
//! every read-modify-write under the folder lock):
//!
//! | File | Content |
//! |---|---|
//! | `removed` | Append-only. `<key> removed <source> <unix time>` or `<key> restored local <unix time>`; source is `local` or `<admin fingerprint>:<log id hex>:<seq>` |
//! | `removal-log` | Admins only. Line 1: log id (hex); then `<seq> <key> <unix time>` |
//! | `removal-sync/<admin fingerprint>` | `<log id hex> <highest seq held in a row>` |
//! | `admin-votes` | `<target key> <admin fingerprint> <log id hex> <seq>` until a second admin agrees |
//! | `rotation-pending` | One line per operator removed from a drone; the signer (phase B) reads it |
//!
//! A key in `removed` is never trusted, whatever `trusted-peers.v1` says.
//! A removal writes the tombstone first and edits the list second, so a crash
//! or a reader in between can only ever see "removed", never "still trusted".
//!
//! This module does file work only: no sockets and no clocks (times come in
//! as arguments).

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::files::{
    DirLock, append_private_line, open_private_file, read_private_file_opt, write_private_file,
};
use crate::identity::{check_peer_public, fingerprint};
use crate::link::FileTimestampStore;
use crate::signing::{AUTOPILOT_KEY_FILE, PEER_KEYS_DIR};
use crate::store::{self, Peer, Role, key_from_text, key_to_text};
use crate::{Error, Result};

pub const REMOVED_FILE: &str = "removed";
pub const LOG_FILE: &str = "removal-log";
pub const SYNC_DIR: &str = "removal-sync";
pub const VOTES_FILE: &str = "admin-votes";
pub const ROTATION_PENDING_FILE: &str = "rotation-pending";

/// A removal log's random 4-byte id, made when the log is created.
pub type LogId = [u8; 4];

pub fn log_id_text(id: &LogId) -> String {
    data_encoding::HEXLOWER.encode(id)
}

fn log_id_parse(text: &str) -> Result<LogId> {
    let bad = || Error::BadKeyFile("bad log id".into());
    if text.len() != 8 {
        return Err(bad());
    }
    data_encoding::HEXLOWER
        .decode(text.as_bytes())
        .map_err(|_| bad())?
        .try_into()
        .map_err(|_| bad())
}

fn bad(what: &str) -> Error {
    Error::BadKeyFile(what.to_string())
}

fn parse_u64(text: &str) -> Result<u64> {
    // `parse` accepts a leading `+`; the files never write one.
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad("bad number in a removal file"));
    }
    text.parse()
        .map_err(|_| bad("bad number in a removal file"))
}

fn parse_u32(text: &str) -> Result<u32> {
    u32::try_from(parse_u64(text)?).map_err(|_| bad("number too large in a removal file"))
}

// ---- the tombstone file ------------------------------------------------

/// Who asked for a removal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// A person at this device.
    Local,
    /// An entry from an admin's removal log.
    Admin {
        fingerprint: String,
        log_id: LogId,
        seq: u32,
    },
}

impl Source {
    fn to_text(&self) -> String {
        match self {
            Source::Local => "local".to_string(),
            Source::Admin {
                fingerprint,
                log_id,
                seq,
            } => format!("{fingerprint}:{}:{seq}", log_id_text(log_id)),
        }
    }

    fn parse(text: &str) -> Result<Self> {
        if text == "local" {
            return Ok(Source::Local);
        }
        let mut parts = text.rsplitn(3, ':');
        let (Some(seq), Some(log), Some(fp)) = (parts.next(), parts.next(), parts.next()) else {
            return Err(bad("bad source in the removed file"));
        };
        if !crate::pairing::looks_like_fingerprint(fp) {
            return Err(bad("bad admin fingerprint in the removed file"));
        }
        Ok(Source::Admin {
            fingerprint: fp.to_string(),
            log_id: log_id_parse(log)?,
            seq: parse_u32(seq)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordKind {
    Removed(Source),
    Restored,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub key: [u8; 32],
    pub kind: RecordKind,
    /// Unix time, for people only. Nothing is ordered or expired by it.
    pub time: u64,
}

impl Record {
    fn to_line(&self) -> String {
        let (word, source) = match &self.kind {
            RecordKind::Removed(s) => ("removed", s.to_text()),
            RecordKind::Restored => ("restored", "local".to_string()),
        };
        format!("{} {word} {source} {}\n", key_to_text(&self.key), self.time)
    }

    fn parse(line: &str) -> Result<Self> {
        let parts: Vec<&str> = line.split(' ').collect();
        let [key, word, source, time] = parts[..] else {
            return Err(bad("bad line in the removed file"));
        };
        let kind = match (word, source) {
            ("removed", s) => RecordKind::Removed(Source::parse(s)?),
            ("restored", "local") => RecordKind::Restored,
            _ => return Err(bad("bad record in the removed file")),
        };
        Ok(Record {
            key: key_from_text(key)?,
            kind,
            time: parse_u64(time)?,
        })
    }
}

/// The `removed` file, read.
#[derive(Debug, Clone, Default)]
pub struct Removed {
    records: Vec<Record>,
    /// For each key, whether its latest record is a removal (so a lookup does
    /// not walk a long file), and the order keys first appeared in.
    latest: std::collections::HashMap<[u8; 32], bool>,
    order: Vec<[u8; 32]>,
}

impl Removed {
    pub fn records(&self) -> &[Record] {
        &self.records
    }

    /// Is this key removed right now? The latest record for it decides:
    /// removed, or restored by a person at the device.
    pub fn is_removed(&self, key: &[u8; 32]) -> bool {
        self.latest.get(key).copied().unwrap_or(false)
    }

    fn from_records(records: Vec<Record>) -> Self {
        let mut latest = std::collections::HashMap::new();
        let mut order = Vec::new();
        for r in &records {
            if latest
                .insert(r.key, matches!(r.kind, RecordKind::Removed(_)))
                .is_none()
            {
                order.push(r.key);
            }
        }
        Self {
            records,
            latest,
            order,
        }
    }

    /// How many entries from this admin are on record (all its logs).
    pub fn entries_from(&self, admin_fp: &str) -> usize {
        self.records
            .iter()
            .filter(|r| matches!(&r.kind, RecordKind::Removed(Source::Admin { fingerprint, .. }) if fingerprint == admin_fp))
            .count()
    }

    /// Every key that is removed right now, once each.
    pub fn removed_keys(&self) -> Vec<[u8; 32]> {
        self.order
            .iter()
            .copied()
            .filter(|k| self.is_removed(k))
            .collect()
    }

    /// Was this exact entry (same key, admin, log and seq) already received?
    /// Restoring a key does not forget it, so the same entry is never applied
    /// twice, while a newer entry still removes the key again.
    pub fn knows_entry(&self, key: &[u8; 32], admin_fp: &str, log_id: &LogId, seq: u32) -> bool {
        self.records.iter().any(|r| {
            &r.key == key
                && matches!(&r.kind, RecordKind::Removed(Source::Admin { fingerprint, log_id: l, seq: s })
                    if fingerprint == admin_fp && l == log_id && *s == seq)
        })
    }
}

/// The biggest `removed` file read or written (about 150,000 records).
pub const REMOVED_CAP: u64 = 16 << 20;

/// Read `removed`, line by line. Strict: a line it cannot read is an error,
/// because skipping it would trust a key somebody removed. A last line with
/// no newline is a write that was cut short; it was never complete, so it
/// is left out.
pub fn load_removed(dir: &Path) -> Result<Removed> {
    use std::io::{BufRead, BufReader};
    let path = dir.join(REMOVED_FILE);
    if fs::symlink_metadata(&path).is_err() {
        return Ok(Removed::default());
    }
    let (f, _) = open_private_file(&path, REMOVED_CAP)?;
    let mut reader = BufReader::new(f);
    let mut records = Vec::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = reader.read_until(b'\n', &mut line)?;
        if n == 0 {
            break;
        }
        if line.last() != Some(&b'\n') {
            break; // cut short
        }
        let text = std::str::from_utf8(&line[..line.len() - 1])
            .map_err(|_| bad("removed file is not UTF-8"))?;
        if !text.is_empty() {
            records.push(Record::parse(text)?);
        }
    }
    Ok(Removed::from_records(records))
}

/// Append one record: a true append, flushed to disk, so adding a line costs
/// the same however long the file is (and a reader never sees half a record
/// that mattered).
fn append_record(dir: &Path, _lock: &DirLock, rec: &Record) -> Result<()> {
    append_private_line(
        &dir.join(REMOVED_FILE),
        REMOVED_CAP,
        rec.to_line().as_bytes(),
    )
}

// ---- removing on this device -------------------------------------------

/// What a removal did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoveOutcome {
    /// The peer as it was listed before, if it was listed.
    pub peer: Option<Peer>,
    /// It already had a tombstone before this call.
    pub already_removed: bool,
}

fn remove_file_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// The whole local removal, under the lock the caller holds. Tombstone first.
fn remove_key_locked(
    dir: &Path,
    lock: &DirLock,
    target: &[u8; 32],
    source: Source,
    unix: u64,
) -> Result<RemoveOutcome> {
    let removed = load_removed(dir)?;
    let already_removed = removed.is_removed(target);
    let mut listed = store::read_entries(dir)?;
    let pos = listed.iter().position(|p| &p.public == target);
    let peer = pos.map(|i| listed[i].clone());
    let fp = fingerprint(target);

    // 1. The tombstone. After this line is saved the key is never trusted.
    append_record(
        dir,
        lock,
        &Record {
            key: *target,
            kind: RecordKind::Removed(source),
            time: unix,
        },
    )?;
    // 2. Out of the list.
    if let Some(i) = pos {
        listed.remove(i);
        store::write_entries(dir, lock, &listed)?;
    }
    // 3. Its handshake timestamps.
    remove_file_if_exists(FileTimestampStore::new(dir, target).path())?;
    // 4. Votes it cast, and votes against it.
    let mut votes = read_votes(dir)?;
    let before = votes.len();
    votes.retain(|v| v.admin_fp != fp && &v.target != target);
    if votes.len() != before {
        write_votes(dir, lock, &votes)?;
    }
    // 5. Signing keys. A ground station forgets the removed drone's keys.
    let keys = dir.join(PEER_KEYS_DIR);
    if let Ok(rd) = fs::read_dir(&keys) {
        let prefix = format!("{fp}.");
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().starts_with(&prefix) {
                remove_file_if_exists(&e.path())?;
            }
        }
    }
    //    A drone asks for a new signing key when an operator goes.
    if peer.as_ref().is_some_and(|p| p.role == Role::Operator)
        && fs::symlink_metadata(dir.join(AUTOPILOT_KEY_FILE)).is_ok()
    {
        mark_rotation_pending(dir, &fp, unix)?;
    }
    Ok(RemoveOutcome {
        peer,
        already_removed,
    })
}

/// Ask for a signing-key rotation (phase B acts on this file). One line per
/// removed operator; the lock is held by the caller.
fn mark_rotation_pending(dir: &Path, operator_fp: &str, unix: u64) -> Result<()> {
    let path = dir.join(ROTATION_PENDING_FILE);
    let mut text: Vec<u8> = read_private_file_opt(&path)?
        .map(|b| b.to_vec())
        .unwrap_or_default();
    text.extend_from_slice(format!("{unix} operator-removed {operator_fp}\n").as_bytes());
    write_private_file(&path, &text)
}

/// `oasa-pair remove`: remove `target` on this device. A tombstone, then out
/// of the list, its timestamps deleted. Works for keys that were never
/// listed (the tombstone then keeps them out for good). `own` is this
/// device's key; a device cannot remove itself.
pub fn remove_local(
    dir: &Path,
    own: &[u8; 32],
    target: &[u8; 32],
    unix: u64,
) -> Result<RemoveOutcome> {
    if own == target {
        return Err(Error::Link("a device cannot remove itself"));
    }
    store::migrate_if_needed(dir)?;
    let lock = DirLock::acquire(dir)?;
    remove_key_locked(dir, &lock, target, Source::Local, unix)
}

/// `oasa-pair restore`: undo a removal on this device. Appends a restore
/// record; the device is not trusted again until a person pairs or trusts it
/// again. Entries already received for the key are not applied again; a newer
/// one removes it again. Returns false if the key was not removed.
pub fn restore(dir: &Path, key: &[u8; 32], unix: u64) -> Result<bool> {
    let lock = DirLock::acquire(dir)?;
    if !load_removed(dir)?.is_removed(key) {
        return Ok(false);
    }
    append_record(
        dir,
        &lock,
        &Record {
            key: *key,
            kind: RecordKind::Restored,
            time: unix,
        },
    )?;
    Ok(true)
}

// ---- the removal log (admins) -------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    pub seq: u32,
    pub key: [u8; 32],
    pub time: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovalLog {
    pub id: LogId,
    /// `seq` 1, 2, 3... in order, no gaps.
    pub entries: Vec<LogEntry>,
}

impl RemovalLog {
    /// Highest seq (0 for an empty log).
    pub fn highest(&self) -> u32 {
        self.entries.last().map_or(0, |e| e.seq)
    }

    pub fn entry(&self, seq: u32) -> Option<&LogEntry> {
        seq.checked_sub(1)
            .and_then(|i| self.entries.get(i as usize))
    }

    fn to_text(&self) -> String {
        let mut t = format!("{}\n", log_id_text(&self.id));
        for e in &self.entries {
            t.push_str(&format!("{} {} {}\n", e.seq, key_to_text(&e.key), e.time));
        }
        t
    }
}

/// This device's removal log, if it has one.
pub fn load_log(dir: &Path) -> Result<Option<RemovalLog>> {
    let Some(bytes) = read_private_file_opt(&dir.join(LOG_FILE))? else {
        return Ok(None);
    };
    let text = std::str::from_utf8(&bytes).map_err(|_| bad("removal log is not UTF-8"))?;
    let mut lines = text.lines();
    let id = log_id_parse(lines.next().ok_or_else(|| bad("empty removal log"))?)?;
    let mut entries: Vec<LogEntry> = Vec::new();
    for line in lines.filter(|l| !l.is_empty()) {
        let parts: Vec<&str> = line.split(' ').collect();
        let [seq, key, time] = parts[..] else {
            return Err(bad("bad line in the removal log"));
        };
        let seq = parse_u32(seq)?;
        if u64::from(seq) != entries.len() as u64 + 1 {
            return Err(bad("removal log sequence numbers must count 1, 2, 3..."));
        }
        entries.push(LogEntry {
            seq,
            key: key_from_text(key)?,
            time: parse_u64(time)?,
        });
    }
    Ok(Some(RemovalLog { id, entries }))
}

/// What `revoke` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revoked {
    pub log_id: LogId,
    pub seq: u32,
    /// The key was already in the log, so no new entry was added.
    pub was_in_log: bool,
    pub outcome: RemoveOutcome,
}

/// `oasa-pair revoke`: add `target` to this device's removal log (making the
/// log, with a random id, the first time) and remove it locally. The log
/// entry is saved first: if we stop in between, the fleet still learns of it
/// and running `revoke` again finishes the local part. An admin cannot revoke
/// itself.
pub fn revoke(dir: &Path, own: &[u8; 32], target: &[u8; 32], unix: u64) -> Result<Revoked> {
    if own == target {
        return Err(Error::Link("a device cannot revoke itself"));
    }
    check_peer_public(target)?;
    store::migrate_if_needed(dir)?;
    let lock = DirLock::acquire(dir)?;
    let mut log = match load_log(dir)? {
        Some(l) => l,
        None => {
            let mut id = [0u8; 4];
            getrandom::fill(&mut id).map_err(|e| Error::Io(std::io::Error::other(e)))?;
            RemovalLog {
                id,
                entries: Vec::new(),
            }
        }
    };
    let existing = log.entries.iter().find(|e| &e.key == target).map(|e| e.seq);
    let (seq, was_in_log) = match existing {
        Some(seq) => (seq, true),
        None => {
            let seq = log.highest() + 1;
            log.entries.push(LogEntry {
                seq,
                key: *target,
                time: unix,
            });
            write_private_file(&dir.join(LOG_FILE), log.to_text().as_bytes())?;
            (seq, false)
        }
    };
    let outcome = remove_key_locked(dir, &lock, target, Source::Local, unix)?;
    Ok(Revoked {
        log_id: log.id,
        seq,
        was_in_log,
        outcome,
    })
}

// ---- what a device knows about each admin's log --------------------------

fn sync_path(dir: &Path, admin_fp: &str) -> PathBuf {
    dir.join(SYNC_DIR).join(admin_fp)
}

/// `(log id, highest seq held in a row)` for this admin, if any.
pub fn sync_state(dir: &Path, admin_fp: &str) -> Result<Option<(LogId, u32)>> {
    let Some(bytes) = read_private_file_opt(&sync_path(dir, admin_fp))? else {
        return Ok(None);
    };
    let text = std::str::from_utf8(&bytes).map_err(|_| bad("sync file is not UTF-8"))?;
    let parts: Vec<&str> = text.trim_end().split(' ').collect();
    let [id, held] = parts[..] else {
        return Err(bad("bad removal-sync file"));
    };
    Ok(Some((log_id_parse(id)?, parse_u32(held)?)))
}

fn write_sync(dir: &Path, _lock: &DirLock, admin_fp: &str, id: &LogId, held: u32) -> Result<()> {
    write_private_file(
        &sync_path(dir, admin_fp),
        format!("{} {held}\n", log_id_text(id)).as_bytes(),
    )
}

/// An admin's `REMOVE_HEAD`: its log id and highest seq. Returns what to
/// answer with `REMOVE_HAVE`. A new log id, or a head below what we hold
/// (a reinstalled admin), answers 0 and starts that log over.
pub fn on_head(dir: &Path, admin_fp: &str, log_id: &LogId, highest: u32) -> Result<u32> {
    let lock = DirLock::acquire(dir)?;
    match sync_state(dir, admin_fp)? {
        Some((id, held)) if &id == log_id && highest >= held => Ok(held),
        _ => {
            write_sync(dir, &lock, admin_fp, log_id, 0)?;
            Ok(0)
        }
    }
}

// ---- the two-admin rule --------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct Vote {
    target: [u8; 32],
    admin_fp: String,
    log_id: LogId,
    seq: u32,
}

fn read_votes(dir: &Path) -> Result<Vec<Vote>> {
    let Some(bytes) = read_private_file_opt(&dir.join(VOTES_FILE))? else {
        return Ok(Vec::new());
    };
    let text = std::str::from_utf8(&bytes).map_err(|_| bad("votes file is not UTF-8"))?;
    text.lines()
        .filter(|l| !l.is_empty())
        .map(|line| {
            let parts: Vec<&str> = line.split(' ').collect();
            let [target, fp, log, seq] = parts[..] else {
                return Err(bad("bad line in admin-votes"));
            };
            if !crate::pairing::looks_like_fingerprint(fp) {
                return Err(bad("bad fingerprint in admin-votes"));
            }
            Ok(Vote {
                target: key_from_text(target)?,
                admin_fp: fp.to_string(),
                log_id: log_id_parse(log)?,
                seq: parse_u32(seq)?,
            })
        })
        .collect()
}

fn write_votes(dir: &Path, _lock: &DirLock, votes: &[Vote]) -> Result<()> {
    let mut t = String::new();
    for v in votes {
        t.push_str(&format!(
            "{} {} {} {}\n",
            key_to_text(&v.target),
            v.admin_fp,
            log_id_text(&v.log_id),
            v.seq
        ));
    }
    write_private_file(&dir.join(VOTES_FILE), t.as_bytes())
}

/// One entry of an admin's removal log, as received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub log_id: LogId,
    pub seq: u32,
    pub target: [u8; 32],
    pub time: u64,
}

/// What happened to a received entry. All of these are acknowledged except
/// [`Applied::NotAdmin`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applied {
    /// The target is removed now.
    Removed,
    /// The target is an admin here and needs a second admin; one vote is kept.
    Voted,
    /// This exact entry was received before.
    Known,
    /// The entry names this device's own key: ignored.
    OwnKey,
    /// The admin named itself: ignored.
    SelfRevoke,
    /// The sender is not (or no longer) an admin here. Nothing changed.
    NotAdmin,
    /// A limit was reached (this admin already has [`MAX_ENTRIES_PER_ADMIN`]
    /// entries on record, or the caller's budget for new removals is spent).
    /// Nothing changed and the entry must not be acked.
    Limit,
}

/// Entries one admin may have on record here, across all its logs. A stolen
/// admin cannot fill the `removed` file; a real fleet needs far fewer.
pub const MAX_ENTRIES_PER_ADMIN: usize = 4096;

/// Apply an entry from `admin`'s removal log (`REMOVE_ENTRY`), all under the
/// lock. Union semantics: every entry from a valid admin applies, in any
/// order, so a lost or reordered message never undoes anything. A target
/// whose role **on this device** is admin needs entries from two different
/// admins; a removed admin's votes are dropped; this device's own key is
/// never a vote and an entry for it is ignored.
pub fn apply_entry(
    dir: &Path,
    own: &[u8; 32],
    admin: &[u8; 32],
    entry: &Entry,
    unix: u64,
) -> Result<Applied> {
    apply_entry_limited(dir, own, admin, entry, unix, true)
}

/// [`apply_entry`] with a say in whether an entry that would add a new
/// removal or vote may go ahead (`allow_new`); the control layer spends a
/// per-session budget on it.
pub fn apply_entry_limited(
    dir: &Path,
    own: &[u8; 32],
    admin: &[u8; 32],
    entry: &Entry,
    unix: u64,
    allow_new: bool,
) -> Result<Applied> {
    check_peer_public(&entry.target)?;
    store::migrate_if_needed(dir)?;
    let lock = DirLock::acquire(dir)?;
    let removed = load_removed(dir)?;
    let listed = store::read_entries(dir)?;
    let effective = |k: &[u8; 32]| {
        listed
            .iter()
            .find(|p| &p.public == k && !removed.is_removed(k))
    };
    // Checked again here, under the lock: the sender may have been removed
    // since the control layer looked.
    if !effective(admin).is_some_and(|p| p.role == Role::Admin) {
        return Ok(Applied::NotAdmin);
    }
    let admin_fp = fingerprint(admin);
    let outcome = if &entry.target == own {
        Applied::OwnKey
    } else if &entry.target == admin {
        Applied::SelfRevoke
    } else if removed.knows_entry(&entry.target, &admin_fp, &entry.log_id, entry.seq) {
        Applied::Known
    } else if !allow_new || removed.entries_from(&admin_fp) >= MAX_ENTRIES_PER_ADMIN {
        return Ok(Applied::Limit);
    } else {
        let source = Source::Admin {
            fingerprint: admin_fp.clone(),
            log_id: entry.log_id,
            seq: entry.seq,
        };
        match effective(&entry.target).map(|p| p.role) {
            Some(Role::Admin) => {
                match vote(dir, &lock, own, entry, &admin_fp, &listed, &removed)? {
                    None => Applied::Voted,
                    Some(()) => {
                        remove_key_locked(dir, &lock, &entry.target, source, unix)?;
                        Applied::Removed
                    }
                }
            }
            _ => {
                remove_key_locked(dir, &lock, &entry.target, source, unix)?;
                Applied::Removed
            }
        }
    };
    advance_sync(dir, &lock, &admin_fp, entry)?;
    Ok(outcome)
}

/// Record `admin`'s vote against an admin target. `Some(())` if that makes
/// two different, still-valid admins, so the removal goes ahead.
fn vote(
    dir: &Path,
    lock: &DirLock,
    own: &[u8; 32],
    entry: &Entry,
    admin_fp: &str,
    listed: &[Peer],
    removed: &Removed,
) -> Result<Option<()>> {
    let target_fp = fingerprint(&entry.target);
    let own_fp = fingerprint(own);
    // Admins that count: listed as admin here, not removed.
    let valid: BTreeSet<String> = listed
        .iter()
        .filter(|p| p.role == Role::Admin && !removed.is_removed(&p.public))
        .map(|p| p.fingerprint())
        .collect();
    let mut votes = read_votes(dir)?;
    // A removed admin's votes are dropped; so is anyone who is not an admin
    // here any more.
    votes.retain(|v| valid.contains(&v.admin_fp));
    let already = votes
        .iter()
        .any(|v| v.target == entry.target && v.admin_fp == admin_fp);
    if !already {
        votes.push(Vote {
            target: entry.target,
            admin_fp: admin_fp.to_string(),
            log_id: entry.log_id,
            seq: entry.seq,
        });
    }
    let voters: BTreeSet<&str> = votes
        .iter()
        .filter(|v| v.target == entry.target)
        .map(|v| v.admin_fp.as_str())
        // The target never votes for itself, and this device never votes.
        .filter(|fp| *fp != target_fp && *fp != own_fp)
        .collect();
    let done = voters.len() >= 2;
    write_votes(dir, lock, &votes)?;
    Ok(done.then_some(()))
}

/// Move the "held in a row" number forward after an entry was dealt with,
/// including over entries already held out of order.
fn advance_sync(dir: &Path, lock: &DirLock, admin_fp: &str, entry: &Entry) -> Result<()> {
    let Some((id, held)) = sync_state(dir, admin_fp)? else {
        return Ok(());
    };
    if id != entry.log_id {
        // Not the log we last synced with: a head comes first and resets it.
        return Ok(());
    }
    let mut now = held;
    if entry.seq == now.saturating_add(1) {
        now = entry.seq;
    }
    let removed = load_removed(dir)?;
    let mut known: BTreeSet<u32> = removed
        .records()
        .iter()
        .filter_map(|r| match &r.kind {
            RecordKind::Removed(Source::Admin {
                fingerprint,
                log_id,
                seq,
            }) if fingerprint == admin_fp && *log_id == id => Some(*seq),
            _ => None,
        })
        .collect();
    known.extend(
        read_votes(dir)?
            .iter()
            .filter(|v| v.admin_fp == admin_fp && v.log_id == id)
            .map(|v| v.seq),
    );
    while known.contains(&now.saturating_add(1)) && now < u32::MAX {
        now += 1;
    }
    if now != held {
        write_sync(dir, lock, admin_fp, &id, now)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
