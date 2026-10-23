//! Signing-key rotation files (spec R-SEC2 section 4): generations, the
//! pending key, the request file, and what an operator keeps.
//!
//! Every function that changes files takes the folder lock itself, or takes
//! a `&DirLock` as proof that the caller holds it. Nothing here talks to an
//! autopilot (that is [`crate::signer`]) or to a peer (that is
//! [`crate::control`]).
//!
//! # A drone's files
//!
//! | File | What |
//! |---|---|
//! | `mavlink-signing-key.bin` | The autopilot's current key (PX4's 40-byte layout) |
//! | `mavlink-signing-key.gen` | That key's generation (missing means 0: the key from pairing) |
//! | `mavlink-signing-key.next` | A new key not yet proven to be in the autopilot |
//! | `mavlink-signing-gen` | The highest generation ever issued; **never lowered, never reused** |
//! | `rotation-pending` | One line per reason to rotate: `<unix> <reason> <who>` |
//! | `signing-acked/<fp>` | Per operator: `<next gen acked> <commit gen acked>` |
//!
//! While `.next` exists, its generation is the number in `mavlink-signing-gen`
//! (a rotation saves the number first, the key second, and starts only when
//! no `.next` exists).
//!
//! # An operator's files
//!
//! For a drone with fingerprint `FP`, in `signing-keys/`: `FP.bin` (current),
//! `FP.gen`, `FP.next`, `FP.next.gen`. It switches only on a commit.

use std::fs;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::files::{DirLock, read_private_file, read_private_file_opt, write_private_file};
use crate::signing::{AUTOPILOT_KEY_FILE, PEER_KEYS_DIR, SigningKey, peer_key_path};
use crate::{Error, Result};

pub const CURRENT_GEN_FILE: &str = "mavlink-signing-key.gen";
pub const NEXT_KEY_FILE: &str = "mavlink-signing-key.next";
pub const HIGHEST_GEN_FILE: &str = "mavlink-signing-gen";
pub const PENDING_FILE: &str = crate::removal::ROTATION_PENDING_FILE;
pub const ACKED_DIR: &str = "signing-acked";

fn bad(why: &str) -> Error {
    Error::BadKeyFile(why.to_string())
}

fn remove_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// A generation file: one decimal number and a newline.
fn read_gen(path: &Path) -> Result<Option<u32>> {
    let Some(bytes) = read_private_file_opt(path)? else {
        return Ok(None);
    };
    let text = std::str::from_utf8(&bytes).map_err(|_| bad("generation file is not text"))?;
    let t = text.trim_end_matches('\n');
    if t.is_empty() || t.len() > 10 || !t.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad("generation file must hold one number"));
    }
    t.parse().map(Some).map_err(|_| bad("generation too large"))
}

fn write_gen(path: &Path, g: u32) -> Result<()> {
    write_private_file(path, format!("{g}\n").as_bytes())
}

// ---- a drone ------------------------------------------------------------------

/// The drone's keys as they are on disk right now.
pub struct DroneKeys {
    pub current: SigningKey,
    pub current_gen: u32,
    /// A key waiting to be proven, with its generation.
    pub next: Option<(u32, SigningKey)>,
    /// The highest generation ever issued.
    pub highest: u32,
}

/// Read the drone's keys. `Ok(None)` when this folder holds no autopilot key
/// (not a drone). An inconsistent folder is an error: nothing here guesses.
pub fn load_drone_keys(dir: &Path) -> Result<Option<DroneKeys>> {
    let key_path = dir.join(AUTOPILOT_KEY_FILE);
    if fs::symlink_metadata(&key_path).is_err() {
        return Ok(None);
    }
    let current = SigningKey::load(&key_path)?;
    let current_gen = read_gen(&dir.join(CURRENT_GEN_FILE))?.unwrap_or(0);
    let issued = read_gen(&dir.join(HIGHEST_GEN_FILE))?.unwrap_or(0);
    let highest = issued.max(current_gen);
    let next_path = dir.join(NEXT_KEY_FILE);
    let next = if fs::symlink_metadata(&next_path).is_ok() {
        let k = SigningKey::load(&next_path)?;
        if issued <= current_gen {
            return Err(bad(
                "a pending signing key exists but its generation was not saved; \
                 refusing to guess (keep both key files and ask for help)",
            ));
        }
        Some((issued, k))
    } else {
        None
    };
    Ok(Some(DroneKeys {
        current,
        current_gen,
        next,
        highest,
    }))
}

/// A rotation that has begun: what the signer needs to finish it.
pub struct Begun {
    pub generation: u32,
    pub key: SigningKey,
    /// How many lines of `rotation-pending` this rotation answers.
    pub consumed: usize,
}

/// Step 2: issue the next generation and save the new key as `.next`, before
/// anything is sent. The number is saved first, so a crash burns a number and
/// never reuses one. Refuses while a `.next` already exists.
pub fn begin(dir: &Path) -> Result<Begun> {
    let lock = DirLock::acquire(dir)?;
    let keys = load_drone_keys(dir)?.ok_or(Error::Link("this folder holds no autopilot key"))?;
    if keys.next.is_some() {
        return Err(Error::Link("a new signing key is already pending"));
    }
    let generation = keys
        .highest
        .checked_add(1)
        .ok_or(Error::Link("generation numbers are used up"))?;
    let key = SigningKey::generate()?;
    write_gen(&dir.join(HIGHEST_GEN_FILE), generation)?;
    key.save(&dir.join(NEXT_KEY_FILE))?;
    let consumed = pending_lines_locked(dir, &lock)?;
    Ok(Begun {
        generation,
        key,
        consumed,
    })
}

/// Step 6: the autopilot answered under the new key. Replace the current key,
/// then the generation, delete `.next`, and clear the requests this rotation
/// answered (lines added since stay, so a removal that happened meanwhile
/// still gets its own rotation). Safe to run again after a crash part-way:
/// each step is atomic and the order lets a restart finish the job.
pub fn commit(dir: &Path, generation: u32, consumed: usize) -> Result<()> {
    let lock = DirLock::acquire(dir)?;
    let next_path = dir.join(NEXT_KEY_FILE);
    if fs::symlink_metadata(&next_path).is_ok() {
        let keys = load_drone_keys(dir)?.ok_or(Error::Link("no autopilot key"))?;
        match keys.next {
            Some((g, k)) if g == generation => k.save(&dir.join(AUTOPILOT_KEY_FILE))?,
            _ => {
                return Err(Error::Link(
                    "the pending key is not the one being committed",
                ));
            }
        }
    } else {
        // Already switched by an earlier run that stopped part-way.
        let cur = read_gen(&dir.join(CURRENT_GEN_FILE))?.unwrap_or(0);
        if cur != generation && read_gen(&dir.join(HIGHEST_GEN_FILE))? != Some(generation) {
            return Err(Error::Link("no pending key to commit"));
        }
    }
    write_gen(&dir.join(CURRENT_GEN_FILE), generation)?;
    remove_if_exists(&next_path)?;
    clear_pending_locked(dir, &lock, consumed)
}

/// The autopilot kept the old key: forget the new one. The request stays, so
/// the next try runs with a new generation.
pub fn abandon(dir: &Path) -> Result<()> {
    let _lock = DirLock::acquire(dir)?;
    remove_if_exists(&dir.join(NEXT_KEY_FILE))
}

// ---- requests -------------------------------------------------------------------

/// Ask for a rotation: add a line to `rotation-pending`. `who` is a
/// fingerprint or `-`.
pub fn request(dir: &Path, reason: &str, who: &str, unix: u64) -> Result<()> {
    if reason.is_empty()
        || reason.contains(char::is_whitespace)
        || who.contains(char::is_whitespace)
    {
        return Err(Error::Link("bad rotation request"));
    }
    let lock = DirLock::acquire(dir)?;
    let path = dir.join(PENDING_FILE);
    let mut text: Vec<u8> = read_private_file_opt(&path)?
        .map(|b| b.to_vec())
        .unwrap_or_default();
    let _ = &lock;
    text.extend_from_slice(format!("{unix} {reason} {who}\n").as_bytes());
    write_private_file(&path, &text)
}

fn pending_lines_locked(dir: &Path, _lock: &DirLock) -> Result<usize> {
    Ok(match read_private_file_opt(&dir.join(PENDING_FILE))? {
        Some(b) => b.split(|c| *c == b'\n').filter(|l| !l.is_empty()).count(),
        None => 0,
    })
}

/// How many rotation requests are waiting.
pub fn pending_lines(dir: &Path) -> Result<usize> {
    let lock = DirLock::acquire(dir)?;
    pending_lines_locked(dir, &lock)
}

fn clear_pending_locked(dir: &Path, _lock: &DirLock, consumed: usize) -> Result<()> {
    let path = dir.join(PENDING_FILE);
    let Some(bytes) = read_private_file_opt(&path)? else {
        return Ok(());
    };
    let lines: Vec<&[u8]> = bytes
        .split(|c| *c == b'\n')
        .filter(|l| !l.is_empty())
        .collect();
    if lines.len() <= consumed {
        return remove_if_exists(&path);
    }
    let mut keep = Vec::new();
    for l in &lines[consumed..] {
        keep.extend_from_slice(l);
        keep.push(b'\n');
    }
    write_private_file(&path, &keep)
}

/// How many requests are older than the pending key (a crash recovery does
/// not know how many it answered; this counts those dated before `.next`
/// was written, and leaves a request from the same second or later).
pub fn lines_before_next(dir: &Path) -> Result<usize> {
    let _lock = DirLock::acquire(dir)?;
    let made = fs::metadata(dir.join(NEXT_KEY_FILE))?
        .modified()?
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let Some(bytes) = read_private_file_opt(&dir.join(PENDING_FILE))? else {
        return Ok(0);
    };
    let mut n = 0;
    for line in bytes.split(|c| *c == b'\n').filter(|l| !l.is_empty()) {
        let first = line.split(|c| *c == b' ').next().unwrap_or(&[]);
        let unix: u64 = std::str::from_utf8(first)
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(u64::MAX);
        if unix < made {
            n += 1;
        } else {
            break;
        }
    }
    Ok(n)
}

/// The highest signature timestamp `oasa-link` saw on signed MAVLink going
/// through the tunnel (MAVLink units). Missing or unreadable means 0: this is
/// only a floor for the initial timestamp.
pub const SEEN_TS_FILE: &str = "mavlink-signing-ts";

pub fn read_seen_ts(dir: &Path) -> Result<u64> {
    let Some(b) = read_private_file_opt(&dir.join(SEEN_TS_FILE))? else {
        return Ok(0);
    };
    let text = std::str::from_utf8(&b).map_err(|_| bad("not text"))?;
    text.trim().parse().map_err(|_| bad("not a number"))
}

/// Save a new high-water mark (only ever raises it). No lock: a lost race
/// only means a slightly lower floor, and the signer also uses its own clock.
pub fn write_seen_ts(dir: &Path, ts: u64) -> Result<()> {
    if read_seen_ts(dir).unwrap_or(0) >= ts {
        return Ok(());
    }
    write_private_file(&dir.join(SEEN_TS_FILE), format!("{ts}\n").as_bytes())
}

// ---- what a drone remembers about each operator ---------------------------------

/// What an operator has acked: the generation of the last `SIGNING_KEY_NEXT`
/// it acked, and of the last `SIGNING_KEY_COMMIT`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Acked {
    pub next: u32,
    pub commit: u32,
}

fn acked_path(dir: &Path, fp: &str) -> PathBuf {
    dir.join(ACKED_DIR).join(fp)
}

pub fn read_acked(dir: &Path, fp: &str) -> Result<Acked> {
    let Some(b) = read_private_file_opt(&acked_path(dir, fp))? else {
        return Ok(Acked::default());
    };
    let text = std::str::from_utf8(&b).map_err(|_| bad("signing-acked is not text"))?;
    let mut it = text.split_whitespace();
    let (Some(n), Some(c), None) = (it.next(), it.next(), it.next()) else {
        return Err(bad("signing-acked must hold two numbers"));
    };
    Ok(Acked {
        next: n.parse().map_err(|_| bad("bad number in signing-acked"))?,
        commit: c.parse().map_err(|_| bad("bad number in signing-acked"))?,
    })
}

pub fn write_acked(dir: &Path, fp: &str, a: Acked) -> Result<()> {
    if !crate::pairing::looks_like_fingerprint(fp) {
        return Err(Error::Link("bad fingerprint"));
    }
    let _lock = DirLock::acquire(dir)?;
    crate::files::ensure_private_dir(&dir.join(ACKED_DIR))?;
    write_private_file(
        &acked_path(dir, fp),
        format!("{} {}\n", a.next, a.commit).as_bytes(),
    )
}

/// What a drone should send an operator next, from the files alone.
#[derive(Debug, PartialEq, Eq)]
pub enum Owed {
    Nothing,
    Next(u32),
    Commit(u32),
}

/// The next message an operator is owed. A pending key goes out as soon as it
/// exists; a commit only after the autopilot took the key (no `.next`). An
/// operator that never got the current key's `NEXT` gets it first, so one that
/// was away over a rotation (or an older generation) catches up.
pub fn owed(keys: &DroneKeys, acked: Acked) -> Owed {
    match &keys.next {
        Some((n, _)) if acked.next != *n => Owed::Next(*n),
        Some(_) => Owed::Nothing,
        None if acked.commit >= keys.current_gen => Owed::Nothing,
        None if acked.next != keys.current_gen => Owed::Next(keys.current_gen),
        None => Owed::Commit(keys.current_gen),
    }
}

// ---- an operator ----------------------------------------------------------------

fn op_path(dir: &Path, fp: &str, suffix: &str) -> PathBuf {
    dir.join(PEER_KEYS_DIR).join(format!("{fp}{suffix}"))
}

#[derive(Debug, PartialEq, Eq)]
pub enum NextOutcome {
    /// Saved as the pending key.
    Stored,
    /// Already pending (same generation, same key).
    Known,
    /// Not newer than the current key: ignored, but safe to ack.
    Old,
    /// Same generation, different key: someone is confused or lying.
    Conflict,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CommitOutcome {
    Switched,
    AlreadyCurrent,
    /// No pending key for that generation: not acked.
    NoPending,
}

/// The generation of the key an operator holds for this drone (0 if none
/// was ever told).
pub fn operator_gen(dir: &Path, fp: &str) -> Result<u32> {
    Ok(read_gen(&op_path(dir, fp, ".gen"))?.unwrap_or(0))
}

/// `SIGNING_KEY_NEXT` arrived from the drone `fp`.
pub fn operator_on_next(
    dir: &Path,
    fp: &str,
    generation: u32,
    key: &[u8; 32],
) -> Result<NextOutcome> {
    let new_key = SigningKey::from_bytes(*key)?;
    let _lock = DirLock::acquire(dir)?;
    if fs::symlink_metadata(peer_key_path(dir, fp)).is_err() {
        return Err(Error::Link("no signing key held for this drone"));
    }
    if generation <= operator_gen(dir, fp)? {
        return Ok(NextOutcome::Old);
    }
    let (next, next_gen) = (op_path(dir, fp, ".next"), op_path(dir, fp, ".next.gen"));
    if let Some(g) = read_gen(&next_gen)?
        && g == generation
        && fs::symlink_metadata(&next).is_ok()
    {
        return if SigningKey::load(&next)? == new_key {
            Ok(NextOutcome::Known)
        } else {
            Ok(NextOutcome::Conflict)
        };
    }
    // Replace whatever was pending (a failed rotation's key, say). Remove the
    // old pair first, so a crash never leaves a key with the wrong number.
    remove_if_exists(&next)?;
    remove_if_exists(&next_gen)?;
    write_gen(&next_gen, generation)?;
    new_key.save(&next)?;
    Ok(NextOutcome::Stored)
}

/// `SIGNING_KEY_COMMIT` arrived from the drone `fp`: switch, only if that
/// generation is the pending one. Each step is atomic and the order lets a
/// repeat finish an interrupted switch.
pub fn operator_on_commit(dir: &Path, fp: &str, generation: u32) -> Result<CommitOutcome> {
    let _lock = DirLock::acquire(dir)?;
    if fs::symlink_metadata(peer_key_path(dir, fp)).is_err() {
        return Err(Error::Link("no signing key held for this drone"));
    }
    let (next, next_gen) = (op_path(dir, fp, ".next"), op_path(dir, fp, ".next.gen"));
    let cur = operator_gen(dir, fp)?;
    let pending = read_gen(&next_gen)?;
    if pending == Some(generation) && fs::symlink_metadata(&next).is_ok() {
        let k = SigningKey::load(&next)?;
        k.save(&peer_key_path(dir, fp))?;
        write_gen(&op_path(dir, fp, ".gen"), generation)?;
        remove_if_exists(&next)?;
        remove_if_exists(&next_gen)?;
        return Ok(CommitOutcome::Switched);
    }
    if cur == generation {
        // A repeat. Tidy up if a switch stopped before the clean-up.
        if pending == Some(generation) {
            remove_if_exists(&next)?;
            remove_if_exists(&next_gen)?;
        }
        return Ok(CommitOutcome::AlreadyCurrent);
    }
    Ok(CommitOutcome::NoPending)
}

/// The pending key an operator holds for a drone, if any: `(generation, key)`.
pub fn operator_pending(dir: &Path, fp: &str) -> Result<Option<(u32, SigningKey)>> {
    let (next, next_gen) = (op_path(dir, fp, ".next"), op_path(dir, fp, ".next.gen"));
    match (read_gen(&next_gen)?, fs::symlink_metadata(&next).is_ok()) {
        (Some(g), true) => Ok(Some((g, SigningKey::load(&next)?))),
        _ => Ok(None),
    }
}

/// Read a raw key file's bytes (tests and tools).
#[allow(dead_code)]
pub(crate) fn key_bytes(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    read_private_file(path)
}

#[cfg(test)]
mod tests;
