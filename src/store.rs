//! Trusted peers: the devices this device has paired with, and the role each
//! one has (spec R-SEC2 section 1).
//!
//! The file is `trusted-peers.v1`: a format line `oasa-trusted-peers v1`,
//! then one line per peer, `<public key, base32> <role> <name>`. It is
//! owner-only, because anyone who can add a line to it could make this device
//! trust them. Roles are set only here, by a person at the device (pairing,
//! `oasa-pair trust`, or by hand); no message can change one.
//!
//! The file has a new name on purpose. A binary from before roles looks for
//! `trusted-peers`, finds nothing and trusts no one, instead of reading roles
//! as names. A new binary that finds only the old file converts it once
//! ([`migrate_if_needed`]).
//!
//! A key in the device's `removed` file is never loaded, even if it is still
//! in this file ([`crate::removal`]).

use std::fmt;
use std::path::Path;

use crate::files::{DirLock, read_private_file, read_private_file_opt, write_private_file};
use crate::identity::{check_peer_public, fingerprint};
use crate::removal::{Removed, load_removed};
use crate::signing::AUTOPILOT_KEY_FILE;
use crate::{Error, Result};

/// The trusted-peers file with roles.
pub const TRUST_FILE: &str = "trusted-peers.v1";
/// The file before roles (read only to migrate it).
pub const OLD_TRUST_FILE: &str = "trusted-peers";
/// What the old file is renamed to after migration.
pub const MIGRATED_FILE: &str = "trusted-peers.v0-migrated";
/// First line of the trusted-peers file.
pub const FORMAT_LINE: &str = "oasa-trusted-peers v1";

/// What a trusted peer may do (spec R-SEC2 section 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Role {
    /// An owner device. May have this device remove operators and peers.
    Admin,
    /// A ground station paired with this drone.
    Operator,
    /// Everything else. Link traffic only.
    #[default]
    Peer,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Operator => "operator",
            Role::Peer => "peer",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "admin" => Some(Role::Admin),
            "operator" => Some(Role::Operator),
            "peer" => Some(Role::Peer),
            _ => None,
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub public: [u8; 32],
    pub name: String,
    pub role: Role,
}

impl Peer {
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.public)
    }
}

/// A public key as base32 text (how the files write it).
pub(crate) fn key_to_text(key: &[u8; 32]) -> String {
    data_encoding::BASE32_NOPAD.encode(key)
}

/// The other way. Any 32-byte key; callers that trust it also run
/// [`check_peer_public`].
pub(crate) fn key_from_text(text: &str) -> Result<[u8; 32]> {
    let bytes = data_encoding::BASE32_NOPAD
        .decode(text.as_bytes())
        .map_err(|_| Error::BadKeyFile("bad key in file".into()))?;
    bytes
        .try_into()
        .map_err(|_| Error::BadKeyFile("key must be 32 bytes".into()))
}

fn exists(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// Parse `trusted-peers.v1`. Strict: anything unexpected is an error, so a
/// damaged file stops the device instead of quietly trusting less or more.
fn parse_v1(bytes: &[u8]) -> Result<Vec<Peer>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::BadKeyFile("trust file is not UTF-8".into()))?;
    let mut lines = text
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'));
    if lines.next() != Some(FORMAT_LINE) {
        return Err(Error::BadKeyFile(format!(
            "{TRUST_FILE} must start with the line \"{FORMAT_LINE}\" (a newer or damaged file?)"
        )));
    }
    let mut peers: Vec<Peer> = Vec::new();
    for line in lines {
        let mut parts = line.splitn(3, ' ');
        let (Some(key), Some(role), Some(name)) = (parts.next(), parts.next(), parts.next()) else {
            return Err(Error::BadKeyFile("bad trust line".into()));
        };
        let public = key_from_text(key)?;
        check_peer_public(&public)?;
        let role = Role::parse(role)
            .ok_or_else(|| Error::BadKeyFile(format!("unknown role {role:?} in trust file")))?;
        crate::pairing::check_name(name)
            .map_err(|_| Error::BadKeyFile("bad device name in trust file".into()))?;
        if peers.iter().any(|p| p.public == public) {
            return Err(Error::BadKeyFile(
                "a key is listed twice in trust file".into(),
            ));
        }
        peers.push(Peer {
            public,
            name: name.to_string(),
            role,
        });
    }
    Ok(peers)
}

fn serialize_v1(peers: &[Peer]) -> String {
    let mut text = format!("{FORMAT_LINE}\n# <public key> <role> <name>\n");
    for p in peers {
        text.push_str(&key_to_text(&p.public));
        text.push(' ');
        text.push_str(p.role.as_str());
        text.push(' ');
        text.push_str(&p.name);
        text.push('\n');
    }
    text
}

/// Every entry in `trusted-peers.v1`, removed or not. Does not migrate.
/// For code that already holds the lock; everyone else uses [`load`].
pub(crate) fn read_entries(dir: &Path) -> Result<Vec<Peer>> {
    match read_private_file_opt(&dir.join(TRUST_FILE))? {
        Some(bytes) => parse_v1(&bytes),
        None => Ok(Vec::new()),
    }
}

/// Replace `trusted-peers.v1` (atomic). The caller holds the lock.
pub(crate) fn write_entries(dir: &Path, _lock: &DirLock, peers: &[Peer]) -> Result<()> {
    write_private_file(&dir.join(TRUST_FILE), serialize_v1(peers).as_bytes())
}

/// The old format: `<public key> <name>`.
fn parse_v0(bytes: &[u8]) -> Result<Vec<([u8; 32], String)>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::BadKeyFile("old trust file is not UTF-8".into()))?;
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|line| {
            let (key, name) = line
                .split_once(' ')
                .ok_or_else(|| Error::BadKeyFile("bad line in old trust file".into()))?;
            let public = key_from_text(key)?;
            check_peer_public(&public)?;
            crate::pairing::check_name(name).map_err(|_| {
                Error::BadKeyFile(format!(
                    "old trust file: {name:?} is not a valid device name; fix {OLD_TRUST_FILE} and run again"
                ))
            })?;
            Ok((public, name.to_string()))
        })
        .collect()
}

/// Convert an old `trusted-peers` to `trusted-peers.v1` if that is all there
/// is (spec R-SEC2 section 3, "Files and locking"). Done once, under the
/// lock. On a drone (a device with `mavlink-signing-key.bin`) every old entry
/// becomes an `operator`; elsewhere a `peer`. The old file is renamed to
/// `trusted-peers.v0-migrated`.
///
/// Returns the converted list when it migrated something, so the caller can
/// print it and a person can fix the roles. `None` if there was nothing to do.
pub fn migrate_if_needed(dir: &Path) -> Result<Option<Vec<Peer>>> {
    let (new, old) = (dir.join(TRUST_FILE), dir.join(OLD_TRUST_FILE));
    if exists(&new) || !exists(&old) {
        return Ok(None);
    }
    let _lock = DirLock::acquire(dir)?;
    // Someone else may have migrated while we waited.
    if exists(&new) || !exists(&old) {
        return Ok(None);
    }
    let role = if exists(&dir.join(AUTOPILOT_KEY_FILE)) {
        Role::Operator
    } else {
        Role::Peer
    };
    let bytes = read_private_file(&old)?;
    let mut peers: Vec<Peer> = Vec::new();
    for (public, name) in parse_v0(&bytes)? {
        if peers.iter().any(|p| p.public == public) {
            continue; // the old file never listed a key twice; keep the first
        }
        peers.push(Peer { public, name, role });
    }
    write_private_file(&new, serialize_v1(&peers).as_bytes())?;
    // Keep the old list; never overwrite an earlier migrated copy.
    let mut target = dir.join(MIGRATED_FILE);
    let mut n = 1;
    while exists(&target) {
        n += 1;
        target = dir.join(format!("{MIGRATED_FILE}.{n}"));
    }
    std::fs::rename(&old, &target)?;
    Ok(Some(peers))
}

/// The trust state at one moment: who is listed, and what is removed.
#[derive(Debug, Clone)]
pub struct Snapshot {
    /// Peers that may be trusted: listed and not removed.
    pub peers: Vec<Peer>,
    pub removed: Removed,
}

impl Snapshot {
    pub fn get(&self, key: &[u8; 32]) -> Option<&Peer> {
        self.peers.iter().find(|p| &p.public == key)
    }
}

/// Read the trust state (migrating an old file first if needed). Safe
/// without the lock: files are replaced atomically, and a removal writes its
/// tombstone before it edits the list, so a reader never sees a peer that
/// is gone from `removed` but still listed.
pub fn snapshot(dir: &Path) -> Result<Snapshot> {
    migrate_if_needed(dir)?;
    let listed = read_entries(dir)?;
    let removed = load_removed(dir)?;
    let peers = listed
        .into_iter()
        .filter(|p| !removed.is_removed(&p.public))
        .collect();
    Ok(Snapshot { peers, removed })
}

/// All peers that may be trusted in `dir`: listed and not removed. Empty if
/// none yet. A key in `removed` is never returned, even if the file lists it.
pub fn load(dir: &Path) -> Result<Vec<Peer>> {
    Ok(snapshot(dir)?.peers)
}

/// Add or replace a peer (matched by public key) and save, under the lock.
/// Refuses a removed key ([`Error::Removed`]).
pub fn add(dir: &Path, peer: &Peer) -> Result<()> {
    check_peer_public(&peer.public)?;
    migrate_if_needed(dir)?;
    let lock = DirLock::acquire(dir)?;
    // Under the lock: a removal cannot slip in between the check and the save.
    if load_removed(dir)?.is_removed(&peer.public) {
        return Err(Error::Removed);
    }
    let mut peers = read_entries(dir)?;
    peers.retain(|p| p.public != peer.public);
    peers.push(peer.clone());
    write_entries(dir, &lock, &peers)
}

/// Refuse a removed key. For pairing, before anything is shared with it.
pub fn check_not_removed(dir: &Path, key: &[u8; 32]) -> Result<()> {
    if load_removed(dir)?.is_removed(key) {
        return Err(Error::Removed);
    }
    Ok(())
}

/// The effective peer with this public key, if any.
pub fn get(dir: &Path, key: &[u8; 32]) -> Result<Option<Peer>> {
    Ok(snapshot(dir)?.get(key).cloned())
}

/// Find a peer by fingerprint or name. Errors if a name matches more than one.
pub fn find(dir: &Path, fingerprint_or_name: &str) -> Result<Option<Peer>> {
    let peers = load(dir)?;
    if let Some(p) = peers
        .iter()
        .find(|p| p.fingerprint() == fingerprint_or_name)
    {
        return Ok(Some(p.clone()));
    }
    let named: Vec<&Peer> = peers
        .iter()
        .filter(|p| p.name == fingerprint_or_name)
        .collect();
    match named.len() {
        0 => Ok(None),
        1 => Ok(Some(named[0].clone())),
        _ => Err(Error::BadKeyFile(format!(
            "more than one device is named {fingerprint_or_name}; use its fingerprint"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::files::tempdir;

    fn peer(n: u8, name: &str, role: Role) -> Peer {
        Peer {
            public: [n; 32],
            name: name.into(),
            role,
        }
    }

    #[test]
    fn add_load_replace_find() {
        let dir = tempdir("store");
        assert!(load(&dir).unwrap().is_empty());
        let a = peer(1, "gcs-a", Role::Peer);
        let b = peer(2, "gcs-b", Role::Operator);
        add(&dir, &a).unwrap();
        add(&dir, &b).unwrap();
        add(
            &dir,
            &Peer {
                name: "gcs-a2".into(),
                role: Role::Admin,
                ..a.clone()
            },
        )
        .unwrap();
        let peers = load(&dir).unwrap();
        assert_eq!(peers.len(), 2);
        assert!(
            peers
                .iter()
                .any(|p| p.name == "gcs-a2" && p.role == Role::Admin)
        );
        assert_eq!(find(&dir, "gcs-b").unwrap(), Some(b.clone()));
        assert_eq!(find(&dir, &b.fingerprint()).unwrap(), Some(b.clone()));
        assert_eq!(find(&dir, "nobody").unwrap(), None);
        assert_eq!(get(&dir, &b.public).unwrap(), Some(b));
        assert_eq!(get(&dir, &[9; 32]).unwrap(), None);
    }

    #[test]
    fn the_file_has_the_format_line_roles_and_owner_only_mode() {
        let dir = tempdir("store-format");
        add(&dir, &peer(1, "a", Role::Admin)).unwrap();
        let text = std::fs::read_to_string(dir.join(TRUST_FILE)).unwrap();
        assert_eq!(text.lines().next(), Some(FORMAT_LINE));
        assert!(text.contains(&format!("{} admin a\n", key_to_text(&[1; 32]))));
        // The old name is not used.
        assert!(!dir.join(OLD_TRUST_FILE).exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join(TRUST_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn a_damaged_or_foreign_file_is_an_error_not_a_guess() {
        let dir = tempdir("store-bad");
        let key = key_to_text(&[1; 32]);
        for bad in [
            String::new(),
            format!("{key} peer a\n"), // no format line
            format!("oasa-trusted-peers v2\n{key} peer a\n"), // a newer format
            format!("{FORMAT_LINE}\n{key} boss a\n"), // unknown role
            format!("{FORMAT_LINE}\n{key} a\n"), // v0 line shape
            format!("{FORMAT_LINE}\n{key} peer\n"),
            format!("{FORMAT_LINE}\n{key} peer a b\n"), // name with a space
            format!("{FORMAT_LINE}\n{key} peer a\n{key} admin b\n"), // listed twice
            format!("{FORMAT_LINE}\nnot-base32! peer a\n"),
            format!("{FORMAT_LINE}\n{} peer a\n", key_to_text(&[0; 32])), // small order
            format!("{FORMAT_LINE}\n{key} peer \u{0}\n"),
        ] {
            write_private_file(&dir.join(TRUST_FILE), bad.as_bytes()).unwrap();
            assert!(load(&dir).is_err(), "{bad:?}");
        }
        // Comments and blank lines are fine.
        let ok = format!("# hi\n\n{FORMAT_LINE}\n# c\n{key} operator a\n");
        write_private_file(&dir.join(TRUST_FILE), ok.as_bytes()).unwrap();
        assert_eq!(load(&dir).unwrap()[0].role, Role::Operator);
    }

    fn v0_file(dir: &Path, peers: &[(u8, &str)]) {
        let mut text = String::from("# OASA-SEC v0 trusted peers: <public key> <name>\n");
        for (n, name) in peers {
            text.push_str(&format!("{} {name}\n", key_to_text(&[*n; 32])));
        }
        write_private_file(&dir.join(OLD_TRUST_FILE), text.as_bytes()).unwrap();
    }

    #[test]
    fn migration_makes_peers_on_a_ground_station_and_operators_on_a_drone() {
        // A ground station (no autopilot key): peers.
        let gcs = tempdir("store-mig-gcs");
        v0_file(&gcs, &[(1, "drone-1"), (2, "relay")]);
        let done = migrate_if_needed(&gcs).unwrap().unwrap();
        assert!(done.iter().all(|p| p.role == Role::Peer));
        assert_eq!(done.len(), 2);
        assert!(!gcs.join(OLD_TRUST_FILE).exists());
        assert!(gcs.join(MIGRATED_FILE).exists());
        assert_eq!(load(&gcs).unwrap(), done);
        // Once only.
        assert_eq!(migrate_if_needed(&gcs).unwrap(), None);

        // A drone (has mavlink-signing-key.bin): operators.
        let drone = tempdir("store-mig-drone");
        write_private_file(&drone.join(AUTOPILOT_KEY_FILE), &[7u8; 40]).unwrap();
        v0_file(&drone, &[(3, "gcs-1")]);
        // Plain `load` migrates too.
        let peers = load(&drone).unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].role, Role::Operator);
        assert!(drone.join(MIGRATED_FILE).exists());
        // The old list is kept as it was.
        let kept = std::fs::read_to_string(drone.join(MIGRATED_FILE)).unwrap();
        assert!(kept.contains("gcs-1"));
    }

    #[test]
    fn migration_never_runs_over_an_existing_v1_and_never_overwrites_a_copy() {
        let dir = tempdir("store-mig-twice");
        add(&dir, &peer(1, "new", Role::Admin)).unwrap();
        v0_file(&dir, &[(2, "stray")]);
        // v1 exists: the old file is ignored, and left alone.
        assert_eq!(migrate_if_needed(&dir).unwrap(), None);
        assert_eq!(load(&dir).unwrap().len(), 1);
        assert!(dir.join(OLD_TRUST_FILE).exists());

        // An earlier migrated copy is not overwritten.
        let dir = tempdir("store-mig-copy");
        write_private_file(&dir.join(MIGRATED_FILE), b"earlier copy\n").unwrap();
        v0_file(&dir, &[(2, "again")]);
        migrate_if_needed(&dir).unwrap().unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join(MIGRATED_FILE)).unwrap(),
            "earlier copy\n"
        );
        assert!(dir.join(format!("{MIGRATED_FILE}.2")).exists());
    }

    #[test]
    fn a_bad_old_file_does_not_migrate_and_is_left_in_place() {
        let dir = tempdir("store-mig-bad");
        let key = key_to_text(&[1; 32]);
        for bad in [
            format!("{key} has a space\n"),
            "garbage\n".to_string(),
            format!("{} zero\n", key_to_text(&[0; 32])),
        ] {
            write_private_file(&dir.join(OLD_TRUST_FILE), bad.as_bytes()).unwrap();
            assert!(migrate_if_needed(&dir).is_err(), "{bad:?}");
            assert!(dir.join(OLD_TRUST_FILE).exists());
            assert!(!dir.join(TRUST_FILE).exists());
        }
    }

    #[test]
    fn an_old_binary_finds_nothing_and_trusts_no_one() {
        // What the v0 code does: read `trusted-peers`. After migration it is gone.
        let dir = tempdir("store-failclosed");
        v0_file(&dir, &[(1, "x")]);
        load(&dir).unwrap();
        assert!(!dir.join("trusted-peers").exists());
    }

    #[test]
    fn small_order_keys_are_refused_on_add() {
        let dir = tempdir("store-small");
        assert!(add(&dir, &peer(0, "zero", Role::Peer)).is_err());
        assert!(!dir.join(TRUST_FILE).exists());
    }
}
