//! Trusted peers: the devices this device has paired with.
//!
//! One line per peer: `<public key, base32> <name>`. The file is owner-only,
//! because anyone who can add a line to it could make this device trust them.

use std::path::Path;

use crate::files::{read_private_file, write_private_file};
use crate::identity::fingerprint;
use crate::{Error, Result};

pub const TRUST_FILE: &str = "trusted-peers";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub public: [u8; 32],
    pub name: String,
}

impl Peer {
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.public)
    }
}

/// All peers saved in `dir`. Empty if none yet.
pub fn load(dir: &Path) -> Result<Vec<Peer>> {
    let path = dir.join(TRUST_FILE);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = read_private_file(&path)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| Error::BadKeyFile("trust file is not UTF-8".into()))?;
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|line| {
            let (key, name) = line
                .split_once(' ')
                .ok_or_else(|| Error::BadKeyFile("bad trust line".into()))?;
            let bytes = data_encoding::BASE32_NOPAD
                .decode(key.as_bytes())
                .map_err(|_| Error::BadKeyFile("bad key in trust file".into()))?;
            let public: [u8; 32] = bytes
                .try_into()
                .map_err(|_| Error::BadKeyFile("trust key must be 32 bytes".into()))?;
            Ok(Peer {
                public,
                name: name.to_string(),
            })
        })
        .collect()
}

/// Add or replace a peer (matched by public key) and save.
pub fn add(dir: &Path, peer: &Peer) -> Result<()> {
    let mut peers = load(dir)?;
    peers.retain(|p| p.public != peer.public);
    peers.push(peer.clone());
    save(dir, &peers)
}

/// Remove a peer by fingerprint. Returns whether one was removed.
///
/// This edits the list only. To lock a lost device out, its signing key must
/// also be rotated, which is the next node (R-SEC2).
pub fn remove(dir: &Path, fingerprint_text: &str) -> Result<bool> {
    let mut peers = load(dir)?;
    let before = peers.len();
    peers.retain(|p| p.fingerprint() != fingerprint_text);
    if peers.len() == before {
        return Ok(false);
    }
    save(dir, &peers)?;
    Ok(true)
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

/// Write the whole list atomically, so a crash never loses peers.
fn save(dir: &Path, peers: &[Peer]) -> Result<()> {
    let mut text = String::from("# OASA-SEC v0 trusted peers: <public key> <name>\n");
    for p in peers {
        text.push_str(&data_encoding::BASE32_NOPAD.encode(&p.public));
        text.push(' ');
        text.push_str(&p.name);
        text.push('\n');
    }
    write_private_file(&dir.join(TRUST_FILE), text.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_load_replace_remove() {
        let dir = crate::files::tempdir("store");
        assert!(load(&dir).unwrap().is_empty());
        let a = Peer {
            public: [1; 32],
            name: "gcs-a".into(),
        };
        let b = Peer {
            public: [2; 32],
            name: "gcs-b".into(),
        };
        add(&dir, &a).unwrap();
        add(&dir, &b).unwrap();
        add(
            &dir,
            &Peer {
                name: "gcs-a2".into(),
                ..a.clone()
            },
        )
        .unwrap();
        let peers = load(&dir).unwrap();
        assert_eq!(peers.len(), 2);
        assert!(peers.iter().any(|p| p.name == "gcs-a2"));
        assert!(remove(&dir, &a.fingerprint()).unwrap());
        assert!(!remove(&dir, &a.fingerprint()).unwrap());
        assert_eq!(load(&dir).unwrap(), vec![b.clone()]);
        assert_eq!(find(&dir, "gcs-b").unwrap(), Some(b.clone()));
        assert_eq!(find(&dir, &b.fingerprint()).unwrap(), Some(b));
        assert_eq!(find(&dir, "nobody").unwrap(), None);
    }
}
