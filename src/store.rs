//! Trusted peers: the devices this device has paired with.
//!
//! One line per peer: `<public key, base32> <name>`. The file is owner-only,
//! because anyone who can add a line to it could make this device trust them.

use std::fs;
use std::path::Path;

use crate::identity::{check_private_permissions, fingerprint, write_private_file};
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
    check_private_permissions(&path)?;
    let text = fs::read_to_string(&path)?;
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
    let mut text = String::from("# OASA-SEC v0 trusted peers: <public key> <name>\n");
    for p in &peers {
        text.push_str(&data_encoding::BASE32_NOPAD.encode(&p.public));
        text.push(' ');
        text.push_str(&p.name);
        text.push('\n');
    }
    write_private_file(&dir.join(TRUST_FILE), text.as_bytes())
}

/// Remove a peer by fingerprint. Returns whether one was removed.
///
/// Removing a peer only stops this device trusting it. To lock out a lost
/// device fully, also rotate the signing key (R-SEC2 will automate this).
pub fn remove(dir: &Path, fingerprint_text: &str) -> Result<bool> {
    let mut peers = load(dir)?;
    let before = peers.len();
    peers.retain(|p| p.fingerprint() != fingerprint_text);
    if peers.len() == before {
        return Ok(false);
    }
    let path = dir.join(TRUST_FILE);
    fs::remove_file(&path)?;
    for p in &peers {
        add(dir, p)?;
    }
    if peers.is_empty() {
        write_private_file(&path, b"# OASA-SEC v0 trusted peers: <public key> <name>\n")?;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_load_replace_remove() {
        let dir = crate::identity::tempdir("store");
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
        assert_eq!(load(&dir).unwrap(), vec![b]);
    }
}
