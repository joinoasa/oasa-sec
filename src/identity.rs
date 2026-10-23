//! Device identity: one X25519 key pair per device, made on the device.

use std::fs;
use std::io::Write;
use std::path::Path;

use blake2::{Blake2s256, Digest};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, PAIRING_NOISE, Result};

/// File name of the private key inside a device's key directory.
pub const PRIVATE_KEY_FILE: &str = "identity.key";

/// A device identity. The private key is wiped from memory when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Identity {
    private: [u8; 32],
    #[zeroize(skip)]
    public: [u8; 32],
}

impl Identity {
    /// Make a new identity from the operating system's random source.
    pub fn generate() -> Result<Self> {
        let params = PAIRING_NOISE.parse().expect("valid Noise name");
        let kp = snow::Builder::new(params).generate_keypair()?;
        Self::from_private_bytes(&kp.private).inspect(|id| {
            debug_assert_eq!(id.public[..], kp.public[..]);
        })
    }

    /// Rebuild an identity from its 32-byte private key.
    pub fn from_private_bytes(bytes: &[u8]) -> Result<Self> {
        let private: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::BadKeyFile("private key must be 32 bytes".into()))?;
        let public = x25519_public(&private)?;
        Ok(Self { private, public })
    }

    pub fn public_key(&self) -> &[u8; 32] {
        &self.public
    }

    pub(crate) fn private_key(&self) -> &[u8; 32] {
        &self.private
    }

    /// Short, human-checkable ID for this device. See [`fingerprint`].
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.public)
    }

    /// Load the identity in `dir`, or make and save a new one if none exists.
    pub fn load_or_create(dir: &Path) -> Result<(Self, bool)> {
        let path = dir.join(PRIVATE_KEY_FILE);
        if path.exists() {
            return Ok((Self::load(dir)?, false));
        }
        let id = Self::generate()?;
        id.save(dir)?;
        Ok((id, true))
    }

    /// Load the identity saved in `dir`. Refuses key files others can read.
    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join(PRIVATE_KEY_FILE);
        check_private_permissions(&path)?;
        let mut bytes = fs::read(&path)?;
        let id = Self::from_private_bytes(&bytes);
        bytes.zeroize();
        id
    }

    /// Save the private key to `dir`, readable only by its owner.
    pub fn save(&self, dir: &Path) -> Result<()> {
        write_private_file(&dir.join(PRIVATE_KEY_FILE), &self.private)
    }
}

/// Human-checkable fingerprint of a public key: the first 10 bytes of
/// BLAKE2s-256, as base32 in groups of four, e.g. `QX7M-2KD4-...`.
pub fn fingerprint(public: &[u8; 32]) -> String {
    let mut h = Blake2s256::new();
    h.update(b"OASA-SEC v0 fingerprint");
    h.update(public);
    let digest = h.finalize();
    let text = data_encoding::BASE32_NOPAD.encode(&digest[..10]);
    text.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).expect("base32 is ASCII"))
        .collect::<Vec<_>>()
        .join("-")
}

/// X25519 public key for a private key (RFC 7748), using the same curve
/// library the Noise implementation uses.
fn x25519_public(private: &[u8; 32]) -> Result<[u8; 32]> {
    Ok(curve25519_dalek::MontgomeryPoint::mul_base_clamped(*private).to_bytes())
}

/// Write secret bytes to a new file with mode 0600 (owner only).
pub(crate) fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
    }
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

/// Refuse secret files that anyone other than the owner can read or write.
pub(crate) fn check_private_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(Error::BadKeyFile(format!(
                "{} can be read by others (mode {:o}); run chmod 600 on it",
                path.display(),
                mode & 0o777
            )));
        }
    }
    let _ = path;
    Ok(())
}

/// A fresh, empty temporary directory for tests.
#[cfg(test)]
pub(crate) fn tempdir(name: &str) -> std::path::PathBuf {
    let mut r = [0u8; 8];
    getrandom::fill(&mut r).unwrap();
    let p = std::env::temp_dir().join(format!(
        "oasa-sec-test-{name}-{}",
        data_encoding::HEXLOWER.encode(&r)
    ));
    fs::create_dir_all(&p).unwrap();
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_generated_identity_is_different() {
        let a = Identity::generate().unwrap();
        let b = Identity::generate().unwrap();
        assert_ne!(a.public_key(), b.public_key());
    }

    #[test]
    fn public_key_matches_rfc7748_vector() {
        // RFC 7748 section 6.1, Alice's key pair.
        let private = data_encoding::HEXLOWER
            .decode(b"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
            .unwrap();
        let expected = data_encoding::HEXLOWER
            .decode(b"8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
            .unwrap();
        let id = Identity::from_private_bytes(&private).unwrap();
        assert_eq!(&id.public_key()[..], &expected[..]);
    }

    #[test]
    fn save_and_load_round_trip_with_owner_only_permissions() {
        let dir = tempdir("identity");
        let (id, created) = Identity::load_or_create(&dir).unwrap();
        assert!(created);
        let (again, created) = Identity::load_or_create(&dir).unwrap();
        assert!(!created);
        assert_eq!(id.public_key(), again.public_key());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.join(PRIVATE_KEY_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[cfg(unix)]
    #[test]
    fn refuses_key_file_others_can_read() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir("perms");
        Identity::load_or_create(&dir).unwrap();
        let path = dir.join(PRIVATE_KEY_FILE);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(Identity::load(&dir), Err(Error::BadKeyFile(_))));
    }

    #[test]
    fn fingerprint_is_stable_and_grouped() {
        let fp = fingerprint(&[7u8; 32]);
        assert_eq!(fp, fingerprint(&[7u8; 32]));
        assert_ne!(fp, fingerprint(&[8u8; 32]));
        assert_eq!(fp.len(), 16 + 3);
    }
}
