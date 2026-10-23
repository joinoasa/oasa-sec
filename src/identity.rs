//! Device identity: one X25519 key pair per device, made on the device.

use std::fs;
use std::path::Path;

use blake2::{Blake2s256, Digest};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::files::{read_private_file, write_new_private_file};

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
        let private = Zeroizing::new(kp.private);
        Self::from_private_bytes(&private).inspect(|id| {
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
    /// Never overwrites an existing identity, even if two processes race.
    pub fn load_or_create(dir: &Path) -> Result<(Self, bool)> {
        let path = dir.join(PRIVATE_KEY_FILE);
        if fs::symlink_metadata(&path).is_ok() {
            return Ok((Self::load(dir)?, false));
        }
        let id = Self::generate()?;
        match write_new_private_file(&path, &id.private) {
            Ok(()) => Ok((id, true)),
            // Someone else made it first: use theirs.
            Err(Error::BadKeyFile(_)) if path.exists() => Ok((Self::load(dir)?, false)),
            Err(e) => Err(e),
        }
    }

    /// Load the identity saved in `dir`. Refuses key files others can read.
    pub fn load(dir: &Path) -> Result<Self> {
        let bytes = read_private_file(&dir.join(PRIVATE_KEY_FILE))?;
        Self::from_private_bytes(&bytes)
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
        let dir = crate::files::tempdir("identity");
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
        let dir = crate::files::tempdir("perms");
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
