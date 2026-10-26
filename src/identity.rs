//! Device identity: one X25519 key pair per device, made on the device.

use std::fs;
use std::path::Path;

use blake2::{Blake2s256, Digest};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::files::{read_private_file, write_new_private_file};

use crate::{Error, PAIRING_NOISE, Result};

/// File name of the private key inside a device's key directory.
pub const PRIVATE_KEY_FILE: &str = "identity.key";

/// File name of the device's own name inside its key directory. Not secret.
pub const NAME_FILE: &str = "device-name";

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

/// The name this device calls itself, if one was saved (by `oasa-pair init
/// --name`, or the first time it paired).
pub fn device_name(dir: &Path) -> Result<Option<String>> {
    let path = dir.join(NAME_FILE);
    if fs::symlink_metadata(&path).is_err() {
        return Ok(None);
    }
    let bytes = read_private_file(&path)?;
    let name = std::str::from_utf8(&bytes)
        .map_err(|_| Error::BadKeyFile("device name is not UTF-8".into()))?
        .trim_end()
        .to_string();
    crate::pairing::check_name(&name).map_err(|_| Error::BadKeyFile("bad device name".into()))?;
    Ok(Some(name))
}

/// Save the device name. Never changes a name that is already saved: a
/// different name is an error, the same name is fine.
pub fn save_device_name(dir: &Path, name: &str) -> Result<()> {
    crate::pairing::check_name(name)?;
    match device_name(dir)? {
        Some(existing) if existing == name => Ok(()),
        Some(existing) => Err(Error::BadKeyFile(format!(
            "this device is already named {existing}"
        ))),
        None => {
            match write_new_private_file(&dir.join(NAME_FILE), format!("{name}\n").as_bytes()) {
                // Lost a race with a second process that saved the same name.
                Err(Error::BadKeyFile(_)) => save_device_name_again(dir, name),
                r => r,
            }
        }
    }
}

fn save_device_name_again(dir: &Path, name: &str) -> Result<()> {
    match device_name(dir)? {
        Some(existing) if existing == name => Ok(()),
        _ => Err(Error::BadKeyFile("this device is already named".into())),
    }
}

/// A name for a device that was never given one: `device-` and the first
/// four bytes of its public key in hex. Valid under the name rules.
pub fn default_device_name(public: &[u8; 32]) -> String {
    format!("device-{}", data_encoding::HEXLOWER.encode(&public[..4]))
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

/// True if `public` is one of the small-order points of Curve25519 (zero,
/// one, the points of order 2, 4 and 8, and their non-canonical encodings).
/// A Diffie-Hellman with such a key gives the same all-zero result whatever
/// the other secret is, so it must never be trusted as a peer key.
pub fn is_small_order(public: &[u8; 32]) -> bool {
    // A clamped scalar is a multiple of 8, which sends every small-order
    // point to the identity (all-zero output).
    curve25519_dalek::MontgomeryPoint(*public)
        .mul_clamped([9u8; 32])
        .to_bytes()
        == [0u8; 32]
}

/// Refuse a peer public key that cannot be a real device key.
pub fn check_peer_public(public: &[u8; 32]) -> Result<()> {
    if is_small_order(public) {
        return Err(Error::SmallOrderKey);
    }
    Ok(())
}

/// X25519 public key for a private key (RFC 7748), using the same curve
/// library the Noise implementation uses.
fn x25519_public(private: &[u8; 32]) -> Result<[u8; 32]> {
    Ok(curve25519_dalek::MontgomeryPoint::mul_base_clamped(*private).to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SMALL_ORDER: [&str; 7] = [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ];

    fn small_order_keys() -> Vec<[u8; 32]> {
        SMALL_ORDER
            .iter()
            .map(|h| {
                data_encoding::HEXLOWER
                    .decode(h.as_bytes())
                    .unwrap()
                    .try_into()
                    .unwrap()
            })
            .collect()
    }

    #[test]
    fn small_order_keys_are_found_and_real_keys_are_not() {
        for k in small_order_keys() {
            assert!(is_small_order(&k), "{k:?}");
            assert!(check_peer_public(&k).is_err());
        }
        // The high bit is ignored by X25519, so the same points with it set.
        for mut k in small_order_keys() {
            k[31] |= 0x80;
            assert!(is_small_order(&k));
        }
        for _ in 0..50 {
            let id = Identity::generate().unwrap();
            assert!(!is_small_order(id.public_key()));
        }
    }

    #[test]
    fn small_order_keys_are_refused_everywhere_a_peer_key_enters() {
        let dir = crate::files::tempdir("small-order");
        for k in small_order_keys() {
            // trusted-peers: add and load
            let peer = crate::store::Peer {
                public: k,
                name: "evil".into(),
                role: crate::store::Role::Peer,
            };
            assert!(crate::store::add(&dir, &peer).is_err());
            let line = format!(
                "{}\n{} peer evil\n",
                crate::store::FORMAT_LINE,
                data_encoding::BASE32_NOPAD.encode(&k)
            );
            crate::files::write_private_file(&dir.join(crate::store::TRUST_FILE), line.as_bytes())
                .unwrap();
            assert!(crate::store::load(&dir).is_err());
            // pairing code: make and read
            assert!(crate::code::PairingCode::new(k).is_err());
            let text = crate::code::PairingCode::with_secret(k, [1u8; 32]).encode();
            assert!(crate::code::PairingCode::decode(&text).is_err());
            // link: add a peer
            let me = Identity::generate().unwrap();
            let mut ep = crate::link::Endpoint::new(
                &me,
                crate::link::Config::default(),
                Box::new(crate::link::OsEntropy),
                std::time::Duration::ZERO,
            )
            .unwrap();
            assert!(
                ep.add_peer(k, Box::new(crate::link::MemoryTimestampStore::default()))
                    .is_err()
            );
        }
    }

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
    fn device_name_is_saved_once() {
        let dir = crate::files::tempdir("name");
        assert_eq!(device_name(&dir).unwrap(), None);
        save_device_name(&dir, "gcs-1").unwrap();
        assert_eq!(device_name(&dir).unwrap().as_deref(), Some("gcs-1"));
        save_device_name(&dir, "gcs-1").unwrap();
        assert!(save_device_name(&dir, "other").is_err());
        assert!(save_device_name(&dir, "bad name").is_err());
        assert_eq!(device_name(&dir).unwrap().as_deref(), Some("gcs-1"));
        let default = default_device_name(&[0xAB; 32]);
        assert_eq!(default, "device-abababab");
        assert!(crate::pairing::check_name(&default).is_ok());
    }

    #[test]
    fn fingerprint_is_stable_and_grouped() {
        let fp = fingerprint(&[7u8; 32]);
        assert_eq!(fp, fingerprint(&[7u8; 32]));
        assert_ne!(fp, fingerprint(&[8u8; 32]));
        assert_eq!(fp.len(), 16 + 3);
    }
}
