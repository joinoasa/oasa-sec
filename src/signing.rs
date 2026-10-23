//! MAVLink 2 signing keys.
//!
//! MAVLink signing proves who sent a message but does not hide it. In OASA it
//! is only a second layer inside encryption. The MAVLink spec says signing
//! keys must only travel over a secure link and never be broadcast; OASA
//! delivers them inside the encrypted pairing channel, and the drone then
//! loads them into its autopilot over its own wired link.

use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use mavlink::dialects::common::{MavMessage, SETUP_SIGNING_DATA};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::identity::{check_private_permissions, write_private_file};
use crate::{Error, Result};

/// File name for a saved signing key. Same 40-byte layout PX4 uses on its SD
/// card: 32-byte key, then 8-byte little-endian timestamp.
pub const SIGNING_KEY_FILE: &str = "mavlink-signing-key.bin";

/// Seconds from the Unix epoch to 1 January 2015, where MAVLink time starts.
const MAVLINK_EPOCH_UNIX_SECS: u64 = 1_420_070_400;

/// A 32-byte MAVLink signing key. Wiped from memory when dropped.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SigningKey([u8; 32]);

impl SigningKey {
    /// A fresh random key. Never derive keys from passphrases.
    pub fn generate() -> Result<Self> {
        let mut k = [0u8; 32];
        getrandom::fill(&mut k).map_err(|e| Error::Io(std::io::Error::other(e)))?;
        if k == [0u8; 32] {
            // An all-zero key means "signing off" in MAVLink. Vanishingly
            // unlikely, but never hand one out.
            return Self::generate();
        }
        Ok(Self(k))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        if bytes == [0u8; 32] {
            return Err(Error::BadKeyFile(
                "all-zero signing key disables signing".into(),
            ));
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Settings for the `mavlink` crate. Signs everything we send and
    /// rejects unsigned messages we receive.
    pub fn mavlink_config(&self, link_id: u8) -> mavlink::SigningConfig {
        mavlink::SigningConfig::new(self.0, link_id, true, false)
    }

    /// The SETUP_SIGNING message that loads this key into an autopilot.
    /// Send it only over a wired link (USB, serial, or the companion
    /// computer's local link), never over the radio.
    pub fn setup_signing_message(&self, target_system: u8, target_component: u8) -> MavMessage {
        MavMessage::SETUP_SIGNING(SETUP_SIGNING_DATA {
            initial_timestamp: mavlink_timestamp_now(),
            target_system,
            target_component,
            secret_key: self.0,
        })
    }

    /// Save in PX4's 40-byte format, readable only by the owner.
    pub fn save(&self, dir: &Path) -> Result<()> {
        let mut buf = [0u8; 40];
        buf[..32].copy_from_slice(&self.0);
        buf[32..].copy_from_slice(&mavlink_timestamp_now().to_le_bytes());
        let r = write_private_file(&dir.join(SIGNING_KEY_FILE), &buf);
        buf.zeroize();
        r
    }

    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join(SIGNING_KEY_FILE);
        check_private_permissions(&path)?;
        let mut buf = fs::read(&path)?;
        let r = if buf.len() == 40 {
            let mut k = [0u8; 32];
            k.copy_from_slice(&buf[..32]);
            Self::from_bytes(k)
        } else {
            Err(Error::BadKeyFile(
                "signing key file must be 40 bytes".into(),
            ))
        };
        buf.zeroize();
        r
    }
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SigningKey(..)")
    }
}

/// Current time in MAVLink signing units: 10 microseconds since 1 January
/// 2015 (GMT).
pub fn mavlink_timestamp_now() -> u64 {
    let since_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    let since_2015 = since_unix.saturating_sub(Duration::from_secs(MAVLINK_EPOCH_UNIX_SECS));
    (since_2015.as_micros() / 10) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_random_and_never_zero() {
        let a = SigningKey::generate().unwrap();
        let b = SigningKey::generate().unwrap();
        assert_ne!(a, b);
        assert!(SigningKey::from_bytes([0u8; 32]).is_err());
    }

    #[test]
    fn save_load_round_trip_in_px4_layout() {
        let dir = crate::identity::tempdir("signing");
        let k = SigningKey::generate().unwrap();
        k.save(&dir).unwrap();
        let raw = fs::read(dir.join(SIGNING_KEY_FILE)).unwrap();
        assert_eq!(raw.len(), 40);
        assert_eq!(&raw[..32], k.as_bytes());
        assert_eq!(SigningKey::load(&dir).unwrap(), k);
    }

    #[test]
    fn timestamp_is_after_2026() {
        // 2026-01-01 is 11 years after 2015: about 3.47e13 units.
        assert!(mavlink_timestamp_now() > 34_700_000_000_000);
    }

    #[test]
    fn debug_hides_key() {
        let k = SigningKey::from_bytes([0xAB; 32]).unwrap();
        assert_eq!(format!("{k:?}"), "SigningKey(..)");
    }
}
