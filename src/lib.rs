//! OASA-SEC v0 prototype (tech tree node R-SEC1): device identity, encrypted
//! pairing, and MAVLink 2 signing keys.
//!
//! - Every device makes its own X25519 identity ([`identity`]).
//! - A drone shows a one-time pairing code, usually as a QR code ([`code`]).
//! - The ground station uses the code to run an encrypted, authenticated Noise
//!   handshake with the drone ([`pairing`]).
//! - Inside that encrypted channel the ground station hands the drone a fresh
//!   MAVLink 2 signing key, and the drone loads it into its autopilot over its
//!   local wired link ([`signing`]).
//!
//! Signing is only ever a second layer inside encryption. Encrypting the
//! drone link itself is the next node (R-COM2).
//!
//! This is a prototype. Do not fly with it.

pub mod code;
pub mod error;
mod files;
pub mod identity;
pub mod pairing;
pub mod signing;
pub mod store;

pub use error::{Error, Result};

/// The Noise protocol used for pairing.
///
/// IKpsk1: the ground station knows the drone's public key (from the code)
/// and the one-time secret (also from the code). Both sides end up
/// authenticated, and only someone who saw the code can pair. The secret is
/// mixed in at the end of the first message (psk1), so the drone rejects
/// anyone without the code before it sends a single byte back.
pub const PAIRING_NOISE: &str = "Noise_IKpsk1_25519_ChaChaPoly_BLAKE2s";

/// Prologue mixed into every pairing handshake, so it can't be confused with
/// any other protocol that happens to use the same Noise pattern.
pub const PAIRING_PROLOGUE: &[u8] = b"OASA-SEC v0 pairing";
