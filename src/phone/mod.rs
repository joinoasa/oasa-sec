//! Phone pairing for a pocket radio (tech tree node T-MSG1), first part.
//! Spec: `docs/oasa-sec-v0-phone-link.md` (v0.4 draft, sections 2 and 10).
//!
//! A phone pairs with a radio that has no button and no screen. The radio
//! carries a printed **label** ([`LabelCode`], `OASAR1-`): its pairing public
//! key and a 32-byte secret that never changes. To move to a new phone, the
//! old phone shows a one-time **replace code** ([`ReplaceCode`], `OASAT1-`).
//!
//! Pairing is R-SEC1's `Noise_IKpsk1` ([`crate::PAIRING_NOISE`]) with its own
//! prologue ([`crate::PHONE_PAIRING_PROLOGUE`]), in three messages:
//!
//! 1. Phone → radio: hello. The radio checks the secret here.
//! 2. Radio → phone: hello, then the public half of a new **link key** the
//!    radio made for this attempt.
//! 3. Phone → radio (encrypted): confirm. The radio receiving a valid one is
//!    the completion.
//!
//! - [`PhonePairing`]: the phone's side of one pairing.
//! - [`Radio`]: the radio's side, a sans-IO state machine. Time and events
//!   (USB power, enumeration, connections, bytes, `PAIR_OPEN`, the pinhole)
//!   come in as arguments; what the radio does goes out through a sink. It
//!   owns the pairing windows, the attempt slots, the record of message 1s,
//!   the rate limit, completion, replace, reset, and the power-safe order of
//!   writes to its [`RadioStore`].
//!
//! Not here (later parts): the link session with the phone, the messages
//! inside it, wake filters, the hold store, the BLE and USB transports and
//! their framing, firmware and the app.
//!
//! **No new cryptography:** the same `snow` pattern and primitives as R-SEC1
//! pairing, the same X25519 key generation, and `check_peer_public` on every
//! peer key that enters.

mod code;
mod handshake;
mod radio;
#[cfg(test)]
mod tests;

use std::fmt;

use crate::pairing::{MAX_NAME, check_name};
use crate::{Error, Result};

pub use code::{LabelCode, ReplaceCode};
pub use handshake::{
    MAX_MSG1, MAX_MSG2, MIN_MSG1, MIN_MSG2, MSG3_LEN, PairWith, PhonePaired, PhonePairing,
};
pub use radio::{
    Action, CloseReason, ConnId, Marker, Msg2, NoReplyReason, PairOpenRefused, Radio, RadioKeys,
    RadioStore, SavedPhone, Status, StoreFailed, Transport, WindowKind,
};

use std::time::Duration;

/// How long a pairing window stays open (spec section 2.3).
pub const WINDOW: Duration = Duration::from_secs(120);
/// USB power must have been absent this long before it counts as appearing.
pub const USB_ABSENT: Duration = Duration::from_secs(10);
/// ...and then present this long.
pub const USB_PRESENT: Duration = Duration::from_secs(2);
/// After two USB windows in a row close with no pairing, the next needs this
/// long since the last one closed, and a new debounced USB edge after that.
pub const RATE_LIMIT_WAIT: Duration = Duration::from_secs(30 * 60);
/// USB windows in a row that may close with no pairing before the rate limit.
pub const RATE_LIMIT_WINDOWS: u8 = 2;
/// In a USB window, BLE opens this long after the window opens if no USB host
/// enumerated the radio by then (spec section 2.5).
pub const BLE_AFTER_NO_HOST: Duration = Duration::from_secs(10);
/// ...or this long after, if a host enumerated it but no proving message 1
/// arrived on USB.
pub const BLE_AFTER_HOST: Duration = Duration::from_secs(20);
/// Message 1 must arrive within this of connecting.
pub const MSG1_WITHIN: Duration = Duration::from_secs(3);
/// Message 3 must arrive within this of message 2.
pub const MSG3_WITHIN: Duration = Duration::from_secs(6);
/// A pinhole reset with USB power present opens a USB window this long after.
pub const RESET_WINDOW_DELAY: Duration = Duration::from_secs(2);
/// The radio remembers the ephemeral keys of this many proving message 1s
/// per window.
pub const SEEN_RECORD: usize = 16;

/// Payload tag of the radio's link public key in message 2. R-SEC1 uses
/// `0x01` to `0x05`; `0x06` does not collide.
pub const MSG_LINK_KEY: u8 = 0x06;

/// A device name (1 to 32 of `A-Z a-z 0-9 - _ .`, as R-SEC1), kept in a
/// fixed buffer so the radio's state machine needs no allocation for it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Name {
    len: u8,
    bytes: [u8; MAX_NAME],
}

impl Name {
    /// A checked name ([`check_name`]).
    pub fn new(name: &str) -> Result<Self> {
        check_name(name)?;
        let mut bytes = [0u8; MAX_NAME];
        bytes[..name.len()].copy_from_slice(name.as_bytes());
        Ok(Self {
            len: name.len() as u8,
            bytes,
        })
    }

    pub fn as_str(&self) -> &str {
        // Only ever built from a checked ASCII name.
        std::str::from_utf8(&self.bytes[..self.len as usize]).unwrap_or("")
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// True if all 32 bytes are zero, looking at every byte whatever their
/// values (no early exit on the first non-zero byte).
pub(crate) fn all_zero(secret: &[u8; 32]) -> bool {
    secret.iter().fold(0u8, |acc, b| acc | b) == 0
}

/// Parse a hello `[0x01, len, name]` into a [`Name`].
pub(crate) fn parse_hello(p: &[u8]) -> Result<Name> {
    if p.len() < 2 || p[0] != 0x01 || p.len() != 2 + p[1] as usize {
        return Err(Error::Protocol("bad hello"));
    }
    let name = std::str::from_utf8(&p[2..]).map_err(|_| Error::Protocol("name is not UTF-8"))?;
    Name::new(name).map_err(|_| Error::Protocol("bad peer name"))
}

/// Write a hello `[0x01, len, name]` into `out`; returns its length.
pub(crate) fn write_hello(name: &Name, out: &mut [u8]) -> usize {
    let n = name.as_bytes();
    out[0] = 0x01;
    out[1] = n.len() as u8;
    out[2..2 + n.len()].copy_from_slice(n);
    2 + n.len()
}
