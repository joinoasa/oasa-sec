//! One-time pairing codes.
//!
//! A drone makes a new code each time it is put into pairing mode. The code
//! holds the drone's public key and a fresh 32-byte secret. Whoever reads the
//! code (by scanning its QR, or over USB) can pair with that drone once.
//!
//! Text form: `OASA1-` followed by uppercase base32. Uppercase base32 uses
//! only characters from the QR "alphanumeric" set, so the QR stays small.

use blake2::{Blake2s256, Digest};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, Result};

const PREFIX: &str = "OASA1-";
const VERSION: u8 = 1;
const CHECKSUM_LEN: usize = 4;
const BODY_LEN: usize = 1 + 32 + 32;

/// A one-time pairing code. The secret is wiped from memory when dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PairingCode {
    #[zeroize(skip)]
    pub responder_public: [u8; 32],
    secret: [u8; 32],
}

impl PairingCode {
    /// A new code for the device with this public key, with a fresh secret.
    pub fn new(responder_public: [u8; 32]) -> Result<Self> {
        crate::identity::check_peer_public(&responder_public)?;
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).map_err(|e| Error::Io(std::io::Error::other(e)))?;
        Ok(Self {
            responder_public,
            secret,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_secret(responder_public: [u8; 32], secret: [u8; 32]) -> Self {
        Self {
            responder_public,
            secret,
        }
    }

    pub(crate) fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    /// The code as text, for a QR code or for typing.
    pub fn encode(&self) -> String {
        let mut body = [0u8; BODY_LEN + CHECKSUM_LEN];
        body[0] = VERSION;
        body[1..33].copy_from_slice(&self.responder_public);
        body[33..65].copy_from_slice(&self.secret);
        let sum = checksum(&body[..BODY_LEN]);
        body[BODY_LEN..].copy_from_slice(&sum);
        let text = format!("{PREFIX}{}", data_encoding::BASE32_NOPAD.encode(&body));
        body.zeroize();
        text
    }

    /// Read a code from text. Spaces, dashes after the prefix and lowercase
    /// letters are accepted, so people can type it in chunks.
    pub fn decode(text: &str) -> Result<Self> {
        let text = text.trim();
        let rest = text
            .get(..PREFIX.len())
            .filter(|p| p.eq_ignore_ascii_case(PREFIX))
            .map(|_| &text[PREFIX.len()..])
            .ok_or(Error::BadCode("must start with OASA1-"))?;
        let cleaned: zeroize::Zeroizing<String> = zeroize::Zeroizing::new(
            rest.chars()
                .filter(|c| !c.is_whitespace() && *c != '-')
                .map(|c| c.to_ascii_uppercase())
                .collect(),
        );
        let mut body = data_encoding::BASE32_NOPAD
            .decode(cleaned.as_bytes())
            .map_err(|_| Error::BadCode("not valid base32"))?;
        let result = (|| {
            if body.len() != BODY_LEN + CHECKSUM_LEN {
                return Err(Error::BadCode("wrong length"));
            }
            if body[0] != VERSION {
                return Err(Error::BadCode("unsupported version"));
            }
            if checksum(&body[..BODY_LEN]) != body[BODY_LEN..] {
                return Err(Error::BadCode("checksum mismatch (typo?)"));
            }
            let mut responder_public = [0u8; 32];
            let mut secret = [0u8; 32];
            responder_public.copy_from_slice(&body[1..33]);
            if crate::identity::is_small_order(&responder_public) {
                return Err(Error::BadCode("the device key is not valid"));
            }
            secret.copy_from_slice(&body[33..65]);
            Ok(Self {
                responder_public,
                secret,
            })
        })();
        body.zeroize();
        result
    }

    /// The code drawn as a QR code with Unicode block characters, for a
    /// terminal or a log.
    pub fn qr_text(&self) -> String {
        let mut text = self.encode();
        let qr = qrcode::QrCode::with_error_correction_level(text.as_bytes(), qrcode::EcLevel::M)
            .expect("code always fits in a QR");
        text.zeroize();
        qr.render::<qrcode::render::unicode::Dense1x2>()
            .quiet_zone(true)
            .build()
    }
}

impl std::fmt::Debug for PairingCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the secret.
        f.debug_struct("PairingCode")
            .field(
                "responder",
                &crate::identity::fingerprint(&self.responder_public),
            )
            .finish_non_exhaustive()
    }
}

fn checksum(body: &[u8]) -> [u8; CHECKSUM_LEN] {
    let mut h = Blake2s256::new();
    h.update(b"OASA-SEC v0 code checksum");
    h.update(body);
    let d = h.finalize();
    let mut out = [0u8; CHECKSUM_LEN];
    out.copy_from_slice(&d[..CHECKSUM_LEN]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let code = PairingCode::new([9u8; 32]).unwrap();
        let text = code.encode();
        assert!(text.starts_with("OASA1-"));
        let back = PairingCode::decode(&text).unwrap();
        assert_eq!(back.responder_public, code.responder_public);
        assert_eq!(back.secret(), code.secret());
    }

    /// Pins the v0 wire format. If this changes, old codes stop working, so
    /// it needs a version bump.
    #[test]
    fn known_answer() {
        let mut public = [0u8; 32];
        let mut secret = [0u8; 32];
        for i in 0..32 {
            public[i] = i as u8;
            secret[i] = 0xFF - i as u8;
        }
        let code = PairingCode::with_secret(public, secret);
        assert_eq!(code.encode(), KNOWN_CODE);
        let back = PairingCode::decode(KNOWN_CODE).unwrap();
        assert_eq!(back.responder_public, public);
        assert_eq!(back.secret(), &secret);
    }

    const KNOWN_CODE: &str = "OASA1-AEAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB77767X6PX6XZ7D37N5PU6PZPD4HP53W6Z27K5HUOPZXF4TR6FYPAXLTGL5Y";

    #[test]
    fn accepts_lowercase_and_chunks() {
        let code = PairingCode::new([3u8; 32]).unwrap();
        let text = code.encode();
        let body = &text[PREFIX.len()..];
        let chunked: Vec<String> = body
            .as_bytes()
            .chunks(5)
            .map(|c| String::from_utf8(c.to_vec()).unwrap())
            .collect();
        let typed = format!("oasa1-{}", chunked.join(" ").to_lowercase());
        assert_eq!(PairingCode::decode(&typed).unwrap().secret(), code.secret());
    }

    #[test]
    fn every_code_has_a_new_secret() {
        let a = PairingCode::new([1u8; 32]).unwrap();
        let b = PairingCode::new([1u8; 32]).unwrap();
        assert_ne!(a.secret(), b.secret());
    }

    #[test]
    fn rejects_typos() {
        let text = PairingCode::new([5u8; 32]).unwrap().encode();
        let mut chars: Vec<char> = text.chars().collect();
        let i = PREFIX.len() + 10;
        chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
        let bad: String = chars.into_iter().collect();
        assert!(matches!(PairingCode::decode(&bad), Err(Error::BadCode(_))));
    }

    #[test]
    fn rejects_garbage() {
        for bad in [
            "",
            "OASA1-",
            "OASA2-AAAA",
            "hello",
            "OASA1-!!!!",
            "OASA1-AAAAAAAA",
        ] {
            assert!(PairingCode::decode(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn debug_never_shows_secret() {
        let code = PairingCode::new([2u8; 32]).unwrap();
        let shown = format!("{code:?}");
        let text = code.encode();
        assert!(!shown.contains(&text[PREFIX.len()..PREFIX.len() + 20]));
    }

    #[test]
    fn qr_renders() {
        let qr = PairingCode::new([4u8; 32]).unwrap().qr_text();
        assert!(qr.lines().count() > 10);
    }
}
