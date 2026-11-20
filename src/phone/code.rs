//! The radio label (`OASAR1-`) and the replace code (`OASAT1-`), spec section
//! 2.1. Same layout as R-SEC1's drone code ([`crate::code::PairingCode`]),
//! but each kind has its own prefix and checksum label, so none can be taken
//! for another, and each is its own type here.
//!
//! Layout: version (1) ‖ radio pairing public key (32) ‖ secret (32) ‖
//! checksum (4) = first 4 bytes of BLAKE2s-256(checksum label ‖ the 65 bytes
//! before it). Text: prefix + uppercase base32 without padding, 118
//! characters.

use blake2::{Blake2s256, Digest};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{Error, Result};

const VERSION: u8 = 1;
const CHECKSUM_LEN: usize = 4;
const BODY_LEN: usize = 1 + 32 + 32;

/// One kind of code: what tells a label and a replace code apart.
struct Kind {
    /// The prefix without its version digit and dash, e.g. `OASAR`.
    stem: &'static str,
    /// The full prefix, e.g. `OASAR1-`. Its digit is [`VERSION`].
    prefix: &'static str,
    checksum_label: &'static [u8],
    /// The refusal for a wrong prefix.
    wrong_prefix: &'static str,
}

const LABEL: Kind = Kind {
    stem: "OASAR",
    prefix: "OASAR1-",
    checksum_label: b"OASA-SEC v0 label checksum",
    wrong_prefix: "must start with OASAR1-",
};

const REPLACE: Kind = Kind {
    stem: "OASAT",
    prefix: "OASAT1-",
    checksum_label: b"OASA-SEC v0 replace checksum",
    wrong_prefix: "must start with OASAT1-",
};

/// The fields both kinds share. The secret is wiped when dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct Fields {
    #[zeroize(skip)]
    pairing_public: [u8; 32],
    secret: [u8; 32],
}

impl Fields {
    /// A random secret, made in place (no copy of it left elsewhere). An
    /// all-zero secret is refused for every kind: the radio refuses a label
    /// with one and a `PAIR_OPEN` with one, so it could never pair.
    fn random(pairing_public: [u8; 32]) -> Result<Self> {
        crate::identity::check_peer_public(&pairing_public)?;
        let mut f = Self {
            pairing_public,
            secret: [0u8; 32],
        };
        while super::all_zero(&f.secret) {
            getrandom::fill(&mut f.secret).map_err(|e| Error::Io(std::io::Error::other(e)))?;
        }
        Ok(f)
    }

    fn encode(&self, kind: &Kind) -> String {
        let mut body = Zeroizing::new([0u8; BODY_LEN + CHECKSUM_LEN]);
        body[0] = VERSION;
        body[1..33].copy_from_slice(&self.pairing_public);
        body[33..65].copy_from_slice(&self.secret);
        let sum = checksum(kind, &body[..BODY_LEN]);
        body[BODY_LEN..].copy_from_slice(&sum);
        // Written straight into one buffer of the final size, so no
        // temporary copy of the secret's text is left unwiped.
        let enc = &data_encoding::BASE32_NOPAD;
        let mut text = String::with_capacity(kind.prefix.len() + enc.encode_len(body.len()));
        text.push_str(kind.prefix);
        enc.encode_append(&body[..], &mut text);
        text
    }

    fn decode(text: &str, kind: &Kind) -> Result<Self> {
        let text = text.trim();
        let rest = prefix_rest(text, kind)?;
        let cleaned: Zeroizing<String> = Zeroizing::new(
            rest.chars()
                .filter(|c| !c.is_whitespace() && *c != '-')
                .map(|c| c.to_ascii_uppercase())
                .collect(),
        );
        // BASE32_NOPAD refuses non-zero padding bits in the last character.
        let body = Zeroizing::new(
            data_encoding::BASE32_NOPAD
                .decode(cleaned.as_bytes())
                .map_err(|_| Error::BadCode("not valid base32"))?,
        );
        if body.len() != BODY_LEN + CHECKSUM_LEN {
            return Err(Error::BadCode("wrong length"));
        }
        if body[0] != VERSION {
            return Err(Error::BadCode("unsupported version"));
        }
        if checksum(kind, &body[..BODY_LEN]) != body[BODY_LEN..] {
            return Err(Error::BadCode(
                "checksum mismatch (typo, or another kind of code)",
            ));
        }
        let mut pairing_public = [0u8; 32];
        pairing_public.copy_from_slice(&body[1..33]);
        if crate::identity::is_small_order(&pairing_public) {
            return Err(Error::BadCode("the radio key is not valid"));
        }
        let mut f = Fields {
            pairing_public,
            secret: [0u8; 32],
        };
        f.secret.copy_from_slice(&body[33..65]);
        if super::all_zero(&f.secret) {
            return Err(Error::BadCode("the secret is all zero"));
        }
        Ok(f)
    }
}

/// The text after the prefix. A different version digit after the right
/// stem is "unsupported version"; anything else is "wrong prefix".
fn prefix_rest<'a>(text: &'a str, kind: &Kind) -> Result<&'a str> {
    let p = kind.prefix.len();
    if let Some(head) = text.get(..p)
        && head.eq_ignore_ascii_case(kind.prefix)
    {
        return Ok(&text[p..]);
    }
    let s = kind.stem.len();
    let same_stem = text
        .get(..s)
        .is_some_and(|h| h.eq_ignore_ascii_case(kind.stem));
    let digit_then_dash = text.as_bytes().get(s).is_some_and(u8::is_ascii_digit)
        && text.as_bytes().get(s + 1) == Some(&b'-');
    if same_stem && digit_then_dash {
        return Err(Error::BadCode("unsupported version"));
    }
    Err(Error::BadCode(kind.wrong_prefix))
}

fn checksum(kind: &Kind, body: &[u8]) -> [u8; CHECKSUM_LEN] {
    let mut h = Blake2s256::new();
    h.update(kind.checksum_label);
    h.update(body);
    let d = h.finalize();
    let mut out = [0u8; CHECKSUM_LEN];
    out.copy_from_slice(&d[..CHECKSUM_LEN]);
    out
}

/// The label printed on a radio: its pairing public key and its pairing
/// secret, for the radio's whole life (spec section 2.1, 2.2). The secret is
/// wiped from memory when dropped and never shown by `Debug`.
#[derive(Clone)]
pub struct LabelCode(Fields);

/// A replace code: the radio's pairing public key and a one-time secret the
/// old phone made for one replace window (spec section 2.7). The secret is
/// wiped from memory when dropped and never shown by `Debug`.
#[derive(Clone)]
pub struct ReplaceCode(Fields);

macro_rules! code_impl {
    ($t:ident, $kind:expr, $what:literal) => {
        impl $t {
            #[doc = concat!("A new ", $what, " for the radio with this pairing public key, with a fresh random secret from the operating system.")]
            pub fn new(pairing_public: [u8; 32]) -> Result<Self> {
                Fields::random(pairing_public).map(Self)
            }

            #[doc = concat!("Read a ", $what, " from text. Lowercase, spaces and dashes after the prefix are accepted. Refused: a wrong prefix, an unknown version, the wrong length, invalid base32 (including non-zero padding bits in the last character), a bad checksum, or a small-order key or an all-zero secret.")]
            pub fn decode(text: &str) -> Result<Self> {
                Fields::decode(text, &$kind).map(Self)
            }

            /// The code as text (prefix and uppercase base32, 118 characters).
            /// The text holds the secret: wipe it when done.
            pub fn encode(&self) -> String {
                self.0.encode(&$kind)
            }

            /// The radio's pairing public key.
            pub fn pairing_public(&self) -> &[u8; 32] {
                &self.0.pairing_public
            }

            pub(crate) fn secret(&self) -> &[u8; 32] {
                &self.0.secret
            }

            #[cfg(test)]
            pub(crate) fn with_secret(pairing_public: [u8; 32], secret: [u8; 32]) -> Self {
                Self(Fields {
                    pairing_public,
                    secret,
                })
            }
        }

        impl std::fmt::Debug for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                // Never print the secret.
                f.debug_struct(stringify!($t))
                    .field(
                        "radio",
                        &crate::identity::fingerprint(&self.0.pairing_public),
                    )
                    .finish_non_exhaustive()
            }
        }
    };
}

code_impl!(LabelCode, LABEL, "radio label");
code_impl!(ReplaceCode, REPLACE, "replace code");

impl ReplaceCode {
    /// A replace code for this secret (the one the old phone sends in
    /// `PAIR_OPEN`). An all-zero secret is refused. Prefer
    /// [`ReplaceCode::new`] and [`ReplaceCode::pair_open_body`], which make
    /// the secret here.
    pub fn from_secret(pairing_public: [u8; 32], secret: &[u8; 32]) -> Result<Self> {
        crate::identity::check_peer_public(&pairing_public)?;
        if super::all_zero(secret) {
            return Err(Error::BadCode("the secret is all zero"));
        }
        let mut f = Fields {
            pairing_public,
            secret: [0u8; 32],
        };
        f.secret.copy_from_slice(secret);
        Ok(Self(f))
    }

    /// The `PAIR_OPEN` body the old phone sends for this code:
    /// `[0x0B][secret: 32]` (spec sections 4 and 10).
    pub fn pair_open_body(&self) -> PairOpenBody {
        let mut b = Zeroizing::new([0u8; 33]);
        b[0] = super::MSG_PAIR_OPEN;
        b[1..].copy_from_slice(&self.0.secret);
        PairOpenBody(b)
    }
}

/// A `PAIR_OPEN` body, `[0x0B][secret: 32]`. It holds the replace secret:
/// wiped when dropped and never shown by `Debug`.
pub struct PairOpenBody(Zeroizing<[u8; 33]>);

impl PairOpenBody {
    /// The bytes to seal into the link session.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// The secret, as the radio's [`super::Radio::pair_open`] takes it.
    pub fn secret(&self) -> &[u8; 32] {
        self.0[1..].try_into().expect("32 bytes")
    }
}

impl std::fmt::Debug for PairOpenBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairOpenBody(..)")
    }
}

#[cfg(test)]
mod tests {
    //! Spec section 8, case 3, and the refusals of section 2.1.
    use super::*;
    use crate::code::PairingCode;
    use crate::identity::Identity;

    fn key() -> [u8; 32] {
        *Identity::generate().unwrap().public_key()
    }

    fn known() -> ([u8; 32], [u8; 32]) {
        let mut public = [0u8; 32];
        let mut secret = [0u8; 32];
        for i in 0..32 {
            public[i] = i as u8;
            secret[i] = 0xFF - i as u8;
        }
        (public, secret)
    }

    /// Pins the v1 formats. A change here is a protocol change.
    #[test]
    fn known_answers() {
        let (public, secret) = known();
        let l = LabelCode::with_secret(public, secret).encode();
        let r = ReplaceCode::with_secret(public, secret).encode();
        assert_eq!(l, KNOWN_LABEL);
        assert_eq!(r, KNOWN_REPLACE);
        assert_eq!(l.len(), 118);
        assert_eq!(r.len(), 118);
        // Same body as the drone code, different prefix and checksum.
        let d = PairingCode::with_secret(public, secret).encode();
        assert_eq!(l[7..7 + 104], d[6..6 + 104]);
        assert_ne!(l[7..], d[6..]);
        assert_ne!(l[7..], r[7..]);
        let back = LabelCode::decode(KNOWN_LABEL).unwrap();
        assert_eq!(back.pairing_public(), &public);
        assert_eq!(back.secret(), &secret);
        let back = ReplaceCode::decode(KNOWN_REPLACE).unwrap();
        assert_eq!(back.secret(), &secret);
    }

    // Computed outside this code, with Python's hashlib.blake2s and
    // base64.b32encode (the same method gives R-SEC1's KNOWN_CODE).
    const KNOWN_LABEL: &str = "OASAR1-AEAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB77767X6PX6XZ7D37N5PU6PZPD4HP53W6Z27K5HUOPZXF4TR6FYPAVQPSIYI";
    const KNOWN_REPLACE: &str = "OASAT1-AEAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB77767X6PX6XZ7D37N5PU6PZPD4HP53W6Z27K5HUOPZXF4TR6FYPADRZCKAQ";

    /// Every character is in the QR alphanumeric set.
    #[test]
    fn text_is_qr_alphanumeric() {
        let set = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
        for t in [
            LabelCode::new(key()).unwrap().encode(),
            ReplaceCode::new(key()).unwrap().encode(),
        ] {
            assert!(t.chars().all(|c| set.contains(c)), "{}", &t[..7]);
        }
    }

    #[test]
    fn round_trip_with_lowercase_spaces_and_dashes() {
        let l = LabelCode::new(key()).unwrap();
        let t = l.encode();
        let body = &t[7..];
        let chunks: Vec<&str> = body
            .as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        let typed = format!("  oasar1-{} \n", chunks.join(" - ").to_lowercase());
        let back = LabelCode::decode(&typed).unwrap();
        assert_eq!(back.secret(), l.secret());
        assert_eq!(back.pairing_public(), l.pairing_public());
    }

    #[test]
    fn case_3_each_code_is_refused_as_either_of_the_other_two() {
        let k = key();
        let label = LabelCode::new(k).unwrap().encode();
        let replace = ReplaceCode::new(k).unwrap().encode();
        let drone = PairingCode::new(k).unwrap().encode();
        // As written.
        assert!(ReplaceCode::decode(&label).is_err());
        assert!(PairingCode::decode(&label).is_err());
        assert!(LabelCode::decode(&replace).is_err());
        assert!(PairingCode::decode(&replace).is_err());
        assert!(LabelCode::decode(&drone).is_err());
        assert!(ReplaceCode::decode(&drone).is_err());
        // With the prefix swapped: the checksum label still tells them apart.
        let body = |t: &str| t.split_once('-').unwrap().1.to_string();
        for (b, from) in [
            (body(&label), "label"),
            (body(&replace), "replace"),
            (body(&drone), "drone"),
        ] {
            if from != "label" {
                assert!(
                    matches!(
                        LabelCode::decode(&format!("OASAR1-{b}")),
                        Err(Error::BadCode(_))
                    ),
                    "{from} as label"
                );
            }
            if from != "replace" {
                assert!(
                    matches!(
                        ReplaceCode::decode(&format!("OASAT1-{b}")),
                        Err(Error::BadCode(_))
                    ),
                    "{from} as replace"
                );
            }
            if from != "drone" {
                assert!(
                    matches!(
                        PairingCode::decode(&format!("OASA1-{b}")),
                        Err(Error::BadCode(_))
                    ),
                    "{from} as drone"
                );
            }
        }
    }

    fn refused<T>(r: Result<T>, why: &str) {
        match r {
            Err(Error::BadCode(m)) => assert!(m.contains(why), "{m:?} lacks {why:?}"),
            Err(e) => panic!("expected BadCode({why}), got {e}"),
            Ok(_) => panic!("expected BadCode({why}), it was accepted"),
        }
    }

    fn both(text_of: impl Fn(&str, &str) -> (String, String), why: &str) {
        let k = key();
        let l = LabelCode::new(k).unwrap().encode();
        let r = ReplaceCode::new(k).unwrap().encode();
        let (lt, rt) = text_of(&l, &r);
        refused(LabelCode::decode(&lt), why);
        refused(ReplaceCode::decode(&rt), why);
    }

    #[test]
    fn case_3_wrong_prefix_is_refused() {
        both(
            |l, r| (format!("OASAX1-{}", &l[7..]), format!("OASA-{}", &r[7..])),
            "must start with",
        );
        both(
            |l, r| (l[1..].to_string(), r[7..].to_string()),
            "must start with",
        );
        for bad in ["", "OASAR1", "hello", "OASAT", "OASAR1x"] {
            refused(LabelCode::decode(bad), "must start with");
            refused(ReplaceCode::decode(bad), "must start with");
        }
    }

    #[test]
    fn case_3_unknown_version_is_refused() {
        // In the prefix...
        both(
            |l, r| (format!("OASAR2-{}", &l[7..]), format!("OASAT0-{}", &r[7..])),
            "unsupported version",
        );
        // ...and in the version byte, with a correct checksum.
        for v in [0u8, 2, 0xFF] {
            let (public, secret) = known();
            for kind in [&LABEL, &REPLACE] {
                let mut body = [0u8; BODY_LEN + CHECKSUM_LEN];
                body[0] = v;
                body[1..33].copy_from_slice(&public);
                body[33..65].copy_from_slice(&secret);
                let sum = checksum(kind, &body[..BODY_LEN]);
                body[BODY_LEN..].copy_from_slice(&sum);
                let t = format!(
                    "{}{}",
                    kind.prefix,
                    data_encoding::BASE32_NOPAD.encode(&body)
                );
                refused(Fields::decode(&t, kind), "unsupported version");
            }
        }
    }

    #[test]
    fn case_3_wrong_length_is_refused() {
        // One byte short and one byte long, each valid base32 with a checksum.
        for len in [BODY_LEN + CHECKSUM_LEN - 1, BODY_LEN + CHECKSUM_LEN + 1, 5] {
            for kind in [&LABEL, &REPLACE] {
                let mut body = vec![1u8; len];
                body[0] = VERSION;
                let t = format!(
                    "{}{}",
                    kind.prefix,
                    data_encoding::BASE32_NOPAD.encode(&body)
                );
                refused(Fields::decode(&t, kind), "wrong length");
            }
        }
        // Text cut short or with a character added is not valid base32 here.
        both(|l, r| (l[..117].to_string(), format!("{r}A")), "");
    }

    #[test]
    fn case_3_bad_checksum_and_one_changed_character_are_refused() {
        let k = key();
        for text in [
            LabelCode::new(k).unwrap().encode(),
            ReplaceCode::new(k).unwrap().encode(),
        ] {
            // Change each position in turn (not the last, whose padding bits
            // are its own test).
            for i in 7..text.len() - 1 {
                let mut c: Vec<char> = text.chars().collect();
                c[i] = if c[i] == 'A' { 'B' } else { 'A' };
                let bad: String = c.into_iter().collect();
                let r = if text.starts_with("OASAR1-") {
                    LabelCode::decode(&bad).map(|_| ())
                } else {
                    ReplaceCode::decode(&bad).map(|_| ())
                };
                assert!(matches!(r, Err(Error::BadCode(_))), "position {i}");
            }
        }
        // A checksum that is wrong while the rest is intact.
        let (public, secret) = known();
        for kind in [&LABEL, &REPLACE] {
            let mut body = [0u8; BODY_LEN + CHECKSUM_LEN];
            body[0] = VERSION;
            body[1..33].copy_from_slice(&public);
            body[33..65].copy_from_slice(&secret);
            let mut sum = checksum(kind, &body[..BODY_LEN]);
            sum[3] ^= 1;
            body[BODY_LEN..].copy_from_slice(&sum);
            let t = format!(
                "{}{}",
                kind.prefix,
                data_encoding::BASE32_NOPAD.encode(&body)
            );
            refused(Fields::decode(&t, kind), "checksum");
        }
    }

    #[test]
    fn case_3_last_character_differing_only_in_padding_bits_is_refused() {
        // 69 bytes are 552 bits; 111 base32 characters carry 555, so the last
        // character has 3 padding bits that must be zero.
        let k = key();
        for text in [
            LabelCode::new(k).unwrap().encode(),
            ReplaceCode::new(k).unwrap().encode(),
        ] {
            let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            let last = *text.as_bytes().last().unwrap();
            let v = alphabet.iter().position(|&a| a == last).unwrap();
            assert_eq!(v & 0b111, 0, "an encoder writes zero padding bits");
            for pad in 1..8 {
                let mut bad = text.clone();
                bad.pop();
                bad.push(alphabet[v | pad] as char);
                let r = if text.starts_with("OASAR1-") {
                    LabelCode::decode(&bad).map(|_| ())
                } else {
                    ReplaceCode::decode(&bad).map(|_| ())
                };
                assert!(matches!(r, Err(Error::BadCode(_))), "padding {pad}");
            }
        }
    }

    #[test]
    fn case_3_small_order_key_is_refused() {
        // The identity point and a point of order 8, as R-SEC1's tests use.
        let mut eight = [0u8; 32];
        data_encoding::HEXLOWER
            .decode_mut(
                b"e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
                &mut eight,
            )
            .unwrap();
        let mut one = [0u8; 32];
        one[0] = 1;
        for k in [[0u8; 32], one, eight] {
            assert!(LabelCode::new(k).is_err());
            assert!(ReplaceCode::new(k).is_err());
            assert!(ReplaceCode::from_secret(k, &[7u8; 32]).is_err());
            let l = LabelCode::with_secret(k, [7u8; 32]).encode();
            let r = ReplaceCode::with_secret(k, [7u8; 32]).encode();
            refused(LabelCode::decode(&l), "radio key is not valid");
            refused(ReplaceCode::decode(&r), "radio key is not valid");
        }
    }

    #[test]
    fn a_code_with_an_all_zero_secret_is_refused() {
        let k = key();
        assert!(ReplaceCode::from_secret(k, &[0u8; 32]).is_err());
        let r = ReplaceCode::with_secret(k, [0u8; 32]).encode();
        refused(ReplaceCode::decode(&r), "all zero");
        // Nor a label (review C-6).
        let l = LabelCode::with_secret(k, [0u8; 32]).encode();
        refused(LabelCode::decode(&l), "all zero");
    }

    #[test]
    fn the_pair_open_body_carries_the_codes_secret_and_hides_it() {
        let r = ReplaceCode::new(key()).unwrap();
        let b = r.pair_open_body();
        assert_eq!(b.as_bytes().len(), 33);
        assert_eq!(b.as_bytes()[0], 0x0B);
        assert_eq!(b.secret(), r.secret());
        let back = ReplaceCode::from_secret(*r.pairing_public(), b.secret()).unwrap();
        assert_eq!(back.encode(), r.encode());
        let shown = format!("{b:?}");
        assert_eq!(shown, "PairOpenBody(..)");
    }

    #[test]
    fn garbage_is_refused_without_panicking() {
        for bad in [
            "OASAR1-",
            "OASAT1-",
            "OASAR1-!!!!",
            "OASAR1-AAAAAAAA",
            "OASAR1-\u{00e9}\u{00e9}",
            "OASAR\u{00e9}",
            "OASA\u{00e9}1-AAAA",
        ] {
            assert!(LabelCode::decode(bad).is_err(), "{bad}");
            assert!(ReplaceCode::decode(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn every_code_has_a_new_secret() {
        let k = key();
        assert_ne!(
            LabelCode::new(k).unwrap().secret(),
            LabelCode::new(k).unwrap().secret()
        );
        assert_ne!(
            ReplaceCode::new(k).unwrap().secret(),
            ReplaceCode::new(k).unwrap().secret()
        );
    }

    #[test]
    fn debug_and_errors_never_show_the_secret() {
        let k = key();
        let l = LabelCode::new(k).unwrap();
        let r = ReplaceCode::new(k).unwrap();
        for (shown, text) in [
            (format!("{l:?}"), l.encode()),
            (format!("{r:?}"), r.encode()),
        ] {
            let secret_part = &text[7 + 52..7 + 104];
            assert!(!shown.contains(secret_part));
            assert!(!shown.contains(&text[7..]));
        }
        // An error for a nearly right code names no part of it.
        let mut bad = l.encode();
        bad.insert(50, 'A');
        let e = LabelCode::decode(&bad).unwrap_err().to_string();
        assert!(!e.contains(&l.encode()[7 + 52..7 + 60]));
    }
}
