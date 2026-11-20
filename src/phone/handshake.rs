//! The three pairing messages (spec section 2.4), sans-IO: bytes in, bytes
//! out, no streams and no clock. Framing belongs to the transport.
//!
//! `Noise_IKpsk1_25519_ChaChaPoly_BLAKE2s` ([`crate::PAIRING_NOISE`]), psk at
//! position 1, prologue [`crate::PHONE_PAIRING_PROLOGUE`]. The phone is the
//! initiator, the radio the responder.

use snow::{HandshakeState, TransportState};
use zeroize::Zeroizing;

use super::code::{LabelCode, ReplaceCode};
use super::{MSG_LINK_KEY, Name, parse_hello, write_hello};
use crate::identity::{Identity, check_peer_public};
use crate::link::Entropy;
use crate::pairing::MAX_NAME;
use crate::{Error, PAIRING_NOISE, PHONE_PAIRING_PROLOGUE, Result};

const TAG: usize = 16;
const KEY: usize = 32;
const HELLO_MAX: usize = 2 + MAX_NAME;
const HELLO_MIN: usize = 2 + 1;
const LINK_FIELD: usize = 1 + KEY;
/// R-SEC1's confirm byte.
const MSG_CONFIRM: u8 = 0x03;

/// Longest message 1: ephemeral, encrypted static, encrypted hello.
pub const MAX_MSG1: usize = KEY + (KEY + TAG) + HELLO_MAX + TAG;
/// Shortest message 1 (a one-character name).
pub const MIN_MSG1: usize = KEY + (KEY + TAG) + HELLO_MIN + TAG;
/// Longest message 2: ephemeral, encrypted hello and link key field.
pub const MAX_MSG2: usize = KEY + HELLO_MAX + LINK_FIELD + TAG;
/// Shortest message 2.
pub const MIN_MSG2: usize = KEY + HELLO_MIN + LINK_FIELD + TAG;
/// Message 3 is exactly the encrypted confirm byte.
pub const MSG3_LEN: usize = 1 + TAG;

fn builder() -> snow::Builder<'static> {
    snow::Builder::new(PAIRING_NOISE.parse().expect("valid Noise name"))
}

/// Which code the phone pairs with: the label in a USB window, a replace
/// code in a replace window.
#[derive(Clone, Copy, Debug)]
pub enum PairWith<'a> {
    Label(&'a LabelCode),
    Replace(&'a ReplaceCode),
}

impl PairWith<'_> {
    fn pairing_public(&self) -> &[u8; 32] {
        match self {
            PairWith::Label(c) => c.pairing_public(),
            PairWith::Replace(c) => c.pairing_public(),
        }
    }
    fn secret(&self) -> &[u8; 32] {
        match self {
            PairWith::Label(c) => c.secret(),
            PairWith::Replace(c) => c.secret(),
        }
    }
}

/// The phone's side of one pairing, between message 1 and message 2.
///
/// It holds a **new radio-link key** made for this pairing (spec section 1);
/// it is wiped when this is dropped unless the pairing finishes, when it is
/// handed back in [`PhonePaired`].
pub struct PhonePairing {
    hs: HandshakeState,
    radio_link_key: Identity,
    radio_pairing_public: [u8; 32],
}

impl std::fmt::Debug for PhonePairing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PhonePairing")
            .field(
                "radio",
                &crate::identity::fingerprint(&self.radio_pairing_public),
            )
            .finish_non_exhaustive()
    }
}

/// What the phone has once it sent message 3. The pairing is **not yet
/// confirmed**: the spec's confirmation is the first completed link
/// handshake to `radio_link_public` (section 2.4), which is a later part.
pub struct PhonePaired {
    /// The radio's pairing key (from the code).
    pub radio_pairing_public: [u8; 32],
    /// The radio's name from its hello.
    pub radio_name: Name,
    /// The radio's link public key from message 2: the link's peer key.
    pub radio_link_public: [u8; 32],
    /// This phone's radio-link key for this radio. Keep it on the device only.
    pub radio_link_key: Identity,
    /// Message 3, to send to the radio.
    pub msg3: Vec<u8>,
}

impl std::fmt::Debug for PhonePaired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PhonePaired")
            .field(
                "radio",
                &crate::identity::fingerprint(&self.radio_pairing_public),
            )
            .field("radio_name", &self.radio_name)
            .field(
                "radio_link",
                &crate::identity::fingerprint(&self.radio_link_public),
            )
            .finish_non_exhaustive()
    }
}

impl PhonePairing {
    /// Start a pairing with the radio that `code` names. Makes a new
    /// radio-link key from `entropy` and returns message 1.
    pub fn start(
        code: PairWith<'_>,
        my_name: &str,
        entropy: &mut dyn Entropy,
    ) -> Result<(Self, Vec<u8>)> {
        let name = Name::new(my_name)?;
        let radio_pairing_public = *code.pairing_public();
        check_peer_public(&radio_pairing_public)?;
        let radio_link_key = new_key(entropy)?;
        let mut hs = builder()
            .local_private_key(radio_link_key.private_key())?
            .remote_public_key(&radio_pairing_public)?
            .psk(1, code.secret())?
            .prologue(PHONE_PAIRING_PROLOGUE)?
            .build_initiator()?;
        let mut hello = [0u8; HELLO_MAX];
        let n = write_hello(&name, &mut hello);
        let mut out = vec![0u8; MAX_MSG1];
        let len = hs.write_message(&hello[..n], &mut out)?;
        out.truncate(len);
        Ok((
            Self {
                hs,
                radio_link_key,
                radio_pairing_public,
            },
            out,
        ))
    }

    /// Read message 2 and make message 3. Refuses a message of the wrong
    /// size, one that fails to decrypt, a bad hello, a missing or extra link
    /// key field, and a small-order link key.
    pub fn finish(self, msg2: &[u8]) -> Result<PhonePaired> {
        self.finish_with(msg2, &[MSG_CONFIRM])
    }

    /// Tests only: message 3 with another payload than the confirm byte.
    #[cfg(test)]
    pub(crate) fn finish_with_payload(self, msg2: &[u8], payload: &[u8]) -> Result<PhonePaired> {
        self.finish_with(msg2, payload)
    }

    fn finish_with(mut self, msg2: &[u8], confirm: &[u8]) -> Result<PhonePaired> {
        if !(MIN_MSG2..=MAX_MSG2).contains(&msg2.len()) {
            return Err(Error::Protocol("message 2 has the wrong size"));
        }
        let mut payload = [0u8; MAX_MSG2];
        let n = self.hs.read_message(msg2, &mut payload)?;
        let p = &payload[..n];
        if p.len() < LINK_FIELD {
            return Err(Error::Protocol("message 2 has no link key"));
        }
        let (hello, link) = p.split_at(p.len() - LINK_FIELD);
        let radio_name = parse_hello(hello)?;
        if link[0] != MSG_LINK_KEY {
            return Err(Error::Protocol("message 2 has no link key"));
        }
        let radio_link_public: [u8; 32] = link[1..].try_into().expect("32 bytes");
        check_peer_public(&radio_link_public)?;
        let mut t: TransportState = self.hs.into_transport_mode()?;
        let mut msg3 = vec![0u8; confirm.len() + TAG];
        let len = t.write_message(confirm, &mut msg3)?;
        msg3.truncate(len);
        Ok(PhonePaired {
            radio_pairing_public: self.radio_pairing_public,
            radio_name,
            radio_link_public,
            radio_link_key: self.radio_link_key,
            msg3,
        })
    }
}

/// A new X25519 key pair from `entropy`, the same clamped X25519 as
/// [`Identity::generate`] (any 32 bytes are a valid private key).
/// A failed random source makes nothing.
pub(crate) fn new_key(entropy: &mut dyn Entropy) -> Result<Identity> {
    let mut private = Zeroizing::new([0u8; 32]);
    entropy
        .try_fill(&mut private[..])
        .map_err(|_| Error::Io(std::io::Error::other("random source failed")))?;
    Identity::from_private_bytes(&private[..])
}

/// The radio's side, step 1: decrypt message 1 with `psk`. Success means the
/// sender proved the secret; nothing else is checked yet.
pub(crate) struct Opened {
    pub(crate) hs: HandshakeState,
    /// The ephemeral key that starts message 1 (public, in clear).
    pub(crate) ephemeral: [u8; 32],
    hello: [u8; HELLO_MAX],
    hello_len: usize,
}

pub(crate) fn radio_open_msg1(pairing: &Identity, psk: &[u8; 32], msg1: &[u8]) -> Result<Opened> {
    if !(MIN_MSG1..=MAX_MSG1).contains(&msg1.len()) {
        return Err(Error::Protocol("message 1 has the wrong size"));
    }
    let mut hs = builder()
        .local_private_key(pairing.private_key())?
        .psk(1, psk)?
        .prologue(PHONE_PAIRING_PROLOGUE)?
        .build_responder()?;
    let mut payload = [0u8; MAX_MSG1];
    let n = hs.read_message(msg1, &mut payload)?;
    if n > HELLO_MAX {
        return Err(Error::Protocol("bad hello"));
    }
    let mut hello = [0u8; HELLO_MAX];
    hello[..n].copy_from_slice(&payload[..n]);
    Ok(Opened {
        hs,
        ephemeral: msg1[..32].try_into().expect("32 bytes"),
        hello,
        hello_len: n,
    })
}

/// Step 2: the phone's name and radio-link public key, checked.
pub(crate) fn radio_check_msg1(o: &Opened) -> Result<([u8; 32], Name)> {
    let name = parse_hello(&o.hello[..o.hello_len])?;
    let phone: [u8; 32] =
        o.hs.get_remote_static()
            .ok_or(Error::Protocol("phone sent no key"))?
            .try_into()
            .map_err(|_| Error::Protocol("bad phone key"))?;
    check_peer_public(&phone)?;
    Ok((phone, name))
}

/// Step 3: message 2, with the link public key of this attempt.
pub(crate) fn radio_write_msg2(
    mut hs: HandshakeState,
    my_name: &Name,
    link_public: &[u8; 32],
    out: &mut [u8; MAX_MSG2],
) -> Result<(TransportState, usize)> {
    let mut payload = [0u8; HELLO_MAX + LINK_FIELD];
    let n = write_hello(my_name, &mut payload);
    payload[n] = MSG_LINK_KEY;
    payload[n + 1..n + LINK_FIELD].copy_from_slice(link_public);
    let len = hs.write_message(&payload[..n + LINK_FIELD], out)?;
    Ok((hs.into_transport_mode()?, len))
}

/// Step 4: a valid message 3 is the encrypted confirm byte and nothing else.
pub(crate) fn radio_read_msg3(t: &mut TransportState, msg3: &[u8]) -> Result<()> {
    if msg3.len() != MSG3_LEN {
        return Err(Error::Protocol("message 3 has the wrong size"));
    }
    let mut payload = [0u8; MSG3_LEN];
    let n = t.read_message(msg3, &mut payload)?;
    if payload[..n] != [MSG_CONFIRM] {
        return Err(Error::Protocol("message 3 is not a confirm"));
    }
    Ok(())
}
