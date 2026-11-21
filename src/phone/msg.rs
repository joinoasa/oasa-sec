//! The messages inside the phone link session (spec section 4).
//!
//! Each is a link **application** packet (content type `0x00`) whose body is
//! `[type: 1][body]`. The link adds and removes the content type byte; this
//! module sees `[type][body]` only.
//!
//! The spec fixes the type numbers (as "draft numbers"), who sends each one,
//! and one body: `PAIR_OPEN`, `[secret: 32]`. It does **not** fix the body
//! of any other message. This crate does not invent them: the bodies the
//! radio's own logic needs to read or write go through [`BodyFormat`], which
//! the firmware supplies once the spec defines them, and the rest are handed
//! to the firmware as they are (`SEND`, `SETTINGS`, `UPDATE_*`).
// SPEC-GAP: section 4 gives no body layout for SEND, SENT, RECEIVED, FILTERS,
// HELD, FETCH, FETCH_ACK, SETTINGS, STATUS or UPDATE_*. They are left to
// `BodyFormat` / the firmware rather than invented here.

use super::MSG_PAIR_OPEN;
use super::hold::{Filters, HoldNumber, Signal};

/// `SEND`, phone → radio: one sealed packet to transmit.
pub const MSG_SEND: u8 = 0x01;
/// `SENT`, radio → phone: that packet went on the air, or why not.
pub const MSG_SENT: u8 = 0x02;
/// `RECEIVED`, radio → phone: one sealed packet from the air.
pub const MSG_RECEIVED: u8 = 0x03;
/// `FILTERS`, phone → radio: the wake filters; replaces the whole list.
pub const MSG_FILTERS: u8 = 0x04;
/// `HELD`, radio → phone: how many packets are held; sent after each
/// handshake.
pub const MSG_HELD: u8 = 0x05;
/// `FETCH`, phone → radio: hand over held packets.
pub const MSG_FETCH: u8 = 0x06;
/// `FETCH_ACK`, phone → radio: hold numbers the phone has stored.
pub const MSG_FETCH_ACK: u8 = 0x07;
/// `SETTINGS`, phone → radio.
pub const MSG_SETTINGS: u8 = 0x08;
/// `STATUS`, radio → phone.
pub const MSG_STATUS: u8 = 0x09;
/// `UPDATE_*`, phone → radio: firmware update pieces.
pub const MSG_UPDATE: u8 = 0x0A;
/// Length of a `PAIR_OPEN` body after its type byte.
pub const PAIR_OPEN_BODY: usize = 32;

/// Most hold numbers one `FETCH_ACK` can name: the hold store's size.
pub const MAX_ACK: usize = super::hold::HOLD_PACKETS;

/// A message from the phone, by type. Bodies are borrowed from the
/// decrypted packet.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FromPhone<'a> {
    Send(&'a [u8]),
    Filters(&'a [u8]),
    Fetch(&'a [u8]),
    FetchAck(&'a [u8]),
    Settings(&'a [u8]),
    Update(&'a [u8]),
    /// The one-time replace secret. Never shown by `Debug`.
    PairOpen(&'a [u8; PAIR_OPEN_BODY]),
}

impl std::fmt::Debug for FromPhone<'_> {
    // Sizes only: bodies are the phone's (sealed) data, and `PAIR_OPEN`
    // carries a secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (name, len) = match self {
            FromPhone::Send(b) => ("Send", b.len()),
            FromPhone::Filters(b) => ("Filters", b.len()),
            FromPhone::Fetch(b) => ("Fetch", b.len()),
            FromPhone::FetchAck(b) => ("FetchAck", b.len()),
            FromPhone::Settings(b) => ("Settings", b.len()),
            FromPhone::Update(b) => ("Update", b.len()),
            FromPhone::PairOpen(_) => ("PairOpen", PAIR_OPEN_BODY),
        };
        write!(f, "{name}({len} bytes)")
    }
}

/// Why a message from the phone was dropped (and counted). Nothing is done
/// and nothing is answered for any of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgDrop {
    /// No type byte.
    Empty,
    /// A type the spec does not list ("other: dropped and counted").
    Unknown,
    /// A type only the radio sends (`SENT`, `RECEIVED`, `HELD`, `STATUS`).
    WrongDirection,
    /// A `PAIR_OPEN` whose body is not exactly 32 bytes.
    BadPairOpen,
    /// A body that [`BodyFormat`] refused.
    BadBody,
}

/// Sort a decrypted application packet from the phone by its type byte.
pub fn parse_from_phone(plain: &[u8]) -> Result<FromPhone<'_>, MsgDrop> {
    let (&ty, body) = plain.split_first().ok_or(MsgDrop::Empty)?;
    Ok(match ty {
        MSG_SEND => FromPhone::Send(body),
        MSG_FILTERS => FromPhone::Filters(body),
        MSG_FETCH => FromPhone::Fetch(body),
        MSG_FETCH_ACK => FromPhone::FetchAck(body),
        MSG_SETTINGS => FromPhone::Settings(body),
        MSG_UPDATE => FromPhone::Update(body),
        MSG_PAIR_OPEN => FromPhone::PairOpen(body.try_into().map_err(|_| MsgDrop::BadPairOpen)?),
        MSG_SENT | MSG_RECEIVED | MSG_HELD | MSG_STATUS => return Err(MsgDrop::WrongDirection),
        _ => return Err(MsgDrop::Unknown),
    })
}

/// Types the radio sends whose body the firmware builds (`SENT`, `STATUS`).
/// `HELD` and `RECEIVED` are built by the radio's hold logic through
/// [`BodyFormat`].
pub fn firmware_may_send(ty: u8) -> bool {
    matches!(ty, MSG_SENT | MSG_STATUS)
}

/// The body layouts the spec has not fixed yet, supplied by the firmware
/// (and by tests). Each decoder sees one body (after the type byte) and
/// returns `None`/`false` to refuse it; a refused body is dropped and
/// counted. Encoders append the body (without the type byte) to `out`.
pub trait BodyFormat {
    /// A `FILTERS` body: the whole new list.
    fn decode_filters(&mut self, body: &[u8]) -> Option<Filters>;
    /// Whether this is a valid `FETCH` body.
    fn decode_fetch(&mut self, body: &[u8]) -> bool;
    /// A `FETCH_ACK` body: write the hold numbers into `out` and return how
    /// many; `None` refuses the body (including more than `out` holds).
    fn decode_fetch_ack(&mut self, body: &[u8], out: &mut [HoldNumber; MAX_ACK]) -> Option<usize>;
    /// A `HELD` body: how many packets are held.
    fn encode_held(&mut self, count: usize, out: &mut Vec<u8>);
    /// The most bytes [`encode_received`](Self::encode_received) adds to a
    /// packet (its hold number, signal level and any other field). The radio
    /// holds only packets that fit one `RECEIVED` at its MTU with these.
    fn received_overhead(&self) -> usize;
    /// A `RECEIVED` body for a held packet.
    fn encode_received(
        &mut self,
        hold: HoldNumber,
        signal: Signal,
        packet: &[u8],
        out: &mut Vec<u8>,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn types_are_sorted_by_direction() {
        for ty in [MSG_SENT, MSG_RECEIVED, MSG_HELD, MSG_STATUS] {
            assert_eq!(parse_from_phone(&[ty, 1, 2]), Err(MsgDrop::WrongDirection));
        }
        for ty in [0x00, 0x0C, 0x7F, 0xFF] {
            assert_eq!(parse_from_phone(&[ty]), Err(MsgDrop::Unknown));
        }
        assert_eq!(parse_from_phone(&[]), Err(MsgDrop::Empty));
        assert!(matches!(
            parse_from_phone(&[MSG_SEND, 9]),
            Ok(FromPhone::Send([9]))
        ));
        assert!(matches!(
            parse_from_phone(&[MSG_FETCH]),
            Ok(FromPhone::Fetch([]))
        ));
        assert!(firmware_may_send(MSG_SENT) && firmware_may_send(MSG_STATUS));
        for ty in [MSG_HELD, MSG_RECEIVED, MSG_SEND, MSG_PAIR_OPEN, 0x00] {
            assert!(!firmware_may_send(ty));
        }
    }

    #[test]
    fn pair_open_must_be_exactly_32_bytes() {
        let mut m = vec![MSG_PAIR_OPEN];
        m.extend_from_slice(&[7u8; 32]);
        assert!(matches!(parse_from_phone(&m), Ok(FromPhone::PairOpen(_))));
        for len in [0usize, 1, 31, 33, 64] {
            let mut m = vec![MSG_PAIR_OPEN];
            m.extend(std::iter::repeat_n(7u8, len));
            assert_eq!(parse_from_phone(&m), Err(MsgDrop::BadPairOpen), "{len}");
        }
    }

    #[test]
    fn debug_shows_no_body() {
        let secret = [0xA5u8; 32];
        let shown = format!("{:?}", FromPhone::PairOpen(&secret));
        assert!(!shown.contains("165"), "the secret is shown");
        assert_eq!(
            format!("{:?}", FromPhone::Send(&[1, 2, 3])),
            "Send(3 bytes)"
        );
    }
}
