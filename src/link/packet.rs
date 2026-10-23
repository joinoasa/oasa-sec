//! Packet layout (spec section 3). Parsing never allocates and never looks
//! at keys: it only checks the shape.

use super::DropReason;

/// Wire version. Anything else is dropped.
pub const VERSION: u8 = 0;

const TYPE_HANDSHAKE1: u8 = 1;
const TYPE_HANDSHAKE2: u8 = 2;
const TYPE_DATA: u8 = 3;

/// Poly1305 tag. Never shortened.
pub const TAG_LEN: usize = 16;

/// Noise message 1: 32 (e) + 48 (encrypted s) + 12 + 16 (encrypted timestamp).
const NOISE1_LEN: usize = 108;
/// Noise message 2: 32 (e) + 16 (tag of the empty payload).
const NOISE2_LEN: usize = 48;

/// Handshake 1 on the wire: header, sender index, Noise message 1.
pub const HANDSHAKE1_LEN: usize = 1 + 2 + NOISE1_LEN;
/// Handshake 2 on the wire: header, two indexes, Noise message 2.
pub const HANDSHAKE2_LEN: usize = 1 + 2 + 2 + NOISE2_LEN;

/// How many low bytes of the 64-bit counter a data packet carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterLen {
    /// 2 bytes: for links where fewer than 32,768 packets in a row can be lost.
    Short,
    /// 4 bytes: for fast links.
    Long,
}

impl CounterLen {
    pub fn bytes(self) -> usize {
        match self {
            CounterLen::Short => 2,
            CounterLen::Long => 4,
        }
    }

    pub fn bits(self) -> u32 {
        self.bytes() as u32 * 8
    }

    /// From a byte count on a command line: 2 or 4.
    pub fn from_bytes(n: usize) -> Option<Self> {
        match n {
            2 => Some(CounterLen::Short),
            4 => Some(CounterLen::Long),
            _ => None,
        }
    }
}

/// Bytes a data packet adds to the plaintext: header, index, counter, tag.
pub fn data_overhead(len: CounterLen) -> usize {
    1 + 2 + len.bytes() + TAG_LEN
}

/// A packet whose shape is valid. Contents are not yet authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Packet<'a> {
    Handshake1 {
        sender: u16,
        noise: &'a [u8],
    },
    Handshake2 {
        sender: u16,
        receiver: u16,
        noise: &'a [u8],
    },
    Data {
        receiver: u16,
        counter_len: CounterLen,
        /// The counter's low bytes, as sent.
        low: u64,
        /// Ciphertext followed by the 16-byte tag.
        ciphertext: &'a [u8],
    },
}

/// Check the header and the length of `buf`. `mtu` is the largest packet
/// accepted. Every failure is [`DropReason::BadHeader`].
pub fn parse(buf: &[u8], mtu: usize) -> Result<Packet<'_>, DropReason> {
    let bad = DropReason::BadHeader;
    let (&h, rest) = buf.split_first().ok_or(bad)?;
    if buf.len() > mtu {
        return Err(bad);
    }
    let kind = h >> 4;
    let long_flag = (h >> 3) & 1;
    if h & 7 != VERSION {
        return Err(bad);
    }
    match kind {
        TYPE_HANDSHAKE1 => {
            if long_flag != 0 || buf.len() != HANDSHAKE1_LEN {
                return Err(bad);
            }
            Ok(Packet::Handshake1 {
                sender: u16::from_be_bytes([rest[0], rest[1]]),
                noise: &rest[2..],
            })
        }
        TYPE_HANDSHAKE2 => {
            if long_flag != 0 || buf.len() != HANDSHAKE2_LEN {
                return Err(bad);
            }
            Ok(Packet::Handshake2 {
                sender: u16::from_be_bytes([rest[0], rest[1]]),
                receiver: u16::from_be_bytes([rest[2], rest[3]]),
                noise: &rest[4..],
            })
        }
        TYPE_DATA => {
            let counter_len = if long_flag == 0 {
                CounterLen::Short
            } else {
                CounterLen::Long
            };
            if buf.len() < data_overhead(counter_len) {
                return Err(bad);
            }
            let n = counter_len.bytes();
            let low = rest[2..2 + n]
                .iter()
                .fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
            Ok(Packet::Data {
                receiver: u16::from_be_bytes([rest[0], rest[1]]),
                counter_len,
                low,
                ciphertext: &rest[2 + n..],
            })
        }
        _ => Err(bad), // reserved types 0 and 4-15
    }
}

fn header(kind: u8, long: bool) -> u8 {
    (kind << 4) | (u8::from(long) << 3) | VERSION
}

pub(crate) fn encode_handshake1(sender: u16, noise: &[u8]) -> Vec<u8> {
    debug_assert_eq!(noise.len(), NOISE1_LEN);
    let mut v = Vec::with_capacity(HANDSHAKE1_LEN);
    v.push(header(TYPE_HANDSHAKE1, false));
    v.extend_from_slice(&sender.to_be_bytes());
    v.extend_from_slice(noise);
    v
}

pub(crate) fn encode_handshake2(sender: u16, receiver: u16, noise: &[u8]) -> Vec<u8> {
    debug_assert_eq!(noise.len(), NOISE2_LEN);
    let mut v = Vec::with_capacity(HANDSHAKE2_LEN);
    v.push(header(TYPE_HANDSHAKE2, false));
    v.extend_from_slice(&sender.to_be_bytes());
    v.extend_from_slice(&receiver.to_be_bytes());
    v.extend_from_slice(noise);
    v
}

/// The start of a data packet: header, receiver index, low counter bytes.
pub(crate) fn data_header(receiver: u16, counter_len: CounterLen, counter: u64) -> Vec<u8> {
    let n = counter_len.bytes();
    let mut v = Vec::with_capacity(3 + n);
    v.push(header(TYPE_DATA, counter_len == CounterLen::Long));
    v.extend_from_slice(&receiver.to_be_bytes());
    v.extend_from_slice(&counter.to_be_bytes()[8 - n..]);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    const MTU: usize = 1500;

    #[test]
    fn sizes_match_the_spec() {
        assert_eq!(HANDSHAKE1_LEN, 111);
        assert_eq!(HANDSHAKE2_LEN, 53);
        assert_eq!(data_overhead(CounterLen::Short), 21);
        assert_eq!(data_overhead(CounterLen::Long), 23);
    }

    #[test]
    fn data_round_trip_both_counter_lengths() {
        for (len, counter, low) in [
            (CounterLen::Short, 0x1_2345u64, 0x2345u64),
            (CounterLen::Long, 0x1_2345_6789, 0x2345_6789),
        ] {
            let mut p = data_header(0xBEEF, len, counter);
            p.extend_from_slice(&[7u8; 16]); // a keepalive: tag only
            match parse(&p, MTU).unwrap() {
                Packet::Data {
                    receiver,
                    counter_len,
                    low: got,
                    ciphertext,
                } => {
                    assert_eq!(receiver, 0xBEEF);
                    assert_eq!(counter_len, len);
                    assert_eq!(got, low);
                    assert_eq!(ciphertext, &[7u8; 16]);
                }
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn handshakes_round_trip() {
        let p = encode_handshake1(0x0102, &[9u8; NOISE1_LEN]);
        assert_eq!(p.len(), 111);
        assert_eq!(
            parse(&p, MTU).unwrap(),
            Packet::Handshake1 {
                sender: 0x0102,
                noise: &[9u8; NOISE1_LEN]
            }
        );
        let p = encode_handshake2(1, 2, &[5u8; NOISE2_LEN]);
        assert_eq!(p.len(), 53);
        assert_eq!(
            parse(&p, MTU).unwrap(),
            Packet::Handshake2 {
                sender: 1,
                receiver: 2,
                noise: &[5u8; NOISE2_LEN]
            }
        );
    }

    #[test]
    fn every_bad_header_is_rejected() {
        let ok = data_header(1, CounterLen::Short, 0);
        let mut ok = ok;
        ok.extend_from_slice(&[0u8; 16]);
        assert!(parse(&ok, MTU).is_ok());
        // All 256 header bytes against a data-shaped body: only the data
        // headers (type 3, version 0, either flag) may pass, and only when
        // the length fits that flag.
        for h in 0..=255u8 {
            let mut p = ok.clone();
            p[0] = h;
            let got = parse(&p, MTU);
            let valid = h == 0x30; // data, short counter, version 0
            assert_eq!(got.is_ok(), valid, "header byte {h:#04x}");
        }
        // Flag bit on handshakes.
        for h in [0x18u8, 0x28] {
            let mut p = vec![h];
            p.extend_from_slice(&[0u8; 120]);
            assert!(parse(&p, MTU).is_err());
        }
        let mut hs1 = encode_handshake1(1, &[0; NOISE1_LEN]);
        hs1[0] |= 0x08;
        assert!(parse(&hs1, MTU).is_err());
        // Wrong version on each type.
        for p in [
            encode_handshake1(1, &[0; NOISE1_LEN]),
            encode_handshake2(1, 2, &[0; NOISE2_LEN]),
            ok.clone(),
        ] {
            for v in 1..8u8 {
                let mut q = p.clone();
                q[0] = (q[0] & !7) | v;
                assert_eq!(parse(&q, MTU), Err(DropReason::BadHeader));
            }
        }
    }

    #[test]
    fn short_long_and_oversized_packets_are_rejected() {
        assert!(parse(&[], MTU).is_err());
        let hs1 = encode_handshake1(1, &[0; NOISE1_LEN]);
        let hs2 = encode_handshake2(1, 2, &[0; NOISE2_LEN]);
        for n in 0..hs1.len() {
            assert!(parse(&hs1[..n], MTU).is_err(), "hs1 cut to {n}");
        }
        for n in 0..hs2.len() {
            assert!(parse(&hs2[..n], MTU).is_err(), "hs2 cut to {n}");
        }
        let mut long = hs1.clone();
        long.push(0);
        assert!(parse(&long, MTU).is_err());
        // Data: shorter than header + index + counter + tag.
        for (len, min) in [(CounterLen::Short, 21), (CounterLen::Long, 23)] {
            let mut p = data_header(1, len, 5);
            p.extend_from_slice(&[0u8; 16]);
            assert_eq!(p.len(), min);
            assert!(parse(&p, MTU).is_ok());
            for n in 0..min {
                assert!(parse(&p[..n], MTU).is_err(), "{len:?} cut to {n}");
            }
        }
        // Bigger than the MTU.
        let mut big = data_header(1, CounterLen::Short, 5);
        big.extend_from_slice(&[0u8; 200]);
        assert!(parse(&big, 128).is_err());
        assert!(parse(&big, 400).is_ok());
        assert!(parse(&vec![0x30u8; 100_000], 65_535).is_err());
    }

    #[test]
    fn random_bytes_never_panic() {
        let mut x = 0x1234_5678_9abc_def0u64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..20_000 {
            let len = (next() % 140) as usize;
            let buf: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let _ = parse(&buf, MTU);
        }
    }
}
