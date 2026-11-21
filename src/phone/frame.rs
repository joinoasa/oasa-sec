//! Link packets on a BLE stream (spec section 3, "Framing"): each packet is
//! a 2-byte big-endian length and the bytes, as R-SEC1's stream framing,
//! split across writes and notifications as the transport needs. On USB
//! each link packet is one UDP datagram and needs no framing.
//!
//! The deframer keeps one partial packet in a fixed buffer of `MTU` bytes.
//! A length above the MTU **closes the connection** (spec section 3); so
//! does a length of zero, which is no link packet.
// SPEC-GAP: the spec does not say what a zero-length frame means; it is
// treated as a bad frame and closes the connection.

/// Why a stream was refused. The connection is then closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// A packet longer than the MTU.
    TooLong,
    /// A zero length.
    Empty,
}

/// Splits a byte stream into link packets.
pub struct Deframer<const MTU: usize> {
    len: [u8; 2],
    len_have: usize,
    buf: [u8; MTU],
    have: usize,
}

impl<const MTU: usize> Default for Deframer<MTU> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const MTU: usize> std::fmt::Debug for Deframer<MTU> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Deframer({} bytes waiting)", self.len_have + self.have)
    }
}

impl<const MTU: usize> Deframer<MTU> {
    pub const fn new() -> Self {
        Self {
            len: [0; 2],
            len_have: 0,
            buf: [0; MTU],
            have: 0,
        }
    }

    /// Take the next bytes of the stream; `packet` is called for each whole
    /// packet, in order. After an error the deframer must not be used
    /// again (the connection closes).
    pub fn push(
        &mut self,
        mut bytes: &[u8],
        mut packet: impl FnMut(&[u8]),
    ) -> Result<(), FrameError> {
        while !bytes.is_empty() {
            if self.len_have < 2 {
                self.len[self.len_have] = bytes[0];
                self.len_have += 1;
                bytes = &bytes[1..];
                if self.len_have == 2 {
                    let want = usize::from(u16::from_be_bytes(self.len));
                    if want == 0 {
                        return Err(FrameError::Empty);
                    }
                    if want > MTU {
                        return Err(FrameError::TooLong);
                    }
                }
                continue;
            }
            let want = usize::from(u16::from_be_bytes(self.len));
            let take = (want - self.have).min(bytes.len());
            self.buf[self.have..self.have + take].copy_from_slice(&bytes[..take]);
            self.have += take;
            bytes = &bytes[take..];
            if self.have == want {
                packet(&self.buf[..want]);
                self.have = 0;
                self.len_have = 0;
            }
        }
        Ok(())
    }
}

/// One link packet with its 2-byte big-endian length, for a BLE stream.
/// `None` if it does not fit the length field.
pub fn frame(packet: &[u8]) -> Option<Vec<u8>> {
    let len = u16::try_from(packet.len()).ok()?;
    let mut v = Vec::with_capacity(2 + packet.len());
    v.extend_from_slice(&len.to_be_bytes());
    v.extend_from_slice(packet);
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(d: &mut Deframer<128>, bytes: &[u8]) -> Result<Vec<Vec<u8>>, FrameError> {
        let mut v = vec![];
        d.push(bytes, |p| v.push(p.to_vec()))?;
        Ok(v)
    }

    #[test]
    fn packets_split_and_joined_come_out_whole() {
        let a = frame(&[1u8; 100]).unwrap();
        let b = frame(&[2u8; 128]).unwrap();
        let stream: Vec<u8> = a.iter().chain(&b).copied().collect();
        for cut in 0..stream.len() {
            let mut d = Deframer::<128>::new();
            let mut got = all(&mut d, &stream[..cut]).unwrap();
            got.extend(all(&mut d, &stream[cut..]).unwrap());
            assert_eq!(got, vec![vec![1u8; 100], vec![2u8; 128]], "cut at {cut}");
        }
        // One byte at a time.
        let mut d = Deframer::<128>::new();
        let mut got = vec![];
        for b in &stream {
            got.extend(all(&mut d, &[*b]).unwrap());
        }
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn a_length_over_the_mtu_or_zero_is_refused() {
        let mut d = Deframer::<128>::new();
        assert_eq!(all(&mut d, &[0, 129]), Err(FrameError::TooLong));
        let mut d = Deframer::<128>::new();
        assert_eq!(all(&mut d, &[0xFF, 0xFF, 1, 2]), Err(FrameError::TooLong));
        let mut d = Deframer::<128>::new();
        assert_eq!(all(&mut d, &[0, 0]), Err(FrameError::Empty));
        // Exactly the MTU passes.
        let mut d = Deframer::<128>::new();
        assert_eq!(all(&mut d, &frame(&[0u8; 128]).unwrap()).unwrap().len(), 1);
        // A partial packet waits.
        let mut d = Deframer::<128>::new();
        assert!(all(&mut d, &[0, 5, 1, 2]).unwrap().is_empty());
    }

    #[test]
    fn frame_refuses_what_the_length_cannot_hold() {
        assert!(frame(&vec![0u8; 65_536]).is_none());
        assert_eq!(frame(&[9]).unwrap(), vec![0, 1, 9]);
    }
}
