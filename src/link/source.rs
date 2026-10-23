//! Per-source limit on handshake 1 packets, for the layer that knows where a
//! packet came from (the link itself is sans-IO and sees no addresses).
//!
//! `mac1` throws away random junk for free. Someone who recorded a real
//! handshake 1 can still replay it fast enough to use up the responder's
//! global budget; this limit, applied BEFORE `Endpoint::handle_packet`,
//! keeps one address from doing that alone. It is no help against many
//! addresses (spoofed or not): that needs DoS cookies (spec section 9).

use std::collections::HashMap;
use std::hash::Hash;
use std::time::Duration;

use super::packet::{HANDSHAKE1_LEN, VERSION};

/// Most addresses tracked in one second. Past that, new addresses are let
/// through to the global limit rather than refused, so a flood of spoofed
/// addresses cannot lock out real ones.
const MAX_TRACKED: usize = 4096;

/// Whether `buf` has the shape of a handshake 1 (header byte and length).
pub fn looks_like_handshake1(buf: &[u8]) -> bool {
    buf.len() == HANDSHAKE1_LEN && buf[0] == (1 << 4) | VERSION
}

/// At most `per_second` handshake 1 packets a second per source, counted in
/// whole seconds.
#[derive(Debug)]
pub struct SourceLimiter<K> {
    per_second: u32,
    window_start: Duration,
    counts: HashMap<K, u32>,
}

impl<K: Hash + Eq> SourceLimiter<K> {
    pub fn new(per_second: u32) -> Self {
        Self {
            per_second,
            window_start: Duration::ZERO,
            counts: HashMap::new(),
        }
    }

    /// May a handshake 1 from `source` go on to the link?
    pub fn allow(&mut self, now: Duration, source: K) -> bool {
        if now.saturating_sub(self.window_start) >= Duration::from_secs(1) {
            self.window_start = now;
            self.counts.clear();
        }
        if self.counts.len() >= MAX_TRACKED && !self.counts.contains_key(&source) {
            return true;
        }
        let n = self.counts.entry(source).or_insert(0);
        *n = n.saturating_add(1);
        *n <= self.per_second
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_each_source_in_each_second() {
        let mut l = SourceLimiter::new(5);
        let t = Duration::from_millis(100);
        let a: Vec<bool> = (0..8).map(|_| l.allow(t, "a")).collect();
        assert_eq!(a, [true, true, true, true, true, false, false, false]);
        assert!(l.allow(t, "b"), "another source has its own allowance");
        assert!(l.allow(Duration::from_millis(1200), "a"), "new second");
        // Many sources: past the table size, strangers pass (to the global limit).
        let mut l = SourceLimiter::new(1);
        for i in 0..MAX_TRACKED {
            assert!(l.allow(t, i));
        }
        assert!(l.allow(t, usize::MAX));
        assert!(l.allow(t, usize::MAX));
        assert!(!l.allow(t, 0), "tracked sources stay limited");
    }

    #[test]
    fn recognizes_the_shape() {
        let mut p = vec![0x11u8; HANDSHAKE1_LEN];
        assert!(looks_like_handshake1(&p));
        p[0] = 0x31;
        assert!(!looks_like_handshake1(&p));
        p[0] = 0x10; // version 0 is the old wire
        assert!(!looks_like_handshake1(&p));
        assert!(!looks_like_handshake1(&p[..50]));
    }
}
