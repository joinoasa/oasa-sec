//! Counter rebuilding (spec section 3) and the replay window (section 4).

/// Packets the replay window remembers (spec section 4).
pub const WINDOW_SIZE: u64 = 1024;

/// Words in the ring. Must be a power of two and at least
/// `WINDOW_SIZE / 64 + 1`, so the word being cleared never holds live bits.
const WORDS: usize = 32;

/// Rebuild a 64-bit counter from its low `bits` bits (16 or 32), as DTLS 1.3
/// does (RFC 9147 section 4.2.2): the value closest to `expected`, which is
/// the highest counter seen plus one (0 before any packet). Exactly half a
/// range away, the higher value wins.
///
/// The result is always in `0..2^64`; nothing wraps or underflows.
pub fn rebuild_counter(expected: u64, low: u64, bits: u32) -> u64 {
    debug_assert!(bits == 16 || bits == 32);
    let range: i128 = 1i128 << bits;
    let low = i128::from(low) & (range - 1);
    let base = i128::from(expected) & !(range - 1);
    let candidate = base + low;
    let mut best = candidate;
    let mut best_dist = (candidate - i128::from(expected)).abs();
    for c in [candidate - range, candidate + range] {
        if !(0..=i128::from(u64::MAX)).contains(&c) {
            continue;
        }
        let d = (c - i128::from(expected)).abs();
        if d < best_dist || (d == best_dist && c > best) {
            best = c;
            best_dist = d;
        }
    }
    best as u64
}

/// RFC 6479 sliding window. Check first with [`ReplayWindow::is_too_old`],
/// verify the packet's tag, and only then call [`ReplayWindow::mark`], so a
/// forged packet can never move the window.
#[derive(Clone, PartialEq, Eq)]
pub struct ReplayWindow {
    any: bool,
    highest: u64,
    bits: [u64; WORDS],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ReplayWindow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplayWindow")
            .field("highest", &self.highest)
            .finish_non_exhaustive()
    }
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            any: false,
            highest: 0,
            bits: [0; WORDS],
        }
    }

    /// The counter the next new packet is most likely to carry.
    pub fn expected(&self) -> u64 {
        if self.any {
            self.highest.saturating_add(1)
        } else {
            0
        }
    }

    /// The highest counter that passed `mark`, if any.
    pub fn highest(&self) -> Option<u64> {
        self.any.then_some(self.highest)
    }

    /// Older than the window: cannot tell if it is a replay, so refuse.
    pub fn is_too_old(&self, counter: u64) -> bool {
        self.any && counter.saturating_add(WINDOW_SIZE) <= self.highest
    }

    /// Record `counter` as seen. Returns `false` if it was already seen (a
    /// replay) or is too old; the window is unchanged then.
    pub fn mark(&mut self, counter: u64) -> bool {
        if self.is_too_old(counter) {
            return false;
        }
        if !self.any {
            self.any = true;
            self.highest = counter;
            self.bits = [0; WORDS];
        } else if counter > self.highest {
            let cur = self.highest >> 6;
            let new = counter >> 6;
            let steps = (new - cur).min(WORDS as u64);
            for i in 1..=steps {
                self.bits[((cur + i) as usize) & (WORDS - 1)] = 0;
            }
            self.highest = counter;
        }
        let word = ((counter >> 6) as usize) & (WORDS - 1);
        let bit = 1u64 << (counter & 63);
        if self.bits[word] & bit != 0 {
            return false;
        }
        self.bits[word] |= bit;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn rebuild_follows_the_next_expected_counter() {
        // In order, 2 bytes, across the wrap of the low 16 bits.
        for expected in [0u64, 1, 65_534, 65_535, 65_536, 65_537, 131_071, 131_072] {
            assert_eq!(rebuild_counter(expected, expected & 0xFFFF, 16), expected);
        }
        // Wrap: expecting 65_535, a small low value means the next range.
        assert_eq!(rebuild_counter(65_535, 0, 16), 65_536);
        assert_eq!(rebuild_counter(65_535, 3, 16), 65_539);
        // Reordered just behind the wrap: low bits near the top mean the old range.
        assert_eq!(rebuild_counter(65_540, 0xFFFE, 16), 65_534);
        assert_eq!(rebuild_counter(70_000, 0xFFFF, 16), 65_535);
    }

    #[test]
    fn rebuild_near_zero_never_underflows() {
        assert_eq!(rebuild_counter(0, 0, 16), 0);
        assert_eq!(rebuild_counter(0, 1, 16), 1);
        // Low value that would be "previous range" only if negative: stay forward.
        assert_eq!(rebuild_counter(5, 0xFFFF, 16), 0xFFFF);
        assert_eq!(rebuild_counter(5, 0xFFFF_FFFF, 32), 0xFFFF_FFFF);
        assert_eq!(rebuild_counter(3, 2, 16), 2);
    }

    #[test]
    fn rebuild_with_large_gaps_picks_the_closest() {
        // 30,000 ahead is still read as ahead; 40,000 ahead reads as behind (previous range).
        let e = 100_000u64;
        assert_eq!(rebuild_counter(e, (e + 30_000) & 0xFFFF, 16), e + 30_000);
        assert_eq!(rebuild_counter(e, (e - 30_000) & 0xFFFF, 16), e - 30_000);
        // The documented limit: 32,768 or more away is ambiguous and wraps.
        let far = rebuild_counter(e, (e + 40_000) & 0xFFFF, 16);
        assert_eq!(far, e + 40_000 - 65_536);
        // Exactly half a range: the higher one wins.
        assert_eq!(rebuild_counter(65_536, 0x8000, 16), 65_536 + 0x8000);
    }

    #[test]
    fn rebuild_never_overflows_at_the_top() {
        for bits in [16u32, 32] {
            let range = 1u64 << bits;
            for expected in [
                u64::MAX,
                u64::MAX - 1,
                u64::MAX - range,
                1 << 60,
                (1 << 60) + 7,
            ] {
                for low in [0u64, 1, range / 2, range - 1] {
                    let got = rebuild_counter(expected, low, bits);
                    assert_eq!(got & (range - 1), low, "low bits kept");
                    if expected <= 1 << 61 {
                        let dist = (i128::from(got) - i128::from(expected)).abs();
                        assert!(dist <= i128::from(range / 2));
                    }
                }
            }
        }
        // Expected counter at the very top, low bits that point past it: stay in range.
        assert_eq!(rebuild_counter(u64::MAX, 0, 16), u64::MAX - 0xFFFF);
        assert_eq!(rebuild_counter(u64::MAX, 0xFFFF, 32), 0xFFFF_FFFF_0000_FFFF);
    }

    #[test]
    fn rebuild_matches_a_brute_force_search() {
        let mut x = 99u64;
        let mut next = move || {
            x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = x;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };
        for _ in 0..5000 {
            let bits = if next() & 1 == 0 { 16 } else { 32 };
            let range = 1i128 << bits;
            let expected = next() >> (next() % 64);
            let low = next() & ((range as u64) - 1);
            let got = rebuild_counter(expected, low, bits);
            // Brute force: all values with those low bits near expected.
            let mut best: Option<(i128, u64)> = None;
            let k0 = (i128::from(expected) / range) - 2;
            for k in k0..k0 + 5 {
                let v = k * range + i128::from(low);
                if !(0..=i128::from(u64::MAX)).contains(&v) {
                    continue;
                }
                let d = (v - i128::from(expected)).abs();
                if best.is_none_or(|(bd, bv)| d < bd || (d == bd && v as u64 > bv)) {
                    best = Some((d, v as u64));
                }
            }
            assert_eq!(
                got,
                best.unwrap().1,
                "expected {expected} low {low} bits {bits}"
            );
        }
    }

    #[test]
    fn window_accepts_once_and_refuses_replays() {
        let mut w = ReplayWindow::new();
        assert_eq!(w.expected(), 0);
        assert!(w.mark(0));
        assert!(!w.mark(0));
        assert!(w.mark(2));
        assert!(w.mark(1)); // reordered, still new
        assert!(!w.mark(1));
        assert!(!w.mark(2));
        assert_eq!(w.expected(), 3);
        assert_eq!(w.highest(), Some(2));
    }

    #[test]
    fn window_edges() {
        let mut w = ReplayWindow::new();
        assert!(w.mark(5000));
        // 1023 behind is inside, 1024 behind is too old.
        assert!(!w.is_too_old(5000 - 1023));
        assert!(w.is_too_old(5000 - 1024));
        assert!(w.mark(5000 - 1023));
        assert!(!w.mark(5000 - 1024));
        assert!(!w.mark(0));
        // A big jump forward clears everything older.
        assert!(w.mark(1_000_000));
        assert!(w.is_too_old(5000));
        assert!(w.mark(1_000_000 - 500));
        assert!(!w.mark(1_000_000 - 500));
    }

    #[test]
    fn window_first_packet_may_be_anything() {
        let mut w = ReplayWindow::new();
        assert!(!w.is_too_old(0));
        assert!(w.mark(777_777));
        assert!(!w.mark(777_777));
    }

    #[test]
    fn window_matches_a_simple_model() {
        // Model: a counter is accepted iff it was never accepted and is not
        // 1024 or more below the highest accepted.
        let mut x = 7u64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for round in 0..30 {
            let mut w = ReplayWindow::new();
            let mut seen = HashSet::new();
            let mut highest: Option<u64> = None;
            let mut base = 0u64;
            for _ in 0..4000 {
                // Mostly near the front, sometimes far back, sometimes a big jump.
                let r = next() % 100;
                let c = if r < 70 {
                    base + next() % 40
                } else if r < 95 {
                    base.saturating_sub(next() % 2000)
                } else {
                    base += next() % (3000 * (1 + round));
                    base
                };
                let too_old = highest.is_some_and(|h| c + WINDOW_SIZE <= h);
                let want = !too_old && !seen.contains(&c);
                assert_eq!(w.is_too_old(c), too_old);
                assert_eq!(w.mark(c), want, "counter {c}");
                if want {
                    seen.insert(c);
                    highest = Some(highest.map_or(c, |h| h.max(c)));
                    base = base.max(c.saturating_sub(10));
                }
            }
        }
    }

    #[test]
    fn window_near_the_top_of_the_range() {
        let mut w = ReplayWindow::new();
        let top = (1u64 << 60) + 5;
        assert!(w.mark(top));
        assert!(w.mark(top - 1));
        assert!(!w.mark(top - 1));
        assert_eq!(w.expected(), top + 1);
        let mut w = ReplayWindow::new();
        assert!(w.mark(u64::MAX));
        assert_eq!(w.expected(), u64::MAX);
        assert!(!w.mark(u64::MAX));
    }
}
