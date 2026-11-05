//! Link timers that scale with a radio's airtime (spec section 5).
//!
//! The fixed defaults of [`Config`] suit a fast link. On a slow half-duplex
//! radio the handshake itself can take longer than the first retry, so the
//! retry goes out before the answer can arrive. [`Config::for_airtime`] derives
//! the timers from one number, the handshake round trip, and
//! [`RadioProfile`] names the radios the OASA test lab simulates.
//!
//! None of this touches the wire format or the crypto.

use std::time::Duration;

use super::{Config, Entropy};

/// Far above any radio; only stops overflow.
const MAX_ROUND_TRIP: Duration = Duration::from_secs(86_400);

/// `d` plus or minus up to 20%, from `rng`. Spreads handshake and control
/// retries so they do not phase-lock with periodic traffic on a half-duplex
/// radio (WireGuard does the same). Stays above 0.8 x `d`, and the retry
/// derived from the round trip has 1.5 x R + 2 s of headroom, so a jittered
/// retry is still longer than R. The randomness is passed in (sans-IO).
pub fn jittered(d: Duration, rng: &mut dyn Entropy) -> Duration {
    let mut b = [0u8; 2];
    rng.fill(&mut b);
    let permille = 800 + u128::from(u16::from_be_bytes(b)) % 401;
    let nanos = d.as_nanos().saturating_mul(permille) / 1000;
    Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
}

/// Airtime of a LoRa packet at 125 kHz, CR 4/5, 8 symbol preamble, explicit
/// header, CRC on, low data rate optimize when a symbol is over 16 ms: the
/// Semtech SX126x formula, as in the lab's `oasa_lab/airtime.py`. For tests.
#[cfg(test)]
pub(crate) fn lora_airtime(nbytes: usize, sf: u32) -> Duration {
    let bw = 125_000u64;
    let ldro = (1u64 << sf) * 1000 / bw > 16;
    let num = (8 * nbytes as i64 + 16 - 4 * sf as i64 + 20).max(0) as u64;
    let (num, den) = if sf <= 6 {
        (num, 4 * u64::from(sf))
    } else {
        (num + 8, 4 * u64::from(if ldro { sf - 2 } else { sf }))
    };
    let symbols = num.div_ceil(den) * 5 + 8 + 12 + if sf <= 6 { 2 } else { 0 };
    Duration::from_nanos((4 * symbols + 1) * (1u64 << (sf - 2)) * 1_000_000_000 / bw)
}

/// Keepalives are off when the handshake round trip is longer than this: a
/// keepalive costs airtime on a slow radio and the stale rule needs none.
const KEEPALIVE_OFF_ABOVE: Duration = Duration::from_secs(2);

/// A radio the OASA test lab can simulate. The names are the lab's profile
/// names (`oasa_lab/profiles.py`), and `oasa-link --radio-profile` takes them.
///
/// The round trips are the on-air time of a 119 byte handshake 1 plus a 55
/// byte handshake 2, computed with the lab's airtime model
/// (`oasa_lab/airtime.py`; LoRa is the Semtech SX126x formula, CR 4/5,
/// 8 symbol preamble, explicit header, CRC on, 125 kHz, low data rate optimize
/// when a symbol is over 16 ms) and rounded up to a whole millisecond. They
/// are airtime only: queueing and the radio's own turnaround come on top,
/// which the margin in [`Config::for_airtime`] covers. See the lab's
/// `docs/profiles.md` for where each radio setting comes from, and the tests
/// in this module for the numbers.
///
/// `sik-64k-ecc` has a 118 byte MTU, below the 119 byte handshake 1, so on
/// that radio a handshake spans two frames and its number is an
/// underestimate (still far under the 5 s retry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RadioProfile {
    LoraSf7Bw125,
    LoraSf9Bw125,
    LoraSf12Bw125,
    Sik64k,
    Sik64kEcc,
    Mlrs19Hz,
    Mlrs31Hz,
    Mlrs50Hz,
    WifiWfb,
}

impl RadioProfile {
    pub const ALL: [RadioProfile; 9] = [
        RadioProfile::LoraSf7Bw125,
        RadioProfile::LoraSf9Bw125,
        RadioProfile::LoraSf12Bw125,
        RadioProfile::Sik64k,
        RadioProfile::Sik64kEcc,
        RadioProfile::Mlrs19Hz,
        RadioProfile::Mlrs31Hz,
        RadioProfile::Mlrs50Hz,
        RadioProfile::WifiWfb,
    ];

    /// The lab's name for this profile.
    pub fn name(self) -> &'static str {
        match self {
            RadioProfile::LoraSf7Bw125 => "lora-sf7-bw125",
            RadioProfile::LoraSf9Bw125 => "lora-sf9-bw125",
            RadioProfile::LoraSf12Bw125 => "lora-sf12-bw125",
            RadioProfile::Sik64k => "sik-64k",
            RadioProfile::Sik64kEcc => "sik-64k-ecc",
            RadioProfile::Mlrs19Hz => "mlrs-19hz",
            RadioProfile::Mlrs31Hz => "mlrs-31hz",
            RadioProfile::Mlrs50Hz => "mlrs-50hz",
            RadioProfile::WifiWfb => "wifi-wfb",
        }
    }

    /// Look a profile up by the lab's name.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.name() == name)
    }

    /// Airtime of handshake 1 plus handshake 2, in milliseconds (rounded up).
    /// Computed from the lab model for [`HANDSHAKE1_LEN`](super::HANDSHAKE1_LEN) (119) and [`HANDSHAKE2_LEN`](super::HANDSHAKE2_LEN) (55) bytes.
    fn handshake_round_trip_ms(self) -> u64 {
        match self {
            RadioProfile::LoraSf7Bw125 => 308,
            RadioProfile::LoraSf9Bw125 => 986,
            RadioProfile::LoraSf12Bw125 => 7_062,
            RadioProfile::Sik64k => 26,
            RadioProfile::Sik64kEcc => 50,
            RadioProfile::Mlrs19Hz => 159,
            RadioProfile::Mlrs31Hz => 96,
            RadioProfile::Mlrs50Hz => 60,
            RadioProfile::WifiWfb => 1,
        }
    }

    /// Airtime of one handshake round trip on this radio.
    pub fn handshake_round_trip(self) -> Duration {
        Duration::from_millis(self.handshake_round_trip_ms())
    }

    /// The link settings for this radio: [`Config::for_airtime`] of its round trip.
    pub fn config(self) -> Config {
        Config::for_airtime(self.handshake_round_trip())
    }
}

impl Config {
    /// Settings for a radio whose handshake takes `handshake_round_trip` on
    /// the air (handshake 1 out plus handshake 2 back, 174 bytes). Anything
    /// that is already fine for that radio keeps its default, so a fast link
    /// gets exactly [`Config::default`].
    ///
    /// - `retry_initial` = 1.5 x round trip + 2 s, at least 5 s. The answer
    ///   must be able to arrive before the retry goes out.
    /// - `retry_max` = at least 4 x `retry_initial`, at least 60 s.
    /// - `stale_after` = at least 4 x `retry_initial`, at least 30 s. A side
    ///   answers payload with a keepalive after half of it, and that answer
    ///   needs time on the air too.
    /// - `previous_grace` = at least 2 x round trip, at least 10 s: packets
    ///   of the old session may still be in the air or queued.
    /// - `peer_handshake_gap` = at least half the round trip, at least 1 s,
    ///   never above 4 s: each accepted handshake costs a reply on the air.
    ///   The gap limits the *peer's* retries, which we cannot know, so it is
    ///   capped at 4 s, the shortest jittered default retry (5 s less 20%): a
    ///   peer on default timers or slower is never rate limited by it.
    /// - `keepalive` is off when the round trip is over 2 s (the spec's "off
    ///   by default on slow radios"); the stale rule still heals a dead session.
    /// - Left alone: `handshakes_per_second` (a slow radio never reaches it),
    ///   `rekey_after` and `reject_after` (set per radio by the operator; the
    ///   margin between them is checked by [`Config::validate`]).
    ///
    /// The round trip is clamped to a day so the arithmetic cannot overflow;
    /// the retry is always longer than the round trip.
    pub fn for_airtime(handshake_round_trip: Duration) -> Self {
        // A day is far above any radio; the clamp only stops overflow, and it
        // is higher than the retry cap below so the retry always exceeds R.
        let rtt = handshake_round_trip.min(MAX_ROUND_TRIP);
        let base = Self::default();
        let base_retry = base.retry_initial;
        let c = Self {
            previous_grace: base.previous_grace.max(rtt * 2),
            peer_handshake_gap: base
                .peer_handshake_gap
                .max(rtt / 2)
                .min(Duration::from_secs(4)),
            keepalive: if rtt > KEEPALIVE_OFF_ABOVE {
                None
            } else {
                base.keepalive
            },
            ..base
        };
        c.with_retry((rtt.mul_f64(1.5) + Duration::from_secs(2)).max(base_retry))
    }

    /// Set the first handshake retry delay and raise the timers that depend
    /// on it: `retry_max` and `stale_after` to at least 4 x `retry`. Never
    /// lowers `retry_max` or `stale_after`.
    pub fn with_retry(mut self, retry: Duration) -> Self {
        let retry = retry.min(MAX_ROUND_TRIP * 2);
        self.retry_initial = retry;
        let four = retry * 4;
        self.retry_max = self.retry_max.max(four);
        self.stale_after = self.stale_after.max(four);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fast_radio_keeps_the_defaults() {
        let d = Config::default();
        for p in [
            RadioProfile::LoraSf7Bw125,
            RadioProfile::Sik64k,
            RadioProfile::WifiWfb,
            RadioProfile::Mlrs19Hz,
        ] {
            let c = p.config();
            assert_eq!(c.retry_initial, Duration::from_secs(5), "{}", p.name());
            assert_eq!(c.retry_max, d.retry_max);
            assert_eq!(c.stale_after, d.stale_after);
            assert_eq!(c.previous_grace, d.previous_grace);
            assert_eq!(c.peer_handshake_gap, d.peer_handshake_gap);
            assert_eq!(c.keepalive, d.keepalive);
            c.validate().unwrap();
        }
    }

    #[test]
    fn sf12_gets_a_retry_above_its_round_trip() {
        let p = RadioProfile::LoraSf12Bw125;
        let rtt = p.handshake_round_trip();
        let c = p.config();
        assert!(rtt > Duration::from_secs(7));
        assert!(c.retry_initial > rtt * 3 / 2, "{:?}", c.retry_initial);
        assert!(c.retry_max >= c.retry_initial * 4);
        assert!(c.stale_after >= c.retry_initial * 4);
        assert!(c.stale_after / 2 > rtt, "the ack at half of stale must fit");
        assert!(c.previous_grace >= rtt * 2);
        assert!(c.peer_handshake_gap >= rtt / 2);
        assert!(c.peer_handshake_gap <= Duration::from_secs(4));
        assert_eq!(c.keepalive, None);
        c.validate().unwrap();
    }

    #[test]
    fn sf9_round_trip_is_under_two_seconds_so_keepalive_stays() {
        let c = RadioProfile::LoraSf9Bw125.config();
        assert!(c.keepalive.is_some());
        c.validate().unwrap();
    }

    #[test]
    fn profile_names_round_trip_and_unknown_is_refused() {
        for p in RadioProfile::ALL {
            assert_eq!(RadioProfile::from_name(p.name()), Some(p));
            p.config().validate().unwrap();
        }
        assert_eq!(RadioProfile::from_name("ideal"), None);
        assert_eq!(RadioProfile::from_name("LORA-SF12-BW125"), None);
    }

    #[test]
    fn extreme_round_trips_do_not_panic() {
        for d in [Duration::ZERO, Duration::MAX, Duration::from_secs(u64::MAX)] {
            let _ = Config::for_airtime(d).validate();
        }
        // A minute-long round trip still works with the default rekey times;
        // an hour does not (the rekey margin is too short), and validate says so.
        Config::for_airtime(Duration::from_secs(60))
            .validate()
            .unwrap();
        assert!(
            Config::for_airtime(Duration::from_secs(3600))
                .validate()
                .is_err()
        );
        let _ = Config::default().with_retry(Duration::MAX).validate();
    }

    #[test]
    fn with_retry_never_lowers_anything() {
        let c = Config::default().with_retry(Duration::from_secs(1));
        let d = Config::default();
        assert_eq!(c.retry_initial, Duration::from_secs(1));
        assert_eq!((c.retry_max, c.stale_after), (d.retry_max, d.stale_after));
        c.validate().unwrap();
    }
}
