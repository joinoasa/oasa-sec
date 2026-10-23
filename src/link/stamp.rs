//! The handshake 1 timestamp (spec section 2) and where it is saved.
//!
//! An initiator never sends the same or an older timestamp to a peer, even
//! after a reboot. A responder never accepts a handshake 1 that is not newer
//! than the newest it has accepted from that peer, even after a reboot. Both
//! numbers are saved before they are used.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::files::{read_private_file, write_private_file};
use crate::identity::fingerprint;
use crate::{Error, Result};

/// Seconds and nanoseconds, compared in that order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp {
    pub secs: u64,
    pub nanos: u32,
}

impl Timestamp {
    pub const LEN: usize = 12;

    pub fn from_duration(d: Duration) -> Self {
        Self {
            secs: d.as_secs(),
            nanos: d.subsec_nanos(),
        }
    }

    /// One nanosecond later.
    pub fn next(self) -> Self {
        if self.nanos >= 999_999_999 {
            Self {
                secs: self.secs.saturating_add(1),
                nanos: 0,
            }
        } else {
            Self {
                secs: self.secs,
                nanos: self.nanos + 1,
            }
        }
    }

    /// 8-byte seconds then 4-byte nanoseconds, big-endian.
    pub fn to_bytes(self) -> [u8; Self::LEN] {
        let mut b = [0u8; Self::LEN];
        b[..8].copy_from_slice(&self.secs.to_be_bytes());
        b[8..].copy_from_slice(&self.nanos.to_be_bytes());
        b
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        let b: &[u8; Self::LEN] = b.try_into().ok()?;
        Some(Self {
            secs: u64::from_be_bytes(b[..8].try_into().ok()?),
            nanos: u32::from_be_bytes(b[8..].try_into().ok()?),
        })
    }
}

/// What is saved for one peer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StoredStamps {
    /// The newest timestamp we sent to this peer.
    pub sent: Option<Timestamp>,
    /// The newest timestamp we accepted from this peer.
    pub seen: Option<Timestamp>,
}

/// Where a link keeps its timestamps. `save` must be durable before it
/// returns `Ok`; the link does not send or answer a handshake if it fails.
pub trait TimestampStore {
    fn load(&mut self) -> Result<StoredStamps>;
    fn save(&mut self, stamps: &StoredStamps) -> Result<()>;
}

/// Keeps timestamps in memory only. For tests and for devices that cannot
/// write files (they then accept a replayed handshake 1 after a reboot, until
/// a newer one arrives).
#[derive(Debug, Default)]
pub struct MemoryTimestampStore {
    pub stamps: StoredStamps,
}

impl TimestampStore for MemoryTimestampStore {
    fn load(&mut self) -> Result<StoredStamps> {
        Ok(self.stamps)
    }
    fn save(&mut self, stamps: &StoredStamps) -> Result<()> {
        self.stamps = *stamps;
        Ok(())
    }
}

/// Saves timestamps in an owner-only file `link-timestamp-<fingerprint>` in
/// the device directory: 24 bytes, `sent` then `seen`, all zero for "none".
#[derive(Debug)]
pub struct FileTimestampStore {
    path: PathBuf,
}

impl FileTimestampStore {
    pub fn new(dir: &Path, peer_public: &[u8; 32]) -> Self {
        Self {
            path: dir.join(format!("link-timestamp-{}", fingerprint(peer_public))),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Forget the saved timestamps (`sent`, `seen` or both) and return what
    /// was there. For the case where a peer's clock was set far into the
    /// future and its timestamp got saved: nothing newer is accepted from it
    /// until then. Forgetting `seen` makes us accept an old recorded
    /// handshake 1 from this peer once more, until a newer one arrives.
    pub fn reset(&mut self, sent: bool, seen: bool) -> Result<StoredStamps> {
        let old = self.load()?;
        let mut next = old;
        if sent {
            next.sent = None;
        }
        if seen {
            next.seen = None;
        }
        self.save(&next)?;
        Ok(old)
    }
}

impl TimestampStore for FileTimestampStore {
    fn load(&mut self) -> Result<StoredStamps> {
        if std::fs::symlink_metadata(&self.path).is_err() {
            return Ok(StoredStamps::default());
        }
        let bytes = read_private_file(&self.path)?;
        if bytes.len() != 2 * Timestamp::LEN {
            return Err(Error::BadKeyFile(format!(
                "{} is not a timestamp file",
                self.path.display()
            )));
        }
        let get = |b: &[u8]| {
            if b.iter().all(|x| *x == 0) {
                None
            } else {
                Timestamp::from_bytes(b)
            }
        };
        Ok(StoredStamps {
            sent: get(&bytes[..Timestamp::LEN]),
            seen: get(&bytes[Timestamp::LEN..]),
        })
    }

    fn save(&mut self, stamps: &StoredStamps) -> Result<()> {
        let mut b = [0u8; 2 * Timestamp::LEN];
        if let Some(t) = stamps.sent {
            b[..Timestamp::LEN].copy_from_slice(&t.to_bytes());
        }
        if let Some(t) = stamps.seen {
            b[Timestamp::LEN..].copy_from_slice(&t.to_bytes());
        }
        write_private_file(&self.path, &b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_round_trip_and_order() {
        let t = Timestamp {
            secs: 0x0102_0304_0506_0708,
            nanos: 0x0A0B_0C0D,
        };
        assert_eq!(
            t.to_bytes(),
            [1, 2, 3, 4, 5, 6, 7, 8, 0x0A, 0x0B, 0x0C, 0x0D]
        );
        assert_eq!(Timestamp::from_bytes(&t.to_bytes()), Some(t));
        assert_eq!(Timestamp::from_bytes(&[0; 11]), None);
        assert!(
            Timestamp {
                secs: 1,
                nanos: 999_999_999
            } < Timestamp { secs: 2, nanos: 0 }
        );
        assert!(t.next() > t);
        assert_eq!(
            Timestamp {
                secs: 1,
                nanos: 999_999_999
            }
            .next(),
            Timestamp { secs: 2, nanos: 0 }
        );
    }

    #[test]
    fn reset_forgets_only_what_was_asked() {
        let dir = crate::files::tempdir("stamp-reset");
        let mut s = FileTimestampStore::new(&dir, &[4u8; 32]);
        let st = StoredStamps {
            sent: Some(Timestamp { secs: 10, nanos: 5 }),
            seen: Some(Timestamp { secs: 99, nanos: 1 }),
        };
        s.save(&st).unwrap();
        assert_eq!(s.reset(false, true).unwrap(), st);
        let now = s.load().unwrap();
        assert_eq!((now.sent, now.seen), (st.sent, None));
        s.reset(true, false).unwrap();
        assert_eq!(s.load().unwrap(), StoredStamps::default());
    }

    #[test]
    fn file_store_round_trip_is_private() {
        let dir = crate::files::tempdir("stamp");
        let mut s = FileTimestampStore::new(&dir, &[3u8; 32]);
        assert_eq!(s.load().unwrap(), StoredStamps::default());
        let st = StoredStamps {
            sent: Some(Timestamp { secs: 10, nanos: 5 }),
            seen: None,
        };
        s.save(&st).unwrap();
        assert_eq!(
            FileTimestampStore::new(&dir, &[3u8; 32]).load().unwrap(),
            st
        );
        // Another peer has its own file.
        assert_eq!(
            FileTimestampStore::new(&dir, &[4u8; 32]).load().unwrap(),
            StoredStamps::default()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(s.path()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::write(s.path(), b"short").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(s.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(FileTimestampStore::new(&dir, &[3u8; 32]).load().is_err());
    }
}
