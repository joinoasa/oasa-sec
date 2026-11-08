//! The handshake 1 timestamp (spec section 2) and where it is saved.
//!
//! An initiator never sends the same or an older timestamp to a peer, even
//! after a reboot. A responder never accepts a handshake 1 that is not newer
//! than the newest it has accepted from that peer, even after a reboot. Both
//! numbers are saved before they are used.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::rc::Rc;
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

/// Where a link keeps its timestamps. A handshake packet must never leave
/// the device before the timestamps saved for it are durable. The simple way
/// is for `save` to be durable before it returns `Ok` (as
/// [`FileTimestampStore`]); the link does not send or answer a handshake if
/// it fails. A store may instead return `Ok` at once and finish the write
/// elsewhere, but only together with a gate that holds back every handshake
/// packet until the write is durable and drops it if the write fails: that
/// is [`DeferredStore`] with its [`StampGate`].
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

/// What a [`DeferredStore`] and its [`StampGate`] share.
#[derive(Debug, Default)]
struct DeferredState {
    /// The newest timestamps the link saved, and their write number.
    latest: StoredStamps,
    requested: u64,
    /// The newest write number handed out by [`StampGate::take_write`].
    taken: u64,
    /// The newest write number known to be durable.
    durable: u64,
}

/// A [`TimestampStore`] that does not wait for the disk: `save` only records
/// what to write and returns. The caller writes it somewhere else (another
/// thread), and the matching [`StampGate`] holds back every handshake packet
/// until that write is durable. Data packets never wait, so a slow disk
/// (two `fsync`s per handshake, tens of milliseconds on flash) delays only
/// the handshake, never the traffic on the current session.
///
/// The rule of spec section 2 is unchanged: a handshake 1 never leaves
/// before its timestamp is saved, and a handshake 2 never leaves before the
/// timestamp of the handshake 1 it answers is saved. If the write fails, the
/// packets waiting for it are dropped (the initiator's retry timer starts a
/// new handshake, as after any lost packet).
///
/// Sans-IO like the rest of the link: no thread or file inside.
#[derive(Debug)]
pub struct DeferredStore {
    shared: Rc<RefCell<DeferredState>>,
}

impl TimestampStore for DeferredStore {
    fn load(&mut self) -> Result<StoredStamps> {
        Ok(self.shared.borrow().latest)
    }

    fn save(&mut self, stamps: &StoredStamps) -> Result<()> {
        let mut s = self.shared.borrow_mut();
        s.latest = *stamps;
        s.requested += 1;
        Ok(())
    }
}

/// Holds handshake packets until the timestamps they depend on are durable.
/// `A` is where a packet goes (the caller's address type). See
/// [`DeferredStore`].
#[derive(Debug)]
pub struct StampGate<A> {
    shared: Rc<RefCell<DeferredState>>,
    /// Write number each packet waits for, oldest first.
    held: VecDeque<(u64, Vec<u8>, A)>,
}

/// At most this many handshake packets wait for the disk; beyond it the
/// oldest is dropped (handshakes are rate limited, so a working disk never
/// gets near it).
pub const MAX_HELD_HANDSHAKES: usize = 16;

/// What [`StampGate::pass`] decided.
#[derive(Debug, PartialEq, Eq)]
pub enum Pass<A> {
    /// Send it now.
    Send(Vec<u8>, A),
    /// Held until the disk has the timestamps.
    Held,
    /// Held, and the gate was full: this, the oldest held packet, is dropped.
    HeldDroppedOldest(Vec<u8>, A),
}

/// What [`StampGate::written`] did with the packets that were waiting.
#[derive(Debug)]
pub struct Released<A> {
    /// May be sent now, in order.
    pub send: Vec<(Vec<u8>, A)>,
    /// Dropped because the write failed (never sent), in order.
    pub dropped: Vec<(Vec<u8>, A)>,
}

impl<A> StampGate<A> {
    /// A store for the link and its gate. `loaded` is what is on disk now
    /// (read it with the real store, for example [`FileTimestampStore`]).
    pub fn new(loaded: StoredStamps) -> (DeferredStore, StampGate<A>) {
        let shared = Rc::new(RefCell::new(DeferredState {
            latest: loaded,
            ..DeferredState::default()
        }));
        (
            DeferredStore {
                shared: Rc::clone(&shared),
            },
            StampGate {
                shared,
                held: VecDeque::new(),
            },
        )
    }

    /// The newest timestamps to write, with their write number, if the link
    /// saved anything since the last call. Writing only the newest is
    /// enough: both timestamps only ever go up, so it covers every earlier
    /// save.
    pub fn take_write(&mut self) -> Option<(u64, StoredStamps)> {
        let mut s = self.shared.borrow_mut();
        (s.requested > s.taken).then(|| {
            s.taken = s.requested;
            (s.requested, s.latest)
        })
    }

    /// A packet the link wants sent (call it for every `Event::Send`, in
    /// order). Data packets, and any packet while every save is durable, may
    /// go now. A handshake packet made after a save that is not durable yet
    /// is held until [`StampGate::written`] releases it.
    pub fn pass(&mut self, packet: Vec<u8>, to: A) -> Pass<A> {
        let s = self.shared.borrow();
        if super::packet::is_data(&packet) || s.durable >= s.requested {
            return Pass::Send(packet, to);
        }
        let need = s.requested;
        drop(s);
        self.held.push_back((need, packet, to));
        if self.held.len() > MAX_HELD_HANDSHAKES {
            let (_, p, a) = self.held.pop_front().expect("over the limit, so not empty");
            return Pass::HeldDroppedOldest(p, a);
        }
        Pass::Held
    }

    /// The write with number `seq` finished: durable (`ok`) or failed.
    /// Releases what may go now; a failure drops what was waiting for it.
    pub fn written(&mut self, seq: u64, ok: bool) -> Released<A> {
        let mut out = Released {
            send: Vec::new(),
            dropped: Vec::new(),
        };
        let durable = {
            let mut s = self.shared.borrow_mut();
            if ok {
                s.durable = s.durable.max(seq);
            }
            s.durable
        };
        while let Some((need, ..)) = self.held.front() {
            if *need <= durable {
                let (_, p, a) = self.held.pop_front().expect("peeked");
                out.send.push((p, a));
            } else if !ok && *need <= seq {
                let (_, p, a) = self.held.pop_front().expect("peeked");
                out.dropped.push((p, a));
            } else {
                break;
            }
        }
        out
    }

    /// Handshake packets waiting for the disk.
    pub fn held(&self) -> usize {
        self.held.len()
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

    fn ts(secs: u64) -> Option<Timestamp> {
        Some(Timestamp { secs, nanos: 0 })
    }

    const HS1: [u8; 1] = [(1 << 4) | super::super::packet::VERSION];
    const HS2: [u8; 1] = [(2 << 4) | super::super::packet::VERSION];

    fn data() -> Vec<u8> {
        super::super::packet::data_header(7, super::super::packet::CounterLen::Short, 0)
    }

    /// Where the packet goes, if it may go now; `None` if it was held.
    fn now_to<A: std::fmt::Debug>(p: Pass<A>) -> Option<A> {
        match p {
            Pass::Send(_, a) => Some(a),
            Pass::Held => None,
            Pass::HeldDroppedOldest(..) => panic!("unexpected drop: {p:?}"),
        }
    }

    fn released<A>(r: Released<A>) -> (Vec<A>, usize) {
        (
            r.send.into_iter().map(|(_, a)| a).collect(),
            r.dropped.len(),
        )
    }

    #[test]
    fn deferred_store_holds_handshakes_until_the_write_is_durable() {
        let on_disk = StoredStamps {
            sent: ts(5),
            seen: ts(6),
        };
        let (mut store, mut gate) = StampGate::<&str>::new(on_disk);
        assert_eq!(store.load().unwrap(), on_disk);
        // Nothing saved yet: handshakes and data go at once.
        assert_eq!(gate.take_write(), None);
        assert_eq!(now_to(gate.pass(HS1.to_vec(), "early")), Some("early"));
        // The link saves, then makes handshake 1: it waits, data does not.
        let next = StoredStamps {
            sent: ts(10),
            seen: ts(6),
        };
        store.save(&next).unwrap();
        assert_eq!(store.load().unwrap(), next);
        assert_eq!(now_to(gate.pass(HS1.to_vec(), "hs1")), None);
        let d = data();
        assert_eq!(gate.pass(d.clone(), "data"), Pass::Send(d, "data"));
        assert_eq!(gate.held(), 1);
        let (seq, what) = gate.take_write().unwrap();
        assert_eq!(what, next);
        assert_eq!(gate.take_write(), None, "each write is handed out once");
        // A second save before the first is written: only the newest is
        // written, and it covers both.
        let newer = StoredStamps {
            sent: ts(10),
            seen: ts(20),
        };
        store.save(&newer).unwrap();
        assert_eq!(now_to(gate.pass(HS2.to_vec(), "hs2")), None);
        assert_eq!(gate.take_write(), Some((seq + 1, newer)));
        // The first write lands: only what waited for it goes, bytes intact.
        let r = gate.written(seq, true);
        assert_eq!(r.send, vec![(HS1.to_vec(), "hs1")]);
        assert_eq!(
            now_to(gate.pass(HS1.to_vec(), "hs1b")),
            None,
            "waits for the second"
        );
        assert_eq!(
            released(gate.written(seq + 1, true)),
            (vec!["hs2", "hs1b"], 0)
        );
        assert_eq!(gate.held(), 0);
        assert_eq!(now_to(gate.pass(HS1.to_vec(), "after")), Some("after"));
    }

    #[test]
    fn a_failed_write_drops_the_handshakes_that_waited_for_it() {
        let (mut store, mut gate) = StampGate::<u32>::new(StoredStamps::default());
        let st = |s| StoredStamps {
            sent: ts(s),
            seen: None,
        };
        store.save(&st(1)).unwrap();
        assert_eq!(now_to(gate.pass(HS1.to_vec(), 1)), None);
        let (seq, _) = gate.take_write().unwrap();
        store.save(&st(2)).unwrap();
        assert_eq!(now_to(gate.pass(HS1.to_vec(), 2)), None);
        assert_eq!(
            released(gate.written(seq, false)),
            (vec![], 1),
            "only the one that needed it"
        );
        // Still not durable: a handshake now must still wait.
        assert_eq!(now_to(gate.pass(HS2.to_vec(), 3)), None);
        let (seq2, _) = gate.take_write().unwrap();
        assert_eq!(released(gate.written(seq2, true)), (vec![2, 3], 0));
        // Anything that is not a data packet is treated as a handshake.
        store.save(&st(3)).unwrap();
        assert_eq!(now_to(gate.pass(Vec::new(), 4)), None);
        assert_eq!(now_to(gate.pass(vec![0xFF], 5)), None);
    }

    #[test]
    fn the_gate_is_bounded() {
        let (mut store, mut gate) = StampGate::<usize>::new(StoredStamps::default());
        store
            .save(&StoredStamps {
                sent: ts(1),
                seen: None,
            })
            .unwrap();
        for i in 0..MAX_HELD_HANDSHAKES {
            assert_eq!(now_to(gate.pass(HS1.to_vec(), i)), None);
        }
        assert_eq!(
            gate.pass(HS1.to_vec(), 99),
            Pass::HeldDroppedOldest(HS1.to_vec(), 0)
        );
        assert_eq!(gate.held(), MAX_HELD_HANDSHAKES);
    }
}
