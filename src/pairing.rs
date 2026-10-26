//! Encrypted pairing between a ground station and a drone.
//!
//! The drone (Noise responder) shows a one-time [`PairingCode`]. The ground
//! station (Noise initiator) reads it and runs `Noise_IKpsk1`:
//!
//! 1. Ground → drone: ephemeral key, ground's identity (encrypted), hello.
//!    The drone checks the code's secret here and stays silent if it's wrong.
//! 2. Drone → ground: ephemeral key, hello. Handshake done.
//! 3. Drone → ground (encrypted): either the autopilot's current signing key,
//!    if the drone already has one, or "need a key".
//! 4. If the drone needs one, ground → drone (encrypted): a fresh key. The
//!    drone loads it into its autopilot and checks it works.
//! 5. The side that received the key confirms (or the drone reports failure).
//!
//! The ground station knows it reached the right drone because only that
//! drone holds the private key matching the code. The drone knows the ground
//! station saw the code because only the code holds the one-time secret.
//! Nothing secret crosses the link in the clear.
//!
//! Every message is framed as a 2-byte big-endian length and then the bytes.
//! Each step has a size limit, and [`DeadlineStream`] bounds the total time.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::code::PairingCode;
use crate::identity::Identity;
use crate::signing::SigningKey;
use crate::store::{Peer, Role};
use crate::{Error, PAIRING_NOISE, PAIRING_PROLOGUE, Result};

/// Longest device name we accept.
pub const MAX_NAME: usize = 32;

// Upper bounds on each message, with room to spare. Anything bigger is an attack.
const MAX_MSG1: usize = 32 + 48 + (2 + MAX_NAME) + 16 + 32; // e, s, hello, tag, slack
const MAX_MSG2: usize = 32 + (2 + MAX_NAME) + 16 + 32;
const MAX_TRANSPORT: usize = 33 + 16 + 15;

const MSG_HELLO: u8 = 1;
const MSG_SIGNING_KEY: u8 = 2;
const MSG_CONFIRM: u8 = 3;
const MSG_NEED_KEY: u8 = 4;
const MSG_FAILED: u8 = 5;

/// What the ground station gets from pairing.
#[derive(Debug, Clone)]
pub struct GroundResult {
    pub drone: Peer,
    /// The key the drone's autopilot uses.
    pub signing_key: SigningKey,
    /// True if this pairing created the key; false if the drone already had one.
    pub new_key: bool,
}

/// What the drone gets from pairing.
#[derive(Debug)]
pub struct DroneResult {
    pub ground: Peer,
    pub signing_key: SigningKey,
    pub new_key: bool,
}

/// Ground station side. Pairs with the drone that made `code`. If the drone
/// has no signing key yet, `make_key` is called and the result sent to it.
pub fn pair_as_ground<S: Read + Write>(
    stream: &mut S,
    me: &Identity,
    my_name: &str,
    code: &PairingCode,
    make_key: impl FnOnce() -> Result<SigningKey>,
) -> Result<GroundResult> {
    check_name(my_name)?;
    let params = PAIRING_NOISE.parse().expect("valid Noise name");
    let mut hs = snow::Builder::new(params)
        .local_private_key(me.private_key())?
        .remote_public_key(&code.responder_public)?
        .psk(1, code.secret())?
        .prologue(PAIRING_PROLOGUE)?
        .build_initiator()?;

    let mut buf = Zeroizing::new(vec![0u8; 256]);
    let mut payload = Zeroizing::new(vec![0u8; 256]);

    let n = hs.write_message(&hello(my_name), &mut buf)?;
    write_frame(stream, &buf[..n])?;

    let msg = read_frame(stream, MAX_MSG2)?;
    let n = hs.read_message(&msg, &mut payload)?;
    let drone_name = parse_hello(&payload[..n])?;
    let mut t = hs.into_transport_mode()?;

    let msg = read_frame(stream, MAX_TRANSPORT)?;
    let n = t.read_message(&msg, &mut payload)?;
    let (signing_key, new_key) = match &payload[..n] {
        [MSG_SIGNING_KEY, key @ ..] if key.len() == 32 => {
            let k = SigningKey::from_bytes(key.try_into().expect("32 bytes"))?;
            let n = t.write_message(&[MSG_CONFIRM], &mut buf)?;
            write_frame(stream, &buf[..n])?;
            (k, false)
        }
        [MSG_NEED_KEY] => {
            let k = make_key()?;
            let mut m = Zeroizing::new([0u8; 33]);
            m[0] = MSG_SIGNING_KEY;
            m[1..].copy_from_slice(k.as_bytes());
            let n = t.write_message(&m[..], &mut buf)?;
            write_frame(stream, &buf[..n])?;
            let msg = read_frame(stream, MAX_TRANSPORT)?;
            let n = t.read_message(&msg, &mut payload)?;
            match &payload[..n] {
                [MSG_CONFIRM] => (k, true),
                [MSG_FAILED] => {
                    return Err(Error::Protocol(
                        "drone could not load the key into its autopilot",
                    ));
                }
                _ => return Err(Error::Protocol("bad reply from drone")),
            }
        }
        _ => return Err(Error::Protocol("bad key message from drone")),
    };

    Ok(GroundResult {
        // A ground station lists a drone as a plain peer (R-SEC2 section 1).
        drone: Peer {
            public: code.responder_public,
            name: drone_name,
            role: Role::Peer,
        },
        signing_key,
        new_key,
    })
}

/// Drone side. Waits for one ground station holding `code`.
///
/// `current_key` is the autopilot's key, if the drone already has one; it is
/// shared with the new ground station. Otherwise the ground station sends a
/// new key and `install` must load it into the autopilot and check it works
/// before the drone confirms. If `install` fails, pairing fails and the
/// ground station is told.
pub fn pair_as_drone<S: Read + Write>(
    stream: &mut S,
    me: &Identity,
    my_name: &str,
    code: &PairingCode,
    current_key: Option<&SigningKey>,
    install: impl FnOnce(&SigningKey) -> Result<()>,
) -> Result<DroneResult> {
    pair_as_drone_checked(stream, me, my_name, code, current_key, |_| Ok(()), install)
}

/// Like [`pair_as_drone`], with a check on the ground station that runs as
/// soon as its key is known, before the drone answers or shares anything. If
/// `accept` fails, pairing stops there (for example a key this device has
/// removed). The ground station is saved as an `operator`.
pub fn pair_as_drone_checked<S: Read + Write>(
    stream: &mut S,
    me: &Identity,
    my_name: &str,
    code: &PairingCode,
    current_key: Option<&SigningKey>,
    accept: impl FnOnce(&Peer) -> Result<()>,
    install: impl FnOnce(&SigningKey) -> Result<()>,
) -> Result<DroneResult> {
    check_name(my_name)?;
    if &code.responder_public != me.public_key() {
        return Err(Error::Protocol(
            "pairing code was made for a different device",
        ));
    }
    let params = PAIRING_NOISE.parse().expect("valid Noise name");
    let mut hs = snow::Builder::new(params)
        .local_private_key(me.private_key())?
        .psk(1, code.secret())?
        .prologue(PAIRING_PROLOGUE)?
        .build_responder()?;

    let mut buf = Zeroizing::new(vec![0u8; 256]);
    let mut payload = Zeroizing::new(vec![0u8; 256]);

    let msg = read_frame(stream, MAX_MSG1)?;
    let n = hs.read_message(&msg, &mut payload)?;
    let ground_name = parse_hello(&payload[..n])?;
    let ground_public: [u8; 32] = hs
        .get_remote_static()
        .ok_or(Error::Protocol("ground station sent no identity"))?
        .try_into()
        .map_err(|_| Error::Protocol("bad ground station key"))?;
    crate::identity::check_peer_public(&ground_public)?;

    // The ground station is saved as an operator: the drone's owner paired it.
    let ground = Peer {
        public: ground_public,
        name: ground_name,
        role: Role::Operator,
    };
    accept(&ground)?;

    let n = hs.write_message(&hello(my_name), &mut buf)?;
    write_frame(stream, &buf[..n])?;
    let mut t = hs.into_transport_mode()?;

    if let Some(k) = current_key {
        let mut m = Zeroizing::new([0u8; 33]);
        m[0] = MSG_SIGNING_KEY;
        m[1..].copy_from_slice(k.as_bytes());
        let n = t.write_message(&m[..], &mut buf)?;
        write_frame(stream, &buf[..n])?;
        let msg = read_frame(stream, MAX_TRANSPORT)?;
        let n = t.read_message(&msg, &mut payload)?;
        if payload[..n] != [MSG_CONFIRM] {
            return Err(Error::Protocol("ground station did not confirm"));
        }
        return Ok(DroneResult {
            ground,
            signing_key: k.clone(),
            new_key: false,
        });
    }

    let n = t.write_message(&[MSG_NEED_KEY], &mut buf)?;
    write_frame(stream, &buf[..n])?;
    let msg = read_frame(stream, MAX_TRANSPORT)?;
    let n = t.read_message(&msg, &mut payload)?;
    let signing_key = match &payload[..n] {
        [MSG_SIGNING_KEY, key @ ..] if key.len() == 32 => {
            SigningKey::from_bytes(key.try_into().expect("32 bytes"))?
        }
        _ => return Err(Error::Protocol("expected a signing key")),
    };

    let installed = install(&signing_key);
    let reply = if installed.is_ok() {
        MSG_CONFIRM
    } else {
        MSG_FAILED
    };
    let n = t.write_message(&[reply], &mut buf)?;
    write_frame(stream, &buf[..n])?;
    installed?;
    Ok(DroneResult {
        ground,
        signing_key,
        new_key: true,
    })
}

/// A TCP stream whose reads and writes all share one deadline, so a peer
/// can't hold pairing mode open by sending one byte at a time.
pub struct DeadlineStream {
    inner: TcpStream,
    deadline: Instant,
}

impl DeadlineStream {
    pub fn new(inner: TcpStream, budget: Duration) -> io::Result<Self> {
        inner.set_nonblocking(false)?;
        inner.set_nodelay(true)?;
        Ok(Self {
            inner,
            deadline: Instant::now() + budget,
        })
    }

    fn remaining(&self) -> io::Result<Duration> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "pairing took too long",
            ))
        } else {
            Ok(left)
        }
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.set_read_timeout(Some(self.remaining()?))?;
        self.inner.read(buf)
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.set_write_timeout(Some(self.remaining()?))?;
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn hello(name: &str) -> Vec<u8> {
    let mut v = vec![MSG_HELLO, name.len() as u8];
    v.extend_from_slice(name.as_bytes());
    v
}

fn parse_hello(p: &[u8]) -> Result<String> {
    if p.len() < 2 || p[0] != MSG_HELLO || p.len() != 2 + p[1] as usize {
        return Err(Error::Protocol("bad hello"));
    }
    let name = std::str::from_utf8(&p[2..]).map_err(|_| Error::Protocol("name is not UTF-8"))?;
    check_name(name).map_err(|_| Error::Protocol("bad peer name"))?;
    Ok(name.to_string())
}

/// Names are 1–32 characters of letters, digits, `-`, `_` and `.`, so they
/// are safe to show and to store one per line.
pub fn check_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= MAX_NAME
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
    if !ok {
        return Err(Error::Protocol("name must be 1-32 of A-Z a-z 0-9 - _ ."));
    }
    // Lookups try a fingerprint before a name, so a name must not look like one.
    if looks_like_fingerprint(name) {
        return Err(Error::Protocol(
            "name must not look like a fingerprint (XXXX-XXXX-XXXX-XXXX)",
        ));
    }
    Ok(())
}

/// Four groups of four base32 characters, joined by `-`.
pub(crate) fn looks_like_fingerprint(name: &str) -> bool {
    let groups: Vec<&str> = name.split('-').collect();
    groups.len() == 4
        && groups.iter().all(|g| {
            g.len() == 4
                && g.bytes()
                    .all(|b| b.is_ascii_alphabetic() || (b'2'..=b'7').contains(&b))
        })
}

fn write_frame<W: Write>(w: &mut W, data: &[u8]) -> Result<()> {
    let len = u16::try_from(data.len()).map_err(|_| Error::Protocol("message too long"))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(data)?;
    w.flush()?;
    Ok(())
}

/// Read one frame, refusing anything longer than `max` before reading it.
fn read_frame<R: Read>(r: &mut R, max: usize) -> Result<Vec<u8>> {
    let mut len = [0u8; 2];
    r.read_exact(&mut len)?;
    let len = u16::from_be_bytes(len) as usize;
    if len > max {
        return Err(Error::Protocol("message larger than allowed"));
    }
    let mut data = vec![0u8; len];
    r.read_exact(&mut data)?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn connected_pair() -> (TcpStream, TcpStream) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let a = TcpStream::connect(addr).unwrap();
        let (b, _) = l.accept().unwrap();
        for s in [&a, &b] {
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        }
        (a, b)
    }

    fn ok_install(_: &SigningKey) -> Result<()> {
        Ok(())
    }

    struct Run {
        ground: Result<GroundResult>,
        drone: Result<DroneResult>,
        drone_pub: [u8; 32],
        ground_pub: [u8; 32],
    }

    fn run(
        tamper: impl FnOnce(&PairingCode) -> PairingCode,
        existing: Option<SigningKey>,
        install_ok: bool,
    ) -> (Run, SigningKey) {
        let drone_id = Identity::generate().unwrap();
        let ground_id = Identity::generate().unwrap();
        let code = PairingCode::new(*drone_id.public_key()).unwrap();
        let ground_code = tamper(&code);
        let fresh = SigningKey::generate().unwrap();
        let (mut g, mut d) = connected_pair();
        let drone_pub = *drone_id.public_key();
        let ground_pub = *ground_id.public_key();
        let drone = thread::spawn(move || {
            pair_as_drone(
                &mut d,
                &drone_id,
                "drone-1",
                &code,
                existing.as_ref(),
                |_| {
                    if install_ok {
                        Ok(())
                    } else {
                        Err(Error::Protocol("autopilot said no"))
                    }
                },
            )
        });
        let f2 = fresh.clone();
        let ground = pair_as_ground(&mut g, &ground_id, "gcs-1", &ground_code, || Ok(f2));
        drop(g);
        let drone = drone.join().unwrap();
        (
            Run {
                ground,
                drone,
                drone_pub,
                ground_pub,
            },
            fresh,
        )
    }

    #[test]
    fn first_pairing_delivers_a_new_key() {
        let (r, fresh) = run(|c| c.clone(), None, true);
        let g = r.ground.unwrap();
        let d = r.drone.unwrap();
        assert_eq!(g.drone.public, r.drone_pub);
        assert_eq!(g.drone.name, "drone-1");
        assert_eq!(d.ground.public, r.ground_pub);
        assert_eq!(d.ground.name, "gcs-1");
        // The drone saves the ground station as an operator; the ground
        // station saves the drone as a plain peer (R-SEC2 section 1).
        assert_eq!(d.ground.role, Role::Operator);
        assert_eq!(g.drone.role, Role::Peer);
        assert!(g.new_key && d.new_key);
        assert_eq!(g.signing_key, fresh);
        assert_eq!(d.signing_key, fresh);
    }

    #[test]
    fn a_ground_station_the_drone_refuses_gets_nothing_not_even_a_reply() {
        let drone_id = Identity::generate().unwrap();
        let ground_id = Identity::generate().unwrap();
        let removed = *ground_id.public_key();
        let code = PairingCode::new(*drone_id.public_key()).unwrap();
        let ground_code = code.clone();
        let existing = SigningKey::generate().unwrap();
        let (mut g, mut d) = connected_pair();
        let drone = thread::spawn(move || {
            let r = pair_as_drone_checked(
                &mut d,
                &drone_id,
                "drone-1",
                &code,
                Some(&existing),
                |ground| {
                    if ground.public == removed {
                        Err(Error::Removed)
                    } else {
                        Ok(())
                    }
                },
                ok_install,
            );
            drop(d);
            r
        });
        let ground = pair_as_ground(&mut g, &ground_id, "gcs-1", &ground_code, || {
            SigningKey::generate()
        });
        assert!(matches!(drone.join().unwrap(), Err(Error::Removed)));
        // The ground station got no hello and no key: its read just ended.
        assert!(ground.is_err());
    }

    #[test]
    fn second_ground_station_gets_the_existing_key() {
        let existing = SigningKey::generate().unwrap();
        let (r, fresh) = run(|c| c.clone(), Some(existing.clone()), true);
        let g = r.ground.unwrap();
        let d = r.drone.unwrap();
        assert!(!g.new_key && !d.new_key);
        assert_eq!(g.signing_key, existing);
        assert_ne!(g.signing_key, fresh);
    }

    #[test]
    fn failed_install_fails_both_sides() {
        let (r, _) = run(|c| c.clone(), None, false);
        assert!(r.drone.is_err());
        assert!(matches!(r.ground, Err(Error::Protocol(_))));
    }

    #[test]
    fn wrong_secret_fails_and_drone_stays_silent() {
        // Someone who knows the drone's public key but never saw the code.
        let (r, _) = run(
            |c| PairingCode::new(c.responder_public).unwrap(),
            None,
            true,
        );
        assert!(matches!(r.drone, Err(Error::Noise(_))));
        assert!(
            matches!(r.ground, Err(Error::Io(_))),
            "drone must not reply"
        );
    }

    #[test]
    fn wrong_drone_key_fails() {
        // The ground station was given a code naming another device.
        let (r, _) = run(
            |c| {
                let mut c = c.clone();
                c.responder_public = *Identity::generate().unwrap().public_key();
                c
            },
            None,
            true,
        );
        assert!(r.ground.is_err());
        assert!(r.drone.is_err());
    }

    #[test]
    fn drone_refuses_code_for_another_device() {
        let me = Identity::generate().unwrap();
        let other = Identity::generate().unwrap();
        let code = PairingCode::new(*other.public_key()).unwrap();
        let (_g, mut d) = connected_pair();
        assert!(matches!(
            pair_as_drone(&mut d, &me, "drone", &code, None, ok_install),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn tampered_handshake_is_rejected() {
        let drone_id = Identity::generate().unwrap();
        let ground_id = Identity::generate().unwrap();
        let code = PairingCode::new(*drone_id.public_key()).unwrap();
        let gcode = code.clone();
        let (mut g, mut mid_a) = connected_pair();
        let (mut mid_b, mut d) = connected_pair();
        let drone = thread::spawn(move || {
            pair_as_drone(&mut d, &drone_id, "drone", &code, None, ok_install)
        });
        let relay = thread::spawn(move || {
            let mut f = read_frame(&mut mid_a, 1000).unwrap();
            f[40] ^= 1;
            write_frame(&mut mid_b, &f).unwrap();
        });
        let key = SigningKey::generate().unwrap();
        let ground = pair_as_ground(&mut g, &ground_id, "gcs", &gcode, || Ok(key));
        relay.join().unwrap();
        assert!(matches!(drone.join().unwrap(), Err(Error::Noise(_))));
        assert!(ground.is_err());
    }

    #[test]
    fn oversized_frames_are_refused_before_reading() {
        let me = Identity::generate().unwrap();
        let code = PairingCode::new(*me.public_key()).unwrap();
        let (mut g, mut d) = connected_pair();
        let t = thread::spawn(move || pair_as_drone(&mut d, &me, "drone", &code, None, ok_install));
        g.write_all(&u16::MAX.to_be_bytes()).unwrap(); // claims 65535 bytes, sends none
        assert!(matches!(t.join().unwrap(), Err(Error::Protocol(_))));
    }

    #[test]
    fn slow_peer_hits_the_deadline() {
        let me = Identity::generate().unwrap();
        let code = PairingCode::new(*me.public_key()).unwrap();
        let (mut g, d) = connected_pair();
        let mut d = DeadlineStream::new(d, Duration::from_millis(400)).unwrap();
        let start = Instant::now();
        let t = thread::spawn(move || pair_as_drone(&mut d, &me, "drone", &code, None, ok_install));
        // Dribble a byte every 100 ms, which would beat any per-read timeout.
        for _ in 0..10 {
            if g.write_all(&[0]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        assert!(t.join().unwrap().is_err());
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn names_are_checked() {
        assert!(check_name("gcs-1").is_ok());
        for bad in ["", "has space", "new\nline", &"x".repeat(33), "émoji"] {
            assert!(check_name(bad).is_err(), "{bad:?}");
        }
        // A name shaped like a fingerprint could be mistaken for one.
        let fp = crate::identity::fingerprint(&[7u8; 32]);
        assert!(check_name(&fp).is_err());
        assert!(check_name(&fp.to_lowercase()).is_err());
        assert!(check_name("device-1234abcd").is_ok());
        assert!(check_name("ABCD-EFGH-IJKL").is_ok());
    }

    #[test]
    fn hostile_frames_do_not_panic() {
        let me = Identity::generate().unwrap();
        let code = PairingCode::new(*me.public_key()).unwrap();
        for junk in [vec![], vec![0u8; 3], vec![0xFF; 150], vec![0u8; 96]] {
            let (mut g, mut d) = connected_pair();
            let id = Identity::from_private_bytes(me.private_key()).unwrap();
            let c = code.clone();
            let t =
                thread::spawn(move || pair_as_drone(&mut d, &id, "drone", &c, None, ok_install));
            let _ = write_frame(&mut g, &junk);
            drop(g);
            assert!(t.join().unwrap().is_err());
        }
    }
}
