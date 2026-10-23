//! Encrypted pairing between a ground station and a drone.
//!
//! The drone (Noise responder) shows a one-time [`PairingCode`]. The ground
//! station (Noise initiator) reads it and runs `Noise_IKpsk1`:
//!
//! 1. Ground → drone: ephemeral key, ground's identity (encrypted), hello.
//! 2. Drone → ground: ephemeral key, hello. Handshake done.
//! 3. Ground → drone (encrypted): a fresh MAVLink signing key.
//! 4. Drone → ground (encrypted): confirmation.
//!
//! The ground station knows it reached the right drone because only that
//! drone has the private key matching the code. The drone knows the ground
//! station saw the code because only the code holds the one-time secret.
//! Nothing secret crosses the link in the clear.
//!
//! Every message is framed as a 2-byte big-endian length and then the bytes,
//! as the Noise spec suggests for stream transports.

use std::io::{Read, Write};

use zeroize::Zeroize;

use crate::code::PairingCode;
use crate::identity::Identity;
use crate::signing::SigningKey;
use crate::store::Peer;
use crate::{Error, PAIRING_NOISE, PAIRING_PROLOGUE, Result};

/// Noise messages are at most 65535 bytes.
const MAX_MSG: usize = 65535;
/// Longest device name we accept.
pub const MAX_NAME: usize = 32;

const MSG_HELLO: u8 = 1;
const MSG_SIGNING_KEY: u8 = 2;
const MSG_CONFIRM: u8 = 3;

/// What the ground station learns from pairing.
#[derive(Debug, Clone)]
pub struct GroundResult {
    pub drone: Peer,
}

/// What the drone learns from pairing.
#[derive(Debug)]
pub struct DroneResult {
    pub ground: Peer,
    pub signing_key: SigningKey,
}

/// Ground station side. Pairs with the drone that made `code` and hands it
/// `signing_key`.
pub fn pair_as_ground<S: Read + Write>(
    stream: &mut S,
    me: &Identity,
    my_name: &str,
    code: &PairingCode,
    signing_key: &SigningKey,
) -> Result<GroundResult> {
    check_name(my_name)?;
    let params = PAIRING_NOISE.parse().expect("valid Noise name");
    let mut hs = snow::Builder::new(params)
        .local_private_key(me.private_key())?
        .remote_public_key(&code.responder_public)?
        .psk(1, code.secret())?
        .prologue(PAIRING_PROLOGUE)?
        .build_initiator()?;

    let mut buf = vec![0u8; MAX_MSG];
    let mut payload = vec![0u8; MAX_MSG];

    let n = hs.write_message(&hello(my_name), &mut buf)?;
    write_frame(stream, &buf[..n])?;

    let msg = read_frame(stream)?;
    let n = hs.read_message(&msg, &mut payload)?;
    let drone_name = parse_hello(&payload[..n])?;

    let mut transport = hs.into_transport_mode()?;

    let mut key_msg = [0u8; 33];
    key_msg[0] = MSG_SIGNING_KEY;
    key_msg[1..].copy_from_slice(signing_key.as_bytes());
    let n = transport.write_message(&key_msg, &mut buf)?;
    key_msg.zeroize();
    write_frame(stream, &buf[..n])?;

    let msg = read_frame(stream)?;
    let n = transport.read_message(&msg, &mut payload)?;
    if payload[..n] != [MSG_CONFIRM] {
        return Err(Error::Protocol("drone did not confirm the signing key"));
    }

    buf.zeroize();
    payload.zeroize();
    Ok(GroundResult {
        drone: Peer {
            public: code.responder_public,
            name: drone_name,
        },
    })
}

/// Drone side. Waits for one ground station holding `code`.
pub fn pair_as_drone<S: Read + Write>(
    stream: &mut S,
    me: &Identity,
    my_name: &str,
    code: &PairingCode,
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

    let mut buf = vec![0u8; MAX_MSG];
    let mut payload = vec![0u8; MAX_MSG];

    let msg = read_frame(stream)?;
    let n = hs.read_message(&msg, &mut payload)?;
    let ground_name = parse_hello(&payload[..n])?;
    let ground_public: [u8; 32] = hs
        .get_remote_static()
        .ok_or(Error::Protocol("ground station sent no identity"))?
        .try_into()
        .map_err(|_| Error::Protocol("bad ground station key"))?;

    let n = hs.write_message(&hello(my_name), &mut buf)?;
    write_frame(stream, &buf[..n])?;

    let mut transport = hs.into_transport_mode()?;

    let msg = read_frame(stream)?;
    let n = transport.read_message(&msg, &mut payload)?;
    if n != 33 || payload[0] != MSG_SIGNING_KEY {
        return Err(Error::Protocol("expected a signing key"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&payload[1..33]);
    let signing_key = SigningKey::from_bytes(key);
    key.zeroize();
    let signing_key = signing_key?;

    let n = transport.write_message(&[MSG_CONFIRM], &mut buf)?;
    write_frame(stream, &buf[..n])?;

    buf.zeroize();
    payload.zeroize();
    Ok(DroneResult {
        ground: Peer {
            public: ground_public,
            name: ground_name,
        },
        signing_key,
    })
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
    if ok {
        Ok(())
    } else {
        Err(Error::Protocol("name must be 1-32 of A-Z a-z 0-9 - _ ."))
    }
}

fn write_frame<W: Write>(w: &mut W, data: &[u8]) -> Result<()> {
    let len = u16::try_from(data.len()).map_err(|_| Error::Protocol("message too long"))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(data)?;
    w.flush()?;
    Ok(())
}

fn read_frame<R: Read>(r: &mut R) -> Result<Vec<u8>> {
    let mut len = [0u8; 2];
    r.read_exact(&mut len)?;
    let mut data = vec![0u8; u16::from_be_bytes(len) as usize];
    r.read_exact(&mut data)?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

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

    /// Run a full pairing. `tamper` can swap the code the ground side uses.
    fn run(
        ground_code: impl FnOnce(&PairingCode) -> PairingCode,
    ) -> (
        Result<GroundResult>,
        Result<DroneResult>,
        [u8; 32],
        [u8; 32],
        SigningKey,
    ) {
        let drone_id = Identity::generate().unwrap();
        let ground_id = Identity::generate().unwrap();
        let code = PairingCode::new(*drone_id.public_key()).unwrap();
        let ground_code = ground_code(&code);
        let key = SigningKey::generate().unwrap();
        let (mut g, mut d) = connected_pair();
        let drone_pub = *drone_id.public_key();
        let ground_pub = *ground_id.public_key();
        let drone = thread::spawn(move || pair_as_drone(&mut d, &drone_id, "drone-1", &code));
        let k2 = key.clone();
        let ground = pair_as_ground(&mut g, &ground_id, "gcs-1", &ground_code, &k2);
        drop(g);
        (ground, drone.join().unwrap(), drone_pub, ground_pub, key)
    }

    #[test]
    fn pairs_and_delivers_signing_key() {
        let (g, d, drone_pub, ground_pub, key) = run(|c| c.clone());
        let g = g.unwrap();
        let d = d.unwrap();
        assert_eq!(g.drone.public, drone_pub);
        assert_eq!(g.drone.name, "drone-1");
        assert_eq!(d.ground.public, ground_pub);
        assert_eq!(d.ground.name, "gcs-1");
        assert_eq!(d.signing_key, key);
    }

    #[test]
    fn wrong_secret_fails_on_both_sides() {
        // Someone who knows the drone's public key but never saw the code.
        let (g, d, ..) = run(|c| PairingCode::new(c.responder_public).unwrap());
        assert!(g.is_err());
        assert!(matches!(d, Err(Error::Noise(_))));
    }

    #[test]
    fn wrong_drone_key_fails() {
        // A ground station tricked into talking to an impostor: the impostor
        // can't complete the handshake without the real drone's private key.
        let (g, d, ..) = run(|c| {
            let other = Identity::generate().unwrap();
            let mut text = PairingCode::new(*other.public_key()).unwrap();
            // Same secret, different drone key.
            text = PairingCode::decode(&reencode(&text, c)).unwrap();
            text
        });
        assert!(g.is_err());
        assert!(d.is_err());
    }

    /// Build a code with `key_from`'s public key and `secret_from`'s secret.
    fn reencode(key_from: &PairingCode, secret_from: &PairingCode) -> String {
        let a = PairingCode::decode(&key_from.encode()).unwrap();
        let mut c = secret_from.clone();
        c.responder_public = a.responder_public;
        c.encode()
    }

    #[test]
    fn drone_refuses_code_for_another_device() {
        let me = Identity::generate().unwrap();
        let other = Identity::generate().unwrap();
        let code = PairingCode::new(*other.public_key()).unwrap();
        let (_g, mut d) = connected_pair();
        assert!(matches!(
            pair_as_drone(&mut d, &me, "drone", &code),
            Err(Error::Protocol(_))
        ));
    }

    #[test]
    fn tampered_handshake_is_rejected() {
        // A relay in the middle flips one bit of the first message.
        let drone_id = Identity::generate().unwrap();
        let ground_id = Identity::generate().unwrap();
        let code = PairingCode::new(*drone_id.public_key()).unwrap();
        let gcode = code.clone();
        let (mut g, mut mid_a) = connected_pair();
        let (mut mid_b, mut d) = connected_pair();
        let drone = thread::spawn(move || pair_as_drone(&mut d, &drone_id, "drone", &code));
        let relay = thread::spawn(move || {
            let mut f = read_frame(&mut mid_a).unwrap();
            f[40] ^= 1;
            write_frame(&mut mid_b, &f).unwrap();
        });
        let key = SigningKey::generate().unwrap();
        let ground = pair_as_ground(&mut g, &ground_id, "gcs", &gcode, &key);
        relay.join().unwrap();
        assert!(matches!(drone.join().unwrap(), Err(Error::Noise(_))));
        assert!(ground.is_err());
    }

    #[test]
    fn names_are_checked() {
        assert!(check_name("gcs-1").is_ok());
        for bad in ["", "has space", "new\nline", &"x".repeat(33), "émoji"] {
            assert!(check_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn hostile_frames_do_not_panic() {
        let me = Identity::generate().unwrap();
        let code = PairingCode::new(*me.public_key()).unwrap();
        for junk in [vec![], vec![0u8; 3], vec![0xFF; 200], vec![0u8; 96]] {
            let (mut g, mut d) = connected_pair();
            let id = Identity::from_private_bytes(me.private_key()).unwrap();
            let c = code.clone();
            let t = thread::spawn(move || pair_as_drone(&mut d, &id, "drone", &c));
            let _ = write_frame(&mut g, &junk);
            drop(g);
            assert!(t.join().unwrap().is_err());
        }
    }
}
