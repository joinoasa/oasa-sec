//! The MAVLink guard: what `oasa-link` lets through to the autopilot.
//!
//! A drone's autopilot trusts whoever holds the MAVLink signing key. So the
//! tunnel must never carry a change of that key, or of the settings that
//! turn signing off. The guard looks at every datagram that arrives **from
//! the link** (decrypted, before it goes to the autopilot) and drops the
//! whole datagram if any frame in it is malformed or blocked.
//!
//! It checks the shape and length of frames only, never the CRC, so
//! messages from any dialect pass. Design: `docs/oasa-sec-v0-rotation.md`
//! (R-SEC2) and `docs/oasa-sec-v0-link.md` section 7. What the autopilots do
//! with these messages: `docs/sitl.md`.
//!
//! Pure functions on bytes: no sockets, no clock, no logging. Never keeps
//! or prints packet contents; a [`Block`] holds only the message id.

/// `SETUP_SIGNING`: loads a signing key into the autopilot, or (all zero)
/// turns signing off.
pub const MSG_SETUP_SIGNING: u32 = 256;
/// `FILE_TRANSFER_PROTOCOL`: PX4 keeps its key in a file that FTP can read
/// and replace.
pub const MSG_FILE_TRANSFER_PROTOCOL: u32 = 110;
/// `PARAM_SET`.
pub const MSG_PARAM_SET: u32 = 23;
/// `PARAM_EXT_SET`.
pub const MSG_PARAM_EXT_SET: u32 = 323;

/// Where `param_id` (16 bytes, zero padded) starts in each payload. Fields
/// are in wire order: `PARAM_SET` puts its 4-byte `param_value` first,
/// `PARAM_EXT_SET` starts with two bytes of target.
const PARAM_SET_ID_AT: usize = 6;
const PARAM_EXT_SET_ID_AT: usize = 2;
const PARAM_ID_LEN: usize = 16;

/// Parameter names that can weaken signing, matched on the start of the name
/// without regard to case:
/// - `MAV_SIGN`: reserved for a signing setting; no autopilot we tested has
///   one yet (`docs/sitl.md`).
/// - `MAV<n>_OPTIONS` (ArduPilot): bit 0 turns signing off for that serial
///   link at the next restart or key change. Matched by [`is_signing_param`].
const SIGNING_PARAM_PREFIX: &[u8] = b"MAV_SIGN";

const V1_START: u8 = 0xFE;
const V2_START: u8 = 0xFD;
/// MAVLink 2 header: start, len, incompat, compat, seq, sys, comp, msgid x3.
const V2_HEADER: usize = 10;
/// MAVLink 1 header: start, len, seq, sys, comp, msgid.
const V1_HEADER: usize = 6;
const CRC_LEN: usize = 2;
/// The signature block of a signed MAVLink 2 frame: link id, timestamp, tag.
const SIGNATURE_LEN: usize = 13;
const INCOMPAT_SIGNED: u8 = 0x01;

/// Why a datagram was stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// Not made only of whole MAVLink frames.
    Malformed,
    /// `SETUP_SIGNING`.
    SetupSigning,
    /// `FILE_TRANSFER_PROTOCOL`, while FTP is not allowed.
    Ftp,
    /// `PARAM_SET` or `PARAM_EXT_SET` for a signing parameter.
    SigningParam,
}

impl Why {
    /// A short fixed word for logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Why::Malformed => "malformed",
            Why::SetupSigning => "setup_signing",
            Why::Ftp => "ftp",
            Why::SigningParam => "signing_param",
        }
    }
}

/// A datagram the guard refused. Holds no packet contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Block {
    pub why: Why,
    /// The message id that was blocked. `None` when the datagram is malformed.
    pub msgid: Option<u32>,
}

/// The guard's settings.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Guard {
    /// Let `FILE_TRANSFER_PROTOCOL` through (log download needs it).
    pub allow_ftp: bool,
}

impl Guard {
    /// Look at one datagram. `Ok` means every frame in it may go on.
    pub fn check(&self, datagram: &[u8]) -> Result<(), Block> {
        if datagram.is_empty() {
            return Err(malformed());
        }
        let mut rest = datagram;
        while !rest.is_empty() {
            let frame = Frame::parse(rest).ok_or_else(malformed)?;
            self.check_frame(&frame)?;
            rest = &rest[frame.total..];
        }
        Ok(())
    }

    fn check_frame(&self, f: &Frame) -> Result<(), Block> {
        let block = |why| {
            Err(Block {
                why,
                msgid: Some(f.msgid),
            })
        };
        match f.msgid {
            MSG_SETUP_SIGNING => block(Why::SetupSigning),
            MSG_FILE_TRANSFER_PROTOCOL if !self.allow_ftp => block(Why::Ftp),
            MSG_PARAM_SET if is_signing_param(&param_id(f.payload, PARAM_SET_ID_AT)) => {
                block(Why::SigningParam)
            }
            MSG_PARAM_EXT_SET if is_signing_param(&param_id(f.payload, PARAM_EXT_SET_ID_AT)) => {
                block(Why::SigningParam)
            }
            _ => Ok(()),
        }
    }
}

fn malformed() -> Block {
    Block {
        why: Why::Malformed,
        msgid: None,
    }
}

/// One frame's shape: how long it is, its message id and its payload.
struct Frame<'a> {
    total: usize,
    msgid: u32,
    payload: &'a [u8],
}

impl<'a> Frame<'a> {
    /// Read the frame at the start of `buf`. `None` if it is cut short, has
    /// an unknown start byte, or sets an incompatibility flag we don't know
    /// (the spec says such a frame must be rejected, and its length can't be
    /// trusted). The CRC is not checked.
    fn parse(buf: &'a [u8]) -> Option<Frame<'a>> {
        match *buf.first()? {
            V1_START => {
                let len = usize::from(*buf.get(1)?);
                let total = V1_HEADER + len + CRC_LEN;
                if buf.len() < total {
                    return None;
                }
                Some(Frame {
                    total,
                    msgid: u32::from(buf[5]),
                    payload: &buf[V1_HEADER..V1_HEADER + len],
                })
            }
            V2_START => {
                if buf.len() < V2_HEADER {
                    return None;
                }
                let len = usize::from(buf[1]);
                let incompat = buf[2];
                if incompat & !INCOMPAT_SIGNED != 0 {
                    return None;
                }
                let signed = if incompat & INCOMPAT_SIGNED != 0 {
                    SIGNATURE_LEN
                } else {
                    0
                };
                let total = V2_HEADER + len + CRC_LEN + signed;
                if buf.len() < total {
                    return None;
                }
                Some(Frame {
                    total,
                    msgid: u32::from(buf[7]) | u32::from(buf[8]) << 8 | u32::from(buf[9]) << 16,
                    payload: &buf[V2_HEADER..V2_HEADER + len],
                })
            }
            _ => None,
        }
    }
}

/// The 16-byte `param_id` at `at` in a payload. MAVLink 2 drops trailing
/// zero bytes from a payload, so missing bytes read as zero.
fn param_id(payload: &[u8], at: usize) -> [u8; PARAM_ID_LEN] {
    let mut id = [0u8; PARAM_ID_LEN];
    let have = payload.get(at..).unwrap_or(&[]);
    let n = have.len().min(PARAM_ID_LEN);
    id[..n].copy_from_slice(&have[..n]);
    id
}

/// Does this parameter name (as sent: up to 16 bytes, zero padded) belong to
/// a setting that can weaken signing?
pub fn is_signing_param(name: &[u8]) -> bool {
    let up = name.to_ascii_uppercase();
    if up.starts_with(SIGNING_PARAM_PREFIX) {
        return true;
    }
    // ArduPilot: MAV1_OPTIONS, MAV2_OPTIONS ... (one or two digits).
    if let Some(rest) = up.strip_prefix(b"MAV") {
        let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
        return (1..=2).contains(&digits) && rest[digits..].starts_with(b"_OPTIONS");
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A MAVLink 2 frame with a made-up CRC (the guard doesn't check it).
    fn v2(msgid: u32, payload: &[u8], signed: bool) -> Vec<u8> {
        let mut f = vec![
            V2_START,
            payload.len() as u8,
            if signed { INCOMPAT_SIGNED } else { 0 },
            0,
            7,
            255,
            190,
            msgid as u8,
            (msgid >> 8) as u8,
            (msgid >> 16) as u8,
        ];
        f.extend_from_slice(payload);
        f.extend_from_slice(&[0xAA, 0xBB]);
        if signed {
            f.extend_from_slice(&[0x5A; SIGNATURE_LEN]);
        }
        f
    }

    fn v1(msgid: u8, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![V1_START, payload.len() as u8, 3, 255, 190, msgid];
        f.extend_from_slice(payload);
        f.extend_from_slice(&[0xAA, 0xBB]);
        f
    }

    /// PARAM_SET payload in wire order, full length (23 bytes).
    fn param_set(name: &str) -> Vec<u8> {
        let mut p = 1.0f32.to_le_bytes().to_vec();
        p.extend_from_slice(&[1, 1]);
        let mut id = name.as_bytes().to_vec();
        id.resize(PARAM_ID_LEN, 0);
        p.extend_from_slice(&id);
        p.push(9);
        p
    }

    /// PARAM_EXT_SET payload in wire order (147 bytes).
    fn param_ext_set(name: &str) -> Vec<u8> {
        let mut p = vec![1, 1];
        let mut id = name.as_bytes().to_vec();
        id.resize(PARAM_ID_LEN, 0);
        p.extend_from_slice(&id);
        p.extend_from_slice(&[b'1'; 1]);
        p.resize(146, 0);
        p.push(2);
        p
    }

    /// What MAVLink 2 sends: trailing zero bytes removed (but at least one byte).
    fn trimmed(mut p: Vec<u8>) -> Vec<u8> {
        while p.len() > 1 && p.last() == Some(&0) {
            p.pop();
        }
        p
    }

    fn guard() -> Guard {
        Guard::default()
    }

    fn blocked(d: &[u8]) -> Block {
        guard().check(d).unwrap_err()
    }

    #[test]
    fn ordinary_frames_pass() {
        let heartbeat = [0u8, 0, 0, 0, 2, 3, 81, 4, 3];
        assert!(guard().check(&v2(0, &heartbeat, false)).is_ok());
        assert!(guard().check(&v2(0, &heartbeat, true)).is_ok());
        assert!(guard().check(&v1(0, &heartbeat)).is_ok());
        // A message id above 255 and one the common dialect doesn't have.
        assert!(guard().check(&v2(11_000, &[1, 2, 3], false)).is_ok());
        assert!(guard().check(&v2(0x00FF_FFFF, &[], false)).is_ok());
        // A zero-length payload.
        assert!(guard().check(&v1(0, &[])).is_ok());
    }

    #[test]
    fn batched_frames_are_each_checked() {
        let mut d = v2(0, &[1; 9], false);
        d.extend(v1(30, &[2; 28]));
        d.extend(v2(33, &[3; 28], true));
        d.extend(v2(24, &[4; 30], false));
        assert!(guard().check(&d).is_ok());
        // One blocked frame anywhere stops the whole datagram.
        for at in [0, 1, 2, 3, 4] {
            let mut frames = vec![
                v2(0, &[1; 9], false),
                v1(30, &[2; 28]),
                v2(33, &[3; 28], true),
                v2(24, &[4; 30], false),
            ];
            frames.insert(at, v2(MSG_SETUP_SIGNING, &[0; 42], false));
            let d: Vec<u8> = frames.concat();
            let b = blocked(&d);
            assert_eq!((b.why, b.msgid), (Why::SetupSigning, Some(256)), "at {at}");
        }
    }

    #[test]
    fn a_malformed_frame_in_a_batch_stops_the_datagram() {
        let mut d = v2(0, &[1; 9], false);
        d.extend_from_slice(&[V2_START, 200, 0, 0, 1]); // cut short
        assert_eq!(blocked(&d), malformed());
        let mut d = v2(0, &[1; 9], false);
        d.push(0x00); // a stray byte after the last frame
        assert_eq!(blocked(&d), malformed());
        let mut d = vec![0x00];
        d.extend(v2(0, &[1; 9], false)); // a stray byte before
        assert_eq!(blocked(&d), malformed());
    }

    #[test]
    fn truncated_frames_are_malformed() {
        for f in [v2(0, &[1; 9], false), v2(0, &[1; 9], true), v1(0, &[1; 9])] {
            for cut in 1..f.len() {
                assert_eq!(
                    blocked(&f[..cut]),
                    malformed(),
                    "cut at {cut} of {}",
                    f.len()
                );
            }
            assert!(guard().check(&f).is_ok());
        }
    }

    #[test]
    fn the_signed_flag_adds_thirteen_bytes() {
        // A signed frame without its signature is cut short.
        let mut f = v2(0, &[1; 9], true);
        f.truncate(f.len() - SIGNATURE_LEN);
        assert_eq!(blocked(&f), malformed());
        // The same bytes with the flag off are a whole unsigned frame...
        f[2] = 0;
        assert!(guard().check(&f).is_ok());
        // ...and an unsigned frame with the flag turned on is cut short.
        let mut g = v2(0, &[1; 9], false);
        g[2] = INCOMPAT_SIGNED;
        assert_eq!(blocked(&g), malformed());
        // A blocked message is blocked whether or not it is signed.
        assert_eq!(blocked(&v2(256, &[0; 42], true)).why, Why::SetupSigning);
    }

    #[test]
    fn unknown_incompat_flags_are_malformed() {
        for flags in [0x02u8, 0x80, 0x03, 0xFF] {
            let mut f = v2(0, &[1; 9], false);
            f[2] = flags;
            f.extend_from_slice(&[0; 13]);
            assert_eq!(blocked(&f), malformed(), "flags {flags:#x}");
        }
        // Compat flags are ignored by design: any value is fine.
        let mut f = v2(0, &[1; 9], false);
        f[3] = 0xFF;
        assert!(guard().check(&f).is_ok());
    }

    #[test]
    fn the_message_id_is_24_bits() {
        // 0x010100 is not 0x0100 (256): the third byte counts.
        assert!(guard().check(&v2(0x01_0100, &[0; 42], false)).is_ok());
        assert!(guard().check(&v2(0x01_0000 | 110, &[0; 5], false)).is_ok());
        assert!(
            guard()
                .check(&v2(0x80_0000 | 23, &param_set("MAV_SIGN"), false))
                .is_ok()
        );
        // MAVLink 1 has one byte: id 256 can't be sent, and 110 is FTP.
        assert_eq!(blocked(&v1(110, &[0; 5])).why, Why::Ftp);
    }

    #[test]
    fn setup_signing_is_always_blocked() {
        for signed in [false, true] {
            let b = blocked(&v2(256, &[0; 42], signed));
            assert_eq!((b.why, b.msgid), (Why::SetupSigning, Some(256)));
        }
        // Even a trimmed payload (an all-zero "disable signing" message).
        let b = blocked(&v2(256, &trimmed(vec![0; 42]), true));
        assert_eq!(b.why, Why::SetupSigning);
        // Allowing FTP changes nothing here.
        let g = Guard { allow_ftp: true };
        assert_eq!(
            g.check(&v2(256, &[0; 42], false)).unwrap_err().why,
            Why::SetupSigning
        );
    }

    #[test]
    fn ftp_is_blocked_unless_allowed() {
        let f = v2(110, &[0; 254], false);
        let b = blocked(&f);
        assert_eq!((b.why, b.msgid), (Why::Ftp, Some(110)));
        assert_eq!(blocked(&v2(110, &[0; 254], true)).why, Why::Ftp);
        assert_eq!(blocked(&v1(110, &[0; 5])).why, Why::Ftp);
        let g = Guard { allow_ftp: true };
        assert!(g.check(&f).is_ok());
        assert!(g.check(&v1(110, &[0; 5])).is_ok());
    }

    #[test]
    fn signing_parameters_are_blocked_in_param_set() {
        for name in [
            "MAV_SIGN",
            "MAV_SIGN_CFG",
            "mav_sign_cfg",
            "Mav_Sign_X",
            "MAV1_OPTIONS",
            "MAV2_OPTIONS",
            "MAV3_OPTIONS",
            "MAV9_OPTIONS",
            "MAV10_OPTIONS",
            "mav2_options",
        ] {
            let b = blocked(&v2(23, &param_set(name), false));
            assert_eq!((b.why, b.msgid), (Why::SigningParam, Some(23)), "{name}");
            assert_eq!(
                blocked(&v2(23, &param_set(name), true)).why,
                Why::SigningParam
            );
            assert_eq!(blocked(&v1(23, &param_set(name))).why, Why::SigningParam);
            // MAVLink 2 trims trailing zeros, which cuts into the name field.
            let t = trimmed(param_set(name));
            assert_eq!(
                blocked(&v2(23, &t, false)).why,
                Why::SigningParam,
                "{name} trimmed"
            );
        }
    }

    #[test]
    fn signing_parameters_are_blocked_in_param_ext_set() {
        for name in ["MAV_SIGN_CFG", "mav_sign", "MAV2_OPTIONS"] {
            let b = blocked(&v2(323, &param_ext_set(name), false));
            assert_eq!((b.why, b.msgid), (Why::SigningParam, Some(323)), "{name}");
            let t = trimmed(param_ext_set(name));
            assert_eq!(
                blocked(&v2(323, &t, false)).why,
                Why::SigningParam,
                "{name} trimmed"
            );
        }
        // An ordinary one passes.
        assert!(
            guard()
                .check(&v2(323, &param_ext_set("MPC_XY_VEL_MAX"), false))
                .is_ok()
        );
    }

    #[test]
    fn ordinary_parameters_pass() {
        for name in [
            "MPC_XY_VEL_MAX",
            "SERIAL1_BAUD",
            "MAV_SYS_ID",
            "MAV_PROTO_VER",
            "MAV_SYSID",
            "MAV_OPTIONS",
            "MAV_",
            "MAV",
            "MAVX_OPTIONS",
            "MAV100_OPTIONS",
            "MAV2_OPTION",
            "MAV2",
            "",
            "XMAV_SIGN",
            "SIM_ARSPD_SIGN",
            "ADSB_CALLSIGN_1",
        ] {
            assert!(
                guard().check(&v2(23, &param_set(name), false)).is_ok(),
                "{name:?}"
            );
            assert!(
                guard()
                    .check(&v2(23, &trimmed(param_set(name)), false))
                    .is_ok(),
                "{name:?}"
            );
            assert!(
                guard().check(&v2(323, &param_ext_set(name), false)).is_ok(),
                "{name:?}"
            );
        }
    }

    #[test]
    fn param_names_only_count_in_the_param_field() {
        // MAV_SIGN where a different message keeps its data: no block.
        assert!(
            guard()
                .check(&v2(22, &param_set("MAV_SIGN_CFG"), false))
                .is_ok()
        );
        // The name in the wrong place of a PARAM_SET (right at the start): no block.
        let mut p = b"MAV_SIGN_CFG\0\0\0\0".to_vec();
        p.resize(23, 0);
        assert!(guard().check(&v2(23, &p, false)).is_ok());
        // A payload too short to hold any name reads as an empty name.
        assert!(guard().check(&v2(23, &[0, 0, 0x80, 0x3F], false)).is_ok());
        assert!(guard().check(&v2(23, &[], false)).is_ok());
        assert!(guard().check(&v2(323, &[], false)).is_ok());
    }

    #[test]
    fn a_signing_name_cut_short_by_the_payload_still_matches() {
        // A payload that ends in the middle of the name: only the start is there.
        let mut p = 1.0f32.to_le_bytes().to_vec();
        p.extend_from_slice(&[1, 1]);
        p.extend_from_slice(b"MAV_SIGN");
        assert_eq!(blocked(&v2(23, &p, false)).why, Why::SigningParam);
        p.truncate(p.len() - 1);
        assert!(guard().check(&v2(23, &p, false)).is_ok());
    }

    #[test]
    fn param_set_to_a_signing_name_is_blocked_inside_a_batch() {
        let mut d = v2(0, &[1; 9], false);
        d.extend(v2(23, &param_set("MAV2_OPTIONS"), true));
        d.extend(v2(0, &[1; 9], false));
        assert_eq!(blocked(&d).why, Why::SigningParam);
        // The ordinary one next to it passes.
        let mut d = v2(0, &[1; 9], false);
        d.extend(v2(23, &param_set("MPC_XY_VEL_MAX"), true));
        assert!(guard().check(&d).is_ok());
    }

    #[test]
    fn is_signing_param_edge_cases() {
        assert!(is_signing_param(b"MAV_SIGN"));
        assert!(is_signing_param(b"mav_sign_cfg\0\0\0\0"));
        assert!(is_signing_param(b"MAV7_OPTIONS\0\0\0\0"));
        assert!(!is_signing_param(b""));
        assert!(!is_signing_param(b"\0\0\0\0"));
        assert!(!is_signing_param(b"MAV_SIG"));
        assert!(!is_signing_param(b"MAV_OPTIONS"));
        assert!(!is_signing_param(b"MAV123_OPTIONS"));
        assert!(!is_signing_param(&[0xFF; 16]));
    }

    #[test]
    fn bytes_that_are_not_mavlink_are_malformed() {
        for d in [
            &b"hello"[..],
            &[0x00][..],
            &[0xFF; 40][..],
            &[0xFC, 0, 0, 0][..], // a start byte of nothing we know
            &b"\x03\x00\x01\x02"[..],
            &[V2_START][..],
            &[V1_START][..],
            &[V1_START, 0][..],
        ] {
            assert_eq!(blocked(d), malformed(), "{d:?}");
        }
    }

    #[test]
    fn an_empty_datagram_is_refused() {
        assert_eq!(blocked(&[]), malformed());
    }

    #[test]
    fn long_payloads_work() {
        let big = vec![7u8; 255];
        assert!(guard().check(&v2(0, &big, false)).is_ok());
        assert!(guard().check(&v2(0, &big, true)).is_ok());
        assert!(guard().check(&v1(0, &big)).is_ok());
        let mut d = v2(0, &big, true);
        d.extend(v2(0, &big, true));
        assert!(guard().check(&d).is_ok());
        d.pop();
        assert_eq!(blocked(&d), malformed());
    }

    #[test]
    fn the_crc_is_not_checked() {
        let mut f = v2(0, &[1; 9], false);
        let n = f.len();
        f[n - 1] ^= 0xFF;
        f[n - 2] ^= 0xFF;
        assert!(guard().check(&f).is_ok());
        // And a blocked message is blocked whatever its CRC says.
        let mut s = v2(256, &[0; 42], false);
        let n = s.len();
        s[n - 1] ^= 0xFF;
        assert_eq!(blocked(&s).why, Why::SetupSigning);
    }

    #[test]
    fn no_input_makes_it_panic() {
        // A cheap fuzz: every prefix and many one-byte changes of real
        // frames, plus a pseudo-random stream. Only "no panic" is asserted.
        let mut seed = 0x1234_5678_9ABC_DEF0u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let frames = [
            v2(0, &[1; 9], true),
            v2(23, &param_set("MAV2_OPTIONS"), false),
            v2(323, &param_ext_set("MAV_SIGN"), true),
            v1(110, &[3; 20]),
        ];
        for f in &frames {
            for cut in 0..=f.len() {
                let _ = guard().check(&f[..cut]);
            }
            for _ in 0..2000 {
                let mut g = f.clone();
                let i = (next() as usize) % g.len();
                g[i] = next() as u8;
                let _ = guard().check(&g);
            }
        }
        for _ in 0..2000 {
            let n = (next() % 300) as usize;
            let d: Vec<u8> = (0..n).map(|_| next() as u8).collect();
            let _ = guard().check(&d);
        }
    }

    #[test]
    fn why_has_fixed_words() {
        assert_eq!(Why::Malformed.as_str(), "malformed");
        assert_eq!(Why::SetupSigning.as_str(), "setup_signing");
        assert_eq!(Why::Ftp.as_str(), "ftp");
        assert_eq!(Why::SigningParam.as_str(), "signing_param");
    }
}
