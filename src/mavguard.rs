//! The MAVLink guard: the only MAVLink that `oasa-link` lets through to the autopilot.
//!
//! A drone's autopilot trusts whoever holds the MAVLink signing key, and a paired ground station
//! holds it. So the tunnel carries what an operator needs to fly and nothing else: an **allowlist**
//! of messages, of commands (inside `COMMAND_LONG`, `COMMAND_INT` and mission items) and, for
//! writes, of parameter names. The guard looks at every datagram that arrives **from the link**
//! (decrypted, before it goes to the autopilot). A datagram passes only if every frame in it is
//! complete, has a valid CRC, is allowed, and nothing else is in the datagram; otherwise the whole
//! datagram is dropped.
//!
//! Frame boundaries come from the header (v1 `0xFE`, v2 `0xFD` with the signed flag's 13 extra
//! bytes, 24-bit message ids). CRCs use the CRC_EXTRA of the `mavlink` crate's common dialect, so
//! an id the crate doesn't know can't be allowed. The tables below, with a reason for each entry,
//! are mirrored in `docs/oasa-sec-v0-link.md` section 7 (a test keeps them in step).
//!
//! Pure functions on bytes: no sockets, no clock, no logging. Never keeps or prints packet
//! contents; a [`Block`] holds only message and command ids.

use std::collections::BTreeSet;

use mavlink::Message;
use mavlink::dialects::common::MavMessage;

/// `SETUP_SIGNING`: loads a signing key into the autopilot, or (all zero) turns signing off.
/// Never allowed, not even with `--allow-msg`.
pub const MSG_SETUP_SIGNING: u32 = 256;
/// `FILE_TRANSFER_PROTOCOL`: PX4 keeps its key in a file that FTP can read and replace.
pub const MSG_FILE_TRANSFER_PROTOCOL: u32 = 110;
/// `PARAM_SET`.
pub const MSG_PARAM_SET: u32 = 23;
/// `PARAM_EXT_SET`.
pub const MSG_PARAM_EXT_SET: u32 = 323;
const MSG_COMMAND_INT: u32 = 75;
const MSG_COMMAND_LONG: u32 = 76;
const MSG_MISSION_ITEM: u32 = 39;
const MSG_MISSION_ITEM_INT: u32 = 73;

/// Messages a ground station may send by default: (id, name, why).
pub const DEFAULT_MESSAGES: &[(u32, &str, &str)] = &[
    (
        0,
        "HEARTBEAT",
        "Ground station presence; ArduPilot's GCS failsafe needs it",
    ),
    (2, "SYSTEM_TIME", "Clock sync"),
    (4, "PING", "Link latency check"),
    (
        11,
        "SET_MODE",
        "Legacy flight mode change (same effect as DO_SET_MODE)",
    ),
    (20, "PARAM_REQUEST_READ", "Read one parameter"),
    (21, "PARAM_REQUEST_LIST", "Read all parameters"),
    (
        37,
        "MISSION_REQUEST_PARTIAL_LIST",
        "Mission download (part)",
    ),
    (38, "MISSION_WRITE_PARTIAL_LIST", "Mission upload (part)"),
    (
        39,
        "MISSION_ITEM",
        "Mission upload; the item's command is filtered",
    ),
    (40, "MISSION_REQUEST", "Mission download"),
    (41, "MISSION_SET_CURRENT", "Jump to a mission item"),
    (43, "MISSION_REQUEST_LIST", "Mission download"),
    (44, "MISSION_COUNT", "Mission upload"),
    (45, "MISSION_CLEAR_ALL", "Clear the mission"),
    (47, "MISSION_ACK", "Ends a mission transfer"),
    (51, "MISSION_REQUEST_INT", "Mission download"),
    (
        66,
        "REQUEST_DATA_STREAM",
        "Legacy telemetry rate request (Mission Planner); on ArduPlane it saves the SRn_* rates to storage",
    ),
    (69, "MANUAL_CONTROL", "Joystick flying"),
    (70, "RC_CHANNELS_OVERRIDE", "Stick input over the link"),
    (
        73,
        "MISSION_ITEM_INT",
        "Mission upload; the item's command is filtered",
    ),
    (75, "COMMAND_INT", "Commands; the command id is filtered"),
    (76, "COMMAND_LONG", "Commands; the command id is filtered"),
    (77, "COMMAND_ACK", "Answers a command the autopilot sent"),
    (82, "SET_ATTITUDE_TARGET", "Offboard flying"),
    (84, "SET_POSITION_TARGET_LOCAL_NED", "Offboard flying"),
    (86, "SET_POSITION_TARGET_GLOBAL_INT", "Offboard flying"),
    (111, "TIMESYNC", "Clock sync"),
    (
        117,
        "LOG_REQUEST_LIST",
        "List logs (ArduPilot log download over MAVLink)",
    ),
    (119, "LOG_REQUEST_DATA", "Download a log"),
    (122, "LOG_REQUEST_END", "End a log download"),
    (134, "TERRAIN_DATA", "Terrain tiles the autopilot asked for"),
    (320, "PARAM_EXT_REQUEST_READ", "Read one parameter"),
    (321, "PARAM_EXT_REQUEST_LIST", "Read all parameters"),
];

/// Commands allowed inside `COMMAND_LONG`, `COMMAND_INT`, `MISSION_ITEM` and `MISSION_ITEM_INT`:
/// (id, name, why). Nothing that changes configuration, storage, firmware or reboot state.
pub const DEFAULT_COMMANDS: &[(u32, &str, &str)] = &[
    (16, "NAV_WAYPOINT", "Fly to a point"),
    (17, "NAV_LOITER_UNLIM", "Loiter"),
    (18, "NAV_LOITER_TURNS", "Loiter for turns"),
    (19, "NAV_LOITER_TIME", "Loiter for a time"),
    (20, "NAV_RETURN_TO_LAUNCH", "Return to launch"),
    (21, "NAV_LAND", "Land"),
    (22, "NAV_TAKEOFF", "Take off"),
    (30, "NAV_CONTINUE_AND_CHANGE_ALT", "Change altitude"),
    (31, "NAV_LOITER_TO_ALT", "Loiter while changing altitude"),
    (34, "DO_ORBIT", "Orbit a point"),
    (82, "NAV_SPLINE_WAYPOINT", "Fly a spline"),
    (84, "NAV_VTOL_TAKEOFF", "VTOL takeoff"),
    (85, "NAV_VTOL_LAND", "VTOL landing"),
    (92, "NAV_GUIDED_ENABLE", "Hand over to guided control"),
    (93, "NAV_DELAY", "Wait in a mission"),
    (112, "CONDITION_DELAY", "Mission condition"),
    (113, "CONDITION_CHANGE_ALT", "Mission condition"),
    (114, "CONDITION_DISTANCE", "Mission condition"),
    (115, "CONDITION_YAW", "Turn to a heading"),
    (176, "DO_SET_MODE", "Change flight mode"),
    (177, "DO_JUMP", "Mission jump"),
    (178, "DO_CHANGE_SPEED", "Set speed"),
    (179, "DO_SET_HOME", "Set home"),
    (186, "DO_CHANGE_ALTITUDE", "Change altitude"),
    (189, "DO_LAND_START", "Start the landing sequence"),
    (192, "DO_REPOSITION", "Go to a point (PX4's 'fly here')"),
    (193, "DO_PAUSE_CONTINUE", "Pause or continue"),
    (195, "DO_SET_ROI_LOCATION", "Point at a location"),
    (
        196,
        "DO_SET_ROI_WPNEXT_OFFSET",
        "Point at the next waypoint",
    ),
    (197, "DO_SET_ROI_NONE", "Stop pointing"),
    (201, "DO_SET_ROI", "Point at a location"),
    (203, "DO_DIGICAM_CONTROL", "Take a picture"),
    (205, "DO_MOUNT_CONTROL", "Gimbal pointing"),
    (224, "DO_SET_MISSION_CURRENT", "Jump to a mission item"),
    (300, "MISSION_START", "Start the mission"),
    (400, "COMPONENT_ARM_DISARM", "Arm and disarm"),
    (410, "GET_HOME_POSITION", "Ask for the home position"),
    (511, "SET_MESSAGE_INTERVAL", "Telemetry rates"),
    (512, "REQUEST_MESSAGE", "Ask for one message"),
    (519, "REQUEST_PROTOCOL_VERSION", "Protocol version"),
    (520, "REQUEST_AUTOPILOT_CAPABILITIES", "Autopilot version"),
    (1000, "DO_GIMBAL_MANAGER_PITCHYAW", "Gimbal pointing"),
    (2000, "IMAGE_START_CAPTURE", "Start taking pictures"),
    (2001, "IMAGE_STOP_CAPTURE", "Stop taking pictures"),
    (2500, "VIDEO_START_CAPTURE", "Start video"),
    (2501, "VIDEO_STOP_CAPTURE", "Stop video"),
    (3000, "DO_VTOL_TRANSITION", "VTOL transition"),
];

/// Messages allowed only with `--allow-rtk`: raw bytes for the GPS receiver, which could
/// reconfigure it.
pub const RTK_MESSAGES: &[(u32, &str, &str)] = &[
    (
        123,
        "GPS_INJECT_DATA",
        "RTK corrections; raw bytes to the GPS receiver",
    ),
    (
        233,
        "GPS_RTCM_DATA",
        "RTK corrections; raw bytes to the GPS receiver",
    ),
];

/// Commands allowed only with `--allow-fence-rally` (the fence and rally items of a mission).
pub const FENCE_RALLY_COMMANDS: &[(u32, &str, &str)] = &[
    (5000, "NAV_FENCE_RETURN_POINT", "Geofence return point"),
    (
        5001,
        "NAV_FENCE_POLYGON_VERTEX_INCLUSION",
        "Geofence polygon corner (inside)",
    ),
    (
        5002,
        "NAV_FENCE_POLYGON_VERTEX_EXCLUSION",
        "Geofence polygon corner (outside)",
    ),
    (
        5003,
        "NAV_FENCE_CIRCLE_INCLUSION",
        "Geofence circle (inside)",
    ),
    (
        5004,
        "NAV_FENCE_CIRCLE_EXCLUSION",
        "Geofence circle (outside)",
    ),
    (5100, "NAV_RALLY_POINT", "Rally point"),
];

/// `mission_type` values: the normal mission, the geofence and the rally points. `ALL` (255)
/// only appears in a clear-all and is never allowed.
const MISSION_TYPE_MISSION: u8 = 0;
const MISSION_TYPE_FENCE: u8 = 1;
const MISSION_TYPE_RALLY: u8 = 2;

/// Mission-protocol messages and where each keeps its `mission_type` (an extension field, so
/// MAVLink 1 frames and cut-short MAVLink 2 payloads read as 0, the normal mission).
const MISSION_TYPE_AT: &[(u32, usize)] = &[
    (37, 6),  // MISSION_REQUEST_PARTIAL_LIST
    (38, 6),  // MISSION_WRITE_PARTIAL_LIST
    (39, 37), // MISSION_ITEM
    (40, 4),  // MISSION_REQUEST
    (43, 2),  // MISSION_REQUEST_LIST
    (44, 4),  // MISSION_COUNT
    (45, 2),  // MISSION_CLEAR_ALL
    (47, 3),  // MISSION_ACK
    (51, 4),  // MISSION_REQUEST_INT
    (73, 37), // MISSION_ITEM_INT
];

/// Where `param_id` (16 bytes, zero padded) starts in each payload. Fields are in wire order:
/// `PARAM_SET` puts its 4-byte `param_value` first, `PARAM_EXT_SET` starts with two bytes of target.
const PARAM_SET_ID_AT: usize = 6;
const PARAM_EXT_SET_ID_AT: usize = 2;
const PARAM_ID_LEN: usize = 16;
/// Where the 16-bit command sits: after seven 4-byte values (`COMMAND_LONG`, `COMMAND_INT`), or
/// after the sequence number that follows them (`MISSION_ITEM`, `MISSION_ITEM_INT`).
const COMMAND_AT: usize = 28;
const MISSION_ITEM_COMMAND_AT: usize = 30;

/// Parameter names that can weaken signing, matched on the start of the name without regard to
/// case: `MAV_SIGN` (reserved; no autopilot we tested has one yet) and ArduPilot's `MAV<n>_OPTIONS`
/// (bit 0 turns signing off for that serial link). They can never be allowed with `--allow-param`.
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
    /// A frame whose CRC is wrong.
    BadCrc,
    /// `SETUP_SIGNING`.
    SetupSigning,
    /// `FILE_TRANSFER_PROTOCOL`, while FTP is not allowed.
    Ftp,
    /// `PARAM_SET` or `PARAM_EXT_SET` for a signing parameter.
    SigningParam,
    /// `PARAM_SET` or `PARAM_EXT_SET` for any other name that is not allowed.
    ParamWrite,
    /// A message id that is not on the list.
    MsgNotAllowed,
    /// A command id (in a command or a mission item) that is not on the list.
    CommandNotAllowed,
    /// A mission message for the geofence or rally points (or all types).
    MissionType,
}

impl Why {
    /// A short fixed word for logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Why::Malformed => "malformed",
            Why::BadCrc => "bad_crc",
            Why::SetupSigning => "setup_signing",
            Why::Ftp => "ftp",
            Why::SigningParam => "signing_param",
            Why::ParamWrite => "param_write",
            Why::MsgNotAllowed => "msg_not_allowed",
            Why::CommandNotAllowed => "command_not_allowed",
            Why::MissionType => "mission_type",
        }
    }
}

/// A datagram the guard refused. Holds ids only, never contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Block {
    pub why: Why,
    /// The message id that was refused. `None` when the datagram is malformed.
    pub msgid: Option<u32>,
    /// The command id, for `CommandNotAllowed`.
    pub command: Option<u32>,
    /// The `mission_type`, for `MissionType`.
    pub mission_type: Option<u8>,
}

/// The guard's rules: the default lists, plus whatever the operator widened.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Guard {
    allow_ftp: bool,
    allow_rtk: bool,
    allow_fence_rally: bool,
    msgs: BTreeSet<u32>,
    commands: BTreeSet<u32>,
    params: BTreeSet<Vec<u8>>,
}

impl Guard {
    /// The default allowlists only.
    pub fn new() -> Guard {
        Guard::default()
    }

    /// Let `FILE_TRANSFER_PROTOCOL` through (log download needs it).
    pub fn allow_ftp(mut self) -> Guard {
        self.allow_ftp = true;
        self
    }

    pub fn ftp_allowed(&self) -> bool {
        self.allow_ftp
    }

    /// Let `GPS_INJECT_DATA` and `GPS_RTCM_DATA` through (RTK corrections).
    pub fn allow_rtk(mut self) -> Guard {
        self.allow_rtk = true;
        self
    }

    pub fn rtk_allowed(&self) -> bool {
        self.allow_rtk
    }

    /// Let geofence and rally mission messages (`mission_type` 1 and 2) and the fence and rally
    /// commands through. `ALL` (255) stays refused.
    pub fn allow_fence_rally(mut self) -> Guard {
        self.allow_fence_rally = true;
        self
    }

    pub fn fence_rally_allowed(&self) -> bool {
        self.allow_fence_rally
    }

    /// Also allow message `id`. Refused for `SETUP_SIGNING`, for FTP (use `allow_ftp`), for the
    /// parameter writes (use `allow_param`) and for ids the CRC table doesn't know.
    pub fn allow_msg(mut self, id: u32) -> Result<Guard, String> {
        match id {
            MSG_SETUP_SIGNING => {
                return Err("message 256 (SETUP_SIGNING) can never be allowed".into());
            }
            MSG_FILE_TRANSFER_PROTOCOL => {
                return Err("message 110 (FTP) is allowed with --allow-mavlink-ftp".into());
            }
            MSG_PARAM_SET | MSG_PARAM_EXT_SET => {
                return Err("parameter writes are allowed by name with --allow-param".into());
            }
            _ => {}
        }
        if !known_message(id) {
            return Err(format!(
                "message {id} is not in the common dialect, so its CRC can't be checked and it can't be allowed"
            ));
        }
        self.msgs.insert(id);
        Ok(self)
    }

    /// Also allow command `id` inside commands and mission items.
    pub fn allow_command(mut self, id: u32) -> Result<Guard, String> {
        if id > u32::from(u16::MAX) {
            return Err(format!("command {id} does not fit in 16 bits"));
        }
        self.commands.insert(id);
        Ok(self)
    }

    /// Allow `PARAM_SET` and `PARAM_EXT_SET` for this exact name (case-insensitive). Signing
    /// settings can't be allowed.
    pub fn allow_param(mut self, name: &str) -> Result<Guard, String> {
        let b = name.as_bytes();
        if b.is_empty() || b.len() > PARAM_ID_LEN || !b.iter().all(|c| c.is_ascii_graphic()) {
            return Err(format!(
                "{name:?} is not a parameter name (1 to 16 printable characters)"
            ));
        }
        if is_signing_param(b) {
            return Err(format!(
                "{name} can weaken signing and can never be allowed"
            ));
        }
        self.params.insert(b.to_ascii_uppercase());
        Ok(self)
    }

    /// Look at one datagram. `Ok` means every frame in it may go on.
    pub fn check(&self, datagram: &[u8]) -> Result<(), Block> {
        if datagram.is_empty() {
            return Err(block(Why::Malformed, None, None));
        }
        let mut rest = datagram;
        while !rest.is_empty() {
            let frame = Frame::parse(rest).ok_or_else(|| block(Why::Malformed, None, None))?;
            self.check_frame(&frame)?;
            rest = &rest[frame.total..];
        }
        Ok(())
    }

    fn check_frame(&self, f: &Frame) -> Result<(), Block> {
        let id = f.msgid;
        let deny = |why| Err(block(why, Some(id), None));
        if !f.length_ok() {
            return Err(block(Why::Malformed, None, None));
        }
        match id {
            MSG_SETUP_SIGNING => return deny(Why::SetupSigning),
            MSG_FILE_TRANSFER_PROTOCOL if !self.allow_ftp => return deny(Why::Ftp),
            MSG_FILE_TRANSFER_PROTOCOL => {}
            MSG_PARAM_SET | MSG_PARAM_EXT_SET => {
                let at = if id == MSG_PARAM_SET {
                    PARAM_SET_ID_AT
                } else {
                    PARAM_EXT_SET_ID_AT
                };
                let name = param_id(f.payload, at);
                if is_signing_param(&name) {
                    return deny(Why::SigningParam);
                }
                if !self
                    .params
                    .contains(&param_name(&name).to_ascii_uppercase())
                {
                    return deny(Why::ParamWrite);
                }
            }
            _ if self.msgs.contains(&id)
                || DEFAULT_MESSAGES.iter().any(|m| m.0 == id)
                || (self.allow_rtk && RTK_MESSAGES.iter().any(|m| m.0 == id)) => {}
            _ => return deny(Why::MsgNotAllowed),
        }
        if let Some(&(_, at)) = MISSION_TYPE_AT.iter().find(|m| m.0 == id) {
            let t = f.payload.get(at).copied().unwrap_or(0);
            let ok = match t {
                MISSION_TYPE_MISSION => true,
                MISSION_TYPE_FENCE | MISSION_TYPE_RALLY => self.allow_fence_rally,
                _ => false,
            };
            if !ok {
                return Err(Block {
                    mission_type: Some(t),
                    ..block(Why::MissionType, Some(id), None)
                });
            }
        }
        let at = match id {
            MSG_COMMAND_LONG | MSG_COMMAND_INT => Some(COMMAND_AT),
            MSG_MISSION_ITEM | MSG_MISSION_ITEM_INT => Some(MISSION_ITEM_COMMAND_AT),
            _ => None,
        };
        if let Some(at) = at {
            let cmd = u32::from(u16_at(f.payload, at));
            if !self.commands.contains(&cmd)
                && !DEFAULT_COMMANDS.iter().any(|c| c.0 == cmd)
                && !(self.allow_fence_rally && FENCE_RALLY_COMMANDS.iter().any(|c| c.0 == cmd))
            {
                return Err(block(Why::CommandNotAllowed, Some(id), Some(cmd)));
            }
        }
        if !f.crc_ok() {
            return deny(Why::BadCrc);
        }
        Ok(())
    }
}

/// The frame boundaries of a datagram as `(message id, frame length)`, or `None` if it is not
/// made only of whole frames. Shape only: no CRC, no rules. For the differential test.
pub fn frames(datagram: &[u8]) -> Option<Vec<(u32, usize)>> {
    let mut rest = datagram;
    let mut out = Vec::new();
    while !rest.is_empty() {
        let f = Frame::parse(rest)?;
        out.push((f.msgid, f.total));
        rest = &rest[f.total..];
    }
    (!out.is_empty()).then_some(out)
}

fn block(why: Why, msgid: Option<u32>, command: Option<u32>) -> Block {
    Block {
        why,
        msgid,
        command,
        mission_type: None,
    }
}

/// Does the CRC table (the `mavlink` crate's common dialect) know this message id?
fn known_message(id: u32) -> bool {
    MavMessage::extra_crc(id) != 0
}

/// One frame's shape: how long it is, its message id and its payload.
struct Frame<'a> {
    v1: bool,
    total: usize,
    msgid: u32,
    payload: &'a [u8],
    /// The bytes the CRC covers (everything after the start byte up to the CRC) and the CRC.
    covered: &'a [u8],
    crc: u16,
}

impl<'a> Frame<'a> {
    /// Read the frame at the start of `buf`. `None` if it is cut short, has an unknown start
    /// byte, or sets an incompatibility flag we don't know (the spec says such a frame must be
    /// rejected, and its length can't be trusted). The CRC is checked later, by [`Frame::crc_ok`].
    fn parse(buf: &'a [u8]) -> Option<Frame<'a>> {
        let (header, len, msgid, signed) = match *buf.first()? {
            V1_START => {
                let len = usize::from(*buf.get(1)?);
                if buf.len() < V1_HEADER {
                    return None;
                }
                (V1_HEADER, len, u32::from(buf[5]), 0)
            }
            V2_START => {
                if buf.len() < V2_HEADER {
                    return None;
                }
                let incompat = buf[2];
                if incompat & !INCOMPAT_SIGNED != 0 {
                    return None;
                }
                let signed = if incompat & INCOMPAT_SIGNED != 0 {
                    SIGNATURE_LEN
                } else {
                    0
                };
                let id = u32::from(buf[7]) | u32::from(buf[8]) << 8 | u32::from(buf[9]) << 16;
                (V2_HEADER, usize::from(buf[1]), id, signed)
            }
            _ => return None,
        };
        let crc_at = header + len;
        let total = crc_at + CRC_LEN + signed;
        if buf.len() < total {
            return None;
        }
        Some(Frame {
            v1: buf[0] == V1_START,
            total,
            msgid,
            payload: &buf[header..crc_at],
            covered: &buf[1..crc_at],
            crc: u16::from_le_bytes([buf[crc_at], buf[crc_at + 1]]),
        })
    }

    /// Is the payload length one the message can have? MAVLink 1 sends exactly the base length;
    /// MAVLink 2 sends at most the longest length (it cuts trailing zero bytes). Ids that are
    /// not in the length table are not checked here (the CRC check still needs the crate to know them).
    fn length_ok(&self) -> bool {
        match crate::mavlens::LENGTHS.binary_search_by_key(&self.msgid, |l| l.0) {
            Ok(i) => {
                let (_, base, max) = crate::mavlens::LENGTHS[i];
                if self.v1 {
                    self.payload.len() == usize::from(base)
                } else {
                    self.payload.len() <= usize::from(max)
                }
            }
            Err(_) => true,
        }
    }

    /// Is the CRC right for this message id (CRC_EXTRA from the common dialect)? An id the table
    /// doesn't know has no CRC_EXTRA, so it is never "ok".
    fn crc_ok(&self) -> bool {
        known_message(self.msgid)
            && mavlink::calculate_crc(self.covered, MavMessage::extra_crc(self.msgid)) == self.crc
    }
}

fn u16_at(payload: &[u8], at: usize) -> u16 {
    let lo = payload.get(at).copied().unwrap_or(0);
    let hi = payload.get(at + 1).copied().unwrap_or(0);
    u16::from(lo) | u16::from(hi) << 8
}

/// The 16-byte `param_id` at `at` in a payload. MAVLink 2 drops trailing zero bytes from a
/// payload, so missing bytes read as zero.
fn param_id(payload: &[u8], at: usize) -> [u8; PARAM_ID_LEN] {
    let mut id = [0u8; PARAM_ID_LEN];
    let have = payload.get(at..).unwrap_or(&[]);
    let n = have.len().min(PARAM_ID_LEN);
    id[..n].copy_from_slice(&have[..n]);
    id
}

/// The name part of a `param_id`: up to the first zero byte.
fn param_name(id: &[u8]) -> &[u8] {
    let end = id.iter().position(|&b| b == 0).unwrap_or(id.len());
    &id[..end]
}

/// Does this parameter name (as sent: up to 16 bytes, zero padded) belong to a setting that can
/// weaken signing?
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

/// The highest signature timestamp (MAVLink units) among the signed MAVLink 2
/// frames of a datagram **whose signature verifies under `key`**, or 0, never
/// above `clock + ahead`. Meant for a datagram the guard already passed; it
/// reads lengths and the timestamp and stops at anything odd. It is only a
/// floor for the next `SETUP_SIGNING` initial timestamp: a frame that does
/// not verify is not believed (anyone on the link can write any number in
/// it), and one that does can raise the floor no further than the cap.
pub fn max_verified_timestamp(datagram: &[u8], key: &[u8; 32], clock: u64, ahead: u64) -> u64 {
    use mavlink::{MAVLinkV2MessageRaw, consts};
    let cap = clock.saturating_add(ahead);
    let (mut pos, mut best) = (0usize, 0u64);
    while pos + 12 <= datagram.len() {
        if datagram[pos] != V2_START {
            break;
        }
        let len = datagram[pos + 1] as usize;
        let signed = datagram[pos + 2] & INCOMPAT_SIGNED != 0;
        let end = pos + 10 + len + 2 + if signed { SIGNATURE_LEN } else { 0 };
        if end > datagram.len() {
            break;
        }
        if signed {
            let mut raw = MAVLinkV2MessageRaw::new();
            raw.as_mut_slice()[..end - pos].copy_from_slice(&datagram[pos..end]);
            let mut sig = [0u8; consts::v2::SIGNATURE_VALUE_SIZE];
            raw.calculate_signature(key, &mut sig);
            // Not constant-time: the signature is public on the wire.
            if sig == raw.signature_value() {
                best = best.max(raw.signature_timestamp().min(cap));
            }
        }
        pos = end;
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    fn crc_for(id: u32, covered: &[u8]) -> [u8; 2] {
        mavlink::calculate_crc(covered, MavMessage::extra_crc(id)).to_le_bytes()
    }

    /// A MAVLink 2 frame with a correct CRC (and a made-up signature if `signed`).
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
        let crc = crc_for(msgid, &f[1..]);
        f.extend_from_slice(&crc);
        if signed {
            f.extend_from_slice(&[0x5A; SIGNATURE_LEN]);
        }
        f
    }

    /// A MAVLink 1 frame. MAVLink 1 always sends the message's base length, so the payload is cut
    /// or zero-padded to it.
    fn v1(msgid: u8, payload: &[u8]) -> Vec<u8> {
        let base = crate::mavlens::LENGTHS
            .iter()
            .find(|l| l.0 == u32::from(msgid))
            .map_or(payload.len(), |l| usize::from(l.1));
        let mut payload = payload.to_vec();
        payload.resize(base, 0);
        let payload = &payload[..];
        let mut f = vec![V1_START, payload.len() as u8, 3, 255, 190, msgid];
        f.extend_from_slice(payload);
        let crc = crc_for(u32::from(msgid), &f[1..]);
        f.extend_from_slice(&crc);
        f
    }

    /// What MAVLink 2 sends: trailing zero bytes removed (but at least one byte).
    fn trimmed(mut p: Vec<u8>) -> Vec<u8> {
        while p.len() > 1 && p.last() == Some(&0) {
            p.pop();
        }
        p
    }

    /// A payload with `command` where the given message keeps it.
    fn with_command(msgid: u32, command: u32) -> Vec<u8> {
        let at = if msgid == 39 || msgid == 73 {
            MISSION_ITEM_COMMAND_AT
        } else {
            COMMAND_AT
        };
        let mut p = vec![0u8; 40];
        p[at..at + 2].copy_from_slice(&(command as u16).to_le_bytes());
        trimmed(p)
    }

    fn param_set(name: &str) -> Vec<u8> {
        let mut p = 1.0f32.to_le_bytes().to_vec();
        p.extend_from_slice(&[1, 1]);
        let mut id = name.as_bytes().to_vec();
        id.resize(PARAM_ID_LEN, 0);
        p.extend_from_slice(&id);
        p.push(9);
        p
    }

    fn param_ext_set(name: &str) -> Vec<u8> {
        let mut p = vec![1, 1];
        let mut id = name.as_bytes().to_vec();
        id.resize(PARAM_ID_LEN, 0);
        p.extend_from_slice(&id);
        p.resize(146, 0);
        p.push(2);
        p
    }

    fn guard() -> Guard {
        Guard::new()
    }

    fn blocked(d: &[u8]) -> Block {
        guard().check(d).unwrap_err()
    }

    fn malformed() -> Block {
        block(Why::Malformed, None, None)
    }

    fn payload_for(id: u32) -> Vec<u8> {
        match id {
            75 | 76 | 39 | 73 => with_command(id, 400),
            _ => vec![1],
        }
    }

    // --- the tables -----------------------------------------------------------------------

    #[test]
    fn the_tables_are_sorted_unique_and_known_to_the_crc_table() {
        for t in [DEFAULT_MESSAGES, DEFAULT_COMMANDS] {
            assert!(t.windows(2).all(|w| w[0].0 < w[1].0), "sorted and unique");
        }
        for (id, name, _) in DEFAULT_MESSAGES {
            assert!(
                known_message(*id),
                "{name} ({id}) has no CRC_EXTRA in the crate"
            );
            assert_ne!(*id, MSG_SETUP_SIGNING);
            assert_ne!(*id, MSG_FILE_TRANSFER_PROTOCOL);
            assert_ne!(*id, MSG_PARAM_SET);
            assert_ne!(*id, MSG_PARAM_EXT_SET);
        }
    }

    #[test]
    fn the_link_doc_lists_every_entry() {
        let doc = include_str!("../docs/oasa-sec-v0-link.md");
        for (id, name, why) in DEFAULT_MESSAGES
            .iter()
            .chain(DEFAULT_COMMANDS)
            .chain(RTK_MESSAGES)
            .chain(FENCE_RALLY_COMMANDS)
        {
            assert!(
                doc.contains(&format!("| {id} | `{name}` |")),
                "{id} {name} is missing from the link doc"
            );
            assert!(
                doc.contains(why),
                "the reason for {name} differs in the link doc: {why}"
            );
        }
    }

    #[test]
    fn unsafe_things_are_not_on_the_lists() {
        for id in [
            256, 110, 23, 323, 126, /* SERIAL_CONTROL */
            121, /* LOG_ERASE */
            33, 253, 123, 233,
        ] {
            assert!(DEFAULT_MESSAGES.iter().all(|m| m.0 != id), "message {id}");
        }
        // Configuration, storage, calibration, reboot, parameters, servos, flight termination.
        for id in [
            180,
            181,
            183,
            185,
            209,
            241,
            242,
            245,
            246,
            247,
            520 + 1000,
            42000,
            42006,
        ] {
            assert!(DEFAULT_COMMANDS.iter().all(|c| c.0 != id), "command {id}");
        }
    }

    // --- messages -------------------------------------------------------------------------

    #[test]
    fn every_default_message_passes_in_every_framing() {
        for (id, name, _) in DEFAULT_MESSAGES {
            let p = payload_for(*id);
            assert!(guard().check(&v2(*id, &p, false)).is_ok(), "{name} v2");
            assert!(guard().check(&v2(*id, &p, true)).is_ok(), "{name} signed");
            if *id < 256 {
                assert!(guard().check(&v1(*id as u8, &p)).is_ok(), "{name} v1");
            }
            assert!(
                guard().check(&v2(*id, &[], false)).is_ok() || matches!(*id, 39 | 73 | 75 | 76),
                "{name} empty"
            );
        }
    }

    #[test]
    fn messages_not_on_the_list_are_dropped() {
        for id in [
            1u32,
            24,
            30,
            33,
            126,
            121,
            140,
            253,
            258,
            268,
            282,
            11000,
            0x00FF_FFFF,
        ] {
            let b = blocked(&v2(id, &[1], false));
            assert_eq!((b.why, b.msgid), (Why::MsgNotAllowed, Some(id)), "{id}");
        }
        assert_eq!(blocked(&v1(30, &[0; 28])).why, Why::MsgNotAllowed);
    }

    #[test]
    fn the_message_id_is_24_bits() {
        // 0x010000 | 0 is not HEARTBEAT.
        assert_eq!(
            blocked(&v2(0x01_0000, &[0; 9], false)).why,
            Why::MsgNotAllowed
        );
        assert_eq!(
            blocked(&v2(0x01_0000 | 76, &[0; 33], false)).why,
            Why::MsgNotAllowed
        );
        assert!(guard().check(&v2(0, &[0; 9], false)).is_ok());
    }

    #[test]
    fn setup_signing_is_always_blocked() {
        for signed in [false, true] {
            let b = blocked(&v2(256, &[0; 42], signed));
            assert_eq!((b.why, b.msgid), (Why::SetupSigning, Some(256)));
        }
        assert_eq!(
            blocked(&v2(256, &trimmed(vec![0; 42]), true)).why,
            Why::SetupSigning
        );
        // Not even with a wrong CRC, and not even widened.
        assert!(guard().allow_msg(256).is_err());
        assert!(
            guard()
                .allow_ftp()
                .check(&v2(256, &[0; 42], false))
                .is_err()
        );
    }

    #[test]
    fn ftp_is_dropped_unless_allowed() {
        let f = v2(110, &[0; 254], false);
        let b = blocked(&f);
        assert_eq!((b.why, b.msgid), (Why::Ftp, Some(110)));
        assert_eq!(blocked(&v2(110, &[0; 254], true)).why, Why::Ftp);
        assert_eq!(blocked(&v1(110, &[0; 5])).why, Why::Ftp);
        let g = guard().allow_ftp();
        assert!(g.ftp_allowed());
        assert!(g.check(&f).is_ok());
        assert!(g.check(&v1(110, &[0; 5])).is_ok());
        // Allowed FTP still needs a good CRC.
        let mut bad = f.clone();
        let n = bad.len();
        bad[n - 1] ^= 1;
        assert_eq!(g.check(&bad).unwrap_err().why, Why::BadCrc);
        assert!(guard().allow_msg(110).is_err());
    }

    #[test]
    fn allow_msg_widens_the_list() {
        let f = v2(33, &[0; 28], false); // GLOBAL_POSITION_INT
        assert_eq!(blocked(&f).why, Why::MsgNotAllowed);
        let g = guard().allow_msg(33).unwrap();
        assert!(g.check(&f).is_ok());
        assert_eq!(
            blocked(&f).why,
            Why::MsgNotAllowed,
            "the default guard is unchanged"
        );
        // An id the crate doesn't know can't be CRC-checked, so it can't be allowed.
        assert!(guard().allow_msg(11000).is_err());
        assert!(guard().allow_msg(0x00FF_FFFF).is_err());
        assert!(guard().allow_msg(23).is_err());
        assert!(guard().allow_msg(323).is_err());
    }

    // --- parameters -----------------------------------------------------------------------

    #[test]
    fn parameter_writes_are_dropped_by_default() {
        for name in ["MPC_XY_VEL_MAX", "WP_SPD", "SERIAL1_BAUD", ""] {
            let b = blocked(&v2(23, &param_set(name), false));
            assert_eq!((b.why, b.msgid), (Why::ParamWrite, Some(23)), "{name}");
            assert_eq!(blocked(&v1(23, &param_set(name))).why, Why::ParamWrite);
            assert_eq!(
                blocked(&v2(23, &trimmed(param_set(name)), true)).why,
                Why::ParamWrite
            );
            let b = blocked(&v2(323, &param_ext_set(name), false));
            assert_eq!((b.why, b.msgid), (Why::ParamWrite, Some(323)), "{name}");
        }
    }

    #[test]
    fn allow_param_allows_exactly_that_name() {
        let g = guard()
            .allow_param("MPC_XY_VEL_MAX")
            .unwrap()
            .allow_param("wp_spd")
            .unwrap();
        for name in ["MPC_XY_VEL_MAX", "mpc_xy_vel_max", "WP_SPD"] {
            assert!(g.check(&v2(23, &param_set(name), false)).is_ok(), "{name}");
            assert!(
                g.check(&v2(23, &trimmed(param_set(name)), true)).is_ok(),
                "{name} trimmed"
            );
            assert!(g.check(&v1(23, &param_set(name))).is_ok(), "{name} v1");
            assert!(
                g.check(&v2(323, &param_ext_set(name), false)).is_ok(),
                "{name} ext"
            );
        }
        for name in [
            "MPC_XY_VEL_MA",
            "MPC_XY_VEL_MAXX",
            "WP_SPD2",
            "MPC_XY",
            "",
            "OTHER",
        ] {
            assert_eq!(
                g.check(&v2(23, &param_set(name), false)).unwrap_err().why,
                Why::ParamWrite,
                "{name}"
            );
        }
        // A bad CRC is still a bad CRC.
        let mut f = v2(23, &param_set("WP_SPD"), false);
        f[12] ^= 1;
        assert_eq!(g.check(&f).unwrap_err().why, Why::BadCrc);
        // Names longer than 16 characters can't be sent.
        assert!(guard().allow_param("ABCDEFGHIJKLMNOPQ").is_err());
        assert!(guard().allow_param("").is_err());
        assert!(guard().allow_param("A B").is_err());
    }

    #[test]
    fn signing_parameters_can_never_be_allowed() {
        for name in [
            "MAV_SIGN_CFG",
            "mav_sign",
            "MAV1_OPTIONS",
            "MAV2_OPTIONS",
            "mav10_options",
        ] {
            assert!(guard().allow_param(name).is_err(), "{name}");
            let b = blocked(&v2(23, &param_set(name), false));
            assert_eq!((b.why, b.msgid), (Why::SigningParam, Some(23)), "{name}");
            assert_eq!(
                blocked(&v2(23, &trimmed(param_set(name)), false)).why,
                Why::SigningParam
            );
            assert_eq!(
                blocked(&v2(323, &param_ext_set(name), false)).why,
                Why::SigningParam
            );
        }
        assert!(is_signing_param(b"MAV_SIGN"));
        assert!(is_signing_param(b"MAV7_OPTIONS\0\0\0\0"));
        for ok in [
            &b""[..],
            b"MAV_SIG",
            b"MAV_OPTIONS",
            b"MAV123_OPTIONS",
            b"MAVX_OPTIONS",
            b"MAV2_OPTION",
            b"XMAV_SIGN",
        ] {
            assert!(!is_signing_param(ok), "{ok:?}");
        }
    }

    #[test]
    fn param_names_only_count_in_the_param_field() {
        // The name at the start of a PARAM_SET payload is not where the name is.
        let g = guard().allow_param("WP_SPD").unwrap();
        let mut p = b"WP_SPD\0\0\0\0\0\0\0\0\0\0".to_vec();
        p.resize(23, 0);
        assert_eq!(
            g.check(&v2(23, &p, false)).unwrap_err().why,
            Why::ParamWrite
        );
        // A payload too short to hold a name reads as an empty name.
        assert_eq!(
            blocked(&v2(23, &[0, 0, 0x80, 0x3F], false)).why,
            Why::ParamWrite
        );
        assert_eq!(blocked(&v2(323, &[], false)).why, Why::ParamWrite);
    }

    // --- commands -------------------------------------------------------------------------

    #[test]
    fn every_default_command_passes_in_every_message_that_carries_one() {
        for (cmd, name, _) in DEFAULT_COMMANDS {
            for id in [75u32, 76, 39, 73] {
                let p = with_command(id, *cmd);
                assert!(guard().check(&v2(id, &p, false)).is_ok(), "{name} in {id}");
                assert!(
                    guard().check(&v2(id, &p, true)).is_ok(),
                    "{name} in {id} signed"
                );
            }
        }
    }

    #[test]
    fn other_commands_are_dropped_with_their_id() {
        // Reboot, storage, calibration, sensor offsets, set parameter, servo, relay, flight
        // termination, motor test, fence enable, a command nobody has heard of.
        for cmd in [
            246u32, 245, 241, 242, 180, 183, 181, 185, 209, 207, 42000, 0, 1, 65535,
        ] {
            for id in [75u32, 76, 39, 73] {
                let b = blocked(&v2(id, &with_command(id, cmd), false));
                assert_eq!(
                    (b.why, b.msgid, b.command),
                    (Why::CommandNotAllowed, Some(id), Some(cmd)),
                    "{cmd} in {id}"
                );
            }
        }
        assert_eq!(blocked(&v1(76, &with_command(76, 246))).command, Some(246));
    }

    #[test]
    fn the_command_is_read_from_the_right_place() {
        // COMMAND_LONG: 0x0190 = 400 (arm) is allowed; the same two bytes two places earlier are not it.
        let mut p = vec![0u8; 33];
        p[26..28].copy_from_slice(&400u16.to_le_bytes());
        assert_eq!(blocked(&v2(76, &p, false)).command, Some(0));
        // A command whose high byte is set: 0x0190 | 0x0100 = 656 is not 400.
        assert_eq!(
            blocked(&v2(76, &with_command(76, 400 | 0x1000), false)).command,
            Some(4496)
        );
        // Mission items keep the command after the sequence number.
        let mut m = vec![0u8; 38];
        m[28..30].copy_from_slice(&400u16.to_le_bytes()); // that is the sequence number
        assert_eq!(blocked(&v2(73, &m, false)).command, Some(0));
        // A payload cut before the command reads as command 0.
        assert_eq!(blocked(&v2(76, &[1, 2, 3], false)).command, Some(0));
    }

    #[test]
    fn allow_command_widens_the_command_list() {
        let f = v2(76, &with_command(76, 185), false);
        assert_eq!(blocked(&f).command, Some(185));
        let g = guard().allow_command(185).unwrap();
        assert!(g.check(&f).is_ok());
        assert!(g.check(&v2(73, &with_command(73, 185), false)).is_ok());
        assert_eq!(
            blocked(&f).command,
            Some(185),
            "the default guard is unchanged"
        );
        assert!(guard().allow_command(70000).is_err());
    }

    // --- CRC and shape -----------------------------------------------------------------------

    #[test]
    fn a_wrong_crc_drops_the_datagram() {
        for f in [v2(0, &[1; 9], false), v2(0, &[1; 9], true), v1(0, &[1; 9])] {
            assert!(guard().check(&f).is_ok());
            let body_end = if f[0] == V1_START {
                f.len() - 2
            } else if f[2] & 1 == 1 {
                f.len() - SIGNATURE_LEN - 2
            } else {
                f.len() - 2
            };
            for at in [body_end, body_end + 1, 4, 8] {
                let mut g = f.clone();
                g[at] ^= 0x40;
                let b = guard().check(&g);
                assert!(b.is_err(), "flipping byte {at} must be noticed");
            }
        }
        let mut f = v2(0, &[1; 9], false);
        f[11] ^= 1; // payload
        assert_eq!(blocked(&f).why, Why::BadCrc);
    }

    #[test]
    fn the_crc_uses_the_messages_own_crc_extra() {
        // A frame whose CRC was made with another message's CRC_EXTRA is wrong.
        let mut f = v2(0, &[1; 9], false);
        let n = f.len();
        let wrong = mavlink::calculate_crc(&f[1..n - 2], MavMessage::extra_crc(0).wrapping_add(1));
        f[n - 2..].copy_from_slice(&wrong.to_le_bytes());
        assert_eq!(blocked(&f).why, Why::BadCrc);
    }

    #[test]
    fn the_signature_is_not_part_of_the_crc() {
        let mut f = v2(0, &[1; 9], true);
        let n = f.len();
        f[n - 1] ^= 0xFF; // the guard doesn't verify signatures: the autopilot does
        assert!(guard().check(&f).is_ok());
    }

    #[test]
    fn batched_frames_are_each_checked() {
        let hb = v2(0, &[1; 9], false);
        let cmd = v2(76, &with_command(76, 400), true);
        let ping = v1(4, &[0; 14]);
        let mut d = hb.clone();
        d.extend(&cmd);
        d.extend(&ping);
        assert!(guard().check(&d).is_ok());
        // One refused frame anywhere stops the whole datagram.
        let bad: Vec<(Vec<u8>, Why)> = vec![
            (v2(256, &[0; 42], false), Why::SetupSigning),
            (v2(33, &[0; 28], false), Why::MsgNotAllowed),
            (
                v2(76, &with_command(76, 246), false),
                Why::CommandNotAllowed,
            ),
            (v2(23, &param_set("WP_SPD"), false), Why::ParamWrite),
        ];
        for (frame, why) in bad {
            for at in 0..=3 {
                let mut frames = vec![hb.clone(), cmd.clone(), ping.clone()];
                frames.insert(at, frame.clone());
                assert_eq!(blocked(&frames.concat()).why, why, "at {at}");
            }
        }
    }

    #[test]
    fn anything_but_whole_frames_is_malformed() {
        let hb = v2(0, &[1; 9], false);
        let mut d = hb.clone();
        d.push(0x00); // a stray byte after
        assert_eq!(blocked(&d), malformed());
        let mut d = vec![0x00];
        d.extend(&hb); // a stray byte before
        assert_eq!(blocked(&d), malformed());
        let mut d = hb.clone();
        d.extend_from_slice(&[V2_START, 200, 0, 0, 1]); // a second frame cut short
        assert_eq!(blocked(&d), malformed());
        for d in [
            &b"hello"[..],
            &[0xFF; 40][..],
            &[0xFC, 0, 0, 0][..],
            &[V2_START][..],
            &[V1_START][..],
            &[V1_START, 0][..],
            &[],
        ] {
            assert_eq!(blocked(d), malformed(), "{d:?}");
        }
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
        }
    }

    #[test]
    fn the_signed_flag_adds_thirteen_bytes() {
        let mut f = v2(0, &[1; 9], true);
        f.truncate(f.len() - SIGNATURE_LEN);
        assert_eq!(blocked(&f), malformed());
        // The same bytes with the flag off are a whole unsigned frame, but the flag is covered by the CRC.
        f[2] = 0;
        assert_eq!(blocked(&f).why, Why::BadCrc);
        let mut g = v2(0, &[1; 9], false);
        g[2] = INCOMPAT_SIGNED;
        assert_eq!(blocked(&g), malformed());
    }

    #[test]
    fn unknown_incompat_flags_are_malformed() {
        for flags in [0x02u8, 0x80, 0x03, 0xFF] {
            let mut f = v2(0, &[1; 9], false);
            f[2] = flags;
            f.extend_from_slice(&[0; 13]);
            assert_eq!(blocked(&f), malformed(), "flags {flags:#x}");
        }
    }

    #[test]
    fn long_payloads_work() {
        let big = vec![7u8; 182];
        let g = guard().allow_rtk();
        assert!(g.check(&v2(233, &big, false)).is_ok()); // GPS_RTCM_DATA, its longest
        assert!(g.check(&v2(233, &big, true)).is_ok());
        let mut d = v2(233, &big, true);
        d.extend(v2(233, &big, true));
        assert!(g.check(&d).is_ok());
        d.pop();
        assert_eq!(g.check(&d).unwrap_err(), malformed());
    }

    #[test]
    fn limits_of_the_widening_calls() {
        assert!(!guard().ftp_allowed());
        assert!(guard().allow_ftp().ftp_allowed());
        assert!(guard().allow_command(65535).is_ok());
        assert!(guard().allow_command(65536).is_err());
        assert!(guard().allow_param("ABCDEFGHIJKLMNOP").is_ok()); // exactly 16
        assert!(guard().allow_param("ABCDEFGHIJKLMNOPQ").is_err());
        assert!(guard().allow_param("A").is_ok());
    }

    #[test]
    fn frames_reports_boundaries_and_ids() {
        let a = v2(0, &[1; 9], false);
        let b = v2(76, &with_command(76, 400), true);
        let c = v1(4, &[0; 14]);
        let d = [a.clone(), b.clone(), c.clone()].concat();
        assert_eq!(
            frames(&d),
            Some(vec![(0, a.len()), (76, b.len()), (4, c.len())])
        );
        assert_eq!(frames(&a), Some(vec![(0, a.len())]));
        assert_eq!(
            frames(&v2(0x01_02_03, &[], false)),
            Some(vec![(0x01_02_03, 12)])
        );
        assert_eq!(frames(&[]), None);
        assert_eq!(frames(&a[..a.len() - 1]), None);
        assert_eq!(frames(&[a.clone(), vec![0]].concat()), None);
        // Shape only: a wrong CRC still has frame boundaries.
        let mut bad = a.clone();
        let n = bad.len();
        bad[n - 1] ^= 1;
        assert_eq!(frames(&bad), Some(vec![(0, a.len())]));
    }

    /// A payload with `mission_type` `t` at `at`, as MAVLink 2 would send it (trailing zeros cut).
    fn mission_payload(id: u32, at: usize, t: u8) -> Vec<u8> {
        let mut x = vec![0u8; at + 1];
        x[at] = t;
        if id == 39 || id == 73 {
            x[MISSION_ITEM_COMMAND_AT..MISSION_ITEM_COMMAND_AT + 2]
                .copy_from_slice(&16u16.to_le_bytes());
        }
        trimmed(x)
    }

    #[test]
    fn mission_messages_are_for_the_normal_mission_only() {
        for &(id, at) in MISSION_TYPE_AT {
            let q = |t| v2(id, &mission_payload(id, at, t), false);
            assert!(guard().check(&q(0)).is_ok(), "{id} type 0");
            for t in [1u8, 2, 3, 100, 255] {
                let b = blocked(&q(t));
                assert_eq!(
                    (b.why, b.msgid, b.mission_type),
                    (Why::MissionType, Some(id), Some(t)),
                    "{id} type {t}"
                );
            }
            // Fence and rally only with the flag; 255 and the rest never.
            let g = guard().allow_fence_rally();
            assert!(g.check(&q(1)).is_ok(), "{id} fence");
            assert!(g.check(&q(2)).is_ok(), "{id} rally");
            for t in [3u8, 255] {
                assert_eq!(
                    g.check(&q(t)).unwrap_err().why,
                    Why::MissionType,
                    "{id} type {t}"
                );
            }
            // A bad CRC is still caught after the type check passes.
            let mut bad = q(0);
            let n = bad.len();
            bad[n - 1] ^= 1;
            assert_eq!(blocked(&bad).why, Why::BadCrc, "{id}");
        }
    }

    #[test]
    fn the_mission_type_is_read_from_the_right_place() {
        // MISSION_CLEAR_ALL: target_system, target_component, mission_type.
        assert_eq!(
            blocked(&v2(45, &[0, 0, 255], false)).mission_type,
            Some(255)
        );
        assert!(guard().check(&v2(45, &[255, 255], false)).is_ok()); // type cut = 0
        // MISSION_COUNT 0 for the rally points erases them: count(2), targets(2), type.
        assert_eq!(
            blocked(&v2(44, &[0, 0, 1, 1, 2], false)).mission_type,
            Some(2)
        );
        // MISSION_ACK: targets(2), type, mission_type.
        assert!(guard().check(&v2(47, &[1, 1, 5], false)).is_ok());
        assert_eq!(blocked(&v2(47, &[1, 1, 0, 1], false)).mission_type, Some(1));
        // MISSION_SET_CURRENT has no mission_type.
        assert!(guard().check(&v2(41, &[1, 0, 1, 1], false)).is_ok());
        // MAVLink 1 cannot carry the field: it is the normal mission.
        assert!(guard().check(&v1(45, &[1, 1])).is_ok());
        assert_eq!(blocked(&v2(45, &[1, 1, 1], true)).why, Why::MissionType);
    }

    #[test]
    fn fence_and_rally_commands_need_the_flag() {
        for (cmd, name, _) in FENCE_RALLY_COMMANDS {
            for id in [39u32, 73, 75, 76] {
                let f = v2(id, &with_command(id, *cmd), false);
                let b = blocked(&f);
                assert_eq!(
                    (b.why, b.command),
                    (Why::CommandNotAllowed, Some(*cmd)),
                    "{name} in {id}"
                );
                assert!(
                    guard().allow_fence_rally().check(&f).is_ok(),
                    "{name} in {id} with the flag"
                );
            }
        }
        assert!(!guard().fence_rally_allowed());
        assert!(guard().allow_fence_rally().fence_rally_allowed());
        assert!(!guard().rtk_allowed());
        // DO_FENCE_ENABLE (207) is not part of the flag.
        let f = v2(76, &with_command(76, 207), false);
        assert_eq!(
            guard().allow_fence_rally().check(&f).unwrap_err().command,
            Some(207)
        );
    }

    #[test]
    fn rtk_messages_need_the_flag() {
        for (id, name, _) in RTK_MESSAGES {
            assert!(known_message(*id), "{name}");
            let f = v2(*id, &[1, 2, 3], false);
            let b = blocked(&f);
            assert_eq!((b.why, b.msgid), (Why::MsgNotAllowed, Some(*id)), "{name}");
            assert!(guard().allow_rtk().check(&f).is_ok(), "{name}");
            assert!(guard().allow_rtk().rtk_allowed());
            assert!(
                guard().allow_msg(*id).unwrap().check(&f).is_ok(),
                "{name} by id"
            );
        }
        // The flag opens those two and nothing else.
        let g = guard().allow_rtk();
        assert_eq!(
            g.check(&v2(33, &[1], false)).unwrap_err().why,
            Why::MsgNotAllowed
        );
        assert_eq!(
            g.check(&v2(24, &[1], false)).unwrap_err().why,
            Why::MsgNotAllowed
        );
        assert!(DEFAULT_MESSAGES.iter().all(|m| m.0 != 123 && m.0 != 233));
    }

    #[test]
    fn the_length_table_matches_the_crate() {
        use mavlink::MavlinkVersion;
        assert!(crate::mavlens::LENGTHS.windows(2).all(|w| w[0].0 < w[1].0));
        for &(id, base, max) in crate::mavlens::LENGTHS {
            let m = MavMessage::default_message_from_id(id)
                .unwrap_or_else(|| panic!("{id} unknown to the crate"));
            let mut buf = [0u8; 300];
            assert_eq!(
                m.ser(MavlinkVersion::V1, &mut buf),
                usize::from(base),
                "base length of {id}"
            );
            assert!(max >= base);
        }
        // Every message the guard may let through has a length.
        let listed = |id: u32| crate::mavlens::LENGTHS.iter().any(|l| l.0 == id);
        for (id, name, _) in DEFAULT_MESSAGES.iter().chain(RTK_MESSAGES) {
            assert!(listed(*id), "{name} has no length");
        }
        assert!(listed(MSG_FILE_TRANSFER_PROTOCOL) && listed(MSG_SETUP_SIGNING));
    }

    #[test]
    fn payloads_longer_than_the_message_are_malformed() {
        // MAVLink 2: at most the longest length (HEARTBEAT 9; COMMAND_LONG 33).
        assert!(guard().check(&v2(0, &[1; 9], false)).is_ok());
        assert_eq!(blocked(&v2(0, &[1; 10], false)), malformed());
        assert_eq!(blocked(&v2(0, &[1; 255], true)), malformed());
        assert!(
            guard()
                .check(&v2(76, &with_command(76, 400), false))
                .is_ok()
        );
        let mut long = with_command(76, 400);
        long.resize(34, 1);
        assert_eq!(blocked(&v2(76, &long, false)), malformed());
        // GPS_RTCM_DATA is at most 182 bytes, FTP 254.
        let g = guard().allow_rtk();
        assert_eq!(
            g.check(&v2(233, &[1; 183], false)).unwrap_err(),
            malformed()
        );
        assert_eq!(
            guard()
                .allow_ftp()
                .check(&v2(110, &[1; 255], false))
                .unwrap_err(),
            malformed()
        );
        // A bad length is malformed even for a message that would be refused anyway.
        assert_eq!(blocked(&v2(256, &[0; 43], false)), malformed());
    }

    #[test]
    fn mavlink_1_frames_carry_exactly_the_base_length() {
        // Built by hand: the `v1` helper pads to the right length.
        let raw = |id: u8, payload: &[u8]| {
            let mut f = vec![V1_START, payload.len() as u8, 3, 255, 190, id];
            f.extend_from_slice(payload);
            let crc = crc_for(u32::from(id), &f[1..]);
            f.extend_from_slice(&crc);
            f
        };
        assert!(guard().check(&raw(0, &[1; 9])).is_ok());
        assert_eq!(
            blocked(&raw(0, &[1; 8])),
            malformed(),
            "trimmed payloads are MAVLink 2 only"
        );
        assert_eq!(blocked(&raw(0, &[1; 10])), malformed());
        assert_eq!(blocked(&raw(0, &[])), malformed());
        // MISSION_ITEM_INT: the extension (mission_type) is not in a v1 frame.
        assert_eq!(blocked(&raw(73, &[0; 38])), malformed());
    }

    #[test]
    fn a_full_length_param_name_works_with_and_without_trimming() {
        let name = "ABCDEFGHIJKLMNOP"; // 16 characters, no terminating zero
        let g = guard().allow_param(name).unwrap();
        // PARAM_SET: value, targets, 16-byte name, then the type. A zero type is cut by MAVLink 2.
        let mut full = 1.0f32.to_le_bytes().to_vec();
        full.extend_from_slice(&[1, 1]);
        full.extend_from_slice(name.as_bytes());
        let mut with_type = full.clone();
        with_type.push(9);
        assert_eq!(full.len(), 22);
        assert!(
            g.check(&v2(23, &full, false)).is_ok(),
            "the name ends the payload"
        );
        assert!(g.check(&v2(23, &with_type, false)).is_ok());
        assert!(g.check(&v2(23, &with_type, true)).is_ok());
        assert!(g.check(&v1(23, &with_type)).is_ok());
        // One character short or long is a different name.
        for other in ["ABCDEFGHIJKLMNO", "ABCDEFGHIJKLMNOQ"] {
            assert_eq!(
                g.check(&v2(23, &param_set(other), false)).unwrap_err().why,
                Why::ParamWrite
            );
        }
        // PARAM_EXT_SET: targets(2), name, value(128), type; trailing zeros cut.
        let mut ext = vec![1, 1];
        ext.extend_from_slice(name.as_bytes());
        assert!(
            g.check(&v2(323, &ext, false)).is_ok(),
            "ext: the name ends the payload"
        );
        ext.resize(146, 0);
        ext.push(2);
        assert!(g.check(&v2(323, &ext, true)).is_ok());
    }

    #[test]
    fn why_has_fixed_words() {
        let all = [
            (Why::Malformed, "malformed"),
            (Why::BadCrc, "bad_crc"),
            (Why::SetupSigning, "setup_signing"),
            (Why::Ftp, "ftp"),
            (Why::SigningParam, "signing_param"),
            (Why::ParamWrite, "param_write"),
            (Why::MsgNotAllowed, "msg_not_allowed"),
            (Why::CommandNotAllowed, "command_not_allowed"),
            (Why::MissionType, "mission_type"),
        ];
        for (w, s) in all {
            assert_eq!(w.as_str(), s);
        }
    }

    #[test]
    fn no_input_makes_it_panic() {
        // A cheap fuzz: every prefix and many one-byte changes of real frames, plus a pseudo-random
        // stream. Only "no panic" is asserted.
        let mut seed = 0x1234_5678_9ABC_DEF0u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let g = guard().allow_ftp().allow_param("WP_SPD").unwrap();
        let frames = [
            v2(0, &[1; 9], true),
            v2(23, &param_set("WP_SPD"), false),
            v2(76, &with_command(76, 22), true),
            v1(73, &with_command(73, 16)),
        ];
        for f in &frames {
            for cut in 0..=f.len() {
                let _ = g.check(&f[..cut]);
            }
            for _ in 0..2000 {
                let mut x = f.clone();
                let i = (next() as usize) % x.len();
                x[i] = next() as u8;
                let _ = g.check(&x);
            }
        }
        for _ in 0..2000 {
            let n = (next() % 300) as usize;
            let d: Vec<u8> = (0..n).map(|_| next() as u8).collect();
            let _ = g.check(&d);
        }
    }

    /// A signed HEARTBEAT frame with a real signature under `key`.
    fn signed_frame(key: &[u8; 32], ts: u64) -> Vec<u8> {
        use mavlink::{MAVLinkV2MessageRaw, consts};
        let mut f = v2(0, &[0; 9], true);
        let n = f.len();
        f[n - SIGNATURE_LEN] = 3; // link id
        f[n - SIGNATURE_LEN + 1..n - 6].copy_from_slice(&ts.to_le_bytes()[..6]);
        let mut raw = MAVLinkV2MessageRaw::new();
        raw.as_mut_slice()[..n].copy_from_slice(&f);
        let mut sig = [0u8; consts::v2::SIGNATURE_VALUE_SIZE];
        raw.calculate_signature(key, &mut sig);
        f[n - 6..].copy_from_slice(&sig);
        f
    }

    #[test]
    fn the_highest_timestamp_comes_only_from_frames_that_verify_and_is_capped() {
        const K: [u8; 32] = [7; 32];
        let (clock, ahead) = (1_000_000u64, 6_000_000u64);
        let max = |d: &[u8]| max_verified_timestamp(d, &K, clock, ahead);
        assert_eq!(max(&signed_frame(&K, 1234)), 1234);
        // Signed under another key, or with a made-up signature: not believed.
        assert_eq!(max(&signed_frame(&[8; 32], 1234)), 0);
        assert_eq!(max(&v2(0, &[0; 9], true)), 0);
        // Not signed: nothing.
        assert_eq!(max(&v2(0, &[0; 9], false)), 0);
        // Several frames: the highest verified one.
        let mut many = signed_frame(&K, 10);
        many.extend(signed_frame(&K, 99));
        many.extend(signed_frame(&[8; 32], 5_000));
        many.extend(v2(0, &[0; 9], false));
        assert_eq!(max(&many), 99);
        // A genuine signature far ahead of the clock only raises it to the cap.
        assert_eq!(max(&signed_frame(&K, (1 << 48) - 1)), clock + ahead);
        // Cut short, garbage, empty: nothing, no panic.
        let f = signed_frame(&K, 77);
        assert_eq!(max(&f[..f.len() - 1]), 0);
        assert_eq!(max(&[0xFD; 3]), 0);
        assert_eq!(max(&[]), 0);
        assert_eq!(max(&[0x55; 40]), 0);
    }
}
