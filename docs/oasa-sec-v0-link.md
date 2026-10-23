# OASA-SEC v0: the encrypted link (draft)

**Stage:** Idea → Draft · **Node:** R-COM2 · **Last reviewed:** 2026-10-23

**Wire version 1 replaced v0.** This page describes link wire version 1: the header version field is `1`, the prologue is `"OASA-SEC v1 link"` and the `mac1` label is `"OASA-SEC v1 mac1"`. v1 adds a content type byte inside every data plaintext (§3), which carries the control messages of [R-SEC2](oasa-sec-v0-rotation.md). The old wire (v0) is gone: v0 packets are dropped as `bad_header`, and a v0 and a v1 device cannot complete a handshake. (The title says v0 for the draft series of these documents, not for the wire.) After the first release, a wire change needs a new version number.

One encrypted, authenticated link between two paired OASA devices, over any radio that can carry a packet. Modeled on WireGuard. Uses the identities and trusted-peers list from [pairing](oasa-sec-v0-pairing.md). No new crypto: Noise through `snow`, X25519, ChaCha20-Poly1305, BLAKE2s.

## 1. Goals and limits

- **Any radio:** the link takes packets in and out. It never assumes order, delivery or a minimum speed. Smallest supported packet (MTU): **128 bytes**.
- **Every packet stands alone:** loss, reordering and duplicates never break the session.
- **Only trusted peers:** a device not in `trusted-peers` gets no reply at all.
- **Small overhead:** 22 bytes per data packet (24 with the long counter).
- **Not in v0:** one-to-many group keys, padding to fixed sizes, splitting handshakes for tiny MTUs, DoS cookies (a cheap `mac1` check is in, see §2), post-quantum. The version field leaves room for them.

## 2. Handshake

`Noise_IK_25519_ChaChaPoly_BLAKE2s`, prologue `"OASA-SEC v1 link"`.

- **IK:** the initiator knows the responder's public key from `trusted-peers` and sends its own, encrypted. The responder looks it up in `trusted-peers` and **silently drops** the handshake if it isn't there.
- Either side may initiate. Ground stations initiate by default.
- **Message 1** (initiator → responder) payload: a 12-byte **timestamp** (8-byte seconds, 4-byte nanoseconds, big-endian), then the initiator's 2-byte sender index. The timestamp must strictly increase per initiator. A device without a trusted clock uses `max(clock, last_sent + 1 ns)`, saving the last value so it survives reboots. The responder keeps the newest timestamp per peer and drops any handshake that isn't newer (`stale_handshake`), so a recorded message 1 can't be replayed. A responder **with a trusted clock** (an RTC or NTP set before it starts; off by default, `max_future` in the settings, `--trusted-clock` in `oasa-link`) also drops a timestamp more than **10 minutes ahead** of its current wall clock (`stale_handshake`) and does not save it: one wrong clock must not lock a peer out until that time. The clock is read at each check. A device with a slow or unset clock must leave this off, or it would refuse every handshake.
- **Message 2** (responder → initiator) payload: the responder's sender index, then the receiver index (2 bytes each). The receiver index is the initiator's index from message 1.
- **Indexes are authenticated, and message 1 has none in the clear:** the sender index of each side travels only inside the encrypted Noise payload. Message 2 carries the receiver index in the clear to find the handshake; it must equal the one inside the payload, or the handshake is dropped as `bad_header`. Someone on the path can't change an index to break a session or learn one from message 1.
- **`mac1` on message 1:** the last 8 bytes of message 1 are the first 8 bytes of BLAKE2s-256 keyed with `BLAKE2s-256("OASA-SEC v1 mac1" ‖ responder public key)` over the header byte and the Noise message. Anyone who knows the responder's public key (not a secret) can make it. It is only a cheap filter: random junk is dropped (`bad_header`) before any X25519 and **before** the global handshake limit is charged, so junk can't use up the budget. It does not stop someone who recorded a real message 1 (§9).
- **Limits:** cheap checks (header, size, `mac1`) come before any X25519. The responder handles at most 20 handshakes a second in total, and answers each peer at most once a second. The program that sees addresses (`oasa-link`) also limits message 1 per source address (3 a second) before the link sees it.
- **Public keys that can't be real:** small-order Curve25519 points (zero, one and the like) are refused wherever a peer key enters: `trusted-peers`, pairing codes, pairing, and `add_peer`.
- Sizes on the wire: handshake 1 is **119** bytes (1 header + 110 Noise + 8 `mac1`), handshake 2 is **55** bytes (1 header + 2 receiver index + 52 Noise).

The handshake gives two keys (one per direction) used with `snow`'s stateless transport: we pass the nonce ourselves.

## 3. Packets

Every packet starts with one header byte:

| Bits | Field |
|---|---|
| 7–4 | Type: `1` handshake 1, `2` handshake 2, `3` data, `4`–`15` reserved |
| 3 | Counter length, meaningful on data packets only (`0` = 2 bytes, `1` = 4 bytes). On handshake packets it must be `0`, or the packet is dropped |
| 2–0 | Version: `1` (wire version 1). Anything else, version 0 included, is dropped |

**Handshake 1:** `[header][Noise message 1: 110][mac1: 8]`
**Handshake 2:** `[header][receiver index: 2][Noise message 2: 52]`
**Data:** `[header][receiver index: 2][counter: 2 or 4][ciphertext + 16-byte tag]`; the plaintext is `[content type: 1][body]`, or empty for a keepalive

- **Index:** a random 16-bit number each side picks per session, so the receiver finds the session without trying keys. Not secret. A side never picks an index that a live session or handshake of its own already uses.
- **Counter:** a 64-bit number per direction per session, starting at 0, used as the nonce. It never repeats under a key. Only its low 2 or 4 bytes are sent.
- **Rebuilding the counter** (as DTLS 1.3, RFC 9147 §4.2.2): the receiver picks the 64-bit value closest to `highest seen + 1` whose low bytes match. This works while fewer than 32,768 packets in a row are lost or reordered, so the short counter is for links where that can't happen, and the long one for fast links.
- **The tag is never shortened** (RFC 8439 forbids it).
- **No separate header authentication for data:** the type and index pick the key, so changing them makes the tag check fail, and the counter's low bytes are the nonce. The one change that keeps the nonce is re-encoding a short counter as a long one (or back) with the same value: the tag still verifies, and the replay window catches it as a duplicate (or it is the same packet). Handshake indexes are inside the Noise payloads (§2). Any field added later must keep this property or be covered as associated data.
- **Data payload:** an empty plaintext is a **keepalive** (no content type byte). Anything else starts with a **content type** byte, inside the encryption:

  | Content type | Body |
  |---|---|
  | `0x00` | An application packet, unchanged. `oasa-link` adds this byte to **every** local packet, so local programs can never send control messages |
  | `0x01` | A control message ([R-SEC2](oasa-sec-v0-rotation.md) §2). It never reaches the application side |
  | other | Dropped after authentication as `bad_content` |

  A content type with nothing after it (`0x00` or `0x01` alone) is also `bad_content`: an empty application packet is not a packet.

Overhead per data packet: 1 + 2 + 2 + 1 + 16 = **22 bytes** (24 with the long counter). A keepalive is 21 bytes (23).

## 4. Receiving data

In this order, dropping silently on any failure:

1. Header byte valid; packet long enough and not over the MTU. (For message 1 also `mac1`.)
2. Index matches a live session.
3. Counter rebuilt (a tie exactly half a range away takes the higher value); not older than the replay window.
4. Tag verified (decrypt).
5. **Replay window** (RFC 6479, 1024 packets): drop if already seen, otherwise mark it. Updated only after step 4, so forged packets can't move it.
6. **Content type:** empty is a keepalive; `0x00` goes to the application, `0x01` to the control layer; anything else is dropped as `bad_content`. This comes after step 5, so the packet was authentic and counts as proof of life for the session, but nothing is delivered.

Drops are counted by reason (`bad_header`, `unknown_index`, `too_old`, `bad_tag`, `replay`, `untrusted_peer`, `stale_handshake`, `rate_limited`, `bad_content`) and logged without packet contents. A packet whose counter is at or past the receiver's own packet limit is dropped as `bad_tag`: a real peer never sends one.

Sending can fail locally (`empty`, `too_large`, `no_session`, `unknown_peer`); nothing goes on the wire. The tunnel logs at most 10 drop lines a second and then one `drops_suppressed` line a second with the count held back; the statistics always count every drop.

## 5. Session life

| Rule | Default |
|---|---|
| Initiator starts a new handshake after | 10 minutes or 2³² packets sent |
| Nobody sends or accepts on a session after | 15 minutes or 2⁶⁰ packets |
| Handshake retry if no answer | 5 s, then backing off to 60 s |
| Keepalive if nothing sent for | 25 s (off by default on slow radios) |
| Stale: sent payload, heard nothing for | 30 s, then a new handshake |
| Stale: only keepalives sent, heard nothing for | 60 s (2 × stale), then a new handshake |

- The **initiator** may send data as soon as it gets message 2. It sends a keepalive at once so the responder learns the session works.
- The **responder** sends on a new session only after a valid data packet arrives on it. Until then it keeps using the previous session. This stops a stale or replayed handshake from breaking a working link. When it switches, it sends one keepalive so the initiator knows the session is confirmed.
- If the initiator hears nothing on a new session within the retry time, it starts another handshake. An unconfirmed session never replaces a working one.
- The previous session stays readable until the new one is confirmed, or 10 s after its last packet, so a rekey loses no packets.
- **Stale rule** (as WireGuard): a side that has sent payload on its session and heard nothing authenticated for 30 s starts a new handshake, whichever side it is and with keepalives off too. This heals a peer that rebooted and lost its session, and counters that drifted apart in a long one-way loss. If it has only sent idle keepalives (a restarted peer that has no address to dial, and nothing to say) the wait is twice as long. A side that has received payload and sent nothing answers with a keepalive after 15 s (half the stale time), so a healthy one-way link never looks stale.
- A side with **no session** and something to send starts a handshake itself after the retry time, if the other side has not already done it. Rekeys are done by whoever made the current session.
- If both sides start a handshake at once, both sessions work; each side may send on a different one until the next rekey.
- Rekey limits are set per radio from its airtime: a LoRa link may rekey hourly instead. **Set the same rekey and reject limits on both sides.** If they differ, the side with the shorter limit refuses the session first and the stale rule or a new handshake repairs it, at the cost of a gap of a few seconds at each rekey.
- Keys and session state are wiped when a session ends, as far as this crate controls them. `snow` does not wipe its session or handshake state when dropped, and keeps its own copy of our static private key for as long as a handshake or session lives, so a memory dump of the process can contain them. Our own copy is zeroized.

## 6. Who may connect

`trusted-peers.v1` is the gate, with a role per peer, and the `removed` list beats it (see the [roles and removal spec](oasa-sec-v0-rotation.md)). Removing a peer ends its sessions and stops new ones. `oasa-link` checks the trust files every 250 ms and on SIGHUP, so `trust`, `remove` and `revoke` take effect within a second with no restart. If its own peer is removed it prints `peer_removed` and exits with code 3. A lost device is cut off by removal; a stolen key that is not yet removed still works until it is (key rotation, R-SEC2 phase B, changes the autopilot's signing key).

**Threat model note (clocks).** A trusted peer is trusted, including to set its clock. Timestamps stop replay of recorded handshakes, not a misbehaving peer: a peer that sends a far-future timestamp is refused (10 minutes ahead, when the check is on). If a wrong future value was saved before that, or our own clock was once far ahead, nothing newer than that value is accepted until `oasa-pair reset-stamp` clears it. Fix the clock first. Resetting what we have `seen` lets one recorded old handshake from that peer through again until a newer one arrives. `oasa-link` prints a `hint` when handshakes keep being refused as stale.

**Key compromise impersonation.** A stolen device key lets the attacker pose as any peer that device trusts, to that device, as in WireGuard and any IK design. Recovery is key rotation (R-SEC2).

Two ways in:
- **Pairing** (`oasa-pair`), for a ground station and a drone.
- **Manual trust** (`oasa-pair trust`), for devices without an autopilot such as relays and test nodes: add a peer's name and public key after checking its fingerprint out loud, like WireGuard.

## 7. Using it

- **Library:** a sans-IO state machine (`oasa_sec::link`): bytes in, bytes out, and a clock passed in. No sockets or threads inside, so it runs the same on a laptop, a companion computer or a microcontroller later, and tests drive it through a simulated channel.
- **Tunnel:** `oasa-link` carries plaintext UDP packets from local programs (for example MAVLink from a ground station) over the encrypted link. `--plain-listen` must be a loopback address and plaintext is accepted only from the `--plain-send` host, unless `--allow-remote-plain` is given (anyone who reaches that port can otherwise inject packets). Its radio side is UDP for now; radio adapters in [oasa-radio](https://github.com/joinoasa/oasa-radio) plug in there. It logs JSON lines for the [lab](https://github.com/joinoasa/oasa-lab).
- MAVLink signing keeps running inside the link as a second layer.
- **MAVLink guard (allowlist):** `oasa-link` checks every packet that comes **out of** the link, before `--plain-send`. It parses each MAVLink 1 and 2 frame in the datagram (signed frames count their 13 extra bytes; the message id is 24 bits), checks the **CRC** of each one (CRC_EXTRA from the `mavlink` crate) and its **length** (a MAVLink 1 payload is exactly the message's base length; a MAVLink 2 payload is at most its longest length), and passes the datagram only if **every** frame is whole, CRC-valid, the right length and allowed, with nothing else in it. Otherwise the **whole datagram is dropped**. Newer incompatibility flags (such as the 32-bit target ids) are refused as malformed. Rules, in order:
  1. `SETUP_SIGNING` (256) is always dropped.
  2. `FILE_TRANSFER_PROTOCOL` (110) is dropped unless `--allow-mavlink-ftp`.
  3. `PARAM_SET` (23) and `PARAM_EXT_SET` (323) are dropped unless the name was allowed with `--allow-param NAME` (repeatable). Names starting `MAV_SIGN` or `MAV<n>_OPTIONS` (ArduPilot's switch for signing) can never be allowed.
  4. Any other message id not in the message table below is dropped. `--allow-msg ID` (repeatable) adds one; ids the crate has no CRC for, and 256, 110, 23 and 323, are refused. `--allow-rtk` adds the two RTK messages in the third table.
  5. The mission-protocol messages (37, 38, 39, 40, 43, 44, 45, 47, 51, 73) carry a `mission_type`. Only the normal mission (0) passes; the geofence (1), the rally points (2) and "all" (255) are dropped, because a clear-all or an empty count of those types erases the fence or the rally points. `--allow-fence-rally` allows types 1 and 2 (never 255) and the fence and rally commands in the fourth table. A MAVLink 1 frame or a cut-short MAVLink 2 payload has no `mission_type` and counts as 0.
  6. In `COMMAND_LONG`, `COMMAND_INT`, `MISSION_ITEM` and `MISSION_ITEM_INT` the command id must be in the command table below. `--allow-command ID` (repeatable) adds one.

  Each widening flag logs a `warning` line at start naming what it widened. Why this design and what the autopilots do: [sitl.md](sitl.md). The guard is **on by default when the device folder holds `mavlink-signing-key.bin`** (a drone); without the file it starts off and prints a one-line `hint` (drones whose key lives elsewhere: use `--mavlink-guard`). `--mavlink-guard` forces it on, `--no-mavlink-guard` turns it off and prints a warning (the widening flags need the guard on). Drops count as `mavlink_blocked` in the stats and are logged with the rest (rate limited): `{"event":"drop","reason":"mavlink_blocked","why":"command_not_allowed","msgid":76,"command":246}`. `why` is one of `malformed`, `bad_crc`, `setup_signing`, `ftp`, `signing_param`, `param_write`, `msg_not_allowed`, `command_not_allowed`, `mission_type` (which adds `"mission_type":N`). Contents are never logged. The guard is `oasa_sec::mavguard`, a pure module. The stats' `delivered` still counts datagrams the link decrypted, including those the guard then dropped.

  **Allowed messages**

  | Id | Name | Why it is allowed |
  |---|---|---|
  | 0 | `HEARTBEAT` | Ground station presence; ArduPilot's GCS failsafe needs it |
  | 2 | `SYSTEM_TIME` | Clock sync |
  | 4 | `PING` | Link latency check |
  | 11 | `SET_MODE` | Legacy flight mode change (same effect as DO_SET_MODE) |
  | 20 | `PARAM_REQUEST_READ` | Read one parameter |
  | 21 | `PARAM_REQUEST_LIST` | Read all parameters |
  | 37 | `MISSION_REQUEST_PARTIAL_LIST` | Mission download (part) |
  | 38 | `MISSION_WRITE_PARTIAL_LIST` | Mission upload (part) |
  | 39 | `MISSION_ITEM` | Mission upload; the item's command is filtered |
  | 40 | `MISSION_REQUEST` | Mission download |
  | 41 | `MISSION_SET_CURRENT` | Jump to a mission item |
  | 43 | `MISSION_REQUEST_LIST` | Mission download |
  | 44 | `MISSION_COUNT` | Mission upload |
  | 45 | `MISSION_CLEAR_ALL` | Clear the mission |
  | 47 | `MISSION_ACK` | Ends a mission transfer |
  | 51 | `MISSION_REQUEST_INT` | Mission download |
  | 66 | `REQUEST_DATA_STREAM` | Legacy telemetry rate request (Mission Planner); on ArduPlane it saves the SRn_* rates to storage |
  | 69 | `MANUAL_CONTROL` | Joystick flying |
  | 70 | `RC_CHANNELS_OVERRIDE` | Stick input over the link |
  | 73 | `MISSION_ITEM_INT` | Mission upload; the item's command is filtered |
  | 75 | `COMMAND_INT` | Commands; the command id is filtered |
  | 76 | `COMMAND_LONG` | Commands; the command id is filtered |
  | 77 | `COMMAND_ACK` | Answers a command the autopilot sent |
  | 82 | `SET_ATTITUDE_TARGET` | Offboard flying |
  | 84 | `SET_POSITION_TARGET_LOCAL_NED` | Offboard flying |
  | 86 | `SET_POSITION_TARGET_GLOBAL_INT` | Offboard flying |
  | 111 | `TIMESYNC` | Clock sync |
  | 117 | `LOG_REQUEST_LIST` | List logs (ArduPilot log download over MAVLink) |
  | 119 | `LOG_REQUEST_DATA` | Download a log |
  | 122 | `LOG_REQUEST_END` | End a log download |
  | 134 | `TERRAIN_DATA` | Terrain tiles the autopilot asked for |
  | 320 | `PARAM_EXT_REQUEST_READ` | Read one parameter |
  | 321 | `PARAM_EXT_REQUEST_LIST` | Read all parameters |

  **Allowed commands.** None of them writes configuration or storage on PX4 or ArduPilot. Checked and left out: `DO_SET_CAM_TRIGG_DIST` (206) and `DO_SET_CAM_TRIGG_INTERVAL` (214), because PX4's camera trigger driver stores the new value in its `TRIG_*` parameters and autosaves.

  | Id | Name | Why it is allowed |
  |---|---|---|
  | 16 | `NAV_WAYPOINT` | Fly to a point |
  | 17 | `NAV_LOITER_UNLIM` | Loiter |
  | 18 | `NAV_LOITER_TURNS` | Loiter for turns |
  | 19 | `NAV_LOITER_TIME` | Loiter for a time |
  | 20 | `NAV_RETURN_TO_LAUNCH` | Return to launch |
  | 21 | `NAV_LAND` | Land |
  | 22 | `NAV_TAKEOFF` | Take off |
  | 30 | `NAV_CONTINUE_AND_CHANGE_ALT` | Change altitude |
  | 31 | `NAV_LOITER_TO_ALT` | Loiter while changing altitude |
  | 34 | `DO_ORBIT` | Orbit a point |
  | 82 | `NAV_SPLINE_WAYPOINT` | Fly a spline |
  | 84 | `NAV_VTOL_TAKEOFF` | VTOL takeoff |
  | 85 | `NAV_VTOL_LAND` | VTOL landing |
  | 92 | `NAV_GUIDED_ENABLE` | Hand over to guided control |
  | 93 | `NAV_DELAY` | Wait in a mission |
  | 112 | `CONDITION_DELAY` | Mission condition |
  | 113 | `CONDITION_CHANGE_ALT` | Mission condition |
  | 114 | `CONDITION_DISTANCE` | Mission condition |
  | 115 | `CONDITION_YAW` | Turn to a heading |
  | 176 | `DO_SET_MODE` | Change flight mode |
  | 177 | `DO_JUMP` | Mission jump |
  | 178 | `DO_CHANGE_SPEED` | Set speed |
  | 179 | `DO_SET_HOME` | Set home |
  | 186 | `DO_CHANGE_ALTITUDE` | Change altitude |
  | 189 | `DO_LAND_START` | Start the landing sequence |
  | 192 | `DO_REPOSITION` | Go to a point (PX4's 'fly here') |
  | 193 | `DO_PAUSE_CONTINUE` | Pause or continue |
  | 195 | `DO_SET_ROI_LOCATION` | Point at a location |
  | 196 | `DO_SET_ROI_WPNEXT_OFFSET` | Point at the next waypoint |
  | 197 | `DO_SET_ROI_NONE` | Stop pointing |
  | 201 | `DO_SET_ROI` | Point at a location |
  | 203 | `DO_DIGICAM_CONTROL` | Take a picture |
  | 205 | `DO_MOUNT_CONTROL` | Gimbal pointing |
  | 224 | `DO_SET_MISSION_CURRENT` | Jump to a mission item |
  | 300 | `MISSION_START` | Start the mission |
  | 400 | `COMPONENT_ARM_DISARM` | Arm and disarm |
  | 410 | `GET_HOME_POSITION` | Ask for the home position |
  | 511 | `SET_MESSAGE_INTERVAL` | Telemetry rates |
  | 512 | `REQUEST_MESSAGE` | Ask for one message |
  | 519 | `REQUEST_PROTOCOL_VERSION` | Protocol version |
  | 520 | `REQUEST_AUTOPILOT_CAPABILITIES` | Autopilot version |
  | 1000 | `DO_GIMBAL_MANAGER_PITCHYAW` | Gimbal pointing |
  | 2000 | `IMAGE_START_CAPTURE` | Start taking pictures |
  | 2001 | `IMAGE_STOP_CAPTURE` | Stop taking pictures |
  | 2500 | `VIDEO_START_CAPTURE` | Start video |
  | 2501 | `VIDEO_STOP_CAPTURE` | Stop video |
  | 3000 | `DO_VTOL_TRANSITION` | VTOL transition |

  **Allowed with `--allow-rtk`** (raw bytes go to the GPS receiver, which could reconfigure it)

  | Id | Name | Why it is allowed |
  |---|---|---|
  | 123 | `GPS_INJECT_DATA` | RTK corrections; raw bytes to the GPS receiver |
  | 233 | `GPS_RTCM_DATA` | RTK corrections; raw bytes to the GPS receiver |

  **Allowed with `--allow-fence-rally`** (together with mission types 1 and 2)

  | Id | Name | Why it is allowed |
  |---|---|---|
  | 5000 | `NAV_FENCE_RETURN_POINT` | Geofence return point |
  | 5001 | `NAV_FENCE_POLYGON_VERTEX_INCLUSION` | Geofence polygon corner (inside) |
  | 5002 | `NAV_FENCE_POLYGON_VERTEX_EXCLUSION` | Geofence polygon corner (outside) |
  | 5003 | `NAV_FENCE_CIRCLE_INCLUSION` | Geofence circle (inside) |
  | 5004 | `NAV_FENCE_CIRCLE_EXCLUSION` | Geofence circle (outside) |
  | 5100 | `NAV_RALLY_POINT` | Rally point |

  Blocked by default, and commonly sent by ground stations: parameter writes (QGroundControl and Mission Planner parameter editors, tuning), FTP (QGC's parameter and log downloads on PX4, file browser), geofence and rally upload, download and clear, calibration and reboot commands (`PREFLIGHT_CALIBRATION` 241, `PREFLIGHT_REBOOT_SHUTDOWN` 246, `PREFLIGHT_STORAGE` 245), `DO_SET_SERVO`/`DO_SET_RELAY` (183, 181), `DO_FLIGHTTERMINATION` (185), `DO_MOTOR_TEST` (209), `DO_FENCE_ENABLE` (207), camera trigger distance and interval, RTK corrections, `LOG_*` erase messages, `SERIAL_CONTROL` (126), `SET_GPS_GLOBAL_ORIGIN`, `SET_HOME_POSITION`, and everything else not listed.

  What the allowlist cannot see: `RC_CHANNELS_OVERRIDE` and `MANUAL_CONTROL` can trigger an ArduPilot `RCx_OPTION` function, and some of those write to storage. `SYSTEM_TIME` can move the clock (and the signing timestamp) on autopilots that accept it. Keep the paired ground stations to people you trust with the aircraft.
- **Plain side:** decrypted packets leave from the `--plain-listen` socket, so a program that answers the address a packet came from (PX4 does) answers into the tunnel.

## 8. Tested

- L0: unit tests, counter rebuilding edge cases, replay window, hostile headers.
- L1: two endpoints through a seeded simulated channel with loss, delay, reordering, duplicates and replayed or changed packets; rekey under loss; changed handshake indexes refused; a stale rule restart after a reboot or a long blackout; mismatched rekey settings; a flood of replayed handshakes with and without the per-source limit; untrusted peers ignored; captured packets checked for the plaintext.
- L1 (control): removal sync through the lossy channel, with restarts, an admin offline then catching up, and the two-admin rule.
- L2: real `oasa-link` processes over localhost UDP (`scripts/link-e2e.sh`): marked packets both ways, a rekey, a restart from a new port, junk and an untrusted device getting no reply, the stats output, removal mid-run (exit 3), SIGHUP reload, and a revoke carried from an admin to a device.
- Mutation checks: the receive-side packet limit and the previous-session grace are each covered by a test that fails without them.
- Not tested: real radios, long runs, and independent review.

## 9. Open questions

1. Handshakes on radios with an MTU under 128 bytes: split into pieces, or a smaller pattern?
2. DoS cookies (WireGuard's) for radios where someone could flood handshakes. `mac1` uses a public key as its secret, so someone who recorded one real message 1 can replay it (the responder drops it as `stale_handshake` but has spent an X25519 on it) and can use up the 20 a second budget. The per-source limit helps against one address only. Cookies tied to the sender's address would fix it, and need a reply to an unproven sender.
3. Default rekey limits per radio, once we measure airtime.
4. Group keys for broadcast (R-COM2 phase 2).
