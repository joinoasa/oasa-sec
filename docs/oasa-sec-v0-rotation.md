# OASA-SEC v0: roles, device removal and signing-key rotation (draft)

**Stage:** Idea → Draft · **Node:** R-SEC2 · **Last reviewed:** 2026-10-23 (design reviews 1 and 2 applied)

How a lost or stolen device is kicked out, and how a drone replaces its MAVLink signing key. Builds on [pairing](oasa-sec-v0-pairing.md) and the [link](oasa-sec-v0-link.md). No new crypto: every message travels inside a link session, which already proves who sent it.

**Not in v0:** changing a device's identity key in place. Link session keys are already short-lived, and moving trust to a new key can't be made safe without signatures (a key thief could move it first). To replace an identity: remove the old one, pair a fresh one. Revisit with signatures (T-NET1).

## 1. Roles

Each entry in `trusted-peers` has a role, set **only locally** (pairing, `trust`, or by hand). No message can change a role.

| Role | Who | May |
|---|---|---|
| `admin` | 1–3 owner devices, ideally kept at base | Remove operators and peers from this device (§3) |
| `operator` | A ground station paired with this drone | Fly it; receive its MAVLink signing key (§4). May not remove anyone |
| `peer` | Everything else (relays, other drones, a drone in a ground station's list) | Exchange link traffic only |

- Pairing: the drone saves the ground station as `operator`; the ground station saves the drone as `peer`.
- `admin` is only ever given explicitly: `oasa-pair trust … --role admin`. Admins can be listed on drones, ground stations and relays alike.

## 2. Control messages (link wire version 1)

The link gets a **content type** byte at the start of every data plaintext, inside the encryption. This is **link wire version 1**: the header's version field is `1`, the prologue is `"OASA-SEC v1 link"` and the `mac1` label `"OASA-SEC v1 mac1"`. A handshake can't complete between versions, and data from the other version is dropped as `bad_header`, so mixed builds fail clearly instead of misreading data. (The link spec allowed unreleased changes to stay v0; this one changes what the plaintext means, so it gets a number.)

| Content type | Body |
|---|---|
| `0x00` | Application packet. `oasa-link` adds this to **every** local packet; local programs can never send control messages |
| `0x01` | Control message |
| other | Dropped after authentication (`bad_content`) |

Data overhead becomes **22 bytes** (24 with the long counter). An empty keepalive stays empty. Control messages never reach the application side.

A control message is `[type: 1][request id: 4][body]`. The request id is random per message. All integers are big-endian.

| Type | Name | From → to | Body | Bytes |
|---|---|---|---|---|
| `0x01` | `ACK` | any | acked type (1); the request id is the acked message's | 6 |
| `0x10` | `SIGNING_KEY_NEXT` | drone → its operators | generation (4), key (32) | 41 |
| `0x11` | `SIGNING_KEY_COMMIT` | drone → its operators | generation (4) | 9 |
| `0x20` | `REMOVE_HEAD` | admin → device | log id (4), highest seq (4) | 13 |
| `0x21` | `REMOVE_HAVE` | device → admin | highest seq held in a row (4) | 9 |
| `0x22` | `REMOVE_ENTRY` | admin → device | log id (4), seq (4), removed public key (32), time (8) | 53 |
| `0x23` | `NOT_ADMIN` | device → sender of `REMOVE_HEAD` | none | 5 |

All fit the 128-byte minimum MTU (the largest, 53 + 22 = 75 bytes). Rules:
- **Who may send what** is checked against the sender's role; anything else is dropped and counted (`bad_role`). `REMOVE_*` only from an `admin`. `SIGNING_KEY_*` only from a drone this ground station already holds a signing key for, and only into that drone's key file.
- **Every message is idempotent:** messages can be delayed or repeated across sessions. Old generations, known entries and unknown request ids are ignored.
- **Retries:** a sender resends an unacked message after 2 s, doubling to 60 s, for the life of the session; unfinished work resumes at the next session. `REMOVE_HEAD` and `REMOVE_HAVE` are answers to each other and aren't acked. Unsent messages for a peer that is removed are dropped.

## 3. Removing a device

### Removal is a tombstone

A removed key goes into a permanent, append-only file `removed` (`0600`): the public key, which admins removed it, and when. On every load, any key in `removed` is ignored even if it is still in `trusted-peers`. Pairing and `trust` refuse a removed key; a removed device must make a new identity and pair again. Only a person at the device can undo a removal: `oasa-pair restore KEY` appends a **restore record**. Entries already received for that key (same admin and seq) are not applied again; a *new* entry from an admin removes it again.

### On one device

`oasa-pair remove PEER`:
1. Adds the peer to `removed` and takes it out of `trusted-peers`, deleting its timestamps.
2. A running `oasa-link` reloads within 1 s (it watches the files) or at once on `SIGHUP`, ends every session with the peer and drops its handshakes (`untrusted_peer`).
3. On a drone, removing an `operator` (locally or by an admin's entry) marks a signing-key rotation pending (§4). On a ground station, removing a drone deletes that drone's signing-key files.
4. The `oasa-link` process whose own peer was removed logs `peer_removed` and exits with code 3.

### Across the fleet

Each admin keeps a numbered **removal log**: entries `seq 1, 2, 3…`, each one removed key. `oasa-pair revoke PEER` adds an entry and removes the peer locally.

- A device that has a removal log sends `REMOVE_HEAD` at the start of every session (it can't know who lists it as admin). A device that doesn't list the sender as `admin` answers `NOT_ADMIN`, and the sender stops for that session. Otherwise it answers `REMOVE_HAVE` with the highest seq it holds from that admin's log without gaps; the admin sends each missing `REMOVE_ENTRY`, and the device acks each.
- **Log id:** each admin's log has a random 4-byte id, made when the log is created. Sync state is kept per (admin fingerprint, log id). If the id changes (a reinstalled admin) or `REMOVE_HEAD` is lower than what the device holds, the device answers `REMOVE_HAVE 0` and takes the whole log again.
- A device **applies every entry** from a valid admin, in any order: removal is a union, so a lost or reordered message, or an admin whose counter was reset, never undoes anything. Seq numbers only find what's missing.
- **Removing an admin** needs entries from **two different admins**. "An admin" means the target's role **on the receiving device**, so the same entry may need one vote on one device and two on another. A device keeps a single admin's vote until a second arrives; a vote is dropped if its admin is removed. With fewer than three admins, remove a stolen admin on each device by hand.
- A device ignores entries for its own key, and its own key never counts as a vote. An admin can't revoke itself.
- Entry times are for people only; nothing orders or expires by them.

### Files and locking

| File | Content |
|---|---|
| `trusted-peers.v1` | Format line `oasa-trusted-peers v1`, then `<key base32> <role> <name>` per line |
| `removed` | Append-only. `<key base32> removed <source> <unix time>` or `<key base32> restored local <unix time>`; source is `local` or `<admin fingerprint>:<log id hex>:<seq>` |
| `removal-log` | Admins only. Line 1: log id (hex); then `<seq> <key base32> <unix time>` |
| `removal-sync/<admin fingerprint>` | `<log id hex> <highest seq held in a row>` |
| `admin-votes` | `<target key base32> <admin fingerprint> <log id hex> <seq>` until a second admin agrees |

- **New file name on purpose:** older binaries look for `trusted-peers`, find nothing and trust no one (they fail closed) instead of misreading roles as names.
- **Migration:** a new binary that finds only a v0 `trusted-peers` converts it once (under the lock) and renames the old file `trusted-peers.v0-migrated`. On a device that has `mavlink-signing-key.bin` (a drone), v0 entries become `operator`; elsewhere `peer`. It prints the result so a person can fix roles.

Every read-modify-write of these files takes an exclusive lock on `<dir>/.lock`, so `oasa-pair` and several `oasa-link` processes can't save a stale copy over a removal. Files are replaced by atomic rename, so readers never see half a file.

## 4. Signing-key rotation

A drone's autopilot has one MAVLink signing key, shared with its operators. Each key has a **generation** number, never reused: the highest generation ever issued is kept in `mavlink-signing-gen`, separate from the key files. The drone rotates when an operator is removed, or on demand.

### The guard

**The tunnel never carries key or signing changes to the autopilot.** The MAVLink guard on a drone is described once, in the [link spec section 7](oasa-sec-v0-link.md#7-using-it). It is on by default whenever the device has `mavlink-signing-key.bin`, and it is an allowlist: anything not listed there is dropped, so key and signing changes cannot pass.

### Who does what

- `oasa-pair signer --autopilot …` runs on the drone and **owns a dedicated link to the autopilot** (its own serial port or UDP port, never a router endpoint, so `SETUP_SIGNING` never reaches routers or logs). It watches arming state, runs rotations, and probes.
- A rotation is requested by writing `rotation-pending` (under the lock): by `oasa-pair remove`/`rotate-signing`, or by an `oasa-link` that applied an admin's removal of an operator.
- Each drone-side `oasa-link` process sends `SIGNING_KEY_NEXT` and `SIGNING_KEY_COMMIT` to its own operator from the key files, remembering the generation each operator acked (`signing-acked/<fingerprint>`).
- Operators keep `signing-keys/<drone fingerprint>.bin` (current) and `.next`, each with a matching `.gen`. A newer `SIGNING_KEY_NEXT` replaces an older pending one. They switch only on `SIGNING_KEY_COMMIT`.

### Steps

1. **Wait until disarmed** (both autopilots refuse key changes while armed). The rotation is reported as pending. The drone may still fly: a removed device already can't reach it over the link; the old key only matters on other paths.
2. Issue generation `g = highest + 1`, save it to `mavlink-signing-gen`, then save the new key as `mavlink-signing-key.next` (atomic, `0600`), **before** sending anything.
3. Operators get `SIGNING_KEY_NEXT` (now, or at their next session).
4. Send `SETUP_SIGNING` over the dedicated autopilot link, signed with the current key. Initial timestamp: one more than the latest of the companion's clock and every signed timestamp it has seen (from the autopilot and through the tunnel).
5. Prove the new key: send `COMMAND_LONG` `MAV_CMD_REQUEST_MESSAGE` for `AUTOPILOT_VERSION`, signed with the new key, and wait for a signed, matching `COMMAND_ACK`.
6. On success: replace `mavlink-signing-key.bin` with the new key (atomic), delete `.next`, clear `rotation-pending`. Operators get `SIGNING_KEY_COMMIT`.

### When unsure

No answer, a crash or power loss can leave the drone not knowing which key the autopilot has. At every start while `.next` exists, and after any failed step 5:
1. **Listen first:** a keyed autopilot signs what it sends. If its frames verify under one key, that key is in use.
2. Otherwise ask under each key with the step 5 command, retrying for 75 s (ArduPilot refuses new signed streams for up to a minute after a reboot).
3. Keep the key that answered: if it's the new one, finish step 6; if the old one, delete `.next` and leave the rotation pending to try again with a **new** generation.
4. If neither answers, keep both files, report `rotation_stuck`, and try again at the next start or when asked. Never delete a key that might be the autopilot's.

An operator that reconnects with an older generation gets `SIGNING_KEY_NEXT` and `SIGNING_KEY_COMMIT` for the current one. Removed operators never get it. Other components on the drone that sign MAVLink (a gimbal, a second computer) need the new key too; v0 supports only the autopilot.

**Verified in SITL** (results in [sitl.md](sitl.md)): signed key change on PX4 and ArduPilot; both sign their own frames once keyed; PX4 has no signing parameters and its key file is open to FTP (the guard drops FTP); both refuse a key change while armed.

## 5. What it protects against

- **Lost or stolen device:** once removed, it can't open sessions with any device that received the removal, and a stolen ground station's signing key stops working after rotation.
- **Stolen admin:** can remove operators and peers until it is removed (by two admins, or by hand). Its removals stay, as tombstones naming it; a person at each device can restore them.
- **Not covered:** use of a stolen device before anyone removes it; devices that never meet an admin; jamming or handshake floods delaying delivery (the link's open question 2).

## 6. Commands

| Command | What it does |
|---|---|
| `oasa-pair trust … --role admin\|operator\|peer` | Set a role when trusting by hand |
| `oasa-pair remove PEER` | Remove on this device (§3) |
| `oasa-pair revoke PEER` | Admin: add to the removal log, remove locally |
| `oasa-pair restore KEY` | Undo a removal on this device |
| `oasa-pair rotate-signing` | Ask for a signing-key rotation (§4) |
| `oasa-pair signer --autopilot …` | Drone: own the autopilot link, run rotations and probes (§4) |
| `oasa-link … --no-mavlink-guard` | Turn the guard off (not for flying drones) |

## 7. Tests required

- L0/L1: role matrix, every control message hostile and replayed, union and two-admin rules, vote loss, lock contention, a reload removing a peer mid-session, tombstones winning over a stale `trusted-peers`.
- Lab: `oasa-link` removal mid-run (exit code 3); the guard drops `SETUP_SIGNING`, FTP and signing parameters sent through the tunnel, and passes ordinary traffic.
- SITL: rotation on PX4 and ArduPilot, lost `COMMAND_ACK` (probe recovers), power loss between steps 4 and 6, armed (waits), a reconnecting operator catching up, generations never reused.

### Status

Phases A and B are built: sections 1 to 4, and the parts of 6 and 7 that belong to them. Lab and SITL results are in [sitl.md](sitl.md).

**As built in §4** (where the code is more exact than the text above):
- **Files.** The drone keeps `mavlink-signing-key.gen` (the current key's generation, missing means 0, the key from pairing) next to `mavlink-signing-gen` (highest issued). While `.next` exists, its generation is the number in `mavlink-signing-gen`; a `.next` with no saved number is an error, not a guess. `signing-acked/<fp>` holds two numbers: the last `NEXT` and the last `COMMIT` generation the operator acked.
- **Order of writes.** Step 6 replaces `mavlink-signing-key.bin`, then `mavlink-signing-key.gen`, then deletes `.next`, then clears the requests it answered. A crash anywhere in that is finished by the next start (the probe sees the new key in use).
- **Requests.** `rotation-pending` lines present when a rotation began are cleared by its commit; lines added meanwhile (an operator removed during the rotation, who may already hold the new key) stay and get their own rotation. After a crash the count is unknown, so only requests dated before `.next` was written are cleared; one from the same second stays, which can cost one extra rotation and never skips one.
- **Heartbeats.** The signer sends a signed `HEARTBEAT` every second (as a companion computer does), so an autopilot that answers only the last address that spoke keeps answering the signer. It treats the autopilot as disarmed only on a heartbeat younger than 10 s that says so; with none it waits (`rotation_waiting_heartbeat`).
- **Proof.** Step 5 accepts any signed `COMMAND_ACK` for `MAV_CMD_REQUEST_MESSAGE` from the autopilot that verifies under the new key (whatever its result): the signature is the proof. It retries the request once a second for 5 s; failing that, the probe decides.
- **Probe.** It listens 4 s, then asks under both keys once a second for 75 s. Any frame from the autopilot that verifies under one key decides; if the old key is in use the new one is dropped and the next try, 30 s later, uses a new generation. After an I/O error the next round starts with the probe.
- **Timestamps.** The initial timestamp is one more than the latest of the companion's clock, every signature time seen on the autopilot link, the last one the signer used, and `mavlink-signing-ts`. `oasa-link` on a drone saves the highest signature time it forwards from the tunnel to that file (at most every 10 s), unchecked: it is only a floor.
- **Distribution.** A `NEXT` of any generation above the operator's current one replaces a pending key (the text says "newer"; a pending key from a dropped rotation can be higher than the current one an operator that was away still needs). A drone sends one message at a time to each operator: the pending key as soon as it exists, the commit only after the autopilot took it; an operator that never got the current key gets `NEXT` then `COMMIT`. A `COMMIT` that stays unacked for four resends makes the drone send `NEXT` for the current key again. The operator acks a `NEXT` once saved (also a repeat or an old one), and a `COMMIT` once switched; a `COMMIT` for a generation it holds no key for is noted (`signing_key_commit_unknown`) and not acked. A `NEXT` with an all-zero key, or the same generation with another key, is dropped as `bad_control`.
- **Limits.** The signer's link is UDP or TCP (`udpout:`, `tcpout:`...), not a serial port: a serial autopilot needs a bridge for now. Only the autopilot is rekeyed.

**Tested** (unit tests, `tests/link_sim.rs`, `tests/pair_cli.rs`, `scripts/e2e.sh`, `scripts/link-e2e.sh`):
- Phase A: every control message, including malformed, wrong-role and replayed ones; the role matrix; union, two-admin, vote loss and log-id reset; removal sync through the lossy simulated channel (many seeds, restarts, an admin offline then catching up, a removed admin); migration from v0; tombstones beating a stale `trusted-peers`; restore; lock contention (threads and 24 processes); `oasa-link` removal mid-run (exit code 3), reload on SIGHUP, and a revoke carried from an admin to a device.
- Phase B, signer state machine against a simulated autopilot in virtual time: the happy path; armed (waits, sends nothing); no heartbeat (waits); a refused change (rolled back, retried with a new generation); lost acknowledgments (settled by probing); a 60 s reboot window; a silent autopilot (`rotation_stuck`, both keys kept, resolved when asked again); power loss before and after the key change (restart works out the key, by listening or by asking); generations never reused across failures and burnt numbers; a request that arrives mid-rotation getting its own; the initial timestamp above every timestamp seen.
- Phase B, files and messages: the operator's pending key, commit, replays, conflicts, zero key, interrupted switches; the drone's NEXT/COMMIT sequence, retries and restart-from-NEXT; reconnecting operators; removed operators and non-operators getting nothing; keys not in `Debug` output or on the wire; through the lossy simulated channel (8 seeds, with replays), a blackout over two rotations, and a replaced pending key.
- Phase B, real processes with a stand-in autopilot (`scripts/e2e.sh`, `scripts/link-e2e.sh`): an armed autopilot left alone; a rotation after removing an operator, where the removed operator's old key stops working and the other operator gets the new key from the drone's link; a lost acknowledgment; a kill between the key change and the commit, then a restart; a refused change rolled back.
- SITL: see [sitl.md](sitl.md).

Not tested: real radios, the tunnel-timestamp floor against a real autopilot's replay rules beyond the SITL runs, a serial autopilot link, other components that sign MAVLink, and independent review.

## 8. Open questions

1. Signed removal logs relayed through a mesh (T-NET1): need Ed25519, which needs owner approval.
2. Should a fleet be able to opt in to "don't arm until an admin was heard recently"? Never by default: a jammer would ground the fleet.
