# OASA-SEC v0: roles, device removal and signing-key rotation (draft)

**Stage:** Idea → Draft · **Node:** R-SEC2 · **Last reviewed:** 2026-10-23 (design review 1 applied)

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

The link gets a **content type** byte at the start of every data plaintext, inside the encryption. The link header's version field becomes **1**; a v0 device drops v1 packets as `bad_header` and the other way round, so mixed builds fail clearly instead of misreading data.

| Content type | Body |
|---|---|
| `0x00` | Application packet. `oasa-link` adds this to **every** local packet; local programs can never send control messages |
| `0x01` | Control message |
| other | Dropped after authentication (`bad_content`) |

Data overhead becomes **22 bytes** (24 with the long counter). An empty keepalive stays empty. Control messages never reach the application side.

A control message is `[type: 1][request id: 4][body]`. The request id is random per message. All integers are big-endian.

| Type | Name | From → to | Body | Bytes |
|---|---|---|---|---|
| `0x01` | `ACK` | any | acked type (1) | 6 |
| `0x10` | `SIGNING_KEY_NEXT` | drone → its operators | generation (4), key (32) | 41 |
| `0x11` | `SIGNING_KEY_COMMIT` | drone → its operators | generation (4) | 9 |
| `0x20` | `REMOVE_HEAD` | admin → device | highest removal seq (4) | 9 |
| `0x21` | `REMOVE_HAVE` | device → admin | highest seq held in a row (4) | 9 |
| `0x22` | `REMOVE_ENTRY` | admin → device | seq (4), removed public key (32), time (8) | 49 |

All fit the 128-byte minimum MTU. Rules:
- **Who may send what** is checked against the sender's role; anything else is dropped and counted (`bad_role`). `REMOVE_*` only from an `admin`. `SIGNING_KEY_*` only from a drone this ground station already holds a signing key for, and only into that drone's key file.
- **Every message is idempotent:** messages can be delayed or repeated across sessions. Old generations, known entries and unknown request ids are ignored.
- **Retries:** a sender resends an unacked message after 2 s, doubling to 60 s, for the life of the session; unfinished work resumes at the next session.

## 3. Removing a device

### Removal is a tombstone

A removed key goes into a permanent, append-only file `removed` (`0600`): the public key, which admins removed it, and when. On every load, any key in `removed` is ignored even if it is still in `trusted-peers`. Pairing and `trust` refuse a removed key; a removed device must make a new identity and pair again. Only a person at the device can undo a removal (`oasa-pair restore KEY`).

### On one device

`oasa-pair remove PEER`:
1. Adds the peer to `removed` and takes it out of `trusted-peers`, deleting its timestamps.
2. A running `oasa-link` reloads within 1 s (it watches the files) or at once on `SIGHUP`, ends every session with the peer and drops its handshakes (`untrusted_peer`).
3. On a drone, removing an `operator` starts a signing-key rotation (§4). On a ground station, removing a drone deletes that drone's signing-key file.

### Across the fleet

Each admin keeps a numbered **removal log**: entries `seq 1, 2, 3…`, each one removed key. `oasa-pair revoke PEER` adds an entry and removes the peer locally.

- At the start of every session with a device, an admin sends `REMOVE_HEAD`. The device answers `REMOVE_HAVE` with the highest seq it holds from that admin without gaps; the admin sends each missing `REMOVE_ENTRY`. The device acks each.
- A device **applies every entry** from a valid admin, in any order: removal is a union, so a lost or reordered message, or an admin whose counter was reset, never undoes anything. Seq numbers only find what's missing.
- Per-admin sync state is keyed by the admin's fingerprint.
- **Removing an admin** needs entries from **two different admins**. A device keeps a single admin's vote until a second arrives; a vote is dropped if its admin is removed. With fewer than three admins, remove a stolen admin on each device by hand.
- A device ignores entries for its own key, and its own key never counts as a vote. An admin can't revoke itself.
- Entry times are for people only; nothing orders or expires by them.

### Files and locking

`trusted-peers` gets a format line: `# oasa-trusted-peers v1`, then `<key base32> <role> <name>`. A file without the line is v0: its entries load as `peer` with a warning to set roles. Older binaries refuse v1 files.

Every read-modify-write of `trusted-peers`, `removed` and the sync files takes an exclusive lock on `<dir>/.lock`, so `oasa-pair` and several `oasa-link` processes can't save a stale copy over a removal.

## 4. Signing-key rotation

A drone's autopilot has one MAVLink signing key, shared with its operators. Each key has a **generation** number. The drone rotates when an operator is removed, or on demand (`oasa-pair rotate-signing`).

**The tunnel never carries `SETUP_SIGNING`.** On a drone, `oasa-link --mavlink-guard` drops any packet from the link that contains MAVLink message 256 (`SETUP_SIGNING`) or isn't well-formed MAVLink, and counts it (`mavlink_blocked`). Otherwise an operator holding the key, or a ground station app's signing screen, could load its own key into the autopilot and lock everyone else out. Drones must run with the guard.

Steps:
1. **Wait until disarmed.** Both autopilots refuse key changes while armed. The drone reads arming state from the autopilot's `HEARTBEAT` and retries on disarm; the rotation is reported as pending until then.
2. Make the new key, generation `n+1`. Save it as `mavlink-signing-key.next` (atomic, `0600`) **before** sending anything.
3. Send `SIGNING_KEY_NEXT` to every remaining operator. Each saves it as that drone's next key and acks. Operators that are offline get it later.
4. Send `SETUP_SIGNING` to the autopilot over the companion's **local wired link only**, signed with the current key. Initial timestamp: the later of the companion's clock and the newest timestamp seen from the autopilot, plus one.
5. Prove the new key with a signed command and a signed, matching `COMMAND_ACK`.
6. On success: replace `mavlink-signing-key.bin` with the new key and generation (atomic), delete `.next`, and send `SIGNING_KEY_COMMIT` to every operator. Each switches to the new key.
7. **If unsure** (no answer, crash, power loss): probe the autopilot with a signed command under each key and keep the one that gets a signed answer. The drone also probes at every start while a `.next` file exists. Nothing is deleted until one key is proven.

An operator that reconnects with an older generation gets `SIGNING_KEY_NEXT` and `SIGNING_KEY_COMMIT` for the current one. Removed operators never get it. Other components on the drone that sign MAVLink (a gimbal, a second computer) need the new key too; v0 supports only the autopilot.

Autopilot facts this relies on (SITL, October 2026): PX4 and ArduPilot (SERIAL1+) refuse an unsigned key change once keyed; ArduPilot SERIAL0 accepts anything and must be physically protected. **To verify before this leaves Draft:** signed key change on PX4, and both autopilots while armed.

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
| `oasa-pair rotate-signing --autopilot …` | Rotate the drone's signing key (§4) |
| `oasa-link … --mavlink-guard` | Drop `SETUP_SIGNING` and non-MAVLink from the link (drones) |

## 7. Tests required

- L0/L1: role matrix, every control message hostile and replayed, union and two-admin rules, vote loss, lock contention, a reload removing a peer mid-session, tombstones winning over a stale `trusted-peers`.
- Lab: `oasa-link` removal mid-run; the guard drops `SETUP_SIGNING` sent through the tunnel.
- SITL: rotation on PX4 and ArduPilot, lost `COMMAND_ACK` (probe recovers), armed (waits), a reconnecting operator catching up.

## 8. Open questions

1. Signed removal logs relayed through a mesh (T-NET1): need Ed25519, which needs owner approval.
2. Should a fleet be able to opt in to "don't arm until an admin was heard recently"? Never by default: a jammer would ground the fleet.
