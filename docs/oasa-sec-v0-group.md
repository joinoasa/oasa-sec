# OASA-SEC v0: group keys for one-to-many traffic (draft)

**Stage:** Idea → Draft · **Node:** R-COM2 (phase 2) · **Last reviewed:** 2026-10-26 (design reviews 1 and 2 applied; not yet reviewed by a person)

One encrypted packet that every member of a group can read: a ground station's position updates to its fleet, nodes sharing position and velocity for smart beams (T-RF4), discovery beacons. On a radio that is broadcast by nature (LoRa, a shared Wi-Fi channel), one group packet replaces one copy per device.

Builds on the [link](oasa-sec-v0-link.md) and on [roles and removal](oasa-sec-v0-rotation.md). **No new crypto:** keys travel inside link sessions; packets use ChaCha20-Poly1305 through `snow`'s cipher; keys are derived with keyed BLAKE2s (`Blake2sMac256` from the `blake2` crate, as the link's `mac1`).

## 1. What a group key does and doesn't do

- **Does:** keeps group traffic unreadable to anyone outside the group, and proves a packet came from *some* member.
- **Doesn't:** prove *which* member sent it. Every member holds the key, so any member can forge a packet from any other. That is true of every symmetric group key (Wi-Fi's group key is the same; its known insider attack, "Hole196", is this). So:
  - **Group traffic never reaches an autopilot** (§7). Commands to a fleet go one by one over each drone's own link session, as today.
  - **No control messages over group keys.** Removal logs, signing keys and group keys stay on link sessions, which prove the sender.
  - Commands that one packet must carry to many devices need **signatures**. That needs a new algorithm (for example Ed25519), so it waits for an OASA Proposal and owner approval (§10).
- **Removal:** a removed device can read **and forge** group traffic until the owner has applied the removal and each member has switched to the new epoch (§5, §8).
- **Delay:** a packet recorded in an epoch can be delivered late (to a member that didn't hear it first) while that epoch lives. Group data that a device acts on **must** carry its own time (positions do), so a late copy is recognised as old.
- **Owner out of range:** members drop an epoch when its life runs out (§5). Drones within range of each other but not of the owner then stop sharing positions until the owner is heard again. Safety over availability.

## 2. Prior art and why this design

| Design | What we take | Why not as is |
|---|---|---|
| MLS, RFC 9420 | Epochs; a key per sender inside an epoch; its **reuse guard**, which exists "to avoid nonce reuse in the case of state loss or corruption" | Tree math and signatures; messages too large for LoRa. Worth a look for big groups later |
| Bluetooth Mesh | Sequence numbers saved before use; a replay list kept across restarts; an index bit telling two key generations apart | Shared key with per-source nonces; AES-CCM; own stack |
| Wi-Fi group key (IEEE 802.11 GTK) | A group key handed out over each device's own encrypted session; two keys installed during a change (KeyID) | Fixed to Wi-Fi; a new key on leave is only an option (hostapd `wpa_strict_rekey`) |

The main risk in any group design is a **repeated nonce**: two packets under one key and counter leak both plaintexts and allow forgeries. Files can be lost, restored from backup, copied to another device or used by two processes. So this design does not trust saved counters alone: **a sender sends only under a sender id it was given during its own process's life** (§4), and the saved counter is a second layer.

## 3. Groups, owners and members

- A group is identified by **(owner fingerprint, group id)** everywhere: in files, on the command line and in pins. The 2-byte **group id** is what goes on the air; the owner picks it at random.
- The **owner** is one device, usually a ground station. It makes every key, decides who is in, and is also a sender with its own sender id.
- **Who may own a group on this device** is a separate local permission, set only by `oasa-pair group allow-owner PEER` and kept in its own file, `group-owners` (so `trusted-peers.v1` and older programs that read it don't change). Pairing does **not** grant it. Roles (`admin`, `operator`) give no group rights, and a group owner gets no command or removal rights. A device accepts group control messages only from a peer it lists with `group-owner`; anything else is dropped (`bad_role`).
- **Id clash:** if a device already holds a group with the same wire id from another owner, it answers `GROUP_ID_TAKEN` and the new owner picks another id, and logs which member refused it (a device that lets two owners in could use this to make one re-pick). Two owners can never share a wire id on one device.
- **Losing the owner:** when a device removes the owner, or takes away its `group-owner` permission, it deletes every group from that owner. `oasa-pair group forget OWNER` does the same by hand (for an owner that was re-paired).
- **Membership is not trust.** A drone in a group reads packets from other members but does not add them to `trusted-peers`; it can't start a link with them, and they can't command it.

## 4. Keys and packets

**Epoch key.** For each epoch `e` (a 4-byte number that only grows) the owner makes a fresh random 32-byte key `G[e]`. A new epoch replaces the old one completely; nothing is derived from the previous key.

**Sender ids.** The owner gives each member a 2-byte sender id in each `GROUP_KEY` (§5). Rules:

- **A sender id is issued at most once per epoch, to anyone, the same device included.**
- Each epoch has an **id ceiling** set by the owner and sent in `GROUP_KEY` (default 8 × members + 16). Every id in that epoch, including ids issued later, is below it, handed out in a random order, so a device can't be followed across epochs by its id. One member gets at most 8 ids per epoch (more are refused and logged). When the owner runs out of ids it starts a new epoch.
- **Keys and ids loaded from disk are receive-only.** A device sends only under a sender id issued to this process. At the start of every link session with the owner, a device that has no id issued to this process sends `GROUP_ID_REQUEST`, and the owner answers at once with a `GROUP_KEY` for the current epoch carrying a fresh id. A restarted, restored or copied device therefore always sends under a new id.
- **One sender per group per folder:** a sending process holds `.group-<owner>-<id>.lock`. A second process on the same folder only receives.

**Sender keys.** Every sender encrypts with its own key:

```
K[e, s] = BLAKE2s-256(key = G[e], data = "OASA-SEC v1 group" ‖ owner public key (32) ‖ group id (2) ‖ e (4) ‖ s (2))
```

Fixed-length input with a label. Keyed BLAKE2s is a PRF (BLAKE2 paper; the MAC mode is RFC 7693). The receiver derives the same key from the header.

**Packet** (new header type `4`, link wire version 1):

```
[header: 1][group id: 2][epoch: 1][sender id: 2][counter: 4][ciphertext + 16-byte tag]
plaintext: [content type: 1][body]
```

- **Header byte:** type `4`, bit 3 **reserved, must be 0**, version `1`.
- **Epoch:** the low byte of `e`. A device holds at most two epochs, and never two with the same low byte (§5); anything else is dropped (`unknown_group`).
- **Counter:** the whole 32-bit counter per (sender, epoch), starting at 0. A sender stops at 2³² − 1 and waits for the next epoch. A receiver drops nothing for being "far ahead"; the replay window decides.
- **Nonce:** `snow`'s ChaChaPoly takes a 64-bit nonce and lays it out as 4 zero bytes followed by the 64-bit value little-endian. We pass the counter. Known-answer tests state this layout.
- **Associated data:** the whole 10-byte header. Changing any header byte fails the tag.
- **Content type:** `0x00` (application, with a body) or `0x02` (**activation**, empty body, never delivered; §5). Anything else is dropped after authentication (`bad_content`).
- **Size:** at least **27 bytes** (10 header + 1 content type + 16 tag), checked before any crypto (`snow` does not check, and a short packet would crash it). Overhead 27 bytes: a 128-byte radio packet carries 101 bytes of group data.

**Receiving**, in order, dropping silently on failure:
1. Length at least 27 and within the MTU; header byte valid.
2. Group id known; epoch byte matches a held epoch.
3. Sender id below the epoch's id ceiling. If it is this device's own id: a counter this device sent recently (kept in a small ring) is an **echo** (a multicast loopback or a repeater) and is dropped quietly; any other counter is logged as `sender_clash`, the sign of a clone or a jam, and reported to the owner (§5). Group sockets turn multicast loopback off.
4. Counter inside or ahead of the replay window, if the sender has one.
5. Tag verified.
6. **Replay window** (RFC 6479, 1024 packets) per (sender, epoch), **created only after a valid tag**, updated only after the tag.
7. Content type.

Drops are counted (`unknown_group`, `too_old`, `bad_tag`, `replay`, `bad_content`, `sender_clash`) and never logged with contents.

**Counters on disk (second layer).** Before a sender uses counter value `c`, it has saved a reservation above `c`, in blocks of 65,536: write a temp file, `fsync` it, rename it, `fsync` the folder; start at `R`, save `R + 65,536`, then send `R`. A missing or unreadable reservation means **never send in that epoch**.

**Replay across restarts.** As Bluetooth Mesh keeps its replay list, each member saves the highest counter it has accepted per (sender, epoch) at least every 10 s and when it stops. After a restart, anything at or below the saved value is `too_old`. A crash can let packets from at most the last 10 s before it be replayed once; a clean stop leaves no gap. No rotation is needed when a member reboots.

**Wiping keys.** Epoch keys, sender keys and carried keys are `Zeroizing`. `snow`'s cipher keeps its own key copy and doesn't wipe it, so each cipher object is reset with an all-zero key before it is dropped. There is one cipher object per (sender, epoch).

## 5. Epochs: joining, leaving and rotating

New control messages (link spec §3, content type `0x01`), over each member's own link session:

| Type | Name | From → to | Body | Bytes |
|---|---|---|---|---|
| `0x30` | `GROUP_KEY` | owner → member | group id (2), epoch (4), flags (1), your sender id (2), id ceiling (2), epoch life in minutes (2), key (32) | 50 |
| `0x31` | `GROUP_ACTIVATE` | owner → member | group id (2), epoch (4) | 11 |
| `0x32` | `GROUP_LEAVE` | owner → member | group id (2) | 7 |
| `0x33` | `GROUP_HAVE` | member → owner, answering a `GROUP_KEY` (same request id) | group id (2), newest epoch held (4) | 11 |
| `0x34` | `GROUP_ID_TAKEN` | member → owner | group id (2) | 7 |
| `0x35` | `GROUP_REKEY` | member → owner | group id (2), reason (1): sender clash, counter near its limit | 8 |
| `0x36` | `GROUP_ID_REQUEST` | member → owner | group id (2) | 7 |

Flags in `GROUP_KEY`: bit 0 **no grace** (set when the new epoch is caused by a removal). With the link's overhead, the largest is 72 bytes (74 with the long counter): it fits the 128-byte MTU. `GROUP_KEY` is carried in `Zeroizing` buffers. The usual rules hold: `ACK` for each, retries from 2 s doubling to 60 s.

**What a member does with a `GROUP_KEY`:**
- **A newer epoch** (and its low byte differs from the epoch still held, else the older one is dropped at once): save it (file `0600`), receive on it, keep sending on the current epoch. If a newer epoch was already pending (not active), the new one **replaces** it.
- **The epoch it already holds**, same key: take the new sender id (a fresh id for this session, §4). Same epoch with a **different key** is refused and logged (`group_conflict`), never silently ignored.
- **An older epoch:** answer `GROUP_HAVE` with the newest epoch it holds. The owner accepts `GROUP_HAVE` only as the answer to a `GROUP_KEY` it sent, and jumps above the number only if it is less than its own epoch + 2²⁰; otherwise it logs `group_have_refused` (a bad member can't push the epoch to its end). This repairs an owner restored from an old backup. An owner whose epoch numbers run out starts a new group id.

**Rotation:**
1. The owner makes `G[e+1]` and **saves it with the full sender-id table (`fsync`) before any `GROUP_KEY` leaves**. It sends `GROUP_KEY` to every member it keeps.
2. When every member has acked, or after the **activation timeout**, the owner **activates by sending an activation packet** (content type `0x02`) in `e+1`: a member switches on the first packet in `e+1` whose tag verifies, whatever its content type. After another activation timeout, the owner sends `GROUP_ACTIVATE` by link to every member it has not heard on `e+1` (silent members and those out of its radio range included). An `ACTIVATE` for an epoch not held is ignored and not acked. The timeout is 30 s by default and scales with the radio's airtime like the link's retry timer.
3. After switching, a member keeps receiving on `e` for a **grace time** of 60 s, then wipes `G[e]`, its sender keys and windows. With **no grace**, it wipes `e` at once.
4. **Maximum epoch life:** a member drops an epoch once the epoch life given in its `GROUP_KEY` has passed since it received the key (monotonic clock; the owner sets twice its rotation time), even if no new one came. Group traffic then stops until the owner is heard from; it never silently continues on an old key.

**When the owner rotates:**

| Event | What happens |
|---|---|
| A member is removed (locally, by `revoke`, or by an admin's entry the owner has applied) | New epoch at once, without that member, with **no grace**; activate without waiting for acks. Any removal starts a new epoch with a new key, **even in the middle of a rotation**. Queued and retried `GROUP_KEY`s to the removed peer are dropped |
| A member leaves (`oasa-pair group remove`) | Same, plus `GROUP_LEAVE` to that member (a courtesy: safety never depends on it) |
| The owner starts | New epoch. The owner never issues ids in an epoch loaded from disk |
| Time | Every 60 minutes by default (set per radio) |
| The owner's own counter passes 2³¹, or a member's authenticated `GROUP_REKEY` | New epoch, but no sooner than the **minimum rotation interval** after the last one (5 minutes by default; removals ignore it). Requests inside one interval make one rotation, and each member's requests count toward at most one rotation an hour (more are logged, not acted on). A member can't force rotations by forging high counters: only the owner's own counter and link messages count |
| A device joins | New epoch, so a new member can't read what was sent before it joined. Can be turned off per group for busy groups |

**Session start:** the owner can't tell a member's restart from a rekey, so the member asks: it sends `GROUP_ID_REQUEST` when it has no id issued to its process (§4). Otherwise the owner resends a `GROUP_KEY` only if the member hasn't acked the current epoch.

**Airtime on slow radios.** On LoRa SF12 (about 290 bit/s), one `GROUP_KEY` and its `ACK` take about 5 s, so a rotation over 20 members takes over a minute, and an hourly rotation doesn't fit a 1% duty cycle (36 s an hour in the EU868 band). Set long rotation times on such radios, keep groups small, and expect removal to take minutes there, not seconds. Measure in the lab before choosing defaults (§10).

## 6. Files

| File | Content |
|---|---|
| `groups/<owner fingerprint>-<group id>.v1` | Owner, newest epoch, up to two epoch keys, id ceiling and epoch life per epoch (`0600`). Ids and keys loaded from here are receive-only (§4) |
| `groups/<owner fingerprint>-<group id>.seen` | Highest counter accepted per (sender, epoch), saved every 10 s and at stop |
| `group-owners` | Peers allowed to own groups on this device |
| `groups/<owner fingerprint>-<group id>.counter` | The sender's reservation per epoch, with the sender id it belongs to |
| `groups-owned/<group id>.v1` (owner only) | Members with their public key, the sender ids issued per epoch, ack state. Saved with `fsync` before a `GROUP_KEY` leaves |

Files are changed under the same `.lock` and swapped in atomically, as `trusted-peers`; the sender lock is §4.

## 7. Using it in `oasa-link`

- A group gets its own plaintext ports: `--group OWNER:ID --group-plain-listen H:P --group-plain-send H:P`. `--group-plain-listen` must be a loopback address. Group traffic never mixes with a link session's plaintext, so a local program always knows whether a packet was proven to come from one peer or only from some member.
- On the radio side, group packets go to a broadcast address given with `--group-remote H:P` (a UDP broadcast or multicast address, or a radio adapter that broadcasts).
- **Never to an autopilot.** Group traffic is for companion software (position sharing, beam steering, discovery), not for the flight controller. On a drone, `--group-plain-send` must not reach the autopilot or a MAVLink router that forwards to it. Group MAVLink would be dangerous there:
  - `HEARTBEAT` from a forged "ground station" stops PX4's lost-link failsafe;
  - `ADSB_VEHICLE` triggers avoidance actions (PX4 `NAV_TRAFF_AVOID`: return or land; ArduPilot `AVD_F_ACTION`: climb, move, return);
  - `GLOBAL_POSITION_INT` steers ArduPilot's follow mode.

  PX4 accepts `HEARTBEAT` and `ADSB_VEHICLE` unsigned even with signing on, so signing gives no protection here.
- So the **group MAVLink guard starts empty** (a separate guard from the link's, which it never inherits). On a drone it scans every byte offset of every group datagram for a whole, CRC-valid MAVLink 1 or 2 frame, as a router does, and drops the datagram if it finds any frame not allowed. Companion data that holds no MAVLink frame passes. If a drone's companion must pass some MAVLink, `--group-allow-msg ID` adds one, with a warning. `HEARTBEAT` with type ground station or with the drone's own system id, `TIMESYNC`, and everything the link guard blocks can never be allowed. `ADSB_VEHICLE` needs `--group-allow-adsb`, which warns that any member can trigger avoidance, and the docs require warn-only avoidance settings.
- **Send side:** a drone sends to the group only what its companion software writes to the group port, never its autopilot stream: status text, parameters and missions don't go to members it doesn't trust.
- Library: `oasa_sec::group`, sans-IO like the link: keys, counters and time come in as arguments.

## 8. Threats

| Who | Can | Can't |
|---|---|---|
| Outsider on the air | See sizes, timing, group id, epoch byte, sender id and counter (so traffic volume, and that one fleet is the same across days) | Read or forge packets. Replays are dropped by the replay window, also after a restart (saved counters, §4), except up to 10 s of packets after a member crashes. Can deliver a recorded packet late, within its epoch, to a member that didn't hear it |
| A removed device | Read and forge in the current epoch until the owner applies the removal and each member switches (no grace). Toward a member the owner can't reach, until that member's maximum epoch life runs out | Read or forge after that, or get a new key |
| A member that turns bad | Forge packets as any member. Jam a sender, the owner included, by sending its sender id with high counters, which pushes that sender's real packets out of everyone's replay window | Reach an autopilot (§7), force more than one rotation an hour or use up the epoch numbers, change membership, or touch link sessions |
| The owner, if stolen | Everything in its groups | Anything a link session protects, or anything it has no `group-owner` permission for |

A jam has no fix with a shared key. It shows up as one sender's packets suddenly dropping as `too_old`, or as `sender_clash` at the jammed sender. The fix is to remove the member (a new epoch at once).

## 9. To be tested before code is merged

- Known-answer vectors for `K[e, s]` and for one packet (with the stated nonce layout), checked by an independent implementation (Python, as for pairing).
- **No repeated nonce, ever.** Kill and restart a sender mid-epoch; restore its folder from an older copy; copy a folder to a second device; run two processes on one folder; remove and re-add a member in one epoch; crash the owner mid-rotation and restore it from an older copy. Every capture is checked for a repeated (key, nonce) pair.
- L1: three or more members through the lossy simulated channel: rotation with a member offline, removal with no grace, a removal in the middle of a rotation, a forged header byte, an old epoch replayed, a replay to a member after a clean stop and after a crash, a multicast echo (no `sender_clash`), ids issued mid-epoch (accepted by every member), a member asking for ids in a loop (capped), a forged `GROUP_HAVE` near 2³², a member sending with another's sender id, a member forging high counters (no rotation storm), the 256-epoch low-byte wrap, a packet shorter than 27 bytes.
- The guard: with the defaults, nothing from a group reaches the plaintext port as MAVLink; the never-allowed messages stay blocked under every flag.
- Airtime: a rotation over the LoRa profiles, measured.
- Captures checked by the lab's checker for plaintext.

## 10. Open questions

1. **Signatures for fleet commands.** Ed25519 (`ed25519-dalek`, same family as our X25519) would let one group packet carry a command any drone can check. Needs an OASA Proposal: the standard allows only X25519 for now.
2. **Reuse guard instead of fresh ids.** MLS XORs a random 4-byte value into each nonce. It would cost 4 bytes a packet and make restarts cheaper. Fresh ids cost nothing on the air, so they are the choice for now.
3. **More than one owner.** If the owner ground station is lost, today a second device with `group-owner` must start a new group. Should groups have a backup owner?
4. **Big groups.** Rotation costs one `GROUP_KEY` per member. Fine for tens of devices; for hundreds, look at MLS.
5. **Hiding the sender id and counter.** They are in the clear. Bluetooth Mesh and MLS both hide theirs; it costs one more cipher call per packet.
6. **Freshness.** A coarse time field (seconds since activation, in the associated data) would bound late delivery. Members' clocks need not agree, but it adds 2 bytes.
7. **Default rotation and epoch-life times per radio**, once lab runs measure the cost on LoRa.
