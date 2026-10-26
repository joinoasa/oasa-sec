# OASA-SEC v0: group keys for one-to-many traffic (draft)

**Stage:** Idea → Draft · **Node:** R-COM2 (phase 2) · **Last reviewed:** 2026-10-26 (not yet reviewed by a person)

One encrypted packet that every member of a group can read: a ground station's position updates to its fleet, nodes sharing position and velocity for smart beams (T-RF4), discovery beacons. On a radio that is broadcast by nature (LoRa, a shared Wi-Fi channel), one group packet replaces one copy per device.

Builds on the [link](oasa-sec-v0-link.md) and on [roles and removal](oasa-sec-v0-rotation.md). **No new crypto:** keys travel inside link sessions; packets use ChaCha20-Poly1305 through `snow`'s cipher, and keys are derived with keyed BLAKE2s, as the link's `mac1` already does.

## 1. What a group key does and doesn't do

- **Does:** keeps group traffic unreadable to anyone outside the group, and proves a packet came from *some* member.
- **Doesn't:** prove *which* member sent it. Every member holds the key, so any member can forge a packet from any other. That is true of every symmetric group key (Wi-Fi's group key is the same). So:
  - **No commands over group keys.** Commands to a fleet go one by one over each drone's own link session, as today. Group packets carry telemetry, positions and beacons only (§7).
  - **No control messages over group keys.** Removal logs and signing keys stay on link sessions, which prove the sender.
  - Commands that one packet must carry to many devices need **signatures**. That needs a new algorithm (for example Ed25519), so it waits for an OASA Proposal and owner approval (§10).
- **Removal:** a removed device can read group traffic until the next epoch is active, normally a few seconds (§5).

## 2. Prior art and why this design

| Design | What we take | Why not as is |
|---|---|---|
| Wi-Fi group key (IEEE 802.11 GTK) | A group key handed out over each device's own encrypted session; a new one when a device leaves | Fixed to Wi-Fi |
| Bluetooth Mesh | Sequence numbers saved before use, so a reboot never repeats a nonce; a key refresh in phases | AES-CCM and a 4-byte MIC; own stack |
| Signal "sender keys" | A separate key per sender inside a group | Uses signatures for sender proof (not yet ours) |
| MLS, RFC 9420 | Epochs: one key state per membership | Tree math and signatures; large messages for LoRa. Worth a look for big groups later |

## 3. Groups, owners and members

- A **group** has a 2-byte **group id**, picked at random by its **owner** and unique on the owner.
- The **owner** is one device, usually a ground station. It makes every key and decides who is in. A device accepts group messages for a group only from a peer that it lists as **`admin` or `operator`**, and **pins** that owner to the group id when it first joins: later group messages for that id from anyone else are dropped (`bad_role`).
- Each member gets a 2-byte **sender id**, unique within the group and given by the owner. The owner never gives one sender id to two devices in the same epoch, and never gives a device a sender id that another device used in that epoch (this is what keeps nonces unique, §4).
- **Membership is not trust.** A drone in a group reads packets from other members but does not add them to `trusted-peers`; it can't start a link with them, and they can't command it.
- **Owner removed:** when a device removes a group's owner (locally or by an admin's entry), it deletes every group that owner made.

## 4. Keys and packets

**Epoch key.** For each epoch `e` (a 4-byte number that only grows) the owner makes a fresh random 32-byte key `G[e]`. A new epoch replaces the old one completely; nothing is derived from the previous key.

**Sender keys.** Every sender encrypts with its own key, so two senders never share a nonce space:

```
K[e, s] = BLAKE2s-256(key = G[e], data = "OASA-SEC v1 group" ‖ group id (2) ‖ e (4) ‖ s (2))
```

Keyed BLAKE2s is a PRF (RFC 7693) and already in use. The receiver derives the same key from the header.

**Packet** (new header type `4`, link wire version 1):

```
[header: 1][group id: 2][epoch: 1][sender id: 2][counter: 4][ciphertext + 16-byte tag]
plaintext: [content type: 1][body]
```

- **Header byte:** type `4`, counter-length bit `0`, version `1`. Group packets always send 4 counter bytes (many senders, more loss).
- **Epoch:** the low byte of `e`. A receiver holds at most two epochs (§5) and picks the one whose low byte matches; anything else is dropped (`unknown_group`).
- **Counter:** 64 bits per (sender, epoch), starting at 0, used as the ChaCha20-Poly1305 nonce under `K[e, s]`. The low 4 bytes are sent; the receiver rebuilds the rest as for link data (link spec §3).
- **Associated data:** the whole header (the 10 bytes before the ciphertext). Changing any header byte fails the tag.
- **Content type:** only `0x00` (application) is accepted; `0x01` and anything else is dropped after authentication (`bad_content`).
- **Overhead:** 1 + 2 + 1 + 2 + 4 + 1 + 16 = **27 bytes**. A 128-byte radio packet carries 101 bytes of group data.

**Receiving**, in order, dropping silently on failure: header valid and length within MTU; group id known; epoch byte matches a held epoch; sender id is not this device's own; counter rebuilt and inside the replay window; tag verified; **replay window** (RFC 6479, 1024 packets) per (sender, epoch), updated only after the tag; content type. Drops are counted (`unknown_group`, `too_old`, `bad_tag`, `replay`, `bad_content`) and never logged with contents.

**Saving counters (no nonce ever repeats).** Before a sender uses a counter value, it has saved a higher **reservation** to disk (write, `fsync`, rename), in blocks of 65,536. After a restart it starts from the saved reservation. A sender that can't save its reservation **must not send** group packets. This is how Bluetooth Mesh handles its sequence numbers.

**Limits per epoch:** a sender stops at 2³² packets and waits for the next epoch; the owner starts a new epoch before any sender gets there (§5).

## 5. Epochs: joining, leaving and rotating

New control messages (link spec §3, content type `0x01`), sent only from the owner over each member's own link session:

| Type | Name | From → to | Body | Bytes |
|---|---|---|---|---|
| `0x30` | `GROUP_KEY` | owner → member | group id (2), epoch (4), your sender id (2), key (32) | 45 |
| `0x31` | `GROUP_ACTIVATE` | owner → member | group id (2), epoch (4) | 11 |
| `0x32` | `GROUP_LEAVE` | owner → member | group id (2) | 7 |

With the link's 22 bytes, the largest is 67 bytes: it fits the 128-byte MTU. The usual rules hold: `ACK` for each, retries from 2 s doubling to 60 s, idempotent, an epoch at or below the newest held is ignored.

**Rotation:**
1. The owner makes `G[e+1]`, gives sender ids, and sends `GROUP_KEY` to every member it keeps.
2. A member saves the key (file `0600`, wiped from memory when dropped) and **receives** on both `e` and `e+1`, but still **sends** on `e`.
3. When every member has acked, or after the **activation timeout**, the owner sends `GROUP_ACTIVATE`. The timeout is 30 s by default and scales with the radio's airtime like the link's retry timer.
4. On `GROUP_ACTIVATE`, or on the first valid packet it gets in `e+1`, a member sends on `e+1`. It keeps receiving on `e` for a **grace time** of 60 s after its switch, then wipes `G[e]`, its sender keys and windows.

**When the owner rotates:**

| Event | What happens |
|---|---|
| A member is removed (locally, by `revoke`, or by an admin's entry) | New epoch at once, without that member. The owner may activate **without waiting** for acks, for a fast cut-off |
| A member leaves the group (`oasa-pair group remove`) | Same, plus `GROUP_LEAVE` to that member (a courtesy: safety never depends on it) |
| Time | Every 60 minutes by default (set per radio) |
| A sender's counter passes 2³¹ | New epoch |
| A device joins | New epoch, so a new member can't read what was sent before it joined. Can be turned off per group for busy groups |

A member that was offline at a rotation gets the current epoch when its link session comes back: the owner sends `GROUP_KEY` and `GROUP_ACTIVATE` at the start of each session, as admins send `REMOVE_HEAD`.

## 6. Files

| File | Content |
|---|---|
| `groups/<owner fingerprint>-<group id>.v1` | Owner pin, newest epoch number, up to two epoch keys, our sender id per epoch (`0600`) |
| `groups/<…>.counter` | The sender's saved reservation per epoch |
| `groups-owned/<group id>.v1` (owner only) | Members with their public key and sender id per epoch, ack state |

Files are changed under the same `.lock` and swapped in atomically, as `trusted-peers`.

## 7. Using it in `oasa-link`

- A group gets its own plaintext ports: `--group ID --group-plain-listen H:P --group-plain-send H:P`. Group traffic never mixes with a link session's plaintext, so a local program always knows whether a packet was proven to come from one peer or only from some member.
- On the radio side, group packets go to a broadcast address given with `--group-remote H:P` (a UDP broadcast or multicast address, or a radio adapter that broadcasts).
- **MAVLink guard on group traffic:** on a drone, group packets pass a **stricter allowlist** than link packets: `HEARTBEAT`, `GLOBAL_POSITION_INT` (33), `ADSB_VEHICLE` (246), `TIMESYNC` (111) and nothing else by default. No commands, missions, mode changes, RC override or parameter traffic, ever, whatever flags are given (§1).
- Library: `oasa_sec::group`, sans-IO like the link: keys, counters and time come in as arguments.

## 8. Threats

| Who | Can | Can't |
|---|---|---|
| Outsider on the air | See sizes, timing, group id, epoch byte, sender id and counter | Read or forge packets, or replay them (replay window; old epochs wiped) |
| A removed device | Read group traffic until the next epoch is active (seconds) | Read anything after that, or get a new key |
| A member that turns bad | Forge packets as any member; jam a sender by sending its sender id with a high counter, which pushes that sender's real packets out of everyone's replay window | Send commands to a drone (§7), change membership, or touch link sessions |
| The owner, if stolen | Everything in its groups | Anything a link session protects |

The bad-member jam has no fix with a shared key. It shows up as one sender's packets suddenly all dropping as `too_old` (logged with the sender id), and the fix is to remove the member (a new epoch at once).

## 9. To be tested before code is merged

- Known-answer vectors for `K[e, s]` and for one packet, checked by an independent implementation (Python, as for pairing).
- L1: three or more members through the lossy simulated channel: rotation with a member offline, removal with fast activation, a restart in the middle of an epoch (the counter never repeats, checked from the capture), a forged header byte, an old epoch replayed, a member sending with another's sender id (dropped as `replay`/`too_old` as described, and logged).
- The guard: every command, mission and parameter message sent over a group is dropped.
- Captures checked by the lab's checker for plaintext.

## 10. Open questions

1. **Signatures for fleet commands.** Ed25519 (`ed25519-dalek`, same family as our X25519) would let one group packet carry a command any drone can check. Needs an OASA Proposal: the standard allows only X25519 for now.
2. **More than one owner.** If the owner ground station is lost, today a second admin must start a new group. Should groups have a backup owner?
3. **Big groups.** Rotation costs one `GROUP_KEY` per member. Fine for tens of devices; for hundreds, look at MLS (RFC 9420).
4. **Hiding the sender id.** It is in the clear, so an outsider can tell senders apart. Encrypting it (as Bluetooth Mesh obfuscates its header) costs one more block cipher call per packet.
5. **Default rotation time per radio**, once lab runs measure the cost on LoRa.
