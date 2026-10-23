# OASA-SEC v0: identity and pairing (draft)

**Stage:** Idea → Draft (one working prototype: this repo) · **Node:** R-SEC1 · **Last reviewed:** 2026-10-22

How two OASA devices learn to trust each other, and how a drone gets a MAVLink signing key without it ever crossing a link in the clear. Encrypting the drone link itself is the next node (R-COM2) and will reuse these identities.

## 1. Identity

- Each device makes its own **X25519** key pair, on the device, from the operating system's random source. Keys are never copied between devices, built into images or committed anywhere. (Lesson from Meshtastic's 2024 key-reuse CVE.)
- **Fingerprint:** the first 10 bytes of BLAKE2s-256(`"OASA-SEC v0 fingerprint"` ‖ public key), in base32, grouped by four: `RMFD-FA45-4SU3-MDIO`. People compare fingerprints out loud or on screen.
- The private key file is 32 bytes, mode `0600`. Software refuses to load it if others can read it.

## 2. Pairing code

When a drone enters pairing mode it makes a **new one-time code**:

| Bytes | Field |
|---|---|
| 1 | Version (`1`) |
| 32 | Drone's public key |
| 32 | Fresh random secret |
| 4 | Checksum: first 4 bytes of BLAKE2s-256(`"OASA-SEC v0 code checksum"` ‖ the 65 bytes above) |

Text form: `OASA1-` + uppercase base32 without padding (117 characters). Every character is in the QR "alphanumeric" set, so the QR stays small. Readers accept lowercase, spaces and dashes so a person can type it in chunks.

The code is shown as a QR code on the drone's screen or companion app, or passed over USB. **Anyone who sees it can pair once.** The code is thrown away after one successful pairing or when the pairing window closes (5 minutes by default). Failed attempts don't end the window: they can't guess a 256-bit secret, so a lockout would only let a stranger shut pairing down. Each attempt is limited to 15 seconds in total and each message to its real size, so a slow or oversized sender can't hold the drone.

The ground station reads the code from a scan, a file or standard input, never from the command line, where other users could see it. People can pass the fingerprint printed on the drone with `--expect-drone` so a swapped QR code is caught.

## 3. Handshake

`Noise_IKpsk1_25519_ChaChaPoly_BLAKE2s`, prologue `"OASA-SEC v0 pairing"`. The ground station is the initiator; the drone is the responder.

- **IK:** the ground station already knows the drone's public key (from the code) and sends its own identity encrypted.
- **psk1:** the code's secret is mixed in at the end of the first message, so the drone rejects anyone without the code **before replying at all**. (An earlier draft used psk2, which let the drone reply to anyone who knew its public key. A test caught it.)

Messages over a stream transport, each framed as a 2-byte big-endian length and the bytes:

1. Ground → drone (handshake): hello `[0x01, len, name]`. The drone checks the secret here.
2. Drone → ground (handshake): hello. Handshake done; everything after is encrypted.
3. Drone → ground: the autopilot's current key `[0x02, 32 bytes]`, or `[0x04]` "need a key".
4. If the drone had a key: ground → drone `[0x03]` confirm. Done.
5. If the drone needed one: ground → drone `[0x02, fresh key]`. The drone loads it into its autopilot and proves it works (below), then replies `[0x03]` confirm or `[0x05]` failed.

Names are 1–32 characters of `A-Z a-z 0-9 - _ .`.

## 4. Trust

Each side saves the other's public key and name in an owner-only `trusted-peers` file. In v0 this list is a record, not yet a gate: nothing checks it before acting. R-COM2 will use it to decide who may open an encrypted link. Removing a peer edits the list only; locking a lost device out needs key rotation (R-SEC2).

## 5. MAVLink signing

MAVLink 2 signing proves who sent a message but doesn't hide it, so OASA only uses it **inside** encryption. The MAVLink spec says signing keys must only go over a secure link and never be broadcast:

- The first ground station to pair makes a fresh random 32-byte key (never from a passphrase) and sends it **inside** the encrypted pairing channel. Later ground stations receive the drone's existing key the same way, so pairing a second ground station never locks out the first.
- The drone's companion computer loads a new key into the autopilot with `SETUP_SIGNING` over its **local wired link**, never the radio. It then sends a command signed with the new key and waits for a signed, matching acknowledgment. **Only then** is the key saved and the pairing confirmed. If the autopilot didn't take it, nothing is saved on either side.
- A drone keeps one autopilot key (`mavlink-signing-key.bin`). A ground station keeps one key per drone (`signing-keys/<fingerprint>.bin`). Both use PX4's 40-byte layout (key, then 8-byte timestamp), mode `0600`, written atomically.
- Changing an autopilot's existing key is key rotation (R-SEC2). PX4's docs say a key change must be signed with the current key; ArduPilot's behavior here is not yet confirmed.

**Known PX4 behavior to design around:** with no key yet, PX4 accepts the first `SETUP_SIGNING` unsigned on any link. Until a drone is paired, someone in radio range could set a key first. Pair before flight, and keep the radio off or the vehicle disarmed until paired. If someone did get there first, the signed check in pairing fails and nothing is saved, so the problem shows up instead of hiding.

## 6. Known limits (v0)

- `snow` does not wipe its handshake and session state from memory; our own copies of secrets are wiped.
- Secret files are refused if others can read them or if they are symlinks, but the file owner isn't checked yet.
- The drone accepts the first ground station with the code; there's no on-drone confirm button yet.
- One MAVLink link ID per role (ground 0, companion 1).

## 7. Not covered yet

- Encrypting the drone link (R-COM2), key rotation and lost-device lockout (R-SEC2).
- Pairing over the radio itself (today: TCP, so Wi-Fi, Ethernet or USB networking).
- Hardware key storage (secure elements) and other curves.
- Testing against PX4 and ArduPilot SITL.
- Independent review. Required before this moves past Draft.
