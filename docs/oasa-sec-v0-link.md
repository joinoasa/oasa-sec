# OASA-SEC v0: the encrypted link (draft)

**Stage:** Idea → Draft · **Node:** R-COM2 · **Last reviewed:** 2026-10-23

One encrypted, authenticated link between two paired OASA devices, over any radio that can carry a packet. Modeled on WireGuard. Uses the identities and trusted-peers list from [pairing](oasa-sec-v0-pairing.md). No new crypto: Noise through `snow`, X25519, ChaCha20-Poly1305, BLAKE2s.

## 1. Goals and limits

- **Any radio:** the link takes packets in and out. It never assumes order, delivery or a minimum speed. Smallest supported packet (MTU): **128 bytes**.
- **Every packet stands alone:** loss, reordering and duplicates never break the session.
- **Only trusted peers:** a device not in `trusted-peers` gets no reply at all.
- **Small overhead:** 21 bytes per data packet (23 with the long counter).
- **Not in v0:** one-to-many group keys, padding to fixed sizes, splitting handshakes for tiny MTUs, DoS cookies, post-quantum. The version field leaves room for them.

## 2. Handshake

`Noise_IK_25519_ChaChaPoly_BLAKE2s`, prologue `"OASA-SEC v0 link"`.

- **IK:** the initiator knows the responder's public key from `trusted-peers` and sends its own, encrypted. The responder looks it up in `trusted-peers` and **silently drops** the handshake if it isn't there.
- Either side may initiate. Ground stations initiate by default.
- **Message 1** (initiator → responder) payload: a 12-byte **timestamp** (8-byte seconds, 4-byte nanoseconds, big-endian). It must strictly increase per initiator. A device without a trusted clock uses `max(clock, last_sent + 1 ns)`, saving the last value so it survives reboots. The responder keeps the newest timestamp per peer and drops any handshake that isn't newer, so a recorded message 1 can't be replayed.
- **Message 2** (responder → initiator) payload: empty.
- **Limits:** cheap checks (header, size) come before any X25519. The responder handles at most 20 handshakes a second in total, and answers each peer at most once a second.
- Sizes on the wire: handshake 1 is 111 bytes, handshake 2 is 53 bytes.

The handshake gives two keys (one per direction) used with `snow`'s stateless transport: we pass the nonce ourselves.

## 3. Packets

Every packet starts with one header byte:

| Bits | Field |
|---|---|
| 7–4 | Type: `1` handshake 1, `2` handshake 2, `3` data, `4`–`15` reserved |
| 3 | Data only: counter length (`0` = 2 bytes, `1` = 4 bytes). Must be 0 otherwise |
| 2–0 | Version: `0` for v0. Anything else is dropped |

**Handshake 1:** `[header][sender index: 2][Noise message 1]`
**Handshake 2:** `[header][sender index: 2][receiver index: 2][Noise message 2]`
**Data:** `[header][receiver index: 2][counter: 2 or 4][ciphertext + 16-byte tag]`

- **Index:** a random 16-bit number each side picks per session, so the receiver finds the session without trying keys. Not secret.
- **Counter:** a 64-bit number per direction per session, starting at 0, used as the nonce. It never repeats under a key. Only its low 2 or 4 bytes are sent.
- **Rebuilding the counter** (as DTLS 1.3, RFC 9147 §4.2.2): the receiver picks the 64-bit value closest to `highest seen + 1` whose low bytes match. This works while fewer than 32,768 packets in a row are lost or reordered, so the short counter is for links where that can't happen, and the long one for fast links.
- **The tag is never shortened** (RFC 8439 forbids it).
- **No separate header authentication:** every header field picks the key (type, index) or the nonce (counter). Changing any of them makes the tag check fail. Any field added later must keep this property or be covered as associated data.
- **Data payload:** the plaintext packet, unchanged. An empty payload is a **keepalive**.

Overhead per data packet: 1 + 2 + 2 + 16 = **21 bytes** (23 with the long counter).

## 4. Receiving data

In this order, dropping silently on any failure:

1. Header byte valid; packet long enough.
2. Index matches a live session.
3. Counter rebuilt; not older than the replay window.
4. Tag verified (decrypt).
5. **Replay window** (RFC 6479, 1024 packets): drop if already seen, otherwise mark it. Updated only after step 4, so forged packets can't move it.

Drops are counted by reason (`bad_header`, `unknown_index`, `too_old`, `bad_tag`, `replay`, `untrusted_peer`, `stale_handshake`, `rate_limited`) and logged without packet contents.

## 5. Session life

| Rule | Default |
|---|---|
| Initiator starts a new handshake after | 10 minutes or 2³² packets sent |
| Nobody sends or accepts on a session after | 15 minutes or 2⁶⁰ packets |
| Handshake retry if no answer | 5 s, then backing off to 60 s |
| Keepalive if nothing sent for | 25 s (off by default on slow radios) |

- The **initiator** may send data as soon as it gets message 2. It sends a keepalive at once so the responder learns the session works.
- The **responder** sends on a new session only after a valid data packet arrives on it. Until then it keeps using the previous session. This stops a stale or replayed handshake from breaking a working link.
- The previous session stays readable until the new one is confirmed, so a rekey loses no packets.
- Rekey limits are set per radio from its airtime: a LoRa link may rekey hourly instead.
- Keys and session state are wiped when a session ends.

## 6. Who may connect

`trusted-peers` is the gate. Removing a peer ends its sessions and stops new ones. A lost device is locked out only by key rotation (R-SEC2).

Two ways in:
- **Pairing** (`oasa-pair`), for a ground station and a drone.
- **Manual trust** (`oasa-pair trust`), for devices without an autopilot such as relays and test nodes: add a peer's name and public key after checking its fingerprint out loud, like WireGuard.

## 7. Using it

- **Library:** a sans-IO state machine (`oasa_sec::link`): bytes in, bytes out, and a clock passed in. No sockets or threads inside, so it runs the same on a laptop, a companion computer or a microcontroller later, and tests drive it through a simulated channel.
- **Tunnel:** `oasa-link` carries plaintext UDP packets from local programs (for example MAVLink from a ground station) over the encrypted link. Its radio side is UDP for now; radio adapters in [oasa-radio](https://github.com/joinoasa/oasa-radio) plug in there. It logs JSON lines for the [lab](https://github.com/joinoasa/oasa-lab).
- MAVLink signing keeps running inside the link as a second layer.

## 8. Tested

- L0: unit tests, counter rebuilding edge cases, replay window, hostile headers.
- L1: two endpoints through a seeded simulated channel with loss, delay, reordering, duplicates and replayed or changed packets; rekey under loss; untrusted peers ignored; captured packets checked for the plaintext.
- L2: real `oasa-link` processes over localhost UDP (`scripts/link-e2e.sh`): marked packets both ways, a rekey, a restart from a new port, junk and an untrusted device getting no reply, and the stats output.
- Not tested: real radios, long runs, and independent review.

## 9. Open questions

1. Handshakes on radios with an MTU under 128 bytes: split into pieces, or a smaller pattern?
2. DoS cookies (WireGuard's) for radios where someone could flood handshakes.
3. Default rekey limits per radio, once we measure airtime.
4. Group keys for broadcast (R-COM2 phase 2).
