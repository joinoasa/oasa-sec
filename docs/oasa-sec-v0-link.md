# OASA-SEC v0: the encrypted link (draft)

**Stage:** Idea → Draft · **Node:** R-COM2 · **Last reviewed:** 2026-10-23 · **v0 changed before first release:** still Draft and unreleased, so wire changes stay v0 with no version bump. After the first release a wire change needs a new version.

One encrypted, authenticated link between two paired OASA devices, over any radio that can carry a packet. Modeled on WireGuard. Uses the identities and trusted-peers list from [pairing](oasa-sec-v0-pairing.md). No new crypto: Noise through `snow`, X25519, ChaCha20-Poly1305, BLAKE2s.

## 1. Goals and limits

- **Any radio:** the link takes packets in and out. It never assumes order, delivery or a minimum speed. Smallest supported packet (MTU): **128 bytes**.
- **Every packet stands alone:** loss, reordering and duplicates never break the session.
- **Only trusted peers:** a device not in `trusted-peers` gets no reply at all.
- **Small overhead:** 21 bytes per data packet (23 with the long counter).
- **Not in v0:** one-to-many group keys, padding to fixed sizes, splitting handshakes for tiny MTUs, DoS cookies (a cheap `mac1` check is in, see §2), post-quantum. The version field leaves room for them.

## 2. Handshake

`Noise_IK_25519_ChaChaPoly_BLAKE2s`, prologue `"OASA-SEC v0 link"`.

- **IK:** the initiator knows the responder's public key from `trusted-peers` and sends its own, encrypted. The responder looks it up in `trusted-peers` and **silently drops** the handshake if it isn't there.
- Either side may initiate. Ground stations initiate by default.
- **Message 1** (initiator → responder) payload: a 12-byte **timestamp** (8-byte seconds, 4-byte nanoseconds, big-endian), then the initiator's 2-byte sender index. The timestamp must strictly increase per initiator. A device without a trusted clock uses `max(clock, last_sent + 1 ns)`, saving the last value so it survives reboots. The responder keeps the newest timestamp per peer and drops any handshake that isn't newer (`stale_handshake`), so a recorded message 1 can't be replayed. A responder **with a trusted clock** (an RTC or NTP set before it starts; off by default, `max_future` in the settings, `--trusted-clock` in `oasa-link`) also drops a timestamp more than **10 minutes ahead** of its current wall clock (`stale_handshake`) and does not save it: one wrong clock must not lock a peer out until that time. The clock is read at each check. A device with a slow or unset clock must leave this off, or it would refuse every handshake.
- **Message 2** (responder → initiator) payload: the responder's sender index, then the receiver index (2 bytes each). The receiver index is the initiator's index from message 1.
- **Indexes are authenticated, and message 1 has none in the clear:** the sender index of each side travels only inside the encrypted Noise payload. Message 2 carries the receiver index in the clear to find the handshake; it must equal the one inside the payload, or the handshake is dropped as `bad_header`. Someone on the path can't change an index to break a session or learn one from message 1.
- **`mac1` on message 1:** the last 8 bytes of message 1 are the first 8 bytes of BLAKE2s-256 keyed with `BLAKE2s-256("OASA-SEC v0 mac1" ‖ responder public key)` over the header byte and the Noise message. Anyone who knows the responder's public key (not a secret) can make it. It is only a cheap filter: random junk is dropped (`bad_header`) before any X25519 and **before** the global handshake limit is charged, so junk can't use up the budget. It does not stop someone who recorded a real message 1 (§9).
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
| 2–0 | Version: `0` for v0. Anything else is dropped |

**Handshake 1:** `[header][Noise message 1: 110][mac1: 8]`
**Handshake 2:** `[header][receiver index: 2][Noise message 2: 52]`
**Data:** `[header][receiver index: 2][counter: 2 or 4][ciphertext + 16-byte tag]`

- **Index:** a random 16-bit number each side picks per session, so the receiver finds the session without trying keys. Not secret. A side never picks an index that a live session or handshake of its own already uses.
- **Counter:** a 64-bit number per direction per session, starting at 0, used as the nonce. It never repeats under a key. Only its low 2 or 4 bytes are sent.
- **Rebuilding the counter** (as DTLS 1.3, RFC 9147 §4.2.2): the receiver picks the 64-bit value closest to `highest seen + 1` whose low bytes match. This works while fewer than 32,768 packets in a row are lost or reordered, so the short counter is for links where that can't happen, and the long one for fast links.
- **The tag is never shortened** (RFC 8439 forbids it).
- **No separate header authentication for data:** the type and index pick the key, so changing them makes the tag check fail, and the counter's low bytes are the nonce. The one change that keeps the nonce is re-encoding a short counter as a long one (or back) with the same value: the tag still verifies, and the replay window catches it as a duplicate (or it is the same packet). Handshake indexes are inside the Noise payloads (§2). Any field added later must keep this property or be covered as associated data.
- **Data payload:** the plaintext packet, unchanged. An empty payload is a **keepalive**.

Overhead per data packet: 1 + 2 + 2 + 16 = **21 bytes** (23 with the long counter).

## 4. Receiving data

In this order, dropping silently on any failure:

1. Header byte valid; packet long enough and not over the MTU. (For message 1 also `mac1`.)
2. Index matches a live session.
3. Counter rebuilt (a tie exactly half a range away takes the higher value); not older than the replay window.
4. Tag verified (decrypt).
5. **Replay window** (RFC 6479, 1024 packets): drop if already seen, otherwise mark it. Updated only after step 4, so forged packets can't move it.

Drops are counted by reason (`bad_header`, `unknown_index`, `too_old`, `bad_tag`, `replay`, `untrusted_peer`, `stale_handshake`, `rate_limited`) and logged without packet contents. A packet whose counter is at or past the receiver's own packet limit is dropped as `bad_tag`: a real peer never sends one.

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

`trusted-peers` is the gate. Removing a peer ends its sessions and stops new ones. A lost device is locked out only by key rotation (R-SEC2). `oasa-link` reads `trusted-peers` once at startup: restart it after `trust` or `remove`.

**Threat model note (clocks).** A trusted peer is trusted, including to set its clock. Timestamps stop replay of recorded handshakes, not a misbehaving peer: a peer that sends a far-future timestamp is refused (10 minutes ahead, when the check is on). If a wrong future value was saved before that, or our own clock was once far ahead, nothing newer than that value is accepted until `oasa-pair reset-stamp` clears it. Fix the clock first. Resetting what we have `seen` lets one recorded old handshake from that peer through again until a newer one arrives. `oasa-link` prints a `hint` when handshakes keep being refused as stale.

**Key compromise impersonation.** A stolen device key lets the attacker pose as any peer that device trusts, to that device, as in WireGuard and any IK design. Recovery is key rotation (R-SEC2).

Two ways in:
- **Pairing** (`oasa-pair`), for a ground station and a drone.
- **Manual trust** (`oasa-pair trust`), for devices without an autopilot such as relays and test nodes: add a peer's name and public key after checking its fingerprint out loud, like WireGuard.

## 7. Using it

- **Library:** a sans-IO state machine (`oasa_sec::link`): bytes in, bytes out, and a clock passed in. No sockets or threads inside, so it runs the same on a laptop, a companion computer or a microcontroller later, and tests drive it through a simulated channel.
- **Tunnel:** `oasa-link` carries plaintext UDP packets from local programs (for example MAVLink from a ground station) over the encrypted link. `--plain-listen` must be a loopback address and plaintext is accepted only from the `--plain-send` host, unless `--allow-remote-plain` is given (anyone who reaches that port can otherwise inject packets). Its radio side is UDP for now; radio adapters in [oasa-radio](https://github.com/joinoasa/oasa-radio) plug in there. It logs JSON lines for the [lab](https://github.com/joinoasa/oasa-lab).
- MAVLink signing keeps running inside the link as a second layer.

## 8. Tested

- L0: unit tests, counter rebuilding edge cases, replay window, hostile headers.
- L1: two endpoints through a seeded simulated channel with loss, delay, reordering, duplicates and replayed or changed packets; rekey under loss; changed handshake indexes refused; a stale rule restart after a reboot or a long blackout; mismatched rekey settings; a flood of replayed handshakes with and without the per-source limit; untrusted peers ignored; captured packets checked for the plaintext.
- L2: real `oasa-link` processes over localhost UDP (`scripts/link-e2e.sh`): marked packets both ways, a rekey, a restart from a new port, junk and an untrusted device getting no reply, and the stats output.
- Mutation checks: the receive-side packet limit and the previous-session grace are each covered by a test that fails without them.
- Not tested: real radios, long runs, and independent review.

## 9. Open questions

1. Handshakes on radios with an MTU under 128 bytes: split into pieces, or a smaller pattern?
2. DoS cookies (WireGuard's) for radios where someone could flood handshakes. `mac1` uses a public key as its secret, so someone who recorded one real message 1 can replay it (the responder drops it as `stale_handshake` but has spent an X25519 on it) and can use up the 20 a second budget. The per-source limit helps against one address only. Cookies tied to the sender's address would fix it, and need a reply to an unproven sender.
3. Default rekey limits per radio, once we measure airtime.
4. Group keys for broadcast (R-COM2 phase 2).
