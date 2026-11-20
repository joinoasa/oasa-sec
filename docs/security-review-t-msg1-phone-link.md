# Design review: T-MSG1 phone link

**Status:** v0.1, 2026-11-16 · **Kind:** internal design review, written by an AI agent (Claude) that did not write the spec; not an outside review, and no code exists yet · **Owner:** citruscybersec

Review of the first draft of [oasa-sec-v0-phone-link.md](oasa-sec-v0-phone-link.md). It does not replace the person's security review the task card asks for.

## Scope and method

The draft was read against the [pairing](oasa-sec-v0-pairing.md) and [link](oasa-sec-v0-link.md) specs and the code at `26b628f`: `src/link/{mod,endpoint,packet}.rs`, `src/pairing.rs`, `src/lib.rs`, `src/bin/oasa-pair.rs`. Nothing was run. The group and rotation specs were not read in full.

## Findings

Every fix below is a change to the spec's text. None has been tested: there is no code.

| ID | Severity | Finding (in the first draft) | Change made to the spec | Status |
|---|---|---|---|---|
| H1 | High | **Swap during the press wait.** The pairing connection fell under the session's 5 s and eviction rules. A stranger could knock the owner's completed attempt off during the 30 s wait, complete with the code read in the clear, and have the owner's press confirm the stranger. | The first completed handshake uses up the code and closes the window; the pending phone is kept apart from its connection; pairing attempts use R-SEC1's timers (§2 step 5). Suite case 5 | Applied |
| H2 | High | **No confirmation reached the phone.** The phone could not tell whether the press saved it, and an owner who pressed for a stranger was never told. | The first completed link handshake is the confirmation; without it the app deletes the radio and tells the user to reset (§2 step 6). Suite case 7 | Applied |
| M1 | Medium | **"The phone initiates every handshake" was false against the code:** the responder starts handshakes for the late rekey, the stale rule and when it has data and no session (`endpoint.rs`). | §3 now says either side may initiate and both save their timestamps. A "never initiate" setting is open question 8. Suite case 12 | Applied |
| M2 | Medium | **Flash-wear estimate counted only hourly rekeys,** not reconnects or radio-started handshakes. | §3 states 24 a day as a floor and asks the firmware card to count writes on real phones | Applied |
| M3 | Medium | **No way out of a stale-timestamp lock,** and `max_future` on a clockless radio was not addressed. | `max_future` off on the radio; the phone keeps its last-sent value with its keys; reset clears saved timestamps (§2, §3). Suite case 13 | Applied |
| M4 | Medium | **The handshake filter ties the radio to the messaging identity** for anyone who knows the public key; §1 and §6 overstated. | §1, §6 and §7 reworded | Applied |
| M5 | Medium | **The hold store could be flooded** with packets made to match a filter, pushing real packets out and waking the phone. | Shares per filter kind and per filter, wake limit (§5); added to §6. Suite case 15 | Applied |
| M6 | Medium | **"Pairing over USB avoids it" was unfounded** while the code was also readable on BLE. | During a USB pairing the code is not offered on BLE (§2). Suite case 9 | Applied |
| M7 | Medium | **Roles and control messages were undefined.** | Both sides save `peer`; control messages carry no rights (§3). Suite case 17 | Applied |
| L1 | Low | Drop reason names were incomplete (`bad_header` for an unknown radio key, `rate_limited`, `replay` in the previous session's grace). | §3 lists them; the suite checks the outcome, not one reason (§8) | Applied |
| L2 | Low | Signed firmware could be rolled back; Bluetooth update modes were not named. | §4 and §6 require refusing older releases by every path. Suite case 18 | Applied |
| L3 | Low | A returned radio stays a risk after a firmware reload (copied device key; `IK` key compromise impersonation). | §6: retire or re-key; open question 9 | Applied |
| L4 | Low | No acknowledgement message for fetch deletes; MTU unstated; the confirm wait was not tied to the window. | `FETCH_ACK`, the MTU rule, and the window closing at the first completion (§2 to §4) | Applied |
| L5 | Low | The light shows "press" for a stranger's completion while the owner's app may still be retrying. | The app shows "wait" until it completes; kept as a known limit (§7). A blink count from the handshake hash is open question 10, not adopted | Partly applied |
| I1 | Info | The header linked to review notes that did not exist. | This page | Applied |
| I2 | Info | A new pairing prologue needs a new constant beside `PAIRING_PROLOGUE`. | Noted in §10 | Applied |

## Checked and found sound

- No new crypto: Noise `IK` and `IKpsk1`, X25519, ChaCha20-Poly1305, BLAKE2s.
- The radio never holds message keys or plaintext. Two phone key pairs is sound.
- A separate pairing prologue keeps phone and drone pairings apart.
- The label check with `IK` stops a swapped code. A stranger who only listens learns nothing.
- Rekey at 1 hour, reject at 90 minutes, keepalive timer off: accepted by `Config::validate`. The link still answers with keepalives as acknowledgements and still runs the stale rule.
- The handshake timestamp rule works on a responder with no clock: it only compares against the saved value.
- `mac1` keyed from a public key works as a filter (8 bytes; few chance matches).
- A replayed command inside a session is dropped by the 1024-packet window.
- A forged wake shows nothing, because the app handshakes and checks tags before alerting.
- The development-board caveat, and a taken-over phone being out of scope.

## Not verified

- nRF52840 BLE connection slots, and whether wake works with private addresses.
- The flash part's endurance.
- Whether the timestamp store keeps per-peer state a reset can clear.
- The changes made after this review have not been reviewed again.
