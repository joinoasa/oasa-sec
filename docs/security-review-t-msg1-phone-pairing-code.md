# Code review: T-MSG1 phone pairing, first part

**Status:** 2026-11-19 · **Kind:** internal security code review, written by an AI agent (Claude) that did not write the code; it does not replace a person's review, which AGENTS.md and the spec require before this moves past Draft · **Reviewed:** draft PR #41, branch `t-msg1-phone-pairing`, commit `077d3c0`

Threat-and-countermeasure level only: no exploit code. Spec: [oasa-sec-v0-phone-link.md](oasa-sec-v0-phone-link.md) v0.4 (§2, §8, §10). Earlier design reviews: [security-review-t-msg1-phone-link.md](security-review-t-msg1-phone-link.md).

## Scope and method

- **Code read in full:** `src/phone/mod.rs`, `code.rs`, `handshake.rs`, `radio.rs`, `tests.rs`, and the `src/lib.rs` prologue constant (`git diff origin/t-msg1-phone-link-spec..077d3c0`). Compared with the already-reviewed `src/pairing.rs`, `src/code.rs`, `src/identity.rs` (`check_peer_public`, `is_small_order`) and `make_room` in `src/bin/oasa-pair.rs`.
- **Read against:** spec §2.1 to §2.9, §3 (connections), §8 cases 3 to 18, §10, and the ten "spec questions" in the PR body.
- **Run:** `cargo test` (all suites pass; 71 tests under `phone::`), `cargo clippy --all-targets -- -D warnings` (clean), `cargo fmt --check` (clean).
- **Known answers checked independently:** the pinned `OASAR1-` and `OASAT1-` strings, and R-SEC1's `OASA1-` string, were recomputed with Python's `hashlib.blake2s` and `base64.b32encode` from the layout in §2.1. All three match.
- **Mutations:** 21 single-line mutations of security checks, each run against `cargo test --lib phone` and reverted (results below). The tree was left clean.

## Findings

No High findings. Line numbers are at `077d3c0`.

| ID | Severity | File:line | Finding | Suggested fix | Status |
|---|---|---|---|---|---|
| C-1 | Medium | `radio.rs:680-708`, `940-945`, `454-458` | **A store failure does not fail closed, and the pinhole stops working.** After any `Err` from `RadioStore` the radio sets `faulted` and ignores every input, the pinhole included, until a boot. On the reset path, if `set_marker` fails with a write error (not a power loss, e.g. worn flash: the spec itself flags flash wear, open question 8), memory says unpaired (`paired = None`) while flash still holds the old phone and its link key. The doc on `store()` tells the firmware's link layer to read the trust state from the store, so the old phone (perhaps the stolen one the owner was resetting against) can still hold sessions until the boot, and after the boot no marker exists, so it is still paired. Two sources of truth, and the one the link reads is the permissive one. PR question 10 picked "ignore everything"; that is not the most conservative reading. | While faulted, refuse every link session (expose `faulted` or make `paired_phone()` the only source the link may use, and say so on `store()`), keep honouring `pinhole_reset` (it retries the whole idempotent sequence), and show the fault on the light. Add a test: a write error (not a power loss) at each reset step, then assert no session would be accepted before and after the boot | Open |
| C-2 | Low | `radio.rs:434-440`, spec §2.3 | **Every boot on USB opens a window and forgets the rate limit.** `boot(usb_present = true)` arms the edge, and the count is in memory. A warm reboot (watchdog, firmware fault, update) and a flat-battery radio on a pulsing source each count as "starting from no power", so the spec's "a charger that toggles power on purpose opens at most two windows, then one each half hour" does not hold for a radio whose battery is flat, and any crash reachable from input would reopen windows. | Either say so in §2.3 (the limit holds only while the radio stays powered) or keep the count and the last close in flash or retained RAM; let `boot` tell a cold start from a warm one | Open |
| C-3 | Low | `radio.rs:613-619`, `915-938` | **The rate limit can be evaded without the label.** A window is spared when any proved attempt ends other than by its own 6 s timeout. A recorded message 1 from an earlier window (case 9: it proves the secret again, for example one captured over BLE) followed by a disconnect or junk message 3 spares the window. Anyone who can make USB edges and has one recording gets unlimited windows. They cannot pair without the label, so this only widens the windows a label holder can race. This is PR question 4's literal reading. | Cap sparing (for example at most one spared window between counted ones), or spare only on `PreemptedByUsb` and `WindowClosed`; or accept and say it in §2.3 | Open |
| C-4 | Low | `radio.rs:821-830`, spec §2.5 | **A hostile USB host with a recording keeps BLE shut for a whole window.** A recorded message 1 replayed on USB proves the secret, sets `usb_proved` and shuts BLE until the window ends, though its attempt cannot complete. The spec's "a host that is not pairing gains nothing by keeping BLE shut" assumes this needs the label; it needs only a recording. Denial of BLE pairing on that charger, nothing more. | If the proving USB attempt ends without completing (timeout, bad message 3, lost) after the 20 s mark, reopen BLE for the rest of the window; a real cable phone completes within 6 s. Or state the limit in §2.5 | Open |
| C-5 | Low | `radio.rs:586-609`; `tests.rs:1673` | **A connection flood can displace the owner between connecting and message 1.** Full slots displace the oldest unproved attempt, so a flood faster than the slot count per message 1 delay evicts every owner attempt before it proves anything. `case_18` floods only before the owner connects (`pair()` connects and sends message 1 at the same instant), so it does not test spec case 18's "flooding ... does not keep a phone with the right code out". Same policy as `make_room`; the spec accepts jamming and leaves timing to real-hardware check 2. | Test a flood interleaved with the owner's connect and message 1. Consider a short guaranteed time (for example 500 ms) before a new unproved attempt can be displaced, or random eviction among unproved attempts | Open |
| C-6 | Low | `code.rs:31-36`, `radio.rs:233-241` | **An all-zero label secret is accepted** by `LabelCode::decode` and by `RadioKeys::new`. A radio built with one has a psk anyone knows. PR question 9 refuses it only for replace codes. | At least refuse it in `RadioKeys::new` (factory or firmware bug); refusing it in `LabelCode::decode` too costs nothing | Open |
| C-7 | Low | `radio.rs:655-677` | **`PAIR_OPEN` with the label secret is not refused.** A buggy old-phone app that sends the label secret (or a secret it derived from the label it once scanned) opens a replace window that every label holder can race, against §2.9's "replace windows do not take the label secret". The radio already refuses an all-zero secret as a cheap check against app bugs. | Also refuse a secret equal to the label secret, compared in constant time | Open |
| C-8 | Low | `radio.rs:129-136`, `564-610` | **In a replace window every new BLE connection becomes a pairing attempt** (PR question 8). The old phone, which the spec says keeps working, reconnects as an attempt: it holds a pairing slot, gets `Close(Msg1Timeout)` after 3 s, and can be `Displaced` by a flood. Whether its link session survives rests on the firmware not closing a connection that has completed a link handshake, a rule only the `Close` doc comment states. | Start an attempt when the pairing characteristic (BLE) or pairing port (USB) is opened, a separate event from the link connection, so link connections never enter pairing slots | Open |
| C-9 | Info | `handshake.rs:166`, `204`, `261`; `radio.rs:706`; `radio.rs:526` | **Checks no test pins** (mutations survived, below): message 3 must be exactly `[0x03]`; the phone checks the `0x06` tag; the message 1 size bound; a reset on battery followed by a plug within 2 s; PR question 7 (boot on battery, plug in under 10 s). The first three are also enforced by `snow` or need the transport keys, so this is about regressions, not a hole today. | Add one test each | Open |
| C-10 | Info | `radio.rs:737-740`, `879`, `239` | Secrets pass through unwiped stack temporaries: `*self.keys.label_secret` into the window psk, `*link_key.private_key()` into `SavedPhone`, `*label.secret()` into `RadioKeys`. `snow` does not wipe its handshake or transport state (spec §7; known). | Build the `Zeroizing` buffer first and `copy_from_slice` into it | Open |
| C-11 | Info | `radio.rs:706`, `833`, `984-997` | `Duration` additions panic on overflow if `now` is near `Duration::MAX`, and nothing checks that `now` never goes backwards. Not reachable from the air; the firmware supplies `now`. | `checked_add` or `saturating_add`, and a `debug_assert!` that `now` is monotonic | Open |
| C-12 | Info | `code.rs:203-210`, `229-242` | `ReplaceCode::new` makes a secret the app cannot read (`secret()` is `pub(crate)`), but the app must send that secret in `PAIR_OPEN`. Apps will make the secret elsewhere and call `from_secret`, outside the code's zero and randomness checks. | Give the app one constructor that returns the code and the `PAIR_OPEN` body together, the secret in a `Zeroizing` buffer | Open |
| C-13 | Info | `radio.rs:537-542` | `enter_storage` arms the next USB presence with no 10 s absence. Safe only while nothing unauthenticated can put the radio in storage mode. | Say so on the method, and in the firmware card | Open |
| C-14 | Info | spec §2.8 | The spec's text still contradicts the code on two points the PR raised (questions 1 and 2): a reset marker at boot also writes an empty trust state, and a tear before the marker lands means no reset happened. | Amend §2.8 to match the code | Open |

## The ten spec questions

| # | Reading taken | Verdict |
|---|---|---|
| 1 | Reset marker at boot also empties the trust state | **Agree**: the conservative reading, and the only one consistent with "ends unpaired and empty". Fix the spec text (C-14) |
| 2 | A tear before the marker lands keeps the old phone and its state | **Agree**: unavoidable, same as a pin released early. State it in §2.8 (C-14) |
| 3 | Case 12's "together" tested in a replace window, plus the USB-window order | **Agree**: sans-IO serialises the two, and in a USB window the BLE attempt is already gone; the tests cover both orders |
| 4 | Any proved attempt ended other than by its own timeout spares the window; spared windows leave the count; the wait runs from the last close | **Partly agree**: the count and wait choices are the stricter ones, but sparing on disconnect or junk lets a recording without the label evade the limit (C-3) |
| 5 | Only a proving message 1 that also passes the key and hello checks pre-empts BLE; the record takes every decrypting message 1 | **Agree**: equivalent for an attacker with the label, and fewer pre-emptions by junk; the wider record refuses more replays |
| 6 | The reset's window needs USB present for the whole 2 s | **Agree** (one gap: a plug within 2 s of a reset on battery is untested, C-9) |
| 7 | Boot on battery, plug in under 10 s: no window | **Agree** but untested (C-9); the other side, a warm boot on USB, is the permissive one (C-2) |
| 8 | Every new BLE connection in a window is a pairing attempt; firmware must not close a link connection | **Disagree**: the rule belongs in the machine's inputs, not a doc comment (C-8) |
| 9 | All-zero secret refused for replace codes, not labels | **Partly agree**: refuse it for labels too, at least in `RadioKeys::new` (C-6); also refuse a `PAIR_OPEN` secret equal to the label secret (C-7) |
| 10 | A failed store write stops the radio, pinhole included, until a boot | **Disagree**: the conservative reading fails closed for the link and keeps the pinhole working (C-1) |

## Mutations tried

Each was one change, run against the 71 phone tests, then reverted.

| Mutation | Result |
|---|---|
| Phone skips `check_peer_public` on the link key | Killed (`case_16_a_small_order_link_key...`) |
| Radio skips `check_peer_public` on the phone key | Killed (`case_05_...`) |
| Code decode skips the small-order check | Killed (`case_3_small_order_key...`) |
| Replace checksum label made equal to the label's | Killed (`case_3_each_code_is_refused...`, `known_answers`) |
| Replace window keyed with the label secret | Killed (`case_04`, `case_12`, `case_13`, `case_14`) |
| `PAIR_OPEN` accepted from any key when paired | Killed (`case_13` x2) |
| `PAIR_OPEN` all-zero check removed | Killed (`case_13_an_all_zero...`) |
| Late enumeration (after 10 s) also shuts BLE | Killed (`case_12_a_host_enumerated...`) |
| Enumeration ignored | Killed (`case_12_a_host_enumerated...`) |
| Windows spared on every end, timeouts too | Killed (`case_08_a_window_whose...`) |
| Proved attempts may be displaced | Killed (`case_08` x2) |
| Replay record check removed | Killed (`case_09` x2, `case_11`) |
| Replace skips `erase_owner_state` | Killed (`case_13`, `case_15_..._replace`) |
| Boot ignores a reset marker's trust erase | Killed (`case_15` x2) |
| Message 3 payload not checked for `[0x03]` | **Survived** (C-9; needs the transport keys to exploit) |
| Phone ignores the `0x06` tag in message 2 | **Survived** (C-9; needs the pairing key) |
| Message 1 size bound reduced to "at least 32 bytes" | **Survived** (C-9; `snow` refuses the rest) |
| Reset window set even on battery | **Survived** (C-9; differs only for a plug within 2 s) |
| Boot always arms the USB edge | Survived, equivalent (the next `usb_power(true)` recomputes it) |
| `connection_opened` ignores `faulted` | Survived, equivalent (no window exists while faulted) |
| First pairing skips the marker sequence even when a peer exists | Survived, equivalent (unreachable: a USB window needs no peer) |

The author's own 18 mutations of the state machine (PR body) were not repeated.

## Checked and found sound

- **Noise.** Pattern `PAIRING_NOISE` unchanged, psk at position 1 on both sides, the new `PHONE_PAIRING_PROLOGUE` on both sides (a drone message 1 is refused, tested). Phone is initiator, radio responder. The radio builds a fresh `HandshakeState` for every message 1 and never reuses one; each attempt's `TransportState` reads exactly one message 3. `check_peer_public` runs on the label's key (decode and `start`), the phone's static (after message 1 decrypts) and the link key from message 2. Any error ends the attempt with no reply and drops its state; the phone's `finish` consumes `self`, so an error drops the radio-link key (zeroized).
- **Message 3 binding.** It is the first transport message under keys split from that attempt's handshake (`es`, `ss`, `ee`, `se`, psk), so it cannot be replayed on another attempt or after completion (the attempt is gone: `NotAnAttempt`). A recorded message 3 from an earlier window fails (tested). Changing a recorded message 1's ephemeral, including the bit X25519 ignores, changes the handshake hash and fails decryption, so the 16-entry record cannot be sidestepped that way.
- **Sizes.** Message 1 99 to 130, message 2 84 to 115, message 3 17; hellos must match their length byte exactly; no trailing bytes accepted. No indexing reachable from input before a length check; `expect` and `unreachable!` sit behind invariants that hold (attempts exist only inside a window; `find` before `expect("found")`).
- **Test-only resolver.** `small_order_msg1` and its `snow` resolver live in `tests.rs` under `#[cfg(test)] mod tests`; `with_secret` is `#[cfg(test)]`. Neither is reachable from a non-test build.
- **State machine.** Proved attempts are never displaced (as `make_room`); BLE and USB slots are separate; one message 1 per connection; 3 s and 6 s timers; the window closes in memory before the trust write; USB pre-emption ends every BLE attempt and shuts BLE; edges during a window change nothing; the debounce, the rate limit's "new edge after 30 minutes" and "left on power opens nothing" hold; reset clears the count and its window counts as the first of two; `PAIR_OPEN` is refused from anyone but the paired phone, during any window, when unpaired, and all-zero. Timers use the due time, not `now`, for window opening and last-close accounting. No allocation of its own; no growth.
- **Storage order.** Replace: marker, erase, atomic trust swap, clear marker; reset: marker, erase, empty trust, clear marker; boot finishes either. With one trust slot written atomically, no crash point leaves two phones trusted or a new phone with the old owner's state (power loss at every step, including inside the recovering boot, is tested). Only the completing attempt's link key is ever written.
- **Secrets.** `LabelCode`, `ReplaceCode` (`ZeroizeOnDrop`), `RadioKeys`, the window psk, `SavedPhone.link_private` (`Zeroizing`) and every `Identity` are wiped on drop; no `Debug` or error text shows a secret, a private key, message 2's bytes or the input of a failed decode (tested). The only secret comparison is done by the AEAD inside `snow`; `all_zero` reads every byte. Checksum and ephemeral comparisons are of non-secret values.
- **Codes.** Separate prefixes, checksum labels and types; strict `BASE32_NOPAD` (padding bits refused); length, version byte and prefix digit checked; small-order and non-canonical small-order keys refused; every single-character change refused; known answers match an independent computation.

## Not verified

- The link session, `PAIR_OPEN` authentication, wake filters, the hold store and the transports (later parts), so cases 1, 2, 6, 13, 14 and 16 are covered only on the radio's pairing side.
- A real `RadioStore` on flash: the atomic trust write and "erase means gone from flash" are documented requirements, simulated with an opaque `owner_state` value. Real-hardware check 7 is not done.
- `no_std`, memory per attempt, and how `snow`'s ephemeral randomness would be supplied on the radio's chip.
- Behaviour of a real `Entropy` that fails (the trait cannot report failure; a broken hardware RNG would give weak link keys silently).
- Timing on real BLE stacks (C-5), and whether firmware can tell a pairing characteristic from a link connection (C-8).
