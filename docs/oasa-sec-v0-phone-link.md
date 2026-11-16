# OASA-SEC v0: the phone link (draft)

**Stage:** Idea → Draft (no code yet) · **Node:** T-MSG1 · **Last reviewed:** 2026-11-16 (written by an AI agent; one independent AI design review applied, see the [review notes](security-review-t-msg1-phone-link.md); not yet reviewed by a person)

How a phone and its pocket radio pair, and how the phone drives the radio afterwards, over Bluetooth Low Energy (BLE) or a USB cable. Builds on [pairing](oasa-sec-v0-pairing.md) and the [link](oasa-sec-v0-link.md).

**No new crypto.** Pairing is the R-SEC1 one-time code and `Noise_IKpsk1`. The session is the R-COM2 link, unchanged on the wire. What is new: who plays which role, how the code reaches the phone, a confirm press on the radio, and the messages carried inside the session.

## 1. Who holds what

| | Phone (the app) | Radio |
|---|---|---|
| Message keys: the identity people pair with, link sessions with other people, group keys | **Yes** | **Never** |
| Plaintext of any text, voice or position | Yes | Never |
| Its own device key (X25519, made on the device) | Yes: a **radio-link key**, used only toward its own radio | Yes: used only toward its own phone |
| Phone link session keys | Yes | Yes |
| What goes on the air | Builds and seals every packet | Sends, receives and relays sealed packets; keeps voice timing |

Rules:

- The radio's device key and the phone link session keys are **not message keys**. They protect the few metres between phone and radio and nothing else.
- The phone uses **two separate key pairs**: one for messaging (what other people pair with) and one radio-link key. The radio learns the radio-link public key. Of the messaging identity it holds only the handshake filter (§5): a hash of the messaging public key. The hash cannot be turned back into the key, but **anyone who already knows the key can match it**, so it ties the radio to its owner for the owner's contacts.
- The radio never originates a message. Everything it transmits is either a sealed packet the phone handed it, or a sealed packet it is relaying.

## 2. Pairing

Roles from R-SEC1: the **radio is the responder** (the drone's part) and the **phone is the initiator** (the ground station's part). One radio has **one owner phone** in v0.

The radio has one button and one light, and no screen. So:

1. **The label.** Each radio carries a printed label with its fingerprint (R-SEC1 §1), as text and as a QR code. It is not a secret. The production jig prints it after the radio has made its own key. The app scans it first, which also tells the app which radio to talk to in a room full of them.
2. **The window.** The user holds the button for 3 s. The light shows pairing mode. The radio makes a **new one-time pairing code** (R-SEC1 §2: version, public key, 32-byte fresh secret, checksum) and opens a window of **2 minutes**. The window opens only from the button, never from a message.
3. **The code.** While the window is open the phone reads the code from the radio over BLE (or over USB). The app **refuses the code unless its public key matches the label's fingerprint.** The app shows "wait" from here until step 5.
4. **The handshake.** `Noise_IKpsk1_25519_ChaChaPoly_BLAKE2s`, as R-SEC1 §3, with prologue **`"OASA-SEC v0 phone pairing"`** so a phone pairing and a drone pairing can never be mistaken for each other. Message 1 carries the phone's hello (name); the radio checks the code's secret there and gives no reply without it. Message 2 carries the radio's hello. There are no signing-key messages.
5. **One completion, then the press.** The **first completed handshake uses up the code and closes the window.** No second phone can complete in that window, whatever happens to the first one's connection. The radio keeps that phone's public key as **pending**, in memory, for 30 s, and its light shows "press". The pending entry does not depend on the connection staying open. The app whose handshake completed says "press the button once". The radio saves the pending phone as its owner **only if the button is pressed within those 30 s**; otherwise it forgets it.
6. **Proof to the phone.** The phone then starts a normal link handshake (§3). The radio answers it only if it saved this phone, so **the first completed link handshake is the confirmation**. The app saves the radio and shows success only then. If none completes within 60 s, the app deletes the radio and says: "Pairing was not confirmed. If you pressed the button, reset the radio (hold 10 s) and start again."

An app whose handshake did not complete never shows "press". It shows "wait", and when it gives up: "Another phone may be trying to pair. Do not press the button. Let the light go out and start again."

Attempt handling up to the first completion follows R-SEC1 §2 ("nobody can hold the port"), with its own timers (3 s for message 1, 6 s for the reply), not the session rules of §3: several attempts at once, a repeat of a recorded message 1 gets no reply, no lockout.

**While a USB host is pairing** (it has read the code over USB in this window), the radio does not offer the code or accept pairing on BLE.

**Why the code may be read over BLE in the clear.** Anyone in Bluetooth range during the window can read the code; R-SEC1 already says "anyone who sees it can pair once". The steps together cover it:

| Attack during the window | What stops it |
|---|---|
| A stranger swaps the code for their own (sits in the middle) | The label: the app only accepts the public key printed on the radio, and `IK` then proves the radio holds that key |
| A stranger reads the code and completes first | The owner's app never completes, so it never says "press". With no press, nothing is saved |
| A stranger knocks the owner's connection off after it completed, to complete in its place | The code was used up by the first completion; the pending phone stays the owner's |
| The owner pressed although the app did not say so | The owner's phone never gets its link handshake (step 6) and tells the owner to reset the radio |
| A stranger reads the code and only listens | Knowing the code does not decrypt the handshake; that needs a private key |
| A stranger keeps completing first so the owner never does | Nothing. It delays pairing while they are in range, like jamming. Pairing over USB avoids it |

**Without the label** (worn off, lost): the app can pair after the user types the fingerprint from the box or the paperwork. Pairing with no fingerprint at all is refused in v0 (open question 1).

**Reset.** Holding the button 10 s wipes the owner, the saved handshake timestamps, the wake filters and every held packet. The radio **keeps its device key**, so the label stays true. Anyone holding the radio can reset it; a reset radio is an empty radio. To move to a new phone: reset, then pair.

## 3. The session

After pairing, the phone and the radio run the **R-COM2 link, wire version 1, unchanged**: `Noise_IK`, prologue `"OASA-SEC v1 link"`, 16-byte tag, per-packet counter, 1024-packet replay window, trusted-peers gate. Each side has exactly one trusted peer, saved with the role `peer`.

- **Who initiates.** The phone starts the handshake after every connect. As on any link, the radio may also start one (the responder's late rekey, the stale rule, or data to send with no session). Neither side needs a true clock: the handshake timestamp only has to be newer than the last one, and a device without a clock uses "last sent + 1 ns" (link §2). Both sides save their last-sent timestamp and the newest one received, so a recorded handshake cannot be replayed after a power cycle. The phone keeps its last-sent value with its keys, so a restore brings both back together.
- **The radio has no trusted clock**, so the link's "too far ahead" check (`max_future`) is off on the radio. A phone whose clock was once far ahead keeps working (it counts on from its saved value). A phone that lost its saved value and now has an earlier clock gets no answer until it re-pairs after a reset, which clears the radio's saved timestamps.
- **An unpaired phone gets no reply at all.** Its handshake is dropped (`untrusted_peer`, or `bad_header` if it does not even know the radio's public key, or `rate_limited` in a flood); anything else it sends is dropped as `bad_header` or `unknown_index`.
- **A replayed command is dropped.** Every command is a link data packet. A copy is dropped as `replay` or `too_old` while its session can still be read, and as `unknown_index` or `bad_tag` afterwards. Whatever the reason: one counted drop, nothing done, nothing transmitted.
- **Control messages** (content type `0x01`, R-SEC2) carry no rights here: neither side is an `admin` or an `operator` of the other, so removal and signing-key messages are refused by the existing role checks. The phone-link messages of §4 are application packets (`0x00`).
- **Settings** (not wire changes): keepalive timer off; rekey once an hour or at 2³² packets, reject after 90 minutes.
- **Flash writes.** Each handshake costs the radio one or two small writes (the timestamps). There are at least 24 a day from rekeys, plus one per reconnect, and phones drop BLE connections often. The firmware card must count writes per day on real phones and check the number against the flash part's endurance (open question 8).
- **Framing.** On BLE and on USB each link packet travels as a 2-byte big-endian length and the bytes, as R-SEC1's stream framing, split across writes and notifications as the transport needs. The phone link's MTU must fit the largest air packet plus the `SEND` or `RECEIVED` fields plus the link's 22 bytes; a longer length closes the connection.
- **The same on both transports.** BLE and USB carry the same session and the same messages. A session belongs to one transport connection; when the connection drops, the phone handshakes again.

**Connections nobody can hold.** Anyone can open a BLE connection or plug in a cable. Outside a pairing window, the radio closes a connection that has not completed a link handshake within 5 s, and when its connection slots are full a new connection replaces the oldest one that has not completed. A connection that has completed is never displaced by one that has not.

**Bluetooth's own security is not relied on.** BLE pairing and bonding may be used for private addresses (§7), but every protection in this document comes from the link above. A flaw in the phone's or the radio's Bluetooth security must not let anyone drive the radio.

## 4. Messages inside the session

Link application packets (content type `0x00`) whose body is `[type: 1][body]`. Draft numbers; integers big-endian.

| Type | Name | From → to | What it does |
|---|---|---|---|
| `0x01` | `SEND` | phone → radio | One sealed packet to transmit, with its class (text or voice), radio setting and voice slot |
| `0x02` | `SENT` | radio → phone | That packet went on the air, or why not (channel busy, limit, too large) |
| `0x03` | `RECEIVED` | radio → phone | One sealed packet from the air, with signal level and, for a held packet, its hold number |
| `0x04` | `FILTERS` | phone → radio | The wake filters (§5): replaces the whole list |
| `0x05` | `HELD` | radio → phone | How many packets are held; sent after each handshake |
| `0x06` | `FETCH` | phone → radio | Hand over held packets |
| `0x07` | `FETCH_ACK` | phone → radio | Hold numbers the phone has stored; the radio deletes those and no others |
| `0x08` | `SETTINGS` | phone → radio | Radio settings, relay on or off, light, name |
| `0x09` | `STATUS` | radio → phone | Battery, firmware version, counters |
| `0x0A` | `UPDATE_*` | phone → radio | Firmware update pieces (the update standard: signed, checked on the radio, trial boot) |
| other | | | Dropped and counted |

What the radio refuses **even from its own phone**:

- Transmitting outside the frequency, power and airtime limits built into its firmware. The phone can lower them, never raise them.
- Firmware that is not signed by the release key, **or that is older than what it runs**, by any path (the phone link, USB, or a Bluetooth update mode). The phone only carries the file.
- Reading out the radio's private key. There is no message for it.
- Opening the pairing window, confirming a pairing, or resetting. Those are button-only.

So a phone with a hostile app can waste its own radio's battery and airtime inside the limits, and cannot turn the radio into something else.

## 5. What the radio does without the phone

The phone may be asleep, out of range or switched off. The radio then:

| Does | Does not |
|---|---|
| Relays other people's sealed packets, listening before sending | Send anything of its own: no message, no position, no "delivered" or "seen" answer |
| Holds incoming packets that match the wake filters | Read, change or reorder what it holds |
| Wakes the phone over BLE when it holds something | Decide who a message is from or what it says |
| Keeps voice timing for a call in progress until the phone's audio stops arriving | Start or answer a call |
| Charges; shows battery and "something waiting" on its light | Change its own settings |

**Wake filters.** The radio cannot read packets, so the phone tells it what to keep. A filter is one of: a link receiver index (2 bytes, public on the air), a group id (2 bytes, public on the air), or the handshake filter. The handshake filter is the `mac1` key for the phone's messaging identity (link §2): a hash of a public key, not a secret, which lets the radio spot a first handshake addressed to its phone. Filters are hints. A packet that matches by chance, or was made to match, is thrown away by the phone when its tag fails.

**The hold store.** At most 64 packets or 16 kB, each kept at most 24 hours, **in memory only**: a radio that loses power or is reset holds nothing (open question 2). The sender's phone, not the radio, is responsible for retrying.

**Anyone can make a packet that matches a filter** (indexes and group ids are public, and the handshake filter needs only the public key), so the store is built to lose as little as possible to a flood:

- Each kind of filter has its own share of the store, and each index and each group its own share within that, so junk for one conversation cannot push out another's packets.
- Within a share the oldest goes first.
- Wakes are limited (at most one every 10 s, then backing off while the phone fetches nothing it could open; the phone tells the radio with `FETCH_ACK` which packets were real).

A flood can still push real packets out of the one share it aims at, and costs the phone battery. That is the same person who could jam the channel.

**Waking the phone.** The wake is a bare BLE notification with nothing in it and no protection. The app then handshakes, fetches, opens the packets with its own keys, and **only then** notifies or rings. A forged wake therefore costs the phone a little battery and shows nothing.

## 6. What an attacker gets

**Someone who finds or steals the radio**, and can read its memory (assume they can: the chip's readout protection has been bypassed in public before):

| Gets | Does not get |
|---|---|
| The radio's device key. With it they can pose as that radio to the owner's phone, and (a property of `IK`, link §6) as the phone to that radio | Any message key, past or future |
| The phone's radio-link public key (used nowhere else) | The messaging public key itself |
| The wake filters. The handshake filter confirms whose radio this is to anyone who already knows the owner's messaging public key. The indexes and groups, with recordings of the air, link past traffic to this radio | The content of any packet, held or recorded |
| Held packets, still sealed, if it stayed powered | A way to send as the owner, or to read what the owner receives next |
| Radio settings, counters, firmware version | |

What the owner does: remove the radio in the app (the phone deletes it from its trusted list, so the stolen device key is worthless) and pair a new one. Nothing has to be re-keyed with other people. **A radio that comes back is not paired again as it is**: its device key may have been copied, and reloading firmware does not change that. It is retired, or given a new key and a new label by whoever can print one (open question 9).

**A stranger within Bluetooth or radio range:**

| Can | Cannot |
|---|---|
| See that a radio of this kind is near, and possibly follow it by its Bluetooth address (§7) | Complete a handshake, so cannot send, fetch, change settings or update firmware |
| Open connections; each is closed after 5 s | Hold a connection slot against the owner's phone |
| Send a forged wake to the phone if they copy the radio's address | Make the phone show or ring anything |
| Record the phone link | Read it, or replay any part of it |
| Read the pairing code during a pairing window, and delay pairing | Pair: the label, the single completion and the confirm press (§2) |
| Flood the air with packets that match a filter: push real packets out of that share of the hold store, and wake the phone up to the wake limit | Fill the whole store, or make the phone show anything |
| Jam Bluetooth or the radio channel | |

**A borrowed cable, charger or computer:**

| Can | Cannot |
|---|---|
| Charge the radio | Anything a Bluetooth stranger cannot: USB carries the same link and gets no reply without the paired key |
| See the radio's USB name and firmware version | Load firmware that is unsigned or older: the bootloader refuses both |
| | Read memory through the debug port: it is locked on production radios |

The last two rows are **requirements on the product**, and they are **not true of the development boards** (RAK4631 and similar), whose bootloader takes any firmware over USB and whose debug port is open. Development boards are for the bench only.

**Not covered:** a phone that is itself taken over. The phone holds every key; this link cannot help there.

## 7. Known limits and privacy (v0)

- **Following a radio by Bluetooth.** The radio advertises a service id so the phone's system can find it and wake the app. That marks it as one of these radios. Whether the address can also rotate (private addresses, which need Bluetooth bonding) without breaking wake on iPhone and Android is decided by the phone tests (open question 3).
- **The light says "press" for any phone that completes first.** Only the app tells the owner whether that phone is theirs. A user who presses on the light alone can confirm a stranger; step 6 then tells them to reset. The app text must make "wait" and "do not press" hard to miss (open question 10).
- **The label trusts the factory.** Someone who can print a label can pass off a swapped radio. So can someone who had the radio open on a bench.
- **Handshakes on the air can be spotted** by anyone who knows the receiver's public key (`mac1`, link §2). That is the base link's property; the handshake filter uses it and adds nothing to it on the air.
- **Timing.** The radio cannot read packets, but anyone watching the air or the phone link sees when packets flow and how large they are. Padding is not in v0, as on the link.
- **One owner.** No second phone, no shared radio (open question 4).
- **`snow` does not wipe its state** (as R-SEC1 §6); on the radio, session keys sit in memory until power-off.

## 8. What the simulated suite must cover

Suite `l1-phone-link` in oasa-lab (a later card), with a simulated radio and a simulated transport. The first two are the known-bad cases the checker must see. "Refused" and "dropped" mean: one counted drop, no reply where the link gives none, nothing done, nothing transmitted.

1. **An unpaired phone is refused:** a phone whose key the radio does not hold sends a handshake and commands, with and without knowing the radio's public key.
2. **A replayed command is dropped:** a recorded `SEND` played again in the same session, during the previous session's grace, after a rekey and after a reconnect; the radio transmits once.
3. A phone with the right code and the wrong label fingerprint refuses to pair.
4. A second phone that completes first: the owner's app never shows "press"; with no press, nothing is saved.
5. The swap: after the owner's phone completes, its connection is knocked off and a second phone with the code tries; it gets no reply, and the press saves the owner's phone.
6. A press with no pending phone, and a press after 30 s: nothing is saved. A pairing window opened by a message: refused.
7. The owner presses while a stranger is pending: the owner's phone gets no link handshake and reports "not confirmed".
8. A handshake completed but no button press, then a link handshake and commands: refused.
9. During a USB pairing the code is not offered on BLE.
10. A changed bit in any command: dropped.
11. Idle, slow and flooding connections do not keep the paired phone out.
12. The radio starts a handshake (stale rule, late rekey); a recorded handshake from either side replayed after a power cycle of the radio is dropped.
13. A phone that lost its saved timestamp and has an earlier clock: refused until reset and re-pairing, then accepted.
14. Held packets: delivered once after a handshake, deleted only on `FETCH_ACK`; the limits hold; nothing survives a reset or a power cycle.
15. A flood of packets matching one filter: packets held for other filters survive; wakes stay under the limit.
16. A forged wake: the phone shows nothing.
17. Control messages (`0x01`) from either side change nothing.
18. A `SETTINGS` above the built-in limits is refused; an unsigned update and an older signed update are refused.
19. Captures of the phone link contain none of the test plaintext.
20. With no phone connected the radio's transmissions are relays only.

## 9. Open questions

1. Allow pairing with no fingerprint check, behind a warning, for a radio whose label and paperwork are both gone?
2. Hold store in memory only (a dead battery loses waiting messages; a found radio holds less), or in flash (the reverse)? This draft says memory only. How long, and how many?
3. Bluetooth bonding for private addresses: does wake still work on both platforms? (P0 and P4 phone tests.)
4. A second phone for one radio, or one phone with two radios.
5. A theft lock, so a reset radio cannot be paired by a finder. It would need a secret the owner keeps, and a way back when they lose it.
6. An NFC tap in place of scanning the label (the chip supports it; it needs an antenna in the case).
7. Sealed packets the phone leaves with the radio to send later (a position while the phone is dead). Not in v0: the counters need care.
8. The rekey interval and reconnect rate against flash wear, once the flash part is chosen. A link setting that stops the radio from ever starting a handshake would halve the writes; it is a code change to the link.
9. Giving a returned radio a new device key and label: who may do it, and how the old label is made void.
10. A blink count the app and the light both show, taken from the pairing handshake's hash, so the owner can tell their own completion from a stranger's. It adds a comparison step for the user; its strength with a few blinks needs its own review.

## 10. Not covered

The app's screens, USB class details, Bluetooth service layout, the relay rules, voice timing, and the code (which needs a new pairing prologue constant beside `PAIRING_PROLOGUE`). Review by a person is required before this moves past Draft.
