# OASA-SEC v0: the phone link (draft)

**Stage:** Idea → Draft (no code yet) · **Node:** T-MSG1 · **Version:** v0.2 draft, 2026-11-19 (pairing rewritten for a radio with no button; written by an AI agent; v0.1 had one independent AI design review, see the [review notes](security-review-t-msg1-phone-link.md); v0.2 has not been reviewed, by an AI or a person)

How a phone and its pocket radio pair, and how the phone drives the radio afterwards, over Bluetooth Low Energy (BLE) or a USB cable. Builds on [pairing](oasa-sec-v0-pairing.md) and the [link](oasa-sec-v0-link.md).

**No new crypto.** Pairing is R-SEC1's `Noise_IKpsk1`, with the radio's public key and the pre-shared secret taken from a printed label instead of a one-time code. The session is the R-COM2 link, unchanged on the wire. What is new: who plays which role, the label, when the radio accepts pairing, and the messages carried inside the session.

**Changes since v0.1** (2026-11-16):

- The radio has **no button**. Everything the user does goes through the phone, plus a recessed pinhole for reset.
- The one-time code read over BLE or USB is gone. A **printed label** carries the radio's public key and a **per-device pairing secret**; the secret is the psk (§2.1, §2.2).
- The pairing window opens on **USB power while unpaired**, or on request from the paired phone (to replace it). The press and the 30 s pending phone are gone (§2.3).
- Pairing completes only on an encrypted **confirm from the phone** after the radio's reply, because a static secret makes a recorded message 1 valid in every later window (§2.4).
- **USB first:** a phone on a cable gets a 3 s head start and then excludes BLE for that window (§2.5).
- The light is described state by state and carries no security property (§2.6).
- New message `PAIR_OPEN` (§4); §6 and §7 cover a static secret; suite cases and open questions renumbered (§8, §9); constants listed (§10); what each v0.1 review finding becomes (§11).

## 1. Who holds what

| | Phone (the app) | Radio |
|---|---|---|
| Message keys: the identity people pair with, link sessions with other people, group keys | **Yes** | **Never** |
| Plaintext of any text, voice or position | Yes | Never |
| Its own device key (X25519, made on the device) | Yes: a **radio-link key**, used only toward its own radio | Yes: used only toward its own phone |
| The radio's pairing secret | Only while pairing, from the label | Yes, for its whole life |
| Phone link session keys | Yes | Yes |
| What goes on the air | Builds and seals every packet | Sends, receives and relays sealed packets; keeps voice timing |

Rules:

- The radio's device key, its pairing secret and the phone link session keys are **not message keys**. They protect the few metres between phone and radio and nothing else.
- The phone uses **two separate key pairs**: one for messaging (what other people pair with) and one radio-link key. The radio learns the radio-link public key. Of the messaging identity it holds only the handshake filter (§5): a hash of the messaging public key. The hash cannot be turned back into the key, but **anyone who already knows the key can match it**, so it ties the radio to its owner for the owner's contacts.
- The radio never originates a message. Everything it transmits is either a sealed packet the phone handed it, or a sealed packet it is relaying.

## 2. Pairing

Roles from R-SEC1: the **radio is the responder** (the drone's part) and the **phone is the initiator** (the ground station's part). One radio has **one paired phone** in v0 (§2.7).

The radio has one status light, a USB socket and a recessed pinhole. No button, no screen.

### 2.1 The label

Each radio carries a printed label: a QR code, the same payload as text under it, and the radio's fingerprint (R-SEC1 §1) as text. The QR holds the radio's **public key** and its **pairing secret**.

**Why the full public key, not the fingerprint.** `IK` needs the initiator to know the responder's static key before message 1. A fingerprint (80 bits) would need the radio to send its key first, which is a different pattern, and would rest on a shorter value. The full key keeps R-SEC1's handshake exactly.

**Payload.** The same layout as the R-SEC1 code (§2 there), with its own prefix and checksum label so neither can be taken for the other:

| Bytes | Field |
|---|---|
| 1 | Label format version (`1`) |
| 32 | Radio's public key (X25519) |
| 32 | Pairing secret |
| 4 | Checksum: first 4 bytes of BLAKE2s-256(`"OASA-SEC v0 label checksum"` ‖ the 65 bytes above) |

Text form: `OASAR1-` + uppercase base32 without padding: 7 + 111 = **118 characters**, all in the QR alphanumeric set, so it fits a version 5 QR (37 × 37 modules) at error correction level Q. Readers accept lowercase, spaces and dashes after the prefix, as R-SEC1, so a damaged QR can be typed from the text.

The app refuses a label with the wrong prefix, an unknown version, the wrong length, a bad checksum or a small-order public key, before it connects to anything. A misread fails there, with a 2⁻³² chance of a misread passing the checksum (on top of the QR's own error correction); a misread key or secret that did pass would only fail the handshake. `oasa-pair` refuses a label and the app refuses an R-SEC1 code: the prefixes differ.

**Not a URL.** The payload has no scheme and no host, so an ordinary camera app shows it as text and opens nothing. Some camera apps offer to search the web for scanned text; a user who taps that sends the secret to a search engine. The label says "Scan with the app", and §2.8 says what a leaked secret gets. The app does not register a URL scheme or link type for labels.

The app scans with its own camera view, keeps no image, sends the payload nowhere, and wipes the secret when pairing ends. It reads the label again for every pairing.

### 2.2 The pairing secret: making it, keeping it

Requirements on manufacturing and on product firmware:

- **Random.** 32 bytes from the radio chip's hardware random source, made on the radio at first start, like its device key. Not derived from, or stored next to a record of, the serial number, the Bluetooth address, the public key or anything else printed or broadcast.
- **Out once.** The radio hands the payload to the production jig over the factory interface once, for printing. The jig then commits the radio, which closes that output for good. The factory keeps no copy of the secret; its records hold the fingerprint only.
- **Covered.** The label is not visible or scannable through the packaging.
- **Kept on the radio.** The radio must hold the secret itself: Noise mixes the psk into the key schedule, so a hash of it would not do. It sits with the device key, wiped from working memory after each handshake, never in `STATUS`, logs, errors or any message (§4 has none for it).
- **Not readable over the debug port** on product units: it is locked, as for the device key (§6).
- **Never changes.** The label is printed, so the secret cannot rotate on reset. §2.8 says what follows.

**Development boards** (RAK4631 and similar) have no label. Development firmware prints the same `OASAR1-` payload on the USB serial port at start and on request. Anyone who can plug into a development board can read its secret, as they can already load any firmware on it. Development boards are for the bench only.

### 2.3 The pairing window

The radio accepts pairing messages only while a **pairing window** is open. A window lasts **2 minutes** and opens in exactly two ways:

1. **USB power while unpaired.** The radio has no paired phone, and either it starts with USB power present or USB power appears while it runs. Plugging in also wakes the radio from storage mode, so a new radio opens its first window when it is first plugged in. Battery power alone never opens a window. A radio that has a paired phone opens no window on USB power.
2. **`PAIR_OPEN` from the paired phone** (§4), inside a link session: a **replace window**, for moving the radio to a new phone. USB power is not needed. The paired phone keeps working during it.

Nothing else opens a window: no unauthenticated message on BLE or USB, no other message from the phone.

A window closes at the **first completed pairing** (§2.4) or after 2 minutes, whichever comes first. A closed window stays closed until one of the two events above happens again. Each window is one chance: once a pairing completes, no second phone can complete in that window, whatever happens to the first one's connection.

Pairing messages travel on their own channel (their own BLE characteristic and USB interface), never parsed as link packets, and are framed as R-SEC1's stream framing. Outside a window the radio gives them no reply.

### 2.4 The handshake

`Noise_IKpsk1_25519_ChaChaPoly_BLAKE2s`, as R-SEC1 §3, with prologue **`"OASA-SEC v0 phone pairing"`** so a phone pairing and a drone pairing can never be mistaken for each other. The radio's public key and the psk come from the label.

1. **Phone → radio** (handshake): the phone's hello (name). The radio checks the secret here and gives no reply without it. This message **proves the secret** but not that the sender is live: anyone who recorded one can send it again.
2. **Radio → phone** (handshake): the radio's hello. The phone now knows it reached the radio on the label: only that radio holds the private key.
3. **Phone → radio** (encrypted): confirm `[0x03]`. Only the phone that made message 1 can send it, because it needs that message's ephemeral private key.

**Completion is the radio receiving message 3.** At that moment the radio closes the window, then saves the phone's radio-link public key and name as its one peer (role `peer`). In a replace window the new phone replaces the old one: the old key is removed, its sessions end (link §6) and its saved timestamps are deleted.

Why message 3: the secret never changes, so a recorded message 1 from an earlier pairing proves it again in every later window. In R-SEC1 a code dies with its window; here it does not. Without message 3, a recording of the owner's message 1 (or of an old phone's) would pair the radio to that phone's key in any later window. With it, a replay can hold the window briefly (below) and never complete. The same pattern ends every R-SEC1 pairing: the drone saves nothing until a transport message from the ground station arrives.

**Attempts** up to the first completion follow R-SEC1 §2 ("nobody can hold the port"), with its timers, not the session rules of §3:

- Several attempts at once, up to the radio's connection slots; when they are full a new connection replaces the oldest attempt that has not proved the secret.
- Message 1 must arrive within 3 s of connecting.
- The first attempt whose message 1 proves the secret **holds** the window; another attempt that proves it meanwhile gets no reply. The holder must send message 3 within 6 s of message 2, or the window is free again.
- The radio remembers the ephemeral key of every message 1 that proved the secret in this window and gives a repeat no reply. Each recording can therefore hold a window once, for at most 6 s. (Someone with the label can hold it longer with fresh messages, or simply complete: §2.9.)
- No lockout: failed attempts do not end the window.
- The app retries with a new connection, as R-SEC1's ground station does, until it pairs or 2 minutes pass.

**The phone's confirmation.** After message 3 the phone starts a normal link handshake (§3). The radio answers it only if it saved this phone, so **the first completed link handshake is the confirmation**. The app saves the radio and shows success only then. If none completes within 60 s, the app deletes the radio and says: "This radio did not confirm. Another phone may have paired with it. Reset it with a pin (hold 5 s), plug it in and pair again, by cable if you can." A phone that never got message 2 says the same when it gives up.

### 2.5 USB first

A phone on a USB cable is the one path a stranger in Bluetooth range cannot race:

- In a window opened by USB power, the radio **accepts pairing on BLE only from 3 s after USB power appears**. On USB it accepts it at once.
- In any window, once a message 1 that proves the secret arrives **on USB**, the radio accepts no more pairing on BLE for the rest of that window.
- `PAIR_OPEN` carries one flag, **USB only**. A replace window opened with it accepts no pairing on BLE at all.

So a phone that powers the radio by cable and sends message 1 within 3 s cannot lose the window to BLE, and neither can a new phone on a cable in a USB-only replace window. A USB host that holds the radio can pair it over USB too, but it already holds the radio. A plain charger sends nothing, so it leaves BLE pairing as it was after the 3 s.

### 2.6 The light

One status light. It is for convenience only: **no security property depends on anyone reading it.** The app is the only authority on whether pairing worked (§2.4).

| State | Light |
|---|---|
| Storage mode, or off | Dark |
| Pairing window open | Fast blink (4 a second) |
| Pairing completed (the window just closed) | On for 3 s |
| Window closed with no pairing (2 minutes passed) | Three short blinks, then the state below |
| Unpaired, no window (on battery, or after a window) | One short blink every 5 s while on USB power; dark on battery |
| Paired | Charging, battery and "something waiting" patterns as set in `SETTINGS` |
| Pinhole reset accepted | On for 2 s, then the unpaired state |

The light shows "completed" for any phone that completes, the owner's or a stranger's. That is why the app, not the light, says whether the radio is the owner's.

### 2.7 One phone, and moving to a new one

v0 allows **one paired phone**. Why:

- **A stranger who pairs locks the owner out.** With one phone, any pairing the owner did not make removes the owner's, and the owner's app notices at its next connect. With two, someone who paired before the owner (shop staff, a previous owner) or during a replace window could stay paired beside the owner without a sign. Several defences in §2.8 rest on this.
- The hold store and `FETCH_ACK` (§5) assume one phone takes the packets.
- All message keys are on one phone anyway.

**Moving to a new phone:** the paired phone sends `PAIR_OPEN` (USB only, when the new phone will use a cable), the new phone scans the label and pairs, and the old phone is removed at that completion. If the new phone does not confirm, someone else completed and the old phone was removed too; the owner resets with the pinhole. If nobody completes, the old phone stays paired. **A lost or broken phone:** reset the radio with the pinhole, plug it in, pair the new phone. Until then the lost phone can still drive the radio (never read messages through it: the radio has none).

### 2.8 The pinhole, and a secret that never changes

**Pinhole reset.** Holding the recessed pinhole for 5 s, while the radio is awake (on battery or USB), erases the paired phone, every saved handshake timestamp, the wake filters and every held packet, and returns the radio to unpaired. It **keeps the device key and the pairing secret**, so the label stays true. The next USB power opens a window. Anyone holding the radio and a paperclip can do it; a reset radio is an empty radio.

**What a static secret means.** Anyone who has once seen the label (shop or warehouse staff, a previous owner, someone with brief access, a photo, a camera app's web search) knows the psk for the radio's whole life. Knowing it lets them pair **only** when all of these hold:

- the radio has no paired phone, or its paired phone has just opened a replace window;
- a window is open: within 2 minutes of USB power, or of `PAIR_OPEN`;
- they are first to complete in that window, within Bluetooth range (or through a relay, below), and the owner is not pairing by cable;
- for a paired radio, they also first reset it with the pinhole, which needs the radio in their hands.

And when they do, the owner finds out: the owner's own pairing in that window does not confirm (§2.4), or the owner's paired phone stops getting answers. The owner resets and pairs again, by cable. What the stranger gains while paired is a radio: no message key, no plaintext, nothing held from before the reset (§6). Knowing the secret alone does not let anyone read a pairing or a session: that needs a private key.

**It cannot rotate on reset**, so a reset does not undo a leak of the label. What follows:

- A second-hand radio is never clean against its previous owner. They cannot get in while the new owner stays paired, but they can race any window.
- The defences against a known label are the window rules above and the owner noticing, not the secret.
- Making a radio clean again needs a new device key, a new secret and a new label, which only someone who can print a label can do (open question 9).

**Selling or returning a radio:** reset it with the pinhole first (it erases the handshake filter, which ties the radio to its owner). The buyer resets it again before pairing, by cable. A radio returned to a seller is retired or re-keyed and re-labelled, never resold as it is (§6).

### 2.9 Threats during pairing

| Threat | What stops or limits it |
|---|---|
| A stranger with the label completes first in the owner's window | Nothing stops it over BLE; the owner's app does not confirm and says to reset (§2.4). By cable, USB first (§2.5) stops it |
| A stranger knocks the owner's phone off after message 2, to complete in its place | The owner's message 3 never arrived, so after 6 s the stranger can complete. The owner's phone then gets no link handshake and says to reset. It cannot be done silently |
| A recorded message 1, from this window or an old one | It cannot complete (no message 3). Each recording holds a window at most once, for 6 s, and a radio is paired rarely, so there are few recordings |
| A stranger with the label pairs before the owner ever does (in the shop, in transit) | The owner's radio then opens no window on USB power and the app finds no radio in pairing mode; the app says a radio that will not pair must be reset with the pin. The reset removes them |
| A stranger supplies USB power (a hostile charger or computer) | On a paired radio: nothing. On an unpaired radio: a window, which with the label means a pairing (by cable, it wins the race). Leave a radio paired; the owner notices as above |
| A stranger triggers the pinhole | Needs the radio in hand. Then, with USB power and the label, they can pair it. The owner's phone stops getting answers, and they get no message key and nothing held |
| A relay between the radio and a far-off phone | Extends a stranger's range for the race above, nothing more. `IK` with the key from the label means the owner's phone pairs only with that radio, wherever the bytes travel. Range is not a security boundary here |
| A swapped label (another radio's QR stuck on) | The owner's phone pairs with the other radio. See §7 ("the label trusts the factory") |
| A stranger keeps completing first, window after window | Delays pairing over BLE while they are in range, like jamming. Pairing by cable avoids it |
| A stranger listens to a pairing | Knowing the secret does not decrypt it; that needs a private key |
| The user trusts the light | Nothing depends on it; the app decides (§2.6) |

## 3. The session

After pairing, the phone and the radio run the **R-COM2 link, wire version 1, unchanged**: `Noise_IK`, prologue `"OASA-SEC v1 link"`, 16-byte tag, per-packet counter, 1024-packet replay window, trusted-peers gate. Each side has exactly one trusted peer, saved with the role `peer`.

- **Who initiates.** The phone starts the handshake after every connect. As on any link, the radio may also start one (the responder's late rekey, the stale rule, or data to send with no session). Neither side needs a true clock: the handshake timestamp only has to be newer than the last one, and a device without a clock uses "last sent + 1 ns" (link §2). Both sides save their last-sent timestamp and the newest one received, so a recorded handshake cannot be replayed after a power cycle. The phone keeps its last-sent value with its keys, so a restore brings both back together.
- **The radio has no trusted clock**, so the link's "too far ahead" check (`max_future`) is off on the radio. A phone whose clock was once far ahead keeps working (it counts on from its saved value). A phone that lost its saved value and now has an earlier clock gets no answer until it re-pairs after a pinhole reset, which clears the radio's saved timestamps. (`PAIR_OPEN` cannot help: it needs a session.)
- **An unpaired phone gets no reply at all.** Its handshake is dropped (`untrusted_peer`, or `bad_header` if it does not even know the radio's public key, or `rate_limited` in a flood); anything else it sends is dropped as `bad_header` or `unknown_index`.
- **A replayed command is dropped.** Every command is a link data packet. A copy is dropped as `replay` or `too_old` while its session can still be read, and as `unknown_index` or `bad_tag` afterwards. Whatever the reason: one counted drop, nothing done, nothing transmitted.
- **Control messages** (content type `0x01`, R-SEC2) carry no rights here: neither side is an `admin` or an `operator` of the other, so removal and signing-key messages are refused by the existing role checks. The phone-link messages of §4 are application packets (`0x00`).
- **Settings** (not wire changes): keepalive timer off; rekey once an hour or at 2³² packets, reject after 90 minutes.
- **Flash writes.** Each handshake costs the radio one or two small writes (the timestamps). There are at least 24 a day from rekeys, plus one per reconnect, and phones drop BLE connections often. The firmware card must count writes per day on real phones and check the number against the flash part's endurance (open question 8).
- **Framing.** On BLE and on USB each link packet travels as a 2-byte big-endian length and the bytes, as R-SEC1's stream framing, split across writes and notifications as the transport needs. The phone link's MTU must fit the largest air packet plus the `SEND` or `RECEIVED` fields plus the link's 22 bytes; a longer length closes the connection.
- **The same on both transports.** BLE and USB carry the same session and the same messages. A session belongs to one transport connection; when the connection drops, the phone handshakes again.

**Connections nobody can hold.** Anyone can open a BLE connection or plug in a cable. Outside a pairing window, the radio closes a connection that has not completed a link handshake within 5 s, and when its connection slots are full a new connection replaces the oldest one that has not completed. A connection that has completed is never displaced by one that has not. Inside a window, pairing attempts follow §2.4 and the same rule protects a completed link connection.

**Bluetooth's own security is not relied on.** BLE pairing and bonding may be used for private addresses (§7), but every protection in this document comes from the link above and the pairing of §2. A flaw in the phone's or the radio's Bluetooth security must not let anyone drive the radio.

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
| `0x09` | `STATUS` | radio → phone | Battery, firmware version, counters, whether a pairing window is open |
| `0x0A` | `UPDATE_*` | phone → radio | Firmware update pieces (the update standard: signed, checked on the radio, trial boot) |
| `0x0B` | `PAIR_OPEN` | phone → radio | Open a replace window (§2.3), with or without the USB-only flag (§2.5). The radio answers with `STATUS` |
| other | | | Dropped and counted |

What the radio refuses **even from its own phone**:

- Transmitting outside the frequency, power and airtime limits built into its firmware. The phone can lower them, never raise them.
- Firmware that is not signed by the release key, **or that is older than what it runs**, by any path (the phone link, USB, or a Bluetooth update mode). The phone only carries the file.
- Reading out the radio's private key or its pairing secret. There is no message for either.
- Resetting. That is the pinhole only. (The phone can open a replace window with `PAIR_OPEN`, and nothing else about pairing.)

So a phone with a hostile app can waste its own radio's battery and airtime inside the limits, and hand the radio to another phone that has the label, and cannot turn the radio into something else.

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
| The pairing secret (they also have the label) | Anything the secret protects beyond pairing this radio |
| The phone's radio-link public key (used nowhere else) | The messaging public key itself |
| The wake filters. The handshake filter confirms whose radio this is to anyone who already knows the owner's messaging public key. The indexes and groups, with recordings of the air, link past traffic to this radio | The content of any packet, held or recorded |
| Held packets, still sealed, if it stayed powered | A way to send as the owner, or to read what the owner receives next |
| Radio settings, counters, firmware version | |
| Without reading memory: a pinhole reset and a pairing to their own phone (§2.8), which gives them a radio and erases the above | |

What the owner does: remove the radio in the app (the phone deletes it from its trusted list, so the stolen device key is worthless) and pair a new one. Nothing has to be re-keyed with other people. **A radio that comes back is not paired again as it is**: its device key and secret may have been copied, and reloading firmware does not change either. It is retired, or given a new key, a new secret and a new label by whoever can print one (open question 9).

**A stranger within Bluetooth or radio range:**

| Can | Cannot |
|---|---|
| See that a radio of this kind is near, and possibly follow it by its Bluetooth address (§7) | Complete a link handshake, so cannot send, fetch, change settings or update firmware |
| Open connections; each is closed after 5 s outside a window | Hold a connection slot against the owner's phone |
| Send a forged wake to the phone if they copy the radio's address | Make the phone show or ring anything |
| Record the phone link and any pairing | Read either, or replay any part of it to effect |
| With the label's secret, pair a radio during a window it has open, first (§2.8, §2.9) | Do it unnoticed, take a radio that stays paired, or do it against a phone pairing by cable |
| Flood the air with packets that match a filter: push real packets out of that share of the hold store, and wake the phone up to the wake limit | Fill the whole store, or make the phone show anything |
| Jam Bluetooth or the radio channel | |

**A borrowed cable, charger or computer:**

| Can | Cannot |
|---|---|
| Charge the radio | Anything a Bluetooth stranger cannot on a paired radio: USB carries the same link and gets no reply without the paired key, and opens no window |
| On an unpaired radio: open a pairing window, and with the label's secret, pair it (§2.9) | Read the secret from the radio: no message, port or serial output gives it on a product unit |
| See the radio's USB name and firmware version | Load firmware that is unsigned or older: the bootloader refuses both |
| | Read memory through the debug port: it is locked on production radios |

The last three rows are **requirements on the product**, and they are **not true of the development boards** (RAK4631 and similar), whose bootloader takes any firmware over USB, whose debug port is open, and whose firmware prints the label payload on the serial port (§2.2). Development boards are for the bench only.

**Not covered:** a phone that is itself taken over. The phone holds every key; this link cannot help there.

## 7. Known limits and privacy (v0)

- **The pairing secret is printed and never changes.** Anyone who has seen the label can race any window the radio opens, for its whole life (§2.8). The window rules, one phone, the confirmation and pairing by cable limit it; nothing removes it short of a new label.
- **The light shows "completed" for any phone that completes first.** Only the app tells the owner whether that phone is theirs. Nothing depends on the light (§2.6).
- **Following a radio by Bluetooth.** The radio advertises a service id so the phone's system can find it and wake the app. That marks it as one of these radios. During a window it also advertises that a window is open and a 4-byte hint from its public key (§10), so an app in a room full of radios finds the one on its label; the hint ties those 2 minutes to that radio. Whether the address can also rotate (private addresses, which need Bluetooth bonding) without breaking wake on iPhone and Android is decided by the phone tests (open question 3).
- **The label trusts the factory.** Someone who can print a label can pass off a swapped radio, or stick another radio's label on this one. So can someone who had the radio open on a bench. A factory that kept the secrets could pair any unpaired radio in range of a window.
- **No label, no pairing.** A radio whose label is lost or unreadable, and whose text form cannot be read either, cannot be paired (open question 1).
- **Handshakes on the air can be spotted** by anyone who knows the receiver's public key (`mac1`, link §2). That is the base link's property; the handshake filter uses it and adds nothing to it on the air.
- **Timing.** The radio cannot read packets, but anyone watching the air or the phone link sees when packets flow and how large they are. Padding is not in v0, as on the link.
- **One phone.** No second phone, no shared radio (§2.7, open question 4).
- **`snow` does not wipe its state** (as R-SEC1 §6); on the radio, session keys sit in memory until power-off, and the pairing secret is in `snow`'s handshake state until it is dropped.

## 8. What the simulated suite must cover

Suite `l1-phone-link` in oasa-lab (a later card), with a simulated radio, a simulated transport, simulated USB power and a simulated pinhole. The first two are the known-bad cases the checker must see. "Refused" and "dropped" mean: one counted drop, no reply where the link gives none, nothing done, nothing transmitted.

1. **An unpaired phone is refused:** a phone whose key the radio does not hold sends a handshake and commands, with and without knowing the radio's public key.
2. **A replayed command is dropped:** a recorded `SEND` played again in the same session, during the previous session's grace, after a rekey and after a reconnect; the radio transmits once.
3. A label with the wrong prefix, version, length or checksum, a small-order key, or one changed character is refused by the app before it connects. An R-SEC1 code is refused as a label and a label as a code.
4. A message 1 with the right public key and the wrong secret gets no reply, in and out of a window.
5. The race: a second phone with the label completes first. The window closes; the owner's phone is not saved, gets no link handshake and reports "not confirmed" within 60 s.
6. The hold: a phone that sends message 1 and never message 3 holds the window for 6 s, then another phone pairs. A phone whose message 3 is dropped is not saved, and a second phone can then complete; the first reports "not confirmed".
7. A recorded message 1 played again in the same window gets no reply; one from an earlier window holds the window once and never completes. Nothing is saved either way.
8. Window rules: no window on battery start, or on USB power when paired; a window on USB power when unpaired, closed after 2 minutes; the first completion closes it and no second phone completes; a pairing message outside a window gets no reply.
9. `PAIR_OPEN` from the paired phone opens a replace window; the old phone works until a new phone completes and is refused afterwards, with its timestamps deleted. `PAIR_OPEN` from anyone else, or any unauthenticated request for a window on BLE or USB, is refused.
10. USB first: BLE pairing in the first 3 s after USB power is refused; after a proven message 1 on USB, BLE pairing is refused for the rest of the window; in a USB-only replace window BLE pairing is refused throughout; a charger that sends nothing leaves BLE pairing open after 3 s.
11. Pinhole reset: erases the phone, every saved timestamp, the filters and the held packets; keeps the device key and the secret; the old phone is refused; the next USB power opens a window.
12. A changed bit in any command: dropped.
13. Idle, slow and flooding connections do not keep the paired phone out, and do not keep a phone with the label out of an open window.
14. The radio starts a handshake (stale rule, late rekey); a recorded handshake from either side replayed after a power cycle of the radio is dropped.
15. A phone that lost its saved timestamp and has an earlier clock: refused until a pinhole reset and re-pairing, then accepted.
16. Held packets: delivered once after a handshake, deleted only on `FETCH_ACK`; the limits hold; nothing survives a reset or a power cycle.
17. A flood of packets matching one filter: packets held for other filters survive; wakes stay under the limit.
18. A forged wake: the phone shows nothing.
19. Control messages (`0x01`) from either side change nothing.
20. A `SETTINGS` above the built-in limits is refused; an unsigned update and an older signed update are refused.
21. Captures of the phone link and of pairing contain none of the test plaintext and not the pairing secret; in product mode no output of the radio (messages, `STATUS`, USB serial, logs) contains the secret, and in development mode only the serial port does.
22. With no phone connected the radio's transmissions are relays only.

## 9. Open questions

1. A radio whose label is lost: a second copy on a card in the box (one more thing to photograph, and it travels with the radio when sold), a re-label service (open question 9), or nothing?
2. Hold store in memory only (a dead battery loses waiting messages; a found radio holds less), or in flash (the reverse)? This draft says memory only. How long, and how many?
3. Bluetooth bonding for private addresses: does wake still work on both platforms? (P0 and P4 phone tests.)
4. A second phone for one radio, or one phone with two radios. A second phone would need its own answer to §2.7's first point.
5. A theft lock, so a radio reset with the pinhole cannot be paired by a finder. It would need a secret the owner keeps, and a way back when they lose it.
6. An NFC tag in place of scanning the label (the chip supports it; it needs an antenna in the case). A tag readable through the packaging or a pocket would break §2.2, so it could hold the payload only when the radio enables it.
7. Sealed packets the phone leaves with the radio to send later (a position while the phone is dead). Not in v0: the counters need care.
8. The rekey interval and reconnect rate against flash wear, once the flash part is chosen. A link setting that stops the radio from ever starting a handshake would halve the writes; it is a code change to the link.
9. Giving a returned or second-hand radio a new device key, a new secret and a new label: who may do it, and how the old label is made void.
10. Where the label goes: on the outside of the case (easy to scan, easy to photograph), or under a cover or seal that shows it was opened. The same choice decides how easy §2.8's "brief access" is.
11. Replacing a phone: should the radio tell the old phone the new phone's name and fingerprint before removing it, so an owner holding both sees a stranger's completion at once rather than at the new phone's 60 s timeout?

## 10. Implementation notes and what is not covered

Constants and reuse, for the code card:

| What | Value |
|---|---|
| Noise pattern | `PAIRING_NOISE` (`Noise_IKpsk1_25519_ChaChaPoly_BLAKE2s`), psk position 1, unchanged |
| Pairing prologue | a new constant beside `PAIRING_PROLOGUE`: `"OASA-SEC v0 phone pairing"` |
| Label | prefix `OASAR1-`, version byte `1`, 69 bytes, checksum label `"OASA-SEC v0 label checksum"`, 118 characters, QR version 5 level Q |
| Advertised hint during a window | first 4 bytes of the fingerprint hash (BLAKE2s-256(`"OASA-SEC v0 fingerprint"` ‖ public key), R-SEC1 §1) |
| Pairing message 3 | `[0x03]`, R-SEC1's confirm byte, in transport mode |
| Window | 120 s; BLE from 3 s after USB power |
| Attempt timers | message 1 within 3 s of connecting; message 3 within 6 s of message 2 (R-SEC1) |
| App confirmation | first link handshake within 60 s of message 3 |
| Pinhole | held 5 s |
| Unfinished link connection outside a window | closed after 5 s |

- The label is not a `PairingCode`, but shares its rules: the secret is wiped on drop and never in `Debug` (`code.rs`). R-SEC1's per-window memory of message 1 ephemerals (`oasa-pair`'s `seen` set) is reused as is.
- The phone pairing needs its own pair of functions, not `pair_as_drone_checked`: that one saves the peer as `operator` and exchanges signing keys. Here both sides save `peer`, and the only message after the handshake is the phone's confirm.
- Saved timestamps are per peer (`FileTimestampStore::new(dir, peer_public)`, with `reset`), so replacing a phone or a pinhole reset can delete the old phone's.
- The radio closes the window in memory before it writes the new peer, so a second completion cannot slip in during the write; a power loss during the write leaves the radio unpaired and the phone unconfirmed.

Not covered: the app's screens, USB class details, the Bluetooth service layout, the relay rules, voice timing, the production jig and its commit step, and the code. Review by a person is required before this moves past Draft.

## 11. The v0.1 review findings after this rewrite

The [review notes](security-review-t-msg1-phone-link.md) describe v0.1. What each finding becomes:

| ID | v0.1 finding | Now |
|---|---|---|
| H1 | Swap during the press wait | **Gone** with the press and the pending phone. What remains: knocking the owner off between message 2 and message 3 lets a stranger with the label complete after 6 s, and the owner's app then reports it (§2.9). By cable, USB first stops it |
| H2 | No confirmation reached the phone | **Kept**: the first completed link handshake is the confirmation (§2.4) |
| M1 | The radio also starts handshakes | Unchanged (§3) |
| M2 | Flash wear | Unchanged (§3) |
| M3 | Stale-timestamp lock, `max_future` | Unchanged; the way out is now the pinhole reset (§3, §2.8) |
| M4 | The handshake filter ties the radio to its owner | Unchanged; a reset before selling erases it (§2.8) |
| M5 | Hold store flood | Unchanged (§5) |
| M6 | The code readable on BLE during a USB pairing | **Gone**: the radio never sends the secret; it comes only from the label. Replaced by USB first, which keeps "pairing by cable avoids the race" true (§2.5) |
| M7 | Roles and control messages | Unchanged (§3) |
| L1 | Drop reason names | Unchanged |
| L2 | Firmware rollback | Unchanged (§4) |
| L3 | A returned radio stays a risk | **Wider**: the previous owner also keeps the secret for good (§2.8, §6) |
| L4 | `FETCH_ACK`, MTU, confirm wait tied to the window | The first two unchanged; the confirm wait is gone |
| L5 | The light shows "press" for a stranger | **Gone** with the press. The light now shows "completed" for anyone, and nothing depends on it (§2.6). The blink count (old open question 10) is dropped |
| New | A static secret known to everyone who saw the label | §2.8; open questions 1, 9, 10 |
| New | Replay of a recorded message 1 in a later window | Message 3 (§2.4) |
| New | A hostile USB power source, the pinhole, a replace window | §2.9, §2.7 |
| New | The label leaking through a camera app or the packaging | §2.1, §2.2 |
