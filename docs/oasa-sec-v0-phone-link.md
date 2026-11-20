# OASA-SEC v0: the phone link (draft)

**Stage:** Idea → Draft (no code yet) · **Node:** T-MSG1 · **Version:** v0.4 draft, 2026-11-19 (written by an AI agent; v0.1, v0.2 and v0.3 each had one independent AI design review, see the [review notes](security-review-t-msg1-phone-link.md); v0.4's changes have not been reviewed, by an AI or a person)

How a phone and its pocket radio pair, and how the phone drives the radio afterwards, over Bluetooth Low Energy (BLE) or a USB cable. Builds on [pairing](oasa-sec-v0-pairing.md) and the [link](oasa-sec-v0-link.md).

**No new crypto.** Pairing is R-SEC1's `Noise_IKpsk1`, with the radio's pairing key and the pre-shared secret taken from a printed label (or, to move to a new phone, from a one-time code the old phone shows). The session is the R-COM2 link, unchanged on the wire, keyed with a link key the radio makes at each pairing. What is new: who plays which role, the label, when the radio accepts pairing, and the messages carried inside the session.

**Changes since v0.3** (answers the third review, R3; §11 has one line per finding):

- **The middle of a BLE pairing, stated in full.** Someone who holds the radio's pairing private key and label secret and sits in the middle of the next BLE pairing becomes the radio's real paired phone. §2.9 and §6 now say what that gives, what it needs, its one sign, and that it is inherent to a fixed printed label on a radio with no display and no button. The app treats "radio seen but not answering" as "possibly not your radio" (§3). A second-hand or returned radio is paired by cable where a cable path exists, otherwise treated as not clean. A camera reading the light is open question 14, not adopted.
- **Slots:** a proved attempt is never closed to make room for a connection that has proved nothing; one message 1 per connection (§2.4).
- **Erase means gone from flash**, and reset and replace are safe against power loss: a marker, then the erase, then the trust change; at boot a marker means finish the erase (§2.8).
- **Window rules for ordinary use:** BLE also opens if a host enumerated but sent no proving message 1 within 20 s; the rate limit needs a new USB edge; distinct light states for "rate limited" and "window closed"; first-pairing advice in the app (§2.3, §2.5, §2.6).
- The app pairs again while the window is still open instead of raising an alarm; replace flow details; attempt link keys in memory only (§2.4, §2.7).

**Changes since v0.2** (answers the second review, R2):

- **Two radio keys.** The label key is for pairing only. At each pairing the radio makes a new **link key** and sends its public half inside message 2; the link uses it, and a reset or a replace destroys it (§1, §2.4, §3). Someone who read the radio's memory before a sale has no way into the next owner's link, except by sitting in the middle of the next BLE pairing (§2.9).
- **Replace windows use a one-time secret** the old phone makes and shows as a QR code, never the label secret (§2.7). The USB-only flag is gone. A replace erases held packets, filters and settings, as a reset does.
- **USB first is now tied to what the radio sees**, USB enumeration, not a 3 s timer; a proving message 1 on USB ends every BLE attempt that has not completed (§2.5). **Pairing by cable is not promised** on any phone: it exists only where the phone can use the radio's USB network adapter, which is unverified everywhere (§2.5, open question 12). No security property rests on it.
- **USB power edges are debounced and rate limited**; an edge during a window changes nothing (§2.3). **The pinhole reset** ends every window, attempt and session, and with USB present opens a window 2 s later (§2.8).
- **No exclusive hold:** the radio answers every proving message 1 and the first valid message 3 completes (§2.4).
- The QR is version 7 at level Q, and the label size follows (§2.1). The phone's radio-link key is made per pairing and never leaves the phone. Bystander identifiers, label leaks, the jig's failure path and the confirmation's false alarms are covered. The suite is split into simulated cases and checks that need real hardware (§8).

## 1. Who holds what

| | Phone (the app) | Radio |
|---|---|---|
| Message keys: the identity people pair with, link sessions with other people, group keys | **Yes** | **Never** |
| Plaintext of any text, voice or position | Yes | Never |
| A **radio-link key** (X25519), made on the phone at each pairing, used only toward this radio | Yes, on the device only | Its public half |
| The radio's **pairing key** (X25519, made on the radio, public half on the label), used only for pairing | Its public half | Yes, for the radio's whole life |
| The radio's pairing secret | Only while pairing, from the label | Yes, for its whole life |
| The radio's **link key** (X25519, made on the radio at each pairing), used only for the link with this phone | Its public half | Yes, until reset or replace |
| Phone link session keys | Yes | Yes |
| What goes on the air | Builds and seals every packet | Sends, receives and relays sealed packets; keeps voice timing |

Rules:

- None of the radio's keys, its pairing secret or the phone link session keys are **message keys**. They protect the few metres between phone and radio and nothing else.
- The phone uses **separate key pairs**: one for messaging (what other people pair with) and one radio-link key per pairing. The radio learns the radio-link public key. Of the messaging identity it holds only the handshake filter (§5): a hash of the messaging public key. The hash cannot be turned back into the key, but **anyone who already knows the key can match it**, so it ties the radio to its owner for the owner's contacts.
- The radio-link key and its saved timestamp stay on the phone: never in a backup or a sync. Removing the radio in the app deletes them. A restored or new phone pairs again.
- The radio never originates a message. Everything it transmits is either a sealed packet the phone handed it, or a sealed packet it is relaying.

## 2. Pairing

Roles from R-SEC1: the **radio is the responder** (the drone's part) and the **phone is the initiator** (the ground station's part). One radio has **one paired phone** in v0 (§2.7).

The radio has one status light, a USB socket and a recessed pinhole. No button, no screen.

### 2.1 Codes and the label

Three kinds of pairing code share one layout, each with its own prefix and checksum label, so none can be taken for another:

| Code | Prefix | Checksum label | Holds | Where it comes from |
|---|---|---|---|---|
| Drone (R-SEC1 §2) | `OASA1-` | `"OASA-SEC v0 code checksum"` | drone public key, one-time secret | the drone, each pairing |
| **Radio label** | `OASAR1-` | `"OASA-SEC v0 label checksum"` | radio pairing key, pairing secret | printed on the radio |
| **Replace code** | `OASAT1-` | `"OASA-SEC v0 replace checksum"` | radio pairing key, one-time secret | the old phone's screen, for one replace window (§2.7) |

Layout of the label and the replace code:

| Bytes | Field |
|---|---|
| 1 | Format version (`1`) |
| 32 | Radio's pairing public key (X25519) |
| 32 | Secret |
| 4 | Checksum: first 4 bytes of BLAKE2s-256(checksum label ‖ the 65 bytes above) |

Text form: the prefix + uppercase base32 without padding: 7 + 111 = **118 characters**, all in the QR alphanumeric set. Readers accept lowercase, spaces and dashes after the prefix, as R-SEC1. The digit in the prefix is the format version and always equals the version byte: a format change bumps both, and is a protocol change (AGENTS.md).

**Why the full public key, not the fingerprint.** `IK` needs the initiator to know the responder's static key before message 1. A fingerprint (80 bits) would need the radio to send its key first, which is a different pattern, and would rest on a shorter value.

The app refuses a code with the wrong prefix, an unknown version, the wrong length, non-zero padding bits in the last character, a bad checksum or a small-order public key, before it connects to anything. A misread fails there, with a 2⁻³² chance of a misread passing the checksum (on top of the QR's own error correction); a misread key or secret that did pass would only fail the handshake.

**The label.** On the radio: the QR, the text form under it, and the radio's fingerprint (R-SEC1 §1, of the pairing key) as text. The QR is **version 7 (45 × 45 modules) at error correction level Q** (measured: 118 alphanumeric characters need version 5 at L or M, version 7 at Q, version 8 at H). Level Q leaves room for a scuffed label. Each module is at least **0.34 mm** (4 dots at 300 dpi), so the QR with its 4-module quiet zone is **18 × 18 mm**. The text form (four lines at about 1 mm character height) and the fingerprint need about 7 mm more. **The label needs 20 × 27 mm.** If the case gives only 20 × 20 mm, the QR and the fingerprint stay and the text form is left off, so a damaged QR cannot be typed (open question 1).

**Not a URL.** No code has a scheme or a host, so an ordinary camera app shows it as text and opens nothing. The app registers no URL scheme or link type for codes.

**Where a label leaks.** A camera app may offer to search the web for scanned text. A photo of the radio puts the text in the phone's photo library, which many phones index for search and sync to a cloud service. Typed or pasted text passes through the clipboard, which some systems sync between devices. So: the label says "Scan with the app"; the app scans with its own camera view and keeps no image; it accepts typed or user-pasted text but never reads the clipboard by itself; it sends a code nowhere and wipes the secret when pairing ends; support guidance never asks for a photo of the label. §2.9 says what a leaked label gets.

### 2.2 The pairing key and secret: making them, keeping them

Requirements on manufacturing and on product firmware:

- **Random.** The pairing key and the 32-byte secret are made on the radio at first start from the radio chip's hardware random source. The secret is not derived from, or stored next to a record of, the serial number, the Bluetooth address, the public key or anything else printed or broadcast.
- **Out once.** The radio hands the label payload to the production jig over the factory interface once, for printing. The jig then **commits** the radio, which closes that output for good. The factory keeps no copy of the secret; its records hold the fingerprint only.
- **A failed print** (a misprint, a label that does not scan back at the jig) is handled before commit: the unit is scrapped, or makes a new pairing key and a new secret and is printed again. There is no output path after commit. An end-of-line test proves the output is closed. `STATUS` reports whether the radio is committed; the app refuses an uncommitted product radio and warns on a development board (below).
- **Covered.** The label is not visible or scannable through the packaging.
- **Kept on the radio.** The radio stores the psk itself. The label could carry a value whose hash is the psk, but the radio would then store the psk, which pairs just as well; so it stores the secret and protects it like the pairing key: wiped from working memory after each handshake, never in `STATUS`, logs, errors or any message (§4 has none for it).
- **Not readable over the debug port** on product units: it is locked (§6).
- **Never changes.** The label is printed, so the pairing key and secret cannot rotate on reset. §2.9 says what follows.

**Development boards** (RAK4631 and similar) have no label and are never committed. Development firmware prints the same `OASAR1-` payload on the USB serial port at start and on request. Anyone who can plug into a development board can read its secret, as they can already load any firmware on it. Development boards are for the bench only.

### 2.3 The pairing window

The radio accepts pairing messages only while a **pairing window** is open. A window lasts **2 minutes** and opens in exactly three ways:

1. **USB power while unpaired** (a **USB window**). The radio has no paired phone, and USB power **appears and stays**: it has been absent for at least 10 s (or the radio was in storage mode, or is starting from no power) and then present for 2 s. Plugging in wakes the radio from storage mode, so a new radio opens its first window when it is first plugged in. Battery power alone never opens a window. A radio that has a paired phone opens no window on USB power.
2. **`PAIR_OPEN` from the paired phone** (§4), inside a link session: a **replace window**, keyed with the one-time secret in that message (§2.7).
3. **A pinhole reset with USB power present** (§2.8): a USB window, 2 s after the reset.

Nothing else opens a window: no unauthenticated message on BLE or USB, no other message from the phone.

**USB edges.** A USB power edge during an open window changes nothing: not the 2 minutes, not the BLE rules of §2.5, not the record of message 1s seen (§2.4). **Rate limit:** after two USB windows in a row close with no pairing, no USB window opens until 30 minutes after the last one closed **and** a new debounced USB edge comes after that, or until a pinhole reset. A radio left on power opens no more windows by itself. So a cable that flickers, a power bank that pulses, or a charger that toggles power on purpose opens at most two windows, then one each half hour. The count is kept in memory and cleared by a completed pairing or a reset; the window a reset opens counts as the first of a new two.

A window that closes with no pairing counts toward the limit, unless an attempt in it proved the secret and was then ended by something other than its own 6 s timeout (pre-empted by USB, or its connection lost). So a window in which the owner's proved attempt was pending counts only if that attempt timed out by itself, and a stranger who cannot prove the secret cannot spend the owner's windows (they can still jam).

A window closes at the **first completed pairing** (§2.4), at a pinhole reset, or after 2 minutes. Each window is one chance: once a pairing completes, no second phone can complete in that window.

**Transports.** On BLE, pairing messages use their own characteristic, never parsed as link packets. On USB the radio appears as a USB network adapter (CDC-NCM); pairing is a TCP connection to the radio's pairing port on that network, as R-SEC1 pairing runs over USB networking today. Both use R-SEC1's stream framing. Outside a window the radio gives pairing messages no reply.

### 2.4 The handshake

`Noise_IKpsk1_25519_ChaChaPoly_BLAKE2s`, as R-SEC1 §3, with prologue **`"OASA-SEC v0 phone pairing"`** so a phone pairing and a drone pairing can never be mistaken for each other. The responder's static key is the radio's **pairing key**; the psk is the label secret in a USB window, and the replace secret in a replace window (the other is refused). The phone's static key is a **new radio-link key** made for this pairing.

1. **Phone → radio** (handshake): the phone's hello `[0x01, len, name]`. The radio checks the secret here and gives no reply without it, and refuses a small-order phone key. This message **proves the secret** but not that the sender is live: anyone who recorded one can send it again.
2. **Radio → phone** (handshake): the radio's hello `[0x01, len, name]`, then `[0x06, 32 bytes]`: the public half of a **new link key** the radio made for this attempt. The phone refuses a small-order key. The phone now knows it reached a holder of the pairing private key it was given, and that this link key came from that holder. (Normally that is the radio; §2.9 covers someone else who holds the key.)
3. **Phone → radio** (encrypted): confirm `[0x03]`. Only the phone that made message 1 can send it: it needs that message's ephemeral and static private keys.

**Completion is the radio receiving a valid message 3.** At that moment the radio closes the window, then makes **one atomic change** to its trust state: the new phone's radio-link public key and name in, as its one peer (role `peer`), with the link key of that attempt. In a replace window the same change takes the old phone out (§2.7), inside the power-safe sequence of §2.8.

**Attempt link keys.** Each attempt's link private key is made with its message 2 and held in memory only. It is wiped when the attempt ends for any reason: completion of another attempt, its own timeout, closing, pre-emption by USB, a reset, or the window closing. Only the completing attempt's key is ever written to flash, inside the trust change.

Why message 3: the label secret never changes, so a recorded message 1 from an earlier pairing proves it again in every later USB window. Without message 3 it would pair the radio to that old phone's key. With it, a recording gets at most a message 2 it cannot read. The same pattern ends every R-SEC1 pairing: the drone saves nothing until a transport message from the ground station arrives.

**Attempts.** Up to the first completion, pairing follows R-SEC1 §2's "nobody can hold the port", with these changes: no exclusive hold; a bounded record of message 1s; a 2-minute window; completion at the phone's message 3 rather than at the drone's save; separate slot counts for BLE and USB; one message 1 per connection. In R-SEC1 the holder exists because the drone sends key material after message 2; here message 2 gives nothing away, so:

- **Slots.** Pairing attempts on BLE and on USB are counted separately, up to `BLE_PAIRING_SLOTS` and `USB_PAIRING_SLOTS` (values fixed by the firmware card from the chip's real connection limits; §10). When a transport's slots are full, a new connection replaces the oldest attempt on it that has **not** proved the secret. **An attempt that has proved the secret is never closed to make room for one that has not:** if every slot holds a proved attempt, the new connection is refused (each proved attempt ends within 6 s). R-SEC1's `make_room` does the same.
- **One message 1 per connection.** Message 1 must arrive within 3 s of connecting. On BLE, connecting is the connection being made; on USB, the radio accepting the TCP connection to its pairing port. A message 1 that fails (wrong secret, small-order key, bad size) closes the connection; a second message 1 on the same connection closes it too. Each attempt holds at most one Noise handshake state, one link private key and its message buffers: under 1 kB, and the number of attempts is capped at the slot count.
- Every attempt whose message 1 proves the secret gets its own message 2. The first valid message 3 completes; every other attempt is then closed with no reply. An attempt that sends no message 3 within 6 s of its message 2 is closed.
- The radio remembers the ephemeral key of the last 16 message 1s that proved the secret in this window and gives a repeat no reply. When the record is full the oldest entry is forgotten; a recording that comes back after that gets a message 2 and a slot for at most 6 s, and still cannot complete. The record is cleared when the window closes. It matters only against recordings (a label holder can make fresh message 1s at will); replaying forever would need 17 recorded pairings of this radio, and none of them completes.
- No lockout: failed attempts do not end the window.
- The app retries with a new connection, as R-SEC1's ground station does, until it pairs or 2 minutes pass.

**The phone's confirmation.** After message 3 the phone starts a normal link handshake (§3) to the link key from message 2. The radio answers it only if it saved this phone, so **the first completed link handshake is the confirmation**. The app saves the radio and shows success only then. If the link handshake fails while the radio still advertises an open window (§7), this phone's message 3 did not land and nobody has completed: the app runs the pairing again, and that does not count toward the alarm below. The alarm is for a window that closed without this phone. While the app is in the foreground it keeps trying; after 20 s it says "Not confirmed yet: keep the radio close", and after 60 s of trying in the foreground it deletes the radio and says: "This radio did not confirm. Another phone may have paired with it. Reset it with a pin (hold 5 s) and pair again." It adds "by cable" only if this phone has paired over the radio's USB link before (§2.5). A phone that never got message 2 says the same when it gives up. Time in the background does not count toward the 60 s, so a phone that backgrounds the app does not raise a false alarm.

### 2.5 USB first

In a USB window the radio prefers a phone on the cable, by what it observes:

- **Enumeration.** A USB host has enumerated the radio when it has configured it (the USB "set configuration" step). A plain charger never does.
- **When BLE opens.** In a USB window, BLE pairing opens:
  - **10 s after the window opens, if no USB host has enumerated the radio by then** (a plain charger); or
  - **20 s after the window opens, if a host has enumerated it but no proving message 1 has arrived on USB by then** (a laptop, a car port, a monitor's hub, a phone that cannot reach the pairing port, or a host that was unplugged).

  Once a proving message 1 has arrived on USB, BLE stays shut for the rest of the window.
- **USB pre-empts BLE.** When a message 1 that proves the secret arrives on USB, at any time in the window, the radio closes every BLE attempt that has not completed, including any that has its message 2, and accepts no more pairing on BLE in that window.

So: a phone that powers the radio, enumerates it and sends a proving message 1 on its pairing port within 20 s **cannot lose a USB window to BLE**. A cable phone that is slower ends the open BLE attempts with its message 1 and loses only to a BLE phone whose message 3 arrived first. A host that is not pairing gains nothing by keeping BLE shut, so after 20 s it does not. A replace window has no USB rules: its secret is fresh (§2.7).

**First pairing in the app.** Because no cable path is assumed (below), the app's first-pairing flow says: "Plug the radio into a wall charger, not a phone or computer. Open the app within two minutes." And if no radio in pairing mode shows up: "Hold the pin for 5 s while it is plugged in." (A reset on USB power opens a window, §2.8.)

**Cable pairing is not promised.** It exists only on a phone whose system lets the app reach a USB network adapter. That is **unverified on every platform**; on iPhone it may not exist at all without Apple's accessory programme (open question 12). The app offers cable pairing only where it has worked on that phone. **No security property in this document rests on it:** where there is no cable path, the owner relies on detection (§2.4, §2.9), and the residual races in §2.9 stand.

### 2.6 The light

One status light. It is for convenience only: **no security property depends on anyone reading it.** The app is the only authority on whether pairing worked (§2.4).

| State | Light |
|---|---|
| Storage mode, or off | Dark |
| Pairing window open (any kind) | Fast blink (4 a second) |
| Pairing completed (the window just closed) | On for 3 s |
| Window closed with no pairing (2 minutes passed) | Three short blinks, then one short blink every 5 s while on USB power |
| Unpaired, rate limited (§2.3: the next window needs 30 minutes and a replug, or the pin) | Two short blinks every 5 s while on USB power |
| Unpaired, no window, not rate limited (unplug and plug in to open one) | One short blink every 5 s while on USB power; dark on battery |
| Paired | Charging, battery and "something waiting" patterns as set in `SETTINGS` |
| Pinhole reset accepted | On for 2 s, then the unpaired state |

The light shows "completed" for any phone that completes, the owner's or a stranger's. That is why the app, not the light, says whether the radio is the owner's.

### 2.7 One phone, and moving to a new one

v0 allows **one paired phone**. Why:

- **A stranger who pairs locks the owner out.** With one phone, any pairing the owner did not make removes the owner's, and the owner's app notices at its next connect. With two, someone who paired before the owner (shop staff, a previous owner) could stay paired beside the owner without a sign. Several defences in §2.9 rest on this.
- The hold store and `FETCH_ACK` (§5) assume one phone takes the packets.
- All message keys are on one phone anyway.

**Moving to a new phone (replace):**

1. The old phone fetches and acknowledges every held packet (`FETCH`, `FETCH_ACK`). Packets that arrive after that and before the completion are held and then erased with the rest; the sender's phone retries (§5).
2. It makes a fresh random 32-byte secret, kept in memory only and never on disk, and sends `PAIR_OPEN` with it. The radio refuses an all-zero secret (a cheap check against app bugs; the radio chooses nothing else about it, and a hostile app on the old phone is the owner already). The radio opens a replace window whose psk is that secret, and only that secret.
3. The old phone shows the **replace code** (`OASAT1-`, §2.1: the radio's pairing key and the fresh secret) as a QR on its screen. The code is hidden until the user taps to show it, hidden again when the app goes to the background, and screenshots are blocked where the system allows; iPhone cannot block them, and screen sharing, casting, screen recording and accessibility services may still see it. The old phone keeps working during the window.
4. The new phone scans it and pairs (§2.4). At completion the radio runs the replace sequence of §2.8: it erases everything a pinhole reset erases besides the pairing (held packets, wake filters, owner-set `SETTINGS`, saved timestamps), then in one atomic change takes the old phone out and puts the new phone in, with a new link key. The old phone's sessions end at once.
5. When the window closes, with or without a completion, both phones and the radio wipe the replace secret. With no completion, nothing changes: the old phone stays paired with its state.

Only someone who sees the old phone's screen in those 2 minutes can race a replace window; the label does not help. If the new phone does not confirm, the old phone may have been removed (someone else completed) or may still be paired (nobody completed): check the old phone first; if it was removed, reset with the pinhole. If the old phone dies or its app is killed during the window, nothing completes and the radio stays paired to a phone that is gone; the way out is the pinhole.

**A lost or broken phone:** reset the radio with the pinhole and pair the new phone in a USB window. Until then the lost phone can still drive the radio (never read messages through it: the radio has none).

### 2.8 The pinhole reset

Holding the recessed pinhole for 5 s, while the radio is awake (on battery or USB), at once:

- closes any window, ends every pairing attempt and every link session, and clears the record of message 1s seen;
- erases the paired phone, the radio's link key, every saved handshake timestamp, the wake filters, every held packet and owner-set `SETTINGS`, and clears the USB window rate limit;
- picks a new Bluetooth address (§7);
- keeps the **pairing key and the pairing secret**, so the label stays true.

The radio is then unpaired. If USB power is present, a USB window opens 2 s after the reset; otherwise the next debounced USB power does it (§2.3). A window right after a reset adds nothing for an attacker: the reset already needs the radio in hand, and they could unplug and plug it in. It saves the owner, whose radio is usually on its cable, a step.

A reset that comes between closing a window and writing the new peer wins: the write is abandoned, or erased if it landed, and the radio ends unpaired. Anyone holding the radio and a paperclip can reset it; a reset radio is an empty radio.

**Erase means gone from flash.** The usual key-value stores on this class of chip are log-structured: a delete writes a new record and leaves the old one until its page is collected. So the owner's state (the peer, the link key, timestamps, wake filters, owner-set settings, and the marker below) lives where it can be **page-erased**, or the store's clean-up is forced over the old records, **before a reset or a replace counts as done**. After either, no readable copy of the erased items remains anywhere in flash. Held packets are in memory only (§5) and are wiped there.

**Power loss during a reset or a replace.** Each runs in this order:

1. Write a marker in flash saying which operation is running.
2. Erase the owner state as above (for a replace: everything but the peer and the link key).
3. Write the trust state in one atomic change: nothing (reset), or the old phone out and the new phone and link key in (replace).
4. Clear the marker.

At boot, a radio that finds a marker **finishes the erase** of step 2, keeps whatever peer the trust state holds, and clears the marker. So a reset torn by power loss ends unpaired and empty. A replace torn before step 3 ends with the old phone still paired but its filters and settings gone (the old phone sends them again at its next connect), and the new phone reports "not confirmed". A replace torn after step 3 ends complete. No order leaves a new phone with the old owner's state.

### 2.9 What a known label gets, and threats during pairing

**A static secret.** Anyone who has once seen the label (shop or warehouse staff, a previous owner, someone with brief access, a photo, a synced photo library, a camera app's web search) knows the label secret for the radio's whole life. Knowing it lets them pair **only** when all of these hold:

- the radio has no paired phone, and a USB window is open (within 2 minutes of debounced USB power or of a reset on USB power; replace windows do not take the label secret);
- they complete first in that window, within Bluetooth range (or through a relay), and no phone has taken the window by cable (§2.5);
- for a radio that was paired, someone first reset it with the pinhole, which needs it in their hands.

And when they do, the owner finds out: the owner's own pairing in that window does not confirm (§2.4), or the owner's paired phone stops getting answers. The owner resets and pairs again. What the stranger gains while paired is a radio: no message key, no plaintext, nothing held from before the reset (§6). Knowing the secret alone does not let anyone read a pairing or a session: that needs a private key.

**It cannot rotate on reset**, so a reset does not undo a leak of the label. What follows:

- A second-hand radio is never clean against its previous owner. They cannot get in while the new owner stays paired, but they can race any USB window.
- The defences against a known label are the window rules, one phone, the confirmation, and where it exists the cable; not the secret.

**The middle of a BLE pairing.** This is the one way left into a radio after a reset for someone who does not have it in hand.

- **What it needs.** The radio's **pairing private key and label secret**. On a product unit that means reading its memory past the debug lock, or having had the unit before it was locked (in the factory, before commit). The label alone is not enough: without the private key nobody can make message 2. They must also be **in Bluetooth range, or relaying from there, at the moment of the next owner's BLE pairing** in a USB window, and **keep relaying** afterwards.
- **How.** They answer the owner's phone as the radio (they hold its pairing key and secret) and pair the real radio with a phone key of their own (they hold the label secret), and pass traffic between the two.
- **What it gives.** They are **the radio's real paired phone**, and the radio the owner's phone trusts. So they can drive the radio themselves within its firmware limits; `FETCH` and `FETCH_ACK` held packets so the owner never gets them; change wake filters and settings; open replace windows; drop or delay any packet in either direction; push far-future handshake timestamps to both sides; and see everything that crosses: sealed packets, their sizes and timing, filters and settings. Never message content or any message key: the phone seals everything (§1).
- **How long.** As long as they keep relaying, from any distance a relay reaches.
- **The one sign.** When they stop relaying, the owner's phone gets no answer from the radio, because the radio does not hold the owner's phone key. The app shows this as "possibly not your radio", not "out of range" (§3). That needs the app to see the real radio: if the middle used a Bluetooth address of its own, the app sees nothing at the address it knows when the relay stops, and the sign looks like "out of range". Nothing shows while they relay.
- **What stops it.** A pairing whose phone took the window by cable (§2.5), where a cable path exists. A replace window (its secret is fresh, and without it nobody can make message 2). A new pairing key, secret and label (open question 9). A camera reading the light might (open question 14). Nothing else in the design does.
- **It is inherent** to a fixed printed label on a radio with no display and no button: the owner's phone has no channel to the radio that a party in the middle cannot also speak on, except a cable.

**Selling or returning a radio:** reset it with the pinhole first (it erases the handshake filter, which ties the radio to its owner, and the link key). The buyer resets it again before pairing. **A second-hand or returned radio is paired by cable where a cable path exists; otherwise it is treated as not clean**, because a previous holder may have read its pairing key. A radio returned to a seller is retired or re-keyed and re-labelled, never resold as it is (§6).

| Threat | What stops or limits it |
|---|---|
| A stranger with the label completes first in the owner's USB window | Over BLE, nothing stops it; the owner's app does not confirm and says to reset (§2.4). A phone that took the window by cable (§2.5) cannot lose it |
| A stranger knocks the owner's phone off after message 2, to complete in its place | The same race: whoever sends a valid message 3 first completes. The owner's phone then gets no link handshake and says to reset. It cannot be done silently |
| A recorded message 1, from this window or an old one | It cannot complete (no message 3). Within a window a repeat gets no reply; otherwise it gets a message 2 and a slot for 6 s |
| A stranger with the label pairs before the owner ever does (in the shop, in transit) | The owner's radio then opens no window on USB power and the app finds no radio in pairing mode; the app says a radio that will not pair must be reset with the pin. The reset removes them |
| A stranger supplies USB power (a hostile charger or computer) | On a paired radio: nothing. On an unpaired radio: a window, which with the label means a pairing; as a USB host that pairs over USB it also takes the window from BLE. Toggling power opens at most two windows, then one each half hour (§2.3). The owner notices as above |
| A stranger triggers the pinhole | Needs the radio in hand. Then, with USB power and the label, they can pair it. The owner's phone stops getting answers; they get no message key and nothing held |
| A stranger races a replace window | Needs the replace code from the old phone's screen during those 2 minutes; the label does not help (§2.7) |
| A previous holder who read the radio's memory | No access after a reset, except by sitting in the middle of the next BLE pairing, which makes them the radio's real paired phone for as long as they relay; the sign is a radio that stops answering when they stop (above). Not of a cable pairing or a replace |
| A relay between the radio and a far-off phone | Extends a stranger's range for the races above, nothing more. `IK` with the pairing key from the code means the owner's phone pairs only with that radio, wherever the bytes travel. Range is not a security boundary here |
| A swapped label (another radio's QR stuck on) | The owner's phone pairs with the other radio. See §7 ("the label trusts the factory") |
| A stranger keeps completing first, window after window | Delays pairing over BLE while they are in range, like jamming; the rate limit (§2.3) then slows the owner too. A cable path, where there is one, avoids it |
| A stranger listens to a pairing | Knowing the secret does not decrypt it; that needs a private key (but see §6 for someone with the radio's) |
| The user trusts the light | Nothing depends on it; the app decides (§2.6) |

## 3. The session

After pairing, the phone and the radio run the **R-COM2 link, wire version 1, unchanged**: `Noise_IK`, prologue `"OASA-SEC v1 link"`, 16-byte tag, per-packet counter, 1024-packet replay window, trusted-peers gate. Each side has exactly one trusted peer, saved with the role `peer`.

- **Link identities.** The phone's static key is its radio-link key from this pairing; the radio's is the **link key** it sent in message 2, never the pairing key. The phone's trusted peer is that link public key. The radio answers no link handshake addressed to its pairing key: such a handshake fails `mac1` and is dropped as `bad_header`.
- **`mac1`** is keyed from the radio's link public key (link §2). Only the owner's phone, someone who reads the radio's memory, and a party in the middle of the pairing (§2.9) know it, so a stranger who only saw the label cannot spot link handshakes to this radio by `mac1`.
- **Who initiates.** The phone starts the handshake after every connect. As on any link, the radio may also start one (the responder's late rekey, the stale rule, or data to send with no session). Neither side needs a true clock: the handshake timestamp only has to be newer than the last one, and a device without a clock uses "last sent + 1 ns" (link §2). Both sides save their last-sent timestamp and the newest one received, per peer, so a recorded handshake cannot be replayed after a power cycle. Both keys are new at each pairing, so every pairing starts with fresh timestamps, and a reset or replace deletes the old ones with the keys.
- **The radio has no trusted clock**, so the link's "too far ahead" check (`max_future`) is off on the radio. A phone whose clock was once far ahead keeps working (it counts on from its saved value). A phone that lost its saved value and now has an earlier clock gets no answer; it pairs again after a pinhole reset, with new keys. (`PAIR_OPEN` cannot help: it needs a session.) Only a holder of the phone's radio-link private key, or a party in the middle of the pairing (§2.9), can push a far-future timestamp to the radio.
- **When the radio stops answering.** If the app sees the radio's advertisement (its address and service id) but its link handshakes get no answer, it says: "Your radio is near but not answering. It may not be your radio any more, or someone may have been between your phone and it. Reset it with the pin and pair again, by cable if your phone can." It says "out of range" only when it does not see the radio at all.
- **An unpaired phone gets no reply at all.** Its handshake is dropped (`untrusted_peer`, or `bad_header` if it does not even know the radio's link public key, or `rate_limited` in a flood); anything else it sends is dropped as `bad_header` or `unknown_index`.
- **A replayed command is dropped.** Every command is a link data packet. A copy is dropped as `replay` or `too_old` while its session can still be read, and as `unknown_index` or `bad_tag` afterwards. Whatever the reason: one counted drop, nothing done, nothing transmitted.
- **Control messages** (content type `0x01`, R-SEC2) carry no rights here: neither side is an `admin` or an `operator` of the other, so removal and signing-key messages are refused by the existing role checks. The phone-link messages of §4 are application packets (`0x00`).
- **Settings** (not wire changes): keepalive timer off; rekey once an hour or at 2³² packets, reject after 90 minutes.
- **Flash writes.** Each handshake costs the radio one or two small writes (the timestamps). There are at least 24 a day from rekeys, plus one per reconnect, and phones drop BLE connections often. The firmware card must count writes per day on real phones and check the number against the flash part's endurance (open question 8).
- **Framing.** On BLE each link packet travels as a 2-byte big-endian length and the bytes, as R-SEC1's stream framing, split across writes and notifications as the transport needs. On USB, link packets are UDP datagrams on the USB network link, as `oasa-link` carries them. The phone link's MTU must fit the largest air packet plus the `SEND` or `RECEIVED` fields plus the link's 22 bytes; a longer packet closes the connection.
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
| `0x09` | `STATUS` | radio → phone | Battery, firmware version, counters, whether it is committed (§2.2), whether a pairing window is open |
| `0x0A` | `UPDATE_*` | phone → radio | Firmware update pieces (the update standard: signed, checked on the radio, trial boot) |
| `0x0B` | `PAIR_OPEN` | phone → radio | `[32 bytes]`: a fresh one-time secret; opens a replace window keyed with it (§2.7). Refused while a window is open. The radio answers with `STATUS` |
| other | | | Dropped and counted |

What the radio refuses **even from its own phone**:

- Transmitting outside the frequency, power and airtime limits built into its firmware. The phone can lower them, never raise them.
- Firmware that is not signed by the release key, **or that is older than what it runs**, by any path (the phone link, USB, or a Bluetooth update mode). The phone only carries the file.
- Reading out any of the radio's private keys or its pairing secret. There is no message for either.
- Resetting. That is the pinhole only. (The phone can open a replace window with `PAIR_OPEN`, and nothing else about pairing.)

So a phone with a hostile app can waste its own radio's battery and airtime inside the limits, and hand the radio to another phone, and cannot turn the radio into something else.

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

**The hold store.** At most 64 packets or 16 kB, each kept at most 24 hours, **in memory only**: a radio that loses power, is reset or is moved to a new phone holds nothing (open question 2). The sender's phone, not the radio, is responsible for retrying.

**Anyone can make a packet that matches a filter** (indexes and group ids are public, and the handshake filter needs only the public key), so the store is built to lose as little as possible to a flood:

- Each kind of filter has its own share of the store, and each index and each group its own share within that, so junk for one conversation cannot push out another's packets.
- Within a share the oldest goes first.
- Wakes are limited (at most one every 10 s, then backing off while the phone fetches nothing it could open; the phone tells the radio with `FETCH_ACK` which packets were real).

A flood can still push real packets out of the one share it aims at, and costs the phone battery. That is the same person who could jam the channel.

**Waking the phone.** The wake is a bare BLE notification with nothing in it and no protection. The app then handshakes, fetches, opens the packets with its own keys, and **only then** notifies or rings. A forged wake therefore costs the phone a little battery and shows nothing.

## 6. What an attacker gets

**Someone who finds or steals the radio**, and can read its memory (assume they can: the chip's readout protection has been bypassed in public before). This includes someone who had it for a while and gave it back, and a previous owner:

| Gets | Does not get |
|---|---|
| The radio's link key, while the radio is paired. With it they can pose as that radio to the owner's phone, and (a property of `IK`, link §6) as the phone to that radio, without a window and without a sign; and push a far-future handshake timestamp to the owner's phone | Any message key, past or future |
| The pairing key and secret (they also have the label). With these, after the owner's next reset: §2.9's race, and sitting in the middle of the next BLE pairing (below) | Any way into a link made after a reset (the link key is new each pairing), except by sitting in the middle of the next BLE pairing |
| From recordings: with the pairing key, each recorded pairing message 1 gives the phone's name and radio-link public key; with the link key, recorded link handshakes give the phone's timestamps. Message 2 of a pairing, and so the link key it carries, stays hidden (it needs an ephemeral key) | The content of any packet, held or recorded |
| The phone's radio-link public key (used nowhere else, and new at each pairing) | The messaging public key itself |
| The wake filters. The handshake filter confirms whose radio this is to anyone who already knows the owner's messaging public key. The indexes and groups, with recordings of the air, link past traffic to this radio | A way to send as the owner, or to read what the owner receives next |
| Held packets, still sealed, if it stayed powered | |
| Radio settings, counters, firmware version | |
| Without reading memory: a pinhole reset and a pairing to their own phone (§2.9), which gives them a radio and erases the above | |

What the owner does: remove the radio in the app (the phone deletes its radio-link key and the radio's link key, so a stolen link key is worthless) and pair a new one. Nothing has to be re-keyed with other people. **A radio that comes back** after being out of the owner's hands, even briefly ("evil maid"), may have had its keys copied: the link key gives silent access until the next reset, so the owner resets it before using it again. Its pairing key stays copied, so it is re-paired by cable where the phone has a cable path, or otherwise treated as not clean: retired, or given a new pairing key, secret and label by whoever can print one (open question 9).

**Residual: the middle of the next BLE pairing.** Someone who holds this radio's pairing private key and label secret (on a product unit: they read its memory past the debug lock, or had it before it was locked) and who is in Bluetooth range, or relaying from there, when the radio is next paired over BLE can sit in the middle of that pairing. They are then the radio's real paired phone for as long as they keep relaying: they can drive it within its firmware limits, fetch and acknowledge held packets so the owner never gets them, change filters and settings, open replace windows, drop or delay traffic in either direction, and push handshake timestamps to both sides. They never get message content or a message key. The one sign is that the radio stops answering the owner's phone when they stop relaying. A pairing by cable, where the phone has a cable path, and a replace cannot be put in the middle. This residual is inherent to a fixed printed label on a radio with no display and no button (§2.9).

**A stranger within Bluetooth or radio range:**

| Can | Cannot |
|---|---|
| See that a radio of this kind is near, and possibly follow it by its Bluetooth address, and in a window by its hint (§7) | Complete a link handshake, so cannot send, fetch, change settings or update firmware |
| Open connections; each is closed after 5 s outside a window | Hold a connection slot against the owner's phone |
| Send a forged wake to the phone if they copy the radio's address | Make the phone show or ring anything |
| Record the phone link and any pairing | Read either without one of the radio's private keys, or replay any part of it to effect |
| With the label's secret, pair an unpaired radio during a USB window, first (§2.9) | Do it unnoticed, take a radio that stays paired, race a replace window, or beat a phone that took the window by cable |
| Flood the air with packets that match a filter: push real packets out of that share of the hold store, and wake the phone up to the wake limit | Fill the whole store, or make the phone show anything |
| Jam Bluetooth or the radio channel | |

**A borrowed cable, charger or computer:**

| Can | Cannot |
|---|---|
| Charge the radio | Anything a Bluetooth stranger cannot on a paired radio: USB carries the same link and gets no reply without the paired key, and opens no window |
| On an unpaired radio: open a USB window (at most two, then one each half hour), and with the label's secret, pair it over USB, which also takes the window from BLE (§2.9) | Read the secret from the radio: no message, port or serial output gives it on a product unit |
| See the radio's USB name and firmware version (the USB serial number is the same on every unit, §7) | Load firmware that is unsigned or older: the bootloader refuses both |
| | Read memory through the debug port: it is locked on production radios |

The last three rows are **requirements on the product**, and they are **not true of the development boards** (RAK4631 and similar), whose bootloader takes any firmware over USB, whose debug port is open, and whose firmware prints the label payload on the serial port (§2.2). Development boards are for the bench only.

**Not covered:** a phone that is itself taken over. The phone holds every key; this link cannot help there.

## 7. Known limits and privacy (v0)

- **The label secret is printed and never changes.** Anyone who has seen the label can race any USB window the radio opens, for its whole life, and someone who also read the radio's memory can sit in the middle of a BLE pairing while in range (§2.9). The window rules, one phone, the confirmation and a cable path where there is one limit it; nothing removes it short of a new label.
- **Detection, not prevention, on most phones.** Where the phone has no cable path to the radio (possibly every iPhone; unverified everywhere, open question 12), a stranger with the label who is in range can win a USB window; the owner is told, not protected.
- **The light shows "completed" for any phone that completes first.** Only the app tells the owner whether that phone is theirs. Nothing depends on the light (§2.6).
- **Following a radio by Bluetooth.** The radio advertises a service id so the phone's system can find it and wake the app. That marks it as one of these radios. The radio uses a static random Bluetooth address and picks a new one at every pinhole reset and every replace, so the address does not carry across owners. Whether it can also rotate in use (private addresses, which need Bluetooth bonding) without breaking wake on iPhone and Android is decided by the phone tests (open question 3).
- **The pairing hint is a lifelong tag.** During a window, and only then, the radio advertises that a window is open and a 4-byte hint: the first 4 bytes of the fingerprint hash (§10), so an app in a room full of radios finds the one on its code. The hint is the start of the fingerprint printed on the label and kept in factory records, and it is the same in every window. So anyone who has seen the label's fingerprint, or saw the radio in one window, can recognise it in every later window, across owners, and tie it to that window's Bluetooth address. Outside windows nothing advertises it. A hint that differs per window would need a new construction (open question 13).
- **Other identifiers.** The USB serial number string is the same fixed value on every unit (no chip id). The radio's name from `SETTINGS` is never in advertising or the Bluetooth device name, and is readable only inside a session.
- **The label trusts the factory.** Someone who can print a label can pass off a swapped radio, or stick another radio's label on this one. So can someone who had the radio open on a bench. A factory that kept the secrets could race any unpaired radio's window.
- **No label, no pairing.** A radio whose label is lost or unreadable cannot be paired (open question 1).
- **Handshakes on the air can be spotted** by anyone who knows the receiver's public key (`mac1`, link §2). That is the base link's property; the handshake filter uses it and adds nothing to it on the air.
- **Timing.** The radio cannot read packets, but anyone watching the air or the phone link sees when packets flow and how large they are. Padding is not in v0, as on the link.
- **One phone.** No second phone, no shared radio (§2.7, open question 4).
- **`snow` does not wipe its state** (as R-SEC1 §6); on the radio, session keys sit in memory until power-off, and the pairing secret is in `snow`'s handshake state until it is dropped.

## 8. What the suite must cover

### Simulated suite

Suite `l1-phone-link` in oasa-lab (a later card), with a simulated radio, a simulated phone app, a simulated transport, simulated USB power and enumeration events, and a simulated pinhole. The first two are the known-bad cases the checker must see. "Refused" and "dropped" mean: one counted drop, no reply where the link gives none, nothing done, nothing transmitted.

1. **An unpaired phone is refused:** a phone whose key the radio does not hold sends a handshake and commands, with and without knowing the radio's link public key.
2. **A replayed command is dropped:** a recorded `SEND` played again in the same session, during the previous session's grace, after a rekey and after a reconnect; the radio transmits once.
3. Codes: a label, a replace code and a drone code each refused as either of the other two, and each refused with the wrong prefix, version, length or checksum, a small-order key, one changed character, or a last character that differs only in its padding bits.
4. The wrong secret gets no reply, in and out of a window: the label secret in a replace window, a replace secret in a USB window or after its window closed, a random secret anywhere.
5. A small-order phone key in a message 1 with the right secret: no reply, nothing saved, the window stays open.
6. The race: a second phone with the label completes first. The window closes; the owner's phone is not saved, gets no link handshake and reports "not confirmed".
7. No hold: several phones prove message 1 and each gets a message 2; the first valid message 3 completes and the others get no reply; a phone that never sends message 3 blocks nobody. A phone whose message 3 is dropped while the window is still open pairs again and does not report "not confirmed"; one whose message 3 is dropped and the window then closes on another phone's completion reports it.
8. Slots and work: with every slot holding a proved attempt, a new connection with no secret is refused and never ends an attempt that has its message 2; on a full transport a new connection replaces only an unproved attempt; BLE and USB slots are counted separately; a second message 1 on one connection, or a failed one, closes it; a window spent that way does not count toward the rate limit.
9. Replays: a recorded message 1 played again in the same window gets no reply; one from an earlier window, or one forgotten from a full record, gets a message 2 and never completes. Nothing is saved.
10. Window rules: no window on battery start, or on USB power when paired; a window on unpaired USB power only after 10 s absent and 2 s present; closed after 2 minutes; the first completion closes it; a pairing message outside a window gets no reply.
11. USB edges: power toggled faster than the debounce opens nothing; an edge during a window restarts nothing (timer, BLE rules, record of message 1s); a pulsing power source opens two windows, then one each 30 minutes, each only on a new edge; a radio left on power opens no window by itself after the limit; a reset lifts the limit and its window counts as the first of a new two.
12. USB first: with no host, BLE refused until 10 s; a host enumerated by then keeps BLE shut until 20 s, and for the whole window once a proving USB message 1 arrives; a host that enumerates and sends nothing, or is unplugged, lets BLE open at 20 s; a proving USB message 1 ends every BLE attempt that has not completed, including one that has its message 2; a BLE message 3 that arrived before it still completes; a USB and a BLE message 3 arriving together save exactly one phone.
13. Replace: `PAIR_OPEN` opens a window keyed with its secret only; an all-zero secret is refused; the old phone works until a completion; at completion the new phone is saved and the old removed, which is refused at once, and held packets (including any that arrived after the old phone's `FETCH_ACK`), filters, owner settings and timestamps are gone; with no completion nothing changes and the secret is wiped; an old phone that dies during the window leaves the radio paired to it until a reset; `PAIR_OPEN` from anyone else, during a window, or any unauthenticated request for a window, is refused.
14. Pinhole reset: erases the phone, the link key, every timestamp, the filters, the held packets and owner settings; keeps the pairing key and secret; ends a live session at once (the old phone is refused); closes a replace window; with USB present opens a USB window 2 s later; a reset between closing a window and writing the new peer leaves the radio unpaired.
15. Power lost at each step of a first pairing, a replace and a reset (§2.8): at boot a marker makes the radio finish the erase; it comes back paired with the new phone, paired with the old phone with its filters and settings gone, or unpaired and empty, never with a new phone and the old owner's state; a new phone that was not saved reports "not confirmed".
16. Link keys: the link uses the link key from message 2, not the pairing key; a link handshake to the pairing key is dropped; after a reset or a replace, handshakes to the old link key and recorded old handshakes from either side are dropped; a small-order link key in message 2 is refused by the phone; two pairings give two different link keys and two different phone radio-link keys; the link key of an attempt that times out, is closed, is pre-empted or whose window closes is never written to flash.
17. A changed bit in any command: dropped.
18. Idle, slow and flooding connections, as the simulation models them, do not keep the paired phone out, and do not keep a phone with the right code out of an open window.
19. The radio starts a handshake (stale rule, late rekey); a recorded handshake from either side replayed after a power cycle of the radio is dropped.
20. A phone that lost its saved timestamp and has an earlier clock: refused until a pinhole reset and a new pairing, then accepted.
21. Held packets: delivered once after a handshake, deleted only on `FETCH_ACK`; the limits hold; nothing survives a reset, a replace or a power cycle.
22. A flood of packets matching one filter: packets held for other filters survive; wakes stay under the limit.
23. A forged wake: the phone shows nothing.
24. Control messages (`0x01`) from either side change nothing.
25. A `SETTINGS` above the built-in limits is refused; an unsigned update and an older signed update are refused.
26. Captures of the phone link contain none of the test plaintext.
27. With no phone connected the radio's transmissions are relays only.
28. The simulated app refuses a radio whose `STATUS` says uncommitted, unless it is set up as a development board, and then warns.

### Checks that need real hardware

The simulation cannot show these; the firmware and app cards run them on real radios and phones.

1. USB first on real phones: time from USB power to enumeration and to a message 1 on USB, on Android and iPhone; whether the app can reach the CDC-NCM pairing port at all (open question 12).
2. Idle, slow and flooding BLE connections against the nRF52840's real connection slots and timing (case 18 with real radios), which fixes `BLE_PAIRING_SLOTS` and `USB_PAIRING_SLOTS`.
3. Real chargers, power banks, flickering cables, car ports, monitor hubs and phone power-role swaps against the debounce, the enumeration rule and the rate limit; and whether power banks switch off at a radio's low charge current.
4. Product units: the debug port is locked; no output (serial, `STATUS`, logs, any message) contains the pairing secret or a private key; the jig's end-of-line test shows the factory output closed after commit.
5. False "not confirmed" alarms on real phones (P0 tests), with the app backgrounded, the screen locked and BLE dropping.
6. The label: the version 7 QR at 0.34 mm modules scans on a range of phone cameras, new and worn.
7. Erase: dump the whole flash after a reset and after a replace (each also torn by power loss at every step) and find none of the old peer key, link key, timestamps, wake filters or settings.
8. Work per attempt: handshake time on the radio's chip, and the owner's pairing time, under a flood of wrong message 1s on every slot for a whole window.

## 9. Open questions

1. A radio whose label is lost: a second copy on a card in the box (one more thing to photograph, and it travels with the radio when sold), a re-label service (open question 9), or nothing? And whether the text form fits if the case gives only 20 × 20 mm (§2.1).
2. Hold store in memory only (a dead battery loses waiting messages; a found radio holds less), or in flash (the reverse)? This draft says memory only. How long, and how many?
3. Bluetooth bonding for private addresses: does wake still work on both platforms? (P0 and P4 phone tests.) v0 uses a static random address, new at each reset and replace.
4. A second phone for one radio, or one phone with two radios. A second phone would need its own answer to §2.7's first point.
5. A theft lock, so a radio reset with the pinhole cannot be paired by a finder. It would need a secret the owner keeps, and a way back when they lose it.
6. An NFC tag in place of scanning the label (the chip supports it; it needs an antenna in the case). A tag readable through the packaging or a pocket would break §2.2, so it could hold the payload only when the radio enables it.
7. Sealed packets the phone leaves with the radio to send later (a position while the phone is dead). Not in v0: the counters need care.
8. The rekey interval and reconnect rate against flash wear, once the flash part is chosen. A link setting that stops the radio from ever starting a handshake would halve the writes; it is a code change to the link.
9. Giving a returned or second-hand radio a new pairing key, a new secret and a new label: who may do it, and how the old label is made void. Until then a memory read before a sale leaves the middle-of-pairing case of §2.9.
10. Where the label goes: on the outside of the case (easy to scan, easy to photograph), or under a cover or seal that shows it was opened. The same choice decides how easy §2.9's "brief access" is.
11. Replacing a phone: should the radio tell the old phone the new phone's name and fingerprint before removing it, so an owner holding both sees a stranger's completion at once rather than at the new phone's timeout?
12. Cable pairing per platform: can an app reach a CDC-NCM USB network adapter on Android (which versions) and on iPhone, or does iPhone need Apple's accessory programme (MFi)? Is there another race-free path where there is no cable? Until this is answered, the spec assumes no cable path anywhere.
13. The pairing hint (§7): keep the static hint, advertise a per-window value that only someone with the pairing key can match (a new use of BLAKE2s, for the owner to decide under "no new crypto"), or no hint, with the app trying each radio in a window?
14. A phone camera reading the light, to close the middle of a BLE pairing (§2.9). After completion the radio would blink out a long value from its pairing handshake hash (at least 128 bits, with error detection), and the app would compare it with its own: a party in the middle runs two different handshakes and cannot make the hashes match. It compares two existing Noise handshake hashes, as channel binding does, so it needs no new cryptography, but it is a new feature (optical reading in the app, a blink encoder in the firmware), takes seconds of holding the camera on the light, would be the first security property to rest on the light (against §2.6), and whether a phone camera reads one status light reliably is unverified. **A short code the user compares by eye is not safe here:** the middle chooses one ephemeral key after seeing the other side's, so it can search for a match to a short value; making a short code safe needs a commitment step, a new construction. Not adopted in v0; for the owner to decide.

## 10. Implementation notes and what is not covered

Constants and reuse, for the code card:

| What | Value |
|---|---|
| Noise pattern | `PAIRING_NOISE` (`Noise_IKpsk1_25519_ChaChaPoly_BLAKE2s`), psk position 1, unchanged |
| Pairing prologue | a new constant beside `PAIRING_PROLOGUE`: `"OASA-SEC v0 phone pairing"` |
| Label | prefix `OASAR1-`, version byte `1`, 69 bytes, checksum label `"OASA-SEC v0 label checksum"`, 118 characters |
| Replace code | prefix `OASAT1-`, version byte `1`, 69 bytes, checksum label `"OASA-SEC v0 replace checksum"`, 118 characters |
| QR | version 7, level Q, module at least 0.34 mm, 18 × 18 mm with quiet zone; label 20 × 27 mm |
| Pairing message 2 payload | `[0x01, len, name][0x06, link public key: 32]` |
| Pairing message 3 | `[0x03]`, R-SEC1's confirm byte, in transport mode |
| `PAIR_OPEN` body | `[0x0B][secret: 32]` |
| Advertised hint during a window | first 4 bytes of the fingerprint hash (BLAKE2s-256(`"OASA-SEC v0 fingerprint"` ‖ pairing public key), R-SEC1 §1) |
| Window | 120 s |
| USB power debounce | absent 10 s, then present 2 s |
| USB window rate limit | after 2 windows in a row with no pairing, 30 minutes from the last close and then a new debounced edge (or a reset) |
| BLE in a USB window | from 10 s after it opens if no host has enumerated; from 20 s if a host enumerated but no proving USB message 1 arrived |
| Pairing slots | `BLE_PAIRING_SLOTS`, `USB_PAIRING_SLOTS`, counted separately; values fixed by the firmware card (real-hardware check 2); a proved attempt is never displaced |
| Memory per attempt | one Noise handshake state, one link private key, message buffers: under 1 kB |
| Attempt timers | message 1 within 3 s of connecting; message 3 within 6 s of message 2 |
| Record of message 1 ephemerals | last 16 per window |
| App confirmation | "not confirmed yet" at 20 s, "did not confirm" at 60 s of foreground trying |
| Pinhole | held 5 s; a USB window 2 s after a reset with USB power present |
| Unfinished link connection outside a window | closed after 5 s |

- The label and replace code are not `PairingCode`, but share its rules: the secret is wiped on drop and never in `Debug`, and decoding uses `BASE32_NOPAD`, which refuses non-zero padding bits (`code.rs`).
- R-SEC1's record of message 1 ephemerals (`oasa-pair`'s `seen` set) is a `HashSet` in a threaded TCP program and cannot run on the radio. It is reimplemented on the radio as a fixed array of 16 entries per window, oldest forgotten first.
- The phone pairing needs its own pair of functions, not `pair_as_drone_checked`: that one saves the peer as `operator` and exchanges signing keys. Here both sides save `peer`, message 2 carries the link key, and the only message after the handshake is the phone's confirm. They need their own message size limits: `pairing.rs`'s `MAX_MSG2` fits a hello only, and the new message 2 carries 34 bytes more. The tag `0x06` does not collide with R-SEC1's tags (`0x01` to `0x05`). Like `pair_as_drone_checked`, the radio side calls `check_peer_public` on the phone's static key as soon as it is known; the phone calls it on the link key from message 2. `store` also refuses a small-order key on save, so this is defence in depth.
- The radio makes the link key with the same X25519 key generation as `Identity::generate`, from its hardware random source. Nothing beyond existing primitives is needed: one more key pair, one more payload field.
- Saved timestamps are per peer (`FileTimestampStore::new(dir, peer_public)`, with `reset`); a replace or a reset deletes the old phone's.
- The radio closes the window in memory before it writes the new peer, so a second completion cannot slip in during the write. The trust change (new peer and link key in, old peer out) is one atomic write, as `store` already writes atomically; a power loss during it leaves either the old state or the new one.

Not covered: the app's screens, USB class details beyond CDC-NCM, the Bluetooth service layout, the relay rules, voice timing, the production jig and its commit step, and the code. Review by a person is required before this moves past Draft.

## 11. Review findings after this revision

The [review notes](security-review-t-msg1-phone-link.md) hold three reviews: the first of v0.1, the second (R2) of v0.2, the third (R3) of the v0.3 changes.

**First review (v0.1)**

| ID | v0.1 finding | Now |
|---|---|---|
| H1 | Swap during the press wait | **Gone** with the press and the pending phone. What remains is a plain race to message 3: whoever sends a valid one first completes, and the owner's app reports a loss (§2.4, §2.9). A phone that took the window by cable cannot lose it (§2.5), where a cable path exists |
| H2 | No confirmation reached the phone | **Kept**: the first completed link handshake is the confirmation (§2.4) |
| M1 | The radio also starts handshakes | Unchanged (§3) |
| M2 | Flash wear | Unchanged (§3) |
| M3 | Stale-timestamp lock, `max_future` | The way out is a pinhole reset and a new pairing, which makes new keys and fresh timestamps (§3) |
| M4 | The handshake filter ties the radio to its owner | Unchanged; a reset or a replace erases it (§2.7, §2.8) |
| M5 | Hold store flood | Unchanged (§5) |
| M6 | The code readable on BLE during a USB pairing | **Gone**: the radio never sends a secret. USB first (§2.5) keeps a cable pairing race-free where a cable path exists |
| M7 | Roles and control messages | Unchanged (§3) |
| L1 | Drop reason names | Unchanged |
| L2 | Firmware rollback | Unchanged (§4) |
| L3 | A returned radio stays a risk | Narrower for the link (new link key at each pairing), wider for pairing: the label secret and pairing key are kept for good (§2.9, §6) |
| L4 | `FETCH_ACK`, MTU, confirm wait tied to the window | The first two unchanged; the confirm wait is gone |
| L5 | The light shows "press" for a stranger | **Gone** with the press. The light shows "completed" for anyone, and nothing depends on it (§2.6) |

**Second review (v0.2)**

| ID | Finding | Change in v0.3 |
|---|---|---|
| R2-H1 | USB first did not hold | BLE opens on observed enumeration, not a timer; a USB message 1 pre-empts BLE attempts; "connecting" on USB defined (§2.4, §2.5); cases 12, real-hardware check 1 |
| R2-M1 | Cable pairing may not exist on iPhone | Not promised anywhere; app advice conditional; no property rests on it (§2.4, §2.5, §7); open question 12 |
| R2-M2 | A replace handed over the owner's held state | A replace erases what a reset erases; the app fetches first (§2.7); case 13 |
| R2-M3 | Replace windows took the label secret | A one-time secret in `PAIR_OPEN`, shown as an `OASAT1-` code (§2.1, §2.7, §4); case 4, 13 |
| R2-M4 | USB edges undefined | Debounce, rate limit, edges inside a window change nothing (§2.3); case 11, real-hardware check 3 |
| R2-M5 | Pinhole interactions undefined | §2.8: ends everything, reset beats a pending write; atomic replace (§2.4, §10); cases 14, 15. Departs from the suggestion (a window only on the next USB edge): a reset on USB power opens a window 2 s later, because the reset already needs the radio in hand |
| R2-M6 | A copied device key gave silent access | Per-pairing link key in message 2 (§1, §2.4, §3); what remains (middle of a BLE pairing) in §2.9, §6; case 16 |
| R2-L1 | QR did not fit | Version 7 at Q, measured; module 0.34 mm; label 20 × 27 mm (§2.1, §10) |
| R2-L2 | Hint is a lifelong tag | Kept static and window-only, the limit stated (§7); open question 13 |
| R2-L3 | Other identifiers | Fixed USB serial, name never advertised, new address at reset and replace (§7); open question 3 |
| R2-L4 | §2.8's list contradicted itself | Rewritten (§2.9); label holders now only race USB windows |
| R2-L5 | The hold was not needed | Dropped (§2.4); case 7 |
| R2-L6 | `seen` "reused as is" | Reimplemented, 16 entries per window (§2.4, §10) |
| R2-L7 | No failure path at the jig | Scrap or re-key before commit; end-of-line test; `STATUS` reports commit (§2.2, §4); case 28, real-hardware check 4 |
| R2-L8 | More label leaks | Photo library, clipboard, support photos (§2.1, §2.9) |
| R2-L9 | Radio-link key lifetime | New per pairing, device only, deleted on removal (§1, §2.4, §3); case 16 |
| R2-L10 | False "not confirmed" alarms | Foreground-only count, "not confirmed yet" at 20 s (§2.4); real-hardware check 5 |
| R2-L11 | §6 overstated what recordings hide | §6 table row added |
| R2-L12 | Suite cases | Split into simulated cases and real-hardware checks; missing cases added (§8) |
| R2-I1 | Message 3 needs the static key too | §2.4 |
| R2-I2 | Reason for storing the secret | §2.2 |
| R2-I3 | Two version fields | §2.1 |
| R2-I4 | `check_peer_public` on the phone key | §10 |

**Third review (v0.3)**

| ID | Finding | Change in v0.4 |
|---|---|---|
| R3-M1 | The middle of a BLE pairing was understated | What it needs, gives and lasts, its one sign, and that it is inherent (§2.9, §6); three over-claims qualified (changes list, §2.9 table, §6); "radio near but not answering" in the app (§3); second-hand radios by cable or treated as not clean (§2.9, §6). A camera reading the light is open question 14, not adopted |
| R3-M2 | A connection with no secret could end a proved attempt | A proved attempt is never displaced; slots per transport as parameters; windows spent that way do not count toward the rate limit (§2.3, §2.4, §10); case 8 |
| R3-M3 | "Erase" undefined in flash | No readable copy after reset or replace: page erase or forced clean-up first (§2.8); real-hardware check 7 |
| R3-L1 | Attempt link key lifetime | Memory only, wiped when the attempt ends; only the completing key is written (§2.4); case 16 |
| R3-L2 | Reset and replace torn by power loss | Marker, erase, trust change, clear; at boot a marker finishes the erase (§2.8); case 15 |
| R3-L3 | Rate limit wording | A new edge is needed after the 30 minutes; the reset's window starts a new two (§2.3); case 11 |
| R3-L4 | Ordinary users hit the window rules | BLE opens at 20 s if a host enumerated but sent no proving message 1 (§2.5); distinct light states (§2.6); first-pairing advice (§2.5); real-hardware check 3 |
| R3-L5 | False stranger reports | The app pairs again while the window is still advertised (§2.4); §2.7's sentence fixed; case 7 |
| R3-L6 | Replace details | Late packets, a dead old phone, the secret in memory only, the code hidden until tapped, all-zero refused (§2.7); case 13 |
| R3-L7 | Work per attempt | One message 1 per connection, a failed one closes it, attempts capped at the slots, under 1 kB each (§2.4, §10); case 8, real-hardware check 8 |
| R3-I1 | The 16-entry record | One sentence (§2.4) |
| R3-I2 | More changes from R-SEC1 than "one" | Listed (§2.4) |
| R3-I3 | Message sizes | §10 |
| R3-I4 | `mac1` key holders; R2-M5 departure | §3; the R2-M5 row above |
