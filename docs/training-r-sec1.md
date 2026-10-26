# Training: device identity, keys and pairing (R-SEC1)

A hands-on course for people who will pair, run or review OASA drones. About 1 to 2 hours. You need a Linux laptop with Rust (1.89 or newer), `git` and Python 3. No drone, no radio.

You will be able to: explain what a fingerprint, a pairing code and a signing key each do; show that a stranger cannot pair and that unsigned commands are ignored; and take a lost ground station out of a fleet.

> **Prototype.** Not independently reviewed. Do not fly with it. Read the [release record](release-r-sec1.md) for what has and has not been checked.

## 1. Concepts (20 minutes)

**Identity.** Every device makes its own X25519 key pair, on the device. The private key never leaves it (`identity.key`, mode 600). The public key is the device's name to the others. Nobody copies keys between devices or ships them in images: one shared key means one stolen device breaks all of them (Meshtastic had this bug in 2024).

**Fingerprint.** A public key is 64 hex characters, too long to compare. The fingerprint is a short hash of it, like `CYGJ-NYWB-BHFH-4GEA`. People compare fingerprints out loud or on a label. If two fingerprints match, the keys match.

**Pairing code.** A drone in pairing mode makes a one-time code: its public key plus a fresh random secret (shown as a QR code and as text `OASA1-...`). It is used once, and thrown away after one pairing or after the window (5 minutes). Anyone who sees it can pair once, so it is shown only to the person at the drone.

**Noise `IKpsk1`.** The handshake is the Noise Protocol Framework pattern `IKpsk1`, run by the `snow` library (we write no crypto of our own).
- **I:** the ground station sends its identity, encrypted. **K:** it already knows the drone's public key (from the code). Both sides prove who they are. Neither can be impersonated without its private key.
- **psk:** the code's secret is a pre-shared key mixed into the handshake.
- **Why psk1 and not psk2:** the number is where the secret goes in. With psk1 it is mixed into the very first message, so the drone can check it **before it sends anything back**. A stranger who knows only the drone's public key (which is in the QR code, and not secret) gets silence. An earlier draft used psk2, where the drone answered first, so anyone who knew the public key could make it reply. A test caught that.

**Signing runs only inside encryption.** MAVLink 2 signing proves who sent a message, but hides nothing, and a signing key sent in the clear is no key at all. So the signing key travels only inside the encrypted pairing channel, and day-to-day traffic is the encrypted link first; signing is a second layer the autopilot itself checks. Signing alone is never the link.

**Roles.** Pairing makes the ground station an `operator` on the drone and the drone a `peer` on the ground station. `admin` is set by hand. Roles change only on the device, never by a message.

**Removal.** `remove` puts a key on a permanent list; it can no longer pair or link. The autopilot still has the old signing key until the drone's `signer` rotates it.

## 2. Lab setup (15 minutes)

```sh
git clone https://github.com/joinoasa/oasa-sec.git && cd oasa-sec
cargo build --locked --bins --examples
REPO=$PWD
export PATH="$REPO/target/debug:$PATH"
python3 -m venv /tmp/oasa-venv && /tmp/oasa-venv/bin/pip install pymavlink
mkdir -p /tmp/oasa-lab && cd /tmp/oasa-lab
"$REPO"/target/debug/examples/fake_autopilot udpin:127.0.0.1:14540 > ap.log 2>&1 &
oasa-pair init --dir drone --name drone-1
oasa-pair init --dir gcs --name gcs-1
oasa-pair drone --dir drone --name drone-1 --listen 127.0.0.1:7400 \
  --autopilot udpout:127.0.0.1:14540 > drone.log 2>&1 &
sleep 2
```

`fake_autopilot` is a stand-in autopilot with PX4's and ArduPilot's signing rules. `drone` is now in pairing mode, with its output in `drone.log`.

Look at what the drone printed:

```sh
head -3 drone.log; grep -o 'OASA1-[A-Z2-7]*' drone.log | tr -d '\n' | wc -c
```

Expected: `Drone drone-1 (XXXX-XXXX-XXXX-XXXX) is in pairing mode for 300s.` and then `117`, the length of the code.

> Question for yourself: what in that code is secret, and what is not?
> (The drone's public key is not secret. The last random part is.)

## 3. Lab: a stranger tries to pair (15 minutes)

The attacker knows the drone's public key, because it is in the code. Suppose they photographed the QR, and changed the secret. This script builds such a code:

```sh
CODE=$(grep -o 'OASA1-[A-Z2-7]*' drone.log)
FAKE=$(python3 - "$CODE" <<'PY'
import base64, os, sys, hashlib
t = sys.argv[1][6:]
body = bytearray(base64.b32decode(t + "=" * (-len(t) % 8)))
body[33:65] = os.urandom(32)
body[65:] = hashlib.blake2s(b"OASA-SEC v0 code checksum" + bytes(body[:65])).digest()[:4]
print("OASA1-" + base64.b32encode(bytes(body)).decode().rstrip("="))
PY
)
oasa-pair init --dir attacker > /dev/null
echo "$FAKE" | oasa-pair ground --dir attacker --name evil --connect 127.0.0.1:7400
tail -2 drone.log
```

Expected: the attacker gets `error: I/O error: failed to fill whole buffer`: the drone said **nothing**. The drone's log ends with `Pairing attempt failed: encryption or authentication failed: decrypt error`. The attack failed and the drone is **still in pairing mode**, because a lockout would let a stranger shut pairing down.

## 4. Lab: wrong code, code on the command line (10 minutes)

```sh
echo OASA1-AAAA | oasa-pair ground --dir gcs --name gcs-1 --connect 127.0.0.1:7400
oasa-pair ground --dir gcs --name gcs-1 --connect 127.0.0.1:7400 --code "$CODE"
echo "$CODE" | oasa-pair ground --dir gcs --name gcs-1 --connect 127.0.0.1:7400 --code - \
  --expect-drone AAAA-BBBB-CCCC-DDDD
```

Expected, one line each:
1. `error: bad pairing code: wrong length` (a mistyped code is caught before any network traffic).
2. `error: don't put the pairing code on the command line (other users can see it); ...` (the process list and shell history would show it).
3. `error: code is for drone XXXX-..., not AAAA-BBBB-CCCC-DDDD; refusing to pair` (a swapped QR is caught if you compare to the label).

## 5. Lab: pair for real, then send commands (20 minutes)

```sh
FP=$(oasa-pair show --dir drone | sed -E 's/.*"fingerprint":"([^"]+)".*/\1/')
echo "$CODE" | oasa-pair ground --dir gcs --name gcs-1 --connect 127.0.0.1:7400 --code - --expect-drone "$FP"
sleep 1; tail -2 drone.log
oasa-pair peers --dir drone
oasa-pair command --dir gcs --to udpout:127.0.0.1:14540
ls -l gcs gcs/signing-keys
```

Expected: `Paired with drone drone-1 (...) as peer; made a new signing key.` The drone log says the autopilot `accepted the new key (checked with a signed command)` and `Paired with ground station gcs-1 (...) as operator`. `peers` lists `gcs-1` as `operator`. The command prints `Signed acknowledgment received from 1:1: MAV_CMD_REQUEST_MESSAGE accepted.` Every file is mode `-rw-------` and the folders `drwx------`.

Same code, again: the code is used up.

```sh
echo "$CODE" | oasa-pair ground --dir gcs --name gcs-1 --connect 127.0.0.1:7400 --code -
```

Expected: an error (`Connection refused`), because pairing mode ended after one pairing.

## 6. Lab: unsigned commands are ignored (10 minutes)

`pymavlink` is an independent MAVLink library. It is a good outsider: a program that is not us.

```sh
cd "$REPO"
PY=/tmp/oasa-venv/bin/python
$PY -I tests/interop/pymavlink_check.py client none 14540; echo "unsigned: exit=$?"
head -c 40 /dev/urandom > /tmp/oasa-lab/wrong.bin
$PY -I tests/interop/pymavlink_check.py client /tmp/oasa-lab/wrong.bin 14540; echo "wrong key: exit=$?"
$PY -I tests/interop/pymavlink_check.py client /tmp/oasa-lab/gcs/signing-keys/*.bin 14540; echo "right key: exit=$?"
cd /tmp/oasa-lab
```

Expected: `no ACK` / `exit=2` for unsigned and for the wrong key; `ACK 512 result 0` / `exit=0` for the right key. Exit 2 means "the autopilot did not answer".

> The script sets `MAVLINK20=1` for you. In your own pymavlink scripts set it too: pymavlink speaks MAVLink 1 by default, which cannot be signed.

## 7. Lab: lose a ground station (20 minutes)

Pair a second ground station, so there is one left to fly with:

```sh
oasa-pair init --dir gcs2 --name gcs-2
oasa-pair drone --dir drone --name drone-1 --listen 127.0.0.1:7400 \
  --autopilot udpout:127.0.0.1:14540 > drone2.log 2>&1 &
sleep 2
grep -o 'OASA1-[A-Z2-7]*' drone2.log | oasa-pair ground --dir gcs2 --name gcs-2 --connect 127.0.0.1:7400
sleep 1; oasa-pair peers --dir drone
```

Expected: `gcs-2 received the drone's signing key` (the same key, so `gcs-1` still works), and `peers` lists both operators.

Now `gcs-1` is "stolen". Remove it on the drone and rotate the key:

```sh
oasa-pair remove --dir drone gcs-1
oasa-pair removed --dir drone
oasa-pair command --dir gcs --to udpout:127.0.0.1:14540 --wait 3 | cut -c1-60   # still works: the autopilot has not changed yet
oasa-pair signer --dir drone --autopilot udpout:127.0.0.1:14540 > signer.log 2>&1 &
until grep -q rotation_done signer.log; do sleep 1; done; cat signer.log
oasa-pair command --dir gcs --to udpout:127.0.0.1:14540 --wait 3 | cut -c1-60
```

Expected: `Removed gcs-1 ... (operator).` and a note that the key stays the old one until the signer runs; `removed` lists it; the first command still works (the **window of danger**: rotate soon); the signer prints `rotation_started` and `rotation_done` (generation 1); the second command now fails with `error: no signed acknowledgment after 3s...`. The thief's copy of the key is dead.

The removed station cannot come back with the same identity:

```sh
oasa-pair drone --dir drone --name drone-1 --listen 127.0.0.1:7400 \
  --autopilot udpout:127.0.0.1:14540 > drone3.log 2>&1 &
sleep 2
grep -o 'OASA1-[A-Z2-7]*' drone3.log | oasa-pair ground --dir gcs --name gcs-1 --connect 127.0.0.1:7400
tail -1 drone3.log
```

Expected: the ground station fails, and the drone says `that device was removed here; a removed device must make a new identity and pair again`.

Last, `revoke`. It is `remove`, plus it adds the device to this device's removal log, which other devices that list it as `admin` pick up over the link:

```sh
oasa-pair revoke --dir gcs2 drone-1
```

Expected: `Removed drone-1 ... (peer).` and `Added to this device's removal log as entry 1 of log ...`.

Clean up:

```sh
kill $(jobs -p) 2>/dev/null; cd /tmp && rm -rf /tmp/oasa-lab
```

## 8. Self-check (10 minutes)

1. Why must each device make its own key?
2. The pairing code contains the drone's public key. Why is that not a leak?
3. What does psk1 let the drone do that psk2 would not?
4. A stranger sends a handshake with the wrong secret. What does the drone send back?
5. Why is the pairing code never accepted on the command line?
6. Why does signing run only inside encryption?
7. On ArduPilot, which serial port must the companion computer not use, and why?
8. You remove a stolen ground station on the drone. Is the drone safe yet? What else must happen?
9. A signed command to ArduPilot fails right after a reboot. Is something broken?
10. Name three things this prototype has not been tested on.

**Answers**

1. A shared or copied key means one stolen device breaks every device, and the others cannot tell which is which.
2. A public key is meant to be public. Without the secret part of the code nobody can complete the handshake.
3. With psk1 the secret is in the first message, so the drone can check it and stay silent for anyone without it. With psk2 it replied first.
4. Nothing. It logs the failed attempt and stays in pairing mode.
5. Other users on the machine can read it from the process list and shell history. Use a pipe or `--code-file`.
6. Signing only proves who sent a message; it hides nothing. Inside the encrypted channel an outsider cannot read or record the key, or the traffic.
7. SERIAL0 (usually USB). ArduPilot treats it as a trusted cable and accepts unsigned messages there, including a new signing key. Use SERIAL1 or higher and protect SERIAL0.
8. No. The autopilot still holds the old key. Run `oasa-pair signer` on the drone (when disarmed) to rotate it and make sure the remaining operators have received the new key over `oasa-link`.
9. No. ArduPilot refuses signed commands for up to about a minute after a reboot. `oasa-pair command` retries for 75 s.
10. Real hardware, an armed vehicle, key rotation through `oasa-pair` on a real autopilot, a human security review. (See the [release record](release-r-sec1.md).)

## 9. Where next

- [Pairing guide](guide-pairing.md): the same steps on real devices, and what each error means.
- [Pairing design](oasa-sec-v0-pairing.md), [rotation and removal](oasa-sec-v0-rotation.md), [the link](oasa-sec-v0-link.md).
- [SITL](sitl.md): run the checks against real PX4 and ArduPilot simulators (builds take 20+ minutes).
- Read `src/pairing.rs` and `tests/pair_cli.rs`. Try to break the pairing, then report it privately ([SECURITY.md](../SECURITY.md)).
