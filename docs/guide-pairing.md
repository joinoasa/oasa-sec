# Pairing guide: set up, pair, remove, rotate

How to give a drone and its ground stations their identities, pair them, and take a lost device out again. For the design see [pairing](oasa-sec-v0-pairing.md) and [roles and rotation](oasa-sec-v0-rotation.md).

> **Prototype.** Not independently reviewed. Do not fly with it. See [SECURITY.md](../SECURITY.md) and the [release record](release-r-sec1.md).

Every command here was checked against `oasa-pair --help`. Section 2 was run word for word on a laptop with the stand-in autopilot.

## 1. What you need

| Part | What |
|---|---|
| Drone side | A **companion computer** on the drone (Linux), wired to the autopilot (PX4 or ArduPilot). Wired means a serial line, USB or Ethernet on the drone, never a radio. |
| Ground side | A **ground station computer** (Linux). |
| Network | The two computers can reach each other over TCP while pairing (Wi-Fi, Ethernet, USB networking). |
| Software | Rust 1.89 or newer, on both computers. Python with `pymavlink` only for the optional checks. |

Safety notes first. They come from testing (see [sitl.md](sitl.md)):

- **ArduPilot: connect the companion on SERIAL1 or higher, never SERIAL0.** SERIAL0 (normally USB) accepts unsigned messages, even a new signing key. Keep SERIAL0 physically protected or unused.
- **ArduPilot refuses signed commands for up to a minute after a reboot** (its signing timestamp is set ahead). `oasa-pair command` retries for 75 s for this reason. A "no acknowledgment" right after a reboot is normal; wait.
- **PX4 accepts the first `SETUP_SIGNING` unsigned if it has no key yet.** Pair before flight, with the radio off, so nobody else gets there first. A secure bootloader build ships a public **test key**: replace it with your own before anything real.
- **pymavlink defaults to MAVLink 1, which cannot be signed.** Set `MAVLINK20=1` in your own scripts.
- **Never put the pairing code on the command line.** `oasa-pair` refuses it. Use a pipe or `--code-file`.
- Both autopilots refuse a key change while armed. Pair and rotate on the ground.
- The key check and rotation have only run in simulators and with a stand-in autopilot. Real hardware is untested.

## 2. Try it first, no hardware

Do this on one laptop before touching a drone. About 10 minutes. It uses a stand-in autopilot that follows PX4's and ArduPilot's signing rules.

```sh
git clone https://github.com/joinoasa/oasa-sec.git && cd oasa-sec
cargo build --locked --bins --examples
REPO=$PWD
export PATH="$REPO/target/debug:$PATH"
python3 -m venv /tmp/oasa-venv && /tmp/oasa-venv/bin/pip install pymavlink
mkdir -p /tmp/oasa-demo && cd /tmp/oasa-demo
```

Start the stand-in autopilot (it prints a line when it is ready):

```sh
"$REPO"/target/debug/examples/fake_autopilot udpin:127.0.0.1:14540 > ap.log 2>&1 &
sleep 1; cat ap.log
```

Make the two identities. Each device makes its own; `init` prints the fingerprint:

```sh
oasa-pair init --dir drone --name drone-1
oasa-pair init --dir gcs --name gcs-1
```

Put the drone in pairing mode. It prints a QR code and a text code (`OASA1-...`) and waits 5 minutes (change with `--wait SECONDS`):

```sh
oasa-pair drone --dir drone --name drone-1 --listen 127.0.0.1:7400 \
  --autopilot udpout:127.0.0.1:14540 > drone.log 2>&1 &
sleep 2; head -3 drone.log
```

Pair. On real devices you scan the QR or paste the code; here we pipe it from the log. `--expect-drone` makes the ground station refuse a code that is not for the drone with that fingerprint (here read from `show`; on a real drone, read it off its label):

```sh
FP=$(oasa-pair show --dir drone | sed -E 's/.*"fingerprint":"([^"]+)".*/\1/')
grep -o 'OASA1-[A-Z2-7]*' drone.log | oasa-pair ground --dir gcs --name gcs-1 \
  --connect 127.0.0.1:7400 --code - --expect-drone "$FP"
sleep 1; tail -2 drone.log
```

Expected: the ground station says `Paired with drone drone-1 (...) as peer; made a new signing key.` and the drone says the autopilot `accepted the new key (checked with a signed command)` and `Paired with ground station gcs-1 (...) as operator`. Nothing is saved on either side unless the autopilot took the key.

Check the pairing and a signed command:

```sh
oasa-pair peers --dir gcs
oasa-pair peers --dir drone
oasa-pair command --dir gcs --to udpout:127.0.0.1:14540
```

Expected: `Signed acknowledgment received from 1:1: MAV_CMD_REQUEST_MESSAGE accepted.`

Check that unsigned and wrong-key commands are ignored. Run these with pymavlink from the repo (exit 2 means no acknowledgment, which is what you want for the first; the second, signed, should exit 0):

```sh
cd "$REPO"
PY=/tmp/oasa-venv/bin/python
$PY -I tests/interop/pymavlink_check.py client none 14540; echo "unsigned exit=$?"
KEY=$(ls /tmp/oasa-demo/gcs/signing-keys/*.bin)
$PY -I tests/interop/pymavlink_check.py client "$KEY" 14540; echo "signed exit=$?"
cd /tmp/oasa-demo
```

Expected: `no ACK`, `unsigned exit=2`, then `ACK 512 result 0`, `signed exit=0`.

### Add a second ground station

Pairing mode is one-shot: the code dies after one pairing. Start it again and pair the second computer. It gets the **same** signing key, so the first is not locked out.

```sh
oasa-pair init --dir gcs2 --name gcs-2
oasa-pair drone --dir drone --name drone-1 --listen 127.0.0.1:7400 \
  --autopilot udpout:127.0.0.1:14540 > drone2.log 2>&1 &
sleep 2
grep -o 'OASA1-[A-Z2-7]*' drone2.log > code.txt; chmod 600 code.txt
oasa-pair ground --dir gcs2 --name gcs-2 --connect 127.0.0.1:7400 --code-file code.txt
shred -u code.txt
oasa-pair command --dir gcs2 --to udpout:127.0.0.1:14540
oasa-pair command --dir gcs --to udpout:127.0.0.1:14540
```

Expected: both commands print `Signed acknowledgment received`. `--code-file` is for a code you saved as a file; delete the file after use.

### Remove a ground station and rotate the key

`gcs-1` is "lost". On the drone, remove it, then run the signer, which gives the autopilot a new key:

```sh
oasa-pair remove --dir drone gcs-1
oasa-pair signer --dir drone --autopilot udpout:127.0.0.1:14540 > signer.log 2>&1 &
until grep -q rotation_done signer.log; do sleep 1; done; cat signer.log
oasa-pair command --dir drone --to udpout:127.0.0.1:14540 --wait 10
oasa-pair command --dir gcs --to udpout:127.0.0.1:14540 --wait 5 || echo "gcs-1 locked out, as intended"
```

Expected: `signer_started`, `rotation_started`, `rotation_done` (generation 1); the drone's command is acknowledged; `gcs-1` gets `no signed acknowledgment` and the echo.

The good ground station gets the new key over the encrypted link, so run `oasa-link` on both sides for a few seconds (`--duration` stops it). In real use it runs all the time.

```sh
oasa-link --dir drone --peer gcs-2 --bind 127.0.0.1:7001 \
  --plain-listen 127.0.0.1:7011 --plain-send 127.0.0.1:7012 --duration 10 > ldrone.log 2>&1 &
oasa-link --dir gcs2 --peer drone-1 --bind 127.0.0.1:7002 --remote 127.0.0.1:7001 --initiate \
  --plain-listen 127.0.0.1:7021 --plain-send 127.0.0.1:7022 --duration 10 > lgcs.log 2>&1 &
sleep 5; grep -h signing_key ldrone.log lgcs.log | cut -c1-120
oasa-pair command --dir gcs2 --to udpout:127.0.0.1:14540 --wait 5
```

Expected: `signing_key_next`, `signing_key_commit` (`switched`) and acks in the logs, then `Signed acknowledgment received`.

Clean up (stops only these demo processes):

```sh
kill $(jobs -p) 2>/dev/null; sleep 11; rm -rf /tmp/oasa-demo
```

## 3. Real devices

### Install

On both computers:

```sh
git clone https://github.com/joinoasa/oasa-sec.git && cd oasa-sec
cargo build --locked --release --bins
sudo install -m 755 target/release/oasa-pair target/release/oasa-link /usr/local/bin/
```

### Set up each device

Pick a folder that only the service user can read (`init` creates it with mode 700):

```sh
oasa-pair init --dir ~/oasa-device --name drone-1     # on the drone's companion computer
oasa-pair init --dir ~/oasa-device --name gcs-1       # on the ground station
```

Names are 1 to 32 characters of `A-Z a-z 0-9 - _ .`. `init` prints the **fingerprint** (`CYGJ-NYWB-BHFH-4GEA`). Write the drone's on a label. Running `init` again changes nothing and prints the existing one.

### Autopilot link

- ArduPilot: put the companion on **SERIAL1 or higher**. Never SERIAL0.
- Give `oasa-pair` a **dedicated** link to the autopilot: its own UDP or TCP port (for example from a MAVLink router), not shared with the radio. Tested: UDP and TCP (`udpout:HOST:PORT`, `tcpout:HOST:PORT`). `serial:PORT:BAUD` is accepted by the address format but has not been tested.
- The same link is used for pairing and for the `signer` later. Only one program should hold it at a time.
- `--target SYS:COMP` is the autopilot's ids (default 1:1).

### Pair

1. On the drone's companion, with the autopilot disarmed and the radio off:

   ```sh
   oasa-pair drone --dir ~/oasa-device --name drone-1 --listen 0.0.0.0:7400 \
     --autopilot udpout:127.0.0.1:14540
   ```

   It shows a QR code and a text code. **Anyone who sees the code can pair once.** Keep it on the drone's screen or your own terminal only.

2. On the ground station, scan the QR with your app, or paste the code when asked. Pass the fingerprint from the drone's label so a swapped QR is caught:

   ```sh
   oasa-pair ground --dir ~/oasa-device --name gcs-1 --connect DRONE_IP:7400 \
     --expect-drone CYGJ-NYWB-BHFH-4GEA
   ```

   To use a saved code: `--code-file FILE` (then delete the file) or `--code -` with the code piped in.

3. Expected on the ground station: `Paired with drone drone-1 (...) as peer; made a new signing key.` On the drone: the autopilot `accepted the new key (checked with a signed command)`. If the drone says nothing was saved, read the error table below.

4. Confirm: `oasa-pair command --dir ~/oasa-device --to udpout:AUTOPILOT_HOST:PORT` on a computer that can reach the autopilot, or in flight tests whatever your radio setup allows. On ArduPilot, the first command after a reboot can take up to a minute.

Close pairing mode when done: it closes by itself after the window, or after one pairing. Stop it with Ctrl-C if you changed your mind.

### Add another ground station

Run the drone command again, and pair the new ground station with a new name. It gets the same key. Check who is trusted with `oasa-pair peers --dir DIR`.

### The encrypted link

Pairing leaves each side trusting the other. Day to day, `oasa-link` carries MAVLink between them inside the encrypted link, and delivers key rotations. See the [README](../README.md) for the options.

### Remove a device, rotate the key

- **Lost or stolen ground station:** on the drone, `oasa-pair remove --dir DIR gcs-1` (name, fingerprint or 64-hex key). It is trusted never again, even if an old file comes back. A running `oasa-link` notices within a second. Removing an operator asks for a key rotation.
- **Rotate the key:** keep `oasa-pair signer --dir DIR --autopilot udpout:HOST:PORT` running on the drone (on its own link; run it as a service). It waits until the autopilot is **disarmed**, changes the key, proves it works, and prints `rotation_done`. Ask for one by hand with `oasa-pair rotate-signing --dir DIR`. It prints events as JSON lines: `rotation_waiting_armed`, `rotation_started`, `rotation_done`, `rotation_rolled_back`, `rotation_stuck`, `rotation_refused`. `rotation_stuck` keeps both keys and asks again every 5 minutes; check the autopilot link.
- **Until the signer has run, the removed station's key still works on the autopilot.** Rotate soon after a removal.
- **Stolen drone:** on each ground station, `oasa-pair remove --dir DIR drone-1`. That also deletes the signing key it held.
- **Revoke:** `oasa-pair revoke --dir DIR PEER` removes it here and also adds it to this device's removal log, so devices that list this one as `admin` remove it too over the link. Admins are set with `oasa-pair trust ... --role admin`; see the [rotation spec](oasa-sec-v0-rotation.md).
- **Undo:** `oasa-pair restore --dir DIR KEY` only lifts the tombstone. Pair or `trust` again to trust it.
- **List:** `oasa-pair removed --dir DIR`.
- A removed device cannot pair again with its old identity. It must `init` a new folder.

### Back up and protect the device folder

- The folder holds the private identity (`identity.key`), signing keys and the trust files. Everything in it is mode 600 (folder 700). The software refuses to load a key others can read: fix with `chmod 600`.
- **Do not copy a folder to a second device.** Each device makes its own keys. A copy is two devices with one identity.
- Back up only to encrypted, offline storage you control. Restoring the same folder onto the same device is fine. If a backup or device may have been seen by someone else, treat it as stolen: remove it everywhere, rotate, and pair a new identity.
- Do not put device folders in git, images, or cloud sync. Do not log or paste `identity.key` or `*.bin`. `oasa-pair show` prints only public information.
- Do not edit files in the folder by hand; use `oasa-pair`, which locks and writes safely.
- Set the clock on the companion computer before starting `oasa-link`. If a peer's handshakes are refused as stale because a clock was wrong, fix the clock and run `oasa-pair reset-stamp --dir DIR --peer NAME`.

## 4. Errors and what to do

| You see | It means | Do |
|---|---|---|
| `don't put the pairing code on the command line` | You used `--code CODE`. | Pipe it with `--code -` or use `--code-file FILE`. |
| `bad pairing code: wrong length`, `not valid base32` or `must start with OASA1-` | The code was cut off or mistyped. | Copy the whole code, or scan the QR. |
| `code is for drone X, not Y; refusing to pair` | `--expect-drone` does not match the code. | Wrong or swapped QR. Do not pair. Check the label and where the code came from. |
| Ground: `I/O error: failed to fill whole buffer`. Drone: `Pairing attempt failed: encryption or authentication failed` | The drone got a code with the wrong secret (a stale code, another pairing, or an attacker) and stayed silent on purpose. | Use the code from the current pairing mode. Restart the drone side for a fresh code. |
| Drone: `pairing window closed with no ground station` | Nobody paired within the window. | Run `oasa-pair drone` again (`--wait SECONDS` for longer). |
| Ground: `Connection refused (os error 111)` or a timeout | Wrong address, firewall, or drone not in pairing mode. | Check `--connect`, the port, and that the drone is waiting. |
| `no signed acknowledgment after Ns. Likely causes: ...` | The autopilot did not take or use the key. | Check: (1) it already has a different key from an earlier pairing, (2) it is armed, (3) ArduPilot just rebooted (wait a minute), (4) wrong link or address. Nothing was saved on a failed pairing. |
| `that device was removed here; a removed device must make a new identity and pair again` | The ground station's key is in `removed`. | Make a new identity and pair, or on the drone `oasa-pair restore KEY` then pair. |
| `bad key file: ... can be read by others (mode 644)` | File permissions too open. | `chmod 600` on the file. |
| `... (run oasa-pair init --dir DIR first)` | The folder has no identity (or the path is wrong). | Check `--dir`, or `init`. |
| `pairing protocol error: name must be 1-32 of A-Z a-z 0-9 - _ .` | Bad device name. | Choose another. |
| `oasa-link` exits with code 3 | Its own peer was removed. | Expected after `remove`. Pair again if that was a mistake. |
| `trust_unreadable` in `oasa-link` logs | A trust file cannot be read. New removals are not applied meanwhile. | Fix the file or permissions. Watch for this. |
| `rotation_waiting_armed` | The autopilot is armed. | Disarm. Nothing is changed while armed. |
| `rotation_stuck` | The signer cannot tell which key the autopilot has. Both keys are kept. | Check the autopilot link and power; it retries every 5 minutes. |
| `rotation_refused` | The signer would not issue a key (for example a timestamp out of range). | Check the companion's clock. |
| A good ground station is rejected after a rotation | It has not received the new key yet. | Run `oasa-link` to the drone for a few seconds. |
