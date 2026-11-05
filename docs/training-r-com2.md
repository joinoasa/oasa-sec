# Training: the encrypted link over a radio (R-COM2)

A hands-on course for people who will run an OASA link between a ground station and a drone. About 1 hour for steps 1 to 4 and 7 to 8; steps 5 and 6 need a second machine and a radio pair. Needs oasa-sec#19 (merged), which adds `--radio-profile`.

> **Prototype.** Not independently reviewed. Do not fly with it. See [SECURITY.md](../SECURITY.md).

## 1. What you build, and what you need

You will run `oasa-link` on two devices so that plain UDP (for example MAVLink) goes in one end, crosses the air encrypted, and comes out the other end. First on one machine, then over a network, then through a serial radio.

```
 ground side                                            drone side
 your program -> oasa-link -> [oasa-radio bridge] ~~~ [oasa-radio bridge] -> oasa-link -> your program
   plaintext     encrypts      serial radio (air)                           decrypts       plaintext
```

You need:
- A Linux machine with Rust 1.89 or newer, `git`, Python 3, `socat` (`sudo apt install socat`).
- Steps 1 to 4 and 7 to 8: that machine and several terminals (or one terminal; the commands run things in the background).
- Step 5: a second Linux machine on the same network.
- Step 6, practice: [oasa-radio](https://github.com/joinoasa/oasa-radio) built next to this repo. No hardware.
- Step 6, real: a pair of Holybro SiK Telemetry Radio V3 (915 MHz), two USB ports, and fixed attenuators.

> **Safety: radios on a cable, with 60 dB of attenuation.** On the bench, connect the two radios to each other with a coax cable and at least 60 dB of attenuators (for example three 20 dB attenuators in line), rated for the radio's power. Never connect two radios with a bare cable. Never power a radio with nothing on its antenna port. No antennas on the bench setup. Over-the-air tests need the owner's say-so and a test plan: the [oasa-lab rules](https://github.com/joinoasa/oasa-lab) apply.

Not run here: the whole real-radio part of step 6, the two-machine run of step 5, and QGroundControl in step 7. Those are marked.

## 2. Build

```sh
git clone https://github.com/joinoasa/oasa-sec.git && cd oasa-sec
cargo build --locked --bins
```

You should see `Finished` and no errors. Then:

```sh
REPO=$PWD
export PATH="$REPO/target/debug:$PATH"
mkdir -p /tmp/oasa-rcom2 && cd /tmp/oasa-rcom2
oasa-link --help | head -1
```

```
oasa-link: OASA-SEC encrypted link (wire version 1) over UDP (R-COM2). Do not fly with it.
```

## 3. Make identities and trust each other

Each device makes its own key and tells the other its public key. The full way is pairing with a one-time code: do the [pairing guide](guide-pairing.md) (R-SEC1) for real drones. For a link test, `oasa-pair trust` is the short path (like adding a WireGuard peer; it is what `scripts/link-e2e.sh` uses). On one machine:

```sh
oasa-pair init --dir drone --name drone-1
oasa-pair init --dir gcs --name gcs-1
key() { oasa-pair show --dir "$1" | sed -E 's/.*"public_key":"([0-9a-f]{64})".*/\1/'; }
oasa-pair trust --dir gcs --name drone-1 --key "$(key drone)"
oasa-pair trust --dir drone --name gcs-1 --key "$(key gcs)"
```

```
Created identity LWPY-JMOQ-7VTZ-3RPP
Created identity VJFE-EX7U-ODPZ-V5ND
Trusted drone-1 LWPY-JMOQ-7VTZ-3RPP as peer
Check that this fingerprint matches the one shown on that device.
Trusted gcs-1 VJFE-EX7U-ODPZ-V5ND as peer
Check that this fingerprint matches the one shown on that device.
```

Your fingerprints differ. On two real machines, run `init` on each, copy the other's `oasa-pair show` line, and compare the fingerprints out loud before you trust. The private key stays in `identity.key` (mode 600) on its device; never copy it.

## 4. Run the link on one machine

Start the drone side first, then the ground side (which starts the handshake), and two listeners that print what comes out:

```sh
oasa-link --dir drone --peer gcs-1 --bind 127.0.0.1:7701 \
  --plain-listen 127.0.0.1:7711 --plain-send 127.0.0.1:7712 > drone.log 2>&1 &
sleep 0.5
oasa-link --dir gcs --peer drone-1 --bind 127.0.0.1:7702 --remote 127.0.0.1:7701 --initiate \
  --plain-listen 127.0.0.1:7721 --plain-send 127.0.0.1:7722 --rekey-secs 20 > gcs.log 2>&1 &
socat -u UDP-RECV:7712,bind=127.0.0.1 - > drone-got.txt &
socat -u UDP-RECV:7722,bind=127.0.0.1 - > gcs-got.txt &
sleep 3
```

The ports: `--bind` is the encrypted side, `--plain-listen` is where your program sends plaintext, `--plain-send` is where decrypted packets come out. Now send a packet each way and look:

```sh
echo "hello drone, from the ground" | socat -u - UDP-SENDTO:127.0.0.1:7721
echo "hello ground, from the drone" | socat -u - UDP-SENDTO:127.0.0.1:7711
sleep 1
cat drone-got.txt gcs-got.txt
```

```
hello drone, from the ground
hello ground, from the drone
```

Read the logs. One JSON line per event; packet contents and keys never appear:

```sh
cat gcs.log
cat drone.log
```

```
{"ts":"2026-11-05T16:59:58.993Z","event":"mavlink_guard","state":"off","ftp":false}
{"ts":"2026-11-05T16:59:58.993Z","event":"hint","what":"the MAVLink guard is off because --dir has no mavlink-signing-key.bin; drones whose key lives elsewhere: use --mavlink-guard"}
{"ts":"2026-11-05T16:59:59.018Z","event":"handshake_sent","retry":false,"rekey":false}
{"ts":"2026-11-05T16:59:59.024Z","event":"session_established","role":"initiator"}
```

(then the drone's, ending in `"event":"session_established","role":"responder"`.) The guard is off here because this test "drone" has no autopilot signing key (step 7).

Wait 20 seconds for a rekey, send one more packet, then stop both and read the stats:

```sh
sleep 22
echo "after rekey" | socat -u - UDP-SENDTO:127.0.0.1:7721
sleep 1
grep -E 'rekey|session_established' gcs.log
pkill -TERM oasa-link; sleep 1
tail -1 gcs.log
cat drone-got.txt
```

```
{"ts":"...","event":"handshake_sent","retry":false,"rekey":false}
{"ts":"...","event":"session_established","role":"initiator"}
{"ts":"...","event":"handshake_sent","retry":false,"rekey":true}
{"ts":"...","event":"session_established","role":"initiator"}
{"ts":"...","event":"rekey","role":"initiator"}
{"event":"stats","sent":2,"received":1,"delivered":1,"control_sent":0,"control_received":0,"drops":{"bad_header":0,"unknown_index":0,"too_old":0,"bad_tag":0,"replay":0,"untrusted_peer":0,"stale_handshake":0,"rate_limited":0,"bad_content":0}}
hello drone, from the ground
after rekey
```

What it means: `session_established` is a finished handshake. `rekey` is a new key after `--rekey-secs` (default 600), with traffic still flowing. `stats` is printed on exit (exit code 0): `sent` and `delivered` count packets, and every `drops` counter is zero in a clean run. (The first `handshake_sent` matches the grep because it has `"rekey":false`.)

Clean up:

```sh
pkill socat
```

## 5. Two machines over a network

Not run here (one machine only). It is step 4 with real addresses. On both machines build (step 2) and make an identity; copy each other's `oasa-pair show` line, compare fingerprints out loud, and `oasa-pair trust` (step 3). Open UDP port 7701 on the drone's machine. Then, with `DRONE_IP` the drone machine's address:

On the drone machine:

```sh
oasa-link --dir drone --peer gcs-1 --bind 0.0.0.0:7701 \
  --plain-listen 127.0.0.1:7711 --plain-send 127.0.0.1:7712
```

On the ground machine:

```sh
oasa-link --dir gcs --peer drone-1 --bind 0.0.0.0:7702 --remote DRONE_IP:7701 --initiate \
  --plain-listen 127.0.0.1:7721 --plain-send 127.0.0.1:7722
```

You should see `session_established` on both within a second or two. Use the `socat` commands from step 4 on each machine (plaintext ports stay on 127.0.0.1; `oasa-link` refuses a non-loopback plaintext address unless you pass `--allow-remote-plain`, which you should not). The drone does not need `--remote`; it learns the ground station's address from the first packet that authenticates.

## 6. Over a radio

`oasa-radio bridge` moves `oasa-link`'s encrypted UDP packets over a serial radio. It never encrypts and never reads packets. Both ends need the same `--mtu`.

### Practice, no hardware: a pseudo-terminal pair

`socat` makes two linked serial ports in software. This is what `oasa-radio`'s `scripts/serial-e2e.sh` does (with its own relay that also limits the baud rate). Build oasa-radio once:

```sh
git clone https://github.com/joinoasa/oasa-radio.git /tmp/oasa-radio && (cd /tmp/oasa-radio && cargo build --locked --bins)
export PATH="/tmp/oasa-radio/target/debug:$PATH"
oasa-radio info | head -2
```

```
{"ts":"...","event":"adapter","kind":"udp","status":"ready","note":"plain UDP passthrough for simulation and Wi-Fi/Ethernet"}
{"ts":"...","event":"adapter","kind":"serial","status":"ready","note":"transparent serial radios: SiK, mLRS, RFD900x, UART modems"}
```

Make the serial line and a bridge on each side. Each bridge listens for its `oasa-link` and sends to it; the line `lineA`/`lineB` is the "air":

```sh
socat -d -d pty,raw,echo=0,link=lineA pty,raw,echo=0,link=lineB 2> socat-pty.log &
sleep 1
oasa-radio bridge --radio serial --device lineA --baud 57600 --mtu 252 \
  --udp-listen 127.0.0.1:7821 --udp-send 127.0.0.1:7801 > bridge-gcs.log 2>&1 &
oasa-radio bridge --radio serial --device lineB --baud 57600 --mtu 252 \
  --udp-listen 127.0.0.1:7822 --udp-send 127.0.0.1:7802 > bridge-drone.log 2>&1 &
sleep 1
cat bridge-gcs.log
```

```
{"ts":"...","event":"start","radio":"serial","target":"lineA","mtu":252,"bitrate":57600,"udp_listen":"127.0.0.1:7821","udp_send":"127.0.0.1:7801"}
```

Now point each `oasa-link` at its bridge: `--remote` is the bridge's `--udp-listen`, `--bind` is the bridge's `--udp-send`. Give `oasa-link` the radio's profile so its handshake timers fit the air:

```sh
oasa-link --dir drone --peer gcs-1 --bind 127.0.0.1:7802 --remote 127.0.0.1:7822 \
  --mtu 252 --radio-profile sik-64k \
  --plain-listen 127.0.0.1:7711 --plain-send 127.0.0.1:7712 > drone.log 2>&1 &
sleep 0.5
oasa-link --dir gcs --peer drone-1 --bind 127.0.0.1:7801 --remote 127.0.0.1:7821 --initiate \
  --mtu 252 --radio-profile sik-64k \
  --plain-listen 127.0.0.1:7721 --plain-send 127.0.0.1:7722 > gcs.log 2>&1 &
socat -u UDP-RECV:7712,bind=127.0.0.1 - > drone-got.txt &
socat -u UDP-RECV:7722,bind=127.0.0.1 - > gcs-got.txt &
sleep 3
echo "hello over the radio line" | socat -u - UDP-SENDTO:127.0.0.1:7721
echo "and back" | socat -u - UDP-SENDTO:127.0.0.1:7711
sleep 1
cat drone-got.txt gcs-got.txt
grep -c session_established gcs.log drone.log
pkill -TERM oasa-link; pkill -TERM -f "oasa-radio bridge"; sleep 1
tail -1 bridge-gcs.log
pkill socat
```

```
hello over the radio line
and back
gcs.log:1
drone.log:1
{"ts":"...","event":"stats","to_radio":3,"to_radio_bytes":188,"from_radio":3,"from_radio_bytes":107,"drops":{}}
```

**This passes when:** each side logs `session_established`; both packets arrive once and unchanged; the bridge `stats` show packets in both directions (`to_radio` and `from_radio` above zero) and `drops` empty.

### With a SiK pair

Not run here (no radios). Same commands, with the real device names. Plug in one radio per machine (or both into one machine for the bench: the second shows up as `/dev/ttyUSB1`). Find them with `ls /dev/ttyUSB* /dev/ttyACM*`; you may need `sudo usermod -aG dialout $USER` and a new login. Set both radios once with the SiK configuration tool (Mission Planner or the ArduPilot SiK config page): the same NETID, serial speed 57 (57600 baud), air speed 64, ECC off, MAVLink framing off (raw data), RTS/CTS off. Transparent means no radio-side packet mode and no reliance on its own encryption: the OASA link is the encryption.

Then replace `--device lineA` with `--device /dev/ttyUSB0` (and `lineB` with the other radio), and keep `--baud 57600 --mtu 252 --radio-profile sik-64k`. With ECC on, use `--mtu 118 --radio-profile sik-64k-ecc` on both bridges and both links. Before you transmit, check the cable has 60 dB in it (step 1). `oasa-radio info --radio serial --device /dev/ttyUSB0` opens the port and shows its settings.

Passing on real radios is the same as above. Expect the handshake to take longer than on a pseudo-terminal: seconds, not milliseconds.

## 7. Encrypted MAVLink

`oasa-link` carries any UDP, so MAVLink is just what you point at the plaintext ports. On the ground side, send to `--plain-listen` and receive on `--plain-send`; on the drone side, the autopilot or a MAVLink router does the same with the drone's ports. This runs here with pymavlink (`pip install pymavlink`): the "ground station" sends heartbeats in, and a listener where the drone's link delivers them gets them out. Start the step 4 links again first:

```sh
oasa-link --dir drone --peer gcs-1 --bind 127.0.0.1:7701 \
  --plain-listen 127.0.0.1:7711 --plain-send 127.0.0.1:7712 > drone.log 2>&1 &
sleep 0.5
oasa-link --dir gcs --peer drone-1 --bind 127.0.0.1:7702 --remote 127.0.0.1:7701 --initiate \
  --plain-listen 127.0.0.1:7721 --plain-send 127.0.0.1:7722 > gcs.log 2>&1 &
sleep 2
cat > hb.py <<'EOF'
from pymavlink import mavutil
import time
gcs = mavutil.mavlink_connection("udpout:127.0.0.1:7721", source_system=255)
drone = mavutil.mavlink_connection("udpin:127.0.0.1:7712")
for _ in range(3):
    gcs.mav.heartbeat_send(mavutil.mavlink.MAV_TYPE_GCS, mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0)
    time.sleep(0.3)
m = drone.recv_match(type="HEARTBEAT", blocking=True, timeout=5)
print("drone got:", m)
EOF
python3 -I hb.py
pkill -TERM oasa-link
```

```
drone got: HEARTBEAT {type : 6, autopilot : 8, base_mode : 0, custom_mode : 0, system_status : 0, mavlink_version : 3}
```

Type 6 is a ground station: the heartbeat crossed the encrypted link.

With a real ground station (not run here): in QGroundControl add a UDP comm link that listens on port 14550, and set the ground-side `oasa-link` to `--plain-send 127.0.0.1:14550` and `--plain-listen 127.0.0.1:14551`. QGC then sends to 14551 once you add 14551 as a target host on its UDP link (Application Settings, Comm Links). With MAVProxy: `mavproxy.py --master=udpin:127.0.0.1:14550 --out=udpout:127.0.0.1:14551` (check `mavproxy.py --help` on your version).

**The MAVLink guard (drone side).** A drone's device folder holds the autopilot signing key (`mavlink-signing-key.bin`, from pairing). When it does, `oasa-link` turns the guard on by itself: every packet from the link is checked before it goes to `--plain-send`, and only whole, CRC-valid frames of allowed messages and commands pass. Parameter writes, FTP and `SETUP_SIGNING` are blocked unless you widen it with the `--allow-*` flags (each logs a warning). A blocked packet is a `drop` with reason `mavlink_blocked` and the ids, never contents. Force it on with `--mavlink-guard`. The allowlist is in [docs/oasa-sec-v0-link.md](oasa-sec-v0-link.md). In this course the test drone has no signing key, so the guard is off, as the `hint` line said.

## 8. What the attacker checks show

**A device you do not trust.** `evil` knows the drone's public key (it is not secret) but the drone has never trusted it. It is silent to the outside and counted inside:

```sh
oasa-pair init --dir evil --name evil
oasa-pair trust --dir evil --name drone-1 --key "$(key drone)"
oasa-link --dir drone --peer gcs-1 --bind 127.0.0.1:7701 \
  --plain-listen 127.0.0.1:7711 --plain-send 127.0.0.1:7712 > drone.log 2>&1 &
sleep 0.5
oasa-link --dir evil --peer drone-1 --bind 127.0.0.1:7703 --remote 127.0.0.1:7701 --initiate \
  --plain-listen 127.0.0.1:7731 --plain-send 127.0.0.1:7732 --duration 8 > evil.log 2>&1
grep -v -E 'hint|mavlink_guard' drone.log
pkill -TERM oasa-link; sleep 1; tail -1 drone.log
```

```
{"ts":"...","event":"drop","reason":"untrusted_peer","from":"127.0.0.1:7703"}
{"ts":"...","event":"drop","reason":"untrusted_peer","from":"127.0.0.1:7703"}
{"event":"stats",...,"drops":{...,"untrusted_peer":2,...}}
```

On `evil`'s side there is no `session_established` and no reply of any kind, only its own `handshake_sent` lines (a first try and a retry).

**A replayed packet.** A small relay that sends every packet twice stands between the two; the second copy is a replay. Replays are dropped before anything is delivered:

```sh
cat > twice.py <<'EOF'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 7703))
drone, gcs = ("127.0.0.1", 7701), ("127.0.0.1", 7702)
while True:
    data, src = s.recvfrom(2048)
    if src == gcs:
        s.sendto(data, drone)
        s.sendto(data, drone)   # the replay: the same packet again
    else:
        s.sendto(data, gcs)
EOF
python3 -I twice.py &
socat -u UDP-RECV:7712,bind=127.0.0.1 - > replay-got.txt &
oasa-link --dir drone --peer gcs-1 --bind 127.0.0.1:7701 \
  --plain-listen 127.0.0.1:7711 --plain-send 127.0.0.1:7712 > drone.log 2>&1 &
sleep 0.5
oasa-link --dir gcs --peer drone-1 --bind 127.0.0.1:7702 --remote 127.0.0.1:7703 --initiate \
  --plain-listen 127.0.0.1:7721 --plain-send 127.0.0.1:7722 --duration 8 > gcs.log 2>&1 &
sleep 2
echo "once only" | socat -u - UDP-SENDTO:127.0.0.1:7721
sleep 7
pkill -TERM oasa-link; sleep 1
grep -v -E 'hint|mavlink_guard' drone.log
cat replay-got.txt
pkill -f twice.py; pkill socat
```

```
{"ts":"...","event":"drop","reason":"stale_handshake","from":"127.0.0.1:7703"}
{"ts":"...","event":"session_established","role":"responder"}
{"ts":"...","event":"drop","reason":"replay","from":"127.0.0.1:7703"}
{"ts":"...","event":"drop","reason":"replay","from":"127.0.0.1:7703"}
{"event":"stats","sent":0,"received":1,"delivered":1,...,"drops":{...,"replay":2,...,"stale_handshake":1,...}}
once only
```

The doubled handshake and the doubled data packet were both dropped; `"once only"` arrived once. The same checks run in `scripts/link-e2e.sh` (CI) with 60 marked packets each way.

## 9. Troubleshooting

| You see | Cause and fix |
|---|---|
| `error: bad key file: ... can be read by others (mode 644)` | `chmod 600 DIR/identity.key`. The link will not start with a readable key. |
| `error: no trusted peer named X` | `--peer` must be the name you gave to `oasa-pair trust` (`oasa-pair peers --dir DIR` lists them). |
| `handshake_sent` with `"retry":true`, never `session_established` | The other side is not running, `--remote` is wrong, or a firewall blocks the UDP port. The retry is 5 s, backing off to 60 s. Start the other side; it waits for you. |
| Drone logs `drop` with `untrusted_peer` | The drone has not trusted the ground station's key. Redo step 3 in both directions and compare fingerprints. |
| Drops `bad_tag`, `bad_header` | Packets damaged or from something else on the port. On a radio: check that both ends use the same `--mtu` and baud and that the radio is transparent (no MAVLink framing, no radio encryption). |
| `stale_handshake`, repeated handshakes on a slow radio | The handshake takes longer than the 5 s retry, so the retry goes out too early. Give both `oasa-link` the same `--radio-profile` (`sik-64k`, `lora-sf9-bw125`, ...; `oasa-link --help` lists them), or `--handshake-rtt-ms N` for a radio without one. |
| Everything works, then stops after a restart of one side | A restarted ground station follows from a new port; a restarted drone waits up to 90 s unless it has `--remote`. Give `--remote` whenever you know the peer's address. |
| Packets silently missing, no drop lines | A plaintext packet over `MTU - 22` bytes is dropped (`too_large`); on a serial line, sending faster than the baud rate fills the kernel's UDP buffer. Lower the rate, or raise `--mtu` on both ends. |
| `Address already in use` | A listener from an earlier step is still running: `pkill socat; pkill oasa-link`. |

## What to do next

Run `scripts/link-e2e.sh` (`cargo build --locked --bins` first) and oasa-radio's `scripts/serial-e2e.sh` to see the same checks run automatically. Read [docs/oasa-sec-v0-link.md](oasa-sec-v0-link.md) for the wire format and why each drop reason exists.
