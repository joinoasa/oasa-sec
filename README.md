# oasa-sec

**OASA-SEC:** device identity, encrypted pairing and the encrypted link for [OASA](https://joinoasa.org) autonomous systems. Tech tree nodes **R-SEC1** (identity, pairing) and **R-COM2** (the link, milestone M2).

> **Prototype.** Not independently reviewed. Do not fly with it. See [SECURITY.md](SECURITY.md).

## What it does today

1. Every device makes its own X25519 identity.
2. A drone shows a **one-time pairing code** as a QR code.
3. The ground station reads it and runs an encrypted, mutually authenticated **Noise** handshake (`IKpsk1`). Without the code, the drone won't even reply.
4. Inside that encrypted channel they share a **MAVLink 2 signing key**. On first pairing the ground station makes it; the drone loads it into its autopilot over its local wired link and proves it works before saving it. Later ground stations receive the same key.

Signing is only a second layer. The design is in [docs/oasa-sec-v0-pairing.md](docs/oasa-sec-v0-pairing.md).

## The encrypted link (R-COM2)

One encrypted, authenticated link between two trusted devices, over any radio that can carry a packet. Modeled on WireGuard: Noise `IK`, 22 bytes of overhead (handshakes 119 and 55 bytes; wire version 1 adds a content type byte so control messages stay apart from app data), every packet stands alone (loss, reordering and duplicates never break it), and a device that is not in `trusted-peers.v1` gets no reply at all. Design: [docs/oasa-sec-v0-link.md](docs/oasa-sec-v0-link.md).

- **`oasa_sec::link`** is a library with no sockets, threads or clock inside: bytes and the time go in, events come out. `Link` is one peer; `Endpoint` serves several (one ground station, many drones).
- **`oasa-link`** carries local UDP packets (for example MAVLink) over the link and logs one JSON line per event.

Try it on one machine, with no hardware:

```sh
cargo build --bins
B=target/debug
for d in gcs drone; do $B/oasa-pair init --dir /tmp/$d --name $d; done
key() { $B/oasa-pair show --dir /tmp/$1 | sed -E 's/.*"public_key":"([0-9a-f]{64})".*/\1/'; }
$B/oasa-pair trust --dir /tmp/gcs --name drone --key "$(key drone)"   # compare the fingerprints out loud
$B/oasa-pair trust --dir /tmp/drone --name gcs --key "$(key gcs)"

# Drone: waits for the ground station. Plaintext in on 7011, out on 7012.
$B/oasa-link --dir /tmp/drone --peer gcs --bind 127.0.0.1:7001 \
  --plain-listen 127.0.0.1:7011 --plain-send 127.0.0.1:7012 &
# Ground station: starts the handshake. Plaintext in on 7021, out on 7022.
$B/oasa-link --dir /tmp/gcs --peer drone --bind 127.0.0.1:7002 --remote 127.0.0.1:7001 --initiate \
  --plain-listen 127.0.0.1:7021 --plain-send 127.0.0.1:7022 &

# Anything sent to 7021 comes out of 7012 (and the other way round).
echo hello | nc -u -q1 127.0.0.1 7021
```

Over a pair (`oasa-pair drone` and `ground`) the peers trust each other already, so `trust` is only for devices with nothing to pair with, like relays and test nodes. `oasa-link --help` lists every option; on exit (Ctrl-C, SIGTERM or `--duration`) it prints a stats line. It watches the trust files and reloads within a second (or at once on SIGHUP), so `oasa-pair trust`, `remove` and `revoke` need no restart; if its own peer is removed it exits with code 3. `--plain-listen` must be a loopback address unless you pass `--allow-remote-plain`. If a peer's clock was wrong and its handshakes are now refused as stale, fix the clock and run `oasa-pair reset-stamp --dir DIR --peer NAME`. Set the same rekey limits on both sides. On a slow radio give both sides the same `--radio-profile` (`lora-sf12-bw125`, `lora-sf9-bw125`, `lora-sf7-bw125`, `sik-64k`, `sik-64k-ecc`, `mlrs-19hz`, `mlrs-31hz`, `mlrs-50hz`, `wifi-wfb`: the [oasa-lab](https://github.com/joinoasa/oasa-lab) names) or `--handshake-rtt-ms N`: the default 5 s handshake retry is shorter than the 7.1 s a handshake takes on LoRa SF12, so it would resend before the answer arrives. The profile scales the retry, stale, grace and handshake-gap timers and turns keepalives off on slow radios; `--retry-secs N` sets the retry by hand. See section 5 of the link doc. Give `--remote` whenever you know the peer's address: a device without it cannot start a handshake itself. Use `--trusted-clock` only on a device whose clock is set before it starts.

On a drone (a device folder with `mavlink-signing-key.bin`) `oasa-link` also runs a **MAVLink guard** on what comes out of the link. It is an **allowlist**: only whole, CRC-valid frames of the right length, for the messages and commands a ground station needs to monitor and fly, get through (the tables are in section 7 of the link doc). Parameter writes, FTP, `SETUP_SIGNING`, geofence and rally changes, RTK data, reboot, calibration and storage commands and every other message are dropped. `--allow-param NAME`, `--allow-mavlink-ftp`, `--allow-fence-rally`, `--allow-rtk`, `--allow-msg ID` and `--allow-command ID` widen it and each logs a warning; `--no-mavlink-guard` turns it off.

`cargo test` runs two endpoints through a seeded simulated channel (loss, reordering, duplicates, corruption, replays, an untrusted device, rekeys under 20% loss). `scripts/link-e2e.sh` runs real `oasa-link` processes over localhost UDP.

## Try it (no hardware)

```sh
cargo build --bins --examples
pip install pymavlink
scripts/e2e.sh
```

That runs a stand-in autopilot, a drone, two ground stations, an attacker and pymavlink, and checks 14 things, including: the attacker is rejected by the handshake, the code is never taken on the command line, signed commands work, unsigned and wrong-key commands are ignored, our signatures interoperate with pymavlink both ways, a second ground station doesn't lock out the first, and a key the autopilot didn't take is never saved (with a message naming the likely causes), and `command` keeps trying when the autopilot answers late.

By hand:

```sh
B=target/debug
$B/examples/fake_autopilot udpin:127.0.0.1:14540 &
$B/oasa-pair drone --dir /tmp/drone --name drone-1 --listen 127.0.0.1:7400 --autopilot udpout:127.0.0.1:14540
# (shows a QR and a code; in another terminal:)
$B/oasa-pair ground --dir /tmp/gcs --name gcs-1 --connect 127.0.0.1:7400   # then paste the code
$B/oasa-pair command --dir /tmp/gcs --to udpout:127.0.0.1:14540
```

Run `oasa-pair --help` for every command.

## Test against a real autopilot (SITL)

`scripts/sitl/px4-sitl-test.sh` and `scripts/sitl/ardupilot-sitl-test.sh` pair with a real PX4 or ArduPilot simulator and check that signed commands work and unsigned or wrong-key ones don't. They aren't in CI (the builds take 20+ minutes). See [docs/sitl.md](docs/sitl.md), which also records what each autopilot does with key changes. The [oasa-lab](https://github.com/joinoasa/oasa-lab) suite `l1-mavlink-sitl` flies both simulators through the encrypted link and checks the guard. With ArduPilot, connect the companion computer on SERIAL1 or higher, never SERIAL0 (see the design doc).

## Built on

| Project | Used for | License |
|---|---|---|
| [snow](https://github.com/mcginty/snow) | Noise handshakes and the link's packet encryption (stateless transport) | Apache-2.0 or MIT |
| [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) | X25519 public keys (already used inside snow) | BSD-3 |
| [rust-mavlink](https://github.com/mavlink/rust-mavlink) | MAVLink 2 messages and signing | Apache-2.0 or MIT |
| [blake2](https://github.com/RustCrypto/hashes), [zeroize](https://github.com/RustCrypto/utils), [data-encoding](https://github.com/ia0/data-encoding), [qrcode](https://github.com/kennytm/qrcode-rust) | Fingerprints, wiping secrets, base32, QR codes | Apache-2.0 / MIT |
| [pymavlink](https://github.com/ArduPilot/pymavlink) | Independent interop check in tests only | LGPL-3.0 |

Choices follow OASA's [adoption standard](https://joinoasa.org/docs/adopting-software/) and are recorded in the [software register](https://joinoasa.org/docs/software-register/).

## Roles and device removal (R-SEC2)

Every trusted peer has a role: **admin** (its removal log is obeyed, 1 to 3 owner devices), **operator** (flies the drone) or **peer** (link traffic only). Pairing sets them (the drone saves the ground station as operator; the ground station saves the drone as peer); `oasa-pair trust --role` sets them by hand. An old `trusted-peers` is converted on first use and kept as `trusted-peers.v0-migrated`.

- `oasa-pair remove PEER` removes a device here, for good (a `removed` tombstone beats the list). `restore KEY` lifts it, and trusts nothing until you pair or `trust` it again. `removed` lists them.
- `oasa-pair revoke PEER` also adds it to this device's removal log. Devices that list this one as admin pick it up over the link, with retries; removing an admin there needs two admins. The rules are in [docs/oasa-sec-v0-rotation.md](docs/oasa-sec-v0-rotation.md).
- Files are changed under an exclusive lock on `.lock` and swapped in atomically, so several programs can share one folder.

## Signing-key rotation (R-SEC2)

When an operator is removed from a drone (or on request), the drone gets a new MAVLink signing key, so the removed operator's old key stops working.

- `oasa-pair signer --dir DIR --autopilot tcpout:HOST:PORT` runs on the drone and owns a dedicated link to the autopilot (never a router endpoint). It waits until the autopilot is disarmed, issues a new generation and key, loads it with `SETUP_SIGNING` signed by the current key, proves it with a signed command and a signed acknowledgment, and commits. If it cannot tell which key the autopilot has (a crash, a lost reply) it listens and asks under both keys before it does anything, and never deletes a key that might be in use. Only one signer runs per folder. A stuck rotation is asked again every 5 minutes. It prints one JSON line per event (`rotation_waiting_armed`, `rotation_started`, `rotation_done`, `rotation_rolled_back`, `rotation_stuck`, `rotation_refused`).
- `oasa-pair rotate-signing --dir DIR` asks for a rotation. `oasa-pair remove` of an operator asks for one too.
- The drone's `oasa-link` sends each operator the new key (`SIGNING_KEY_NEXT`) as soon as it exists, and the commit once the autopilot has it. Operators switch only on the commit; one that was away catches up when it reconnects; a removed operator is never sent anything.

Generations (`mavlink-signing-gen`) are never reused. Details and what was checked against PX4 and ArduPilot SITL: [docs/oasa-sec-v0-rotation.md](docs/oasa-sec-v0-rotation.md), [docs/sitl.md](docs/sitl.md).

## Next

- Test on real autopilot hardware (PX4 and ArduPilot SITL already pass: [docs/sitl.md](docs/sitl.md)).
- An on-drone confirm button, and checking key file ownership.
- R-COM2: radio adapters in [oasa-radio](https://github.com/joinoasa/oasa-radio) plug in where `oasa-link` uses UDP; handshakes for radios under 128 bytes; DoS cookies; group keys.
- R-SEC2: a serial autopilot link for the signer (UDP and TCP now), and rekeying other MAVLink signers on the drone (a gimbal, a second computer).
- Independent review.

Licensed under [Apache-2.0](LICENSE).
