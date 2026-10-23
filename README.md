# oasa-sec

**OASA-SEC:** device identity, encrypted pairing and link keys for [OASA](https://joinoasa.org) autonomous systems. Tech tree node **R-SEC1**.

> **Prototype.** Not independently reviewed. Do not fly with it. See [SECURITY.md](SECURITY.md).

## What it does today

1. Every device makes its own X25519 identity.
2. A drone shows a **one-time pairing code** as a QR code.
3. The ground station reads it and runs an encrypted, mutually authenticated **Noise** handshake (`IKpsk1`). Without the code, the drone won't even reply.
4. Inside that encrypted channel they share a **MAVLink 2 signing key**. On first pairing the ground station makes it; the drone loads it into its autopilot over its local wired link and proves it works before saving it. Later ground stations receive the same key.

Signing is only a second layer. Encrypting the drone link itself is next (R-COM2). The design is in [docs/oasa-sec-v0-pairing.md](docs/oasa-sec-v0-pairing.md).

## Try it (no hardware)

```sh
cargo build --bins --examples
pip install pymavlink
scripts/e2e.sh
```

That runs a stand-in autopilot, a drone, two ground stations, an attacker and pymavlink, and checks 13 things, including: the attacker is rejected by the handshake, the code is never taken on the command line, signed commands work, unsigned and wrong-key commands are ignored, our signatures interoperate with pymavlink both ways, a second ground station doesn't lock out the first, and a key the autopilot didn't take is never saved.

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

## Built on

| Project | Used for | License |
|---|---|---|
| [snow](https://github.com/mcginty/snow) | Noise handshake | Apache-2.0 or MIT |
| [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) | X25519 public keys (already used inside snow) | BSD-3 |
| [rust-mavlink](https://github.com/mavlink/rust-mavlink) | MAVLink 2 messages and signing | Apache-2.0 or MIT |
| [blake2](https://github.com/RustCrypto/hashes), [zeroize](https://github.com/RustCrypto/utils), [data-encoding](https://github.com/ia0/data-encoding), [qrcode](https://github.com/kennytm/qrcode-rust) | Fingerprints, wiping secrets, base32, QR codes | Apache-2.0 / MIT |
| [pymavlink](https://github.com/ArduPilot/pymavlink) | Independent interop check in tests only | LGPL-3.0 |

Choices follow OASA's [adoption standard](https://joinoasa.org/docs/adopting-software/) and are recorded in the [software register](https://joinoasa.org/docs/software-register/).

## Next

- Test against PX4 SITL and ArduPilot SITL.
- An on-drone confirm button, and checking key file ownership.
- R-COM2: encrypt the drone link with these identities.
- R-SEC2: key rotation and lost-device lockout.
- Independent review.

Licensed under [Apache-2.0](LICENSE).
