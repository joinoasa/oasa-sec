# AGENTS.md: working in oasa-sec

Read by AI coding agents (Claude Code, Codex, Cursor and others) and useful for people too. This repo is **OASA-SEC**: device identity, encrypted pairing and link keys for OASA systems. It covers tech tree nodes R-SEC1 (identity, keys, pairing) and R-COM2 (the encrypted link), and R-SEC2 phase A (roles and device removal; signing-key rotation is phase B).

## Rules that never bend

Follow the [OASA software standard](https://joinoasa.org/docs/software-standard/). In this repo especially:

- **Encrypted, always.** Signing alone (for example MAVLink signing) is never the link; it only runs inside encryption.
- **No new crypto math.** Use the Noise Protocol Framework through `snow`, and X25519 only (for now). The link (`src/link/`) is sans-IO: no sockets, threads or clocks inside; time and randomness come in as arguments. Adding or changing a crypto dependency needs a [register](https://joinoasa.org/docs/software-register/) entry and owner approval.
- **Every device makes its own keys.** Never put keys in code, tests fixtures that ship, firmware images or commits.
- **Secrets never print.** No secret in `Debug`, logs or errors. Wipe secrets with `zeroize`.
- **Tests come with every change**, including hostile input. Changing the pairing code format or the Noise pattern changes the protocol: bump the version and say so in the pull request.

## Commands

| Command | What it does |
|---|---|
| `cargo build --bins --examples` | Build `oasa-pair` and the stand-in autopilot |
| `cargo test` | Unit tests |
| `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` | Format and lint (CI fails otherwise) |
| `scripts/e2e.sh` | End-to-end check of pairing with no hardware (needs `pip install pymavlink`, or set `PYTHON` to a venv python) |
| `scripts/link-e2e.sh` | End-to-end check of the encrypted link: real `oasa-link` processes over localhost UDP (needs `cargo build --bins`) |

## Trust files and removal

Files in a device folder: `trusted-peers.v1` (roles), `removed` (append-only tombstones, decide over the list), `removal-log`, `removal-sync/`, `admin-votes`. Change them only through `store` and `removal`, which take the `.lock` and write atomically. The control layer (`src/control.rs`) is sans-IO like the link and reads roles fresh from the files. Roles are set only by `oasa-pair`, never by a message. Spec: `docs/oasa-sec-v0-rotation.md`. The MSRV is 1.89 (`File::lock`).

## Pull requests

- Branch, then open a pull request into `main`. CI must pass.
- One topic per pull request. Say what changed and what you checked.
- Security code needs a reviewer who didn't write it.
- Commit with your GitHub no-reply email.
