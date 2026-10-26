# Release record: R-SEC1 (device identity, keys, pairing)

OASA release standard: a project is released when it has a working build, docs someone else can follow, a bill of materials (for hardware), test results, a security review (for anything that communicates) and a training guide.

**Status: not released.** Everything below is done except the **human security review**, which is required before the node is done. Real-hardware and armed-vehicle tests are also still open. This is a prototype: do not fly with it.

| Item | Status | Where |
|---|---|---|
| Working build | Done | `cargo build --locked --bins --examples` succeeds; section 2 |
| Docs someone else can follow | Done, run word for word on a laptop | [guide-pairing.md](guide-pairing.md), plus the design in [oasa-sec-v0-pairing.md](oasa-sec-v0-pairing.md) |
| Bill of materials | Not applicable (software only) | none |
| Test results | Done for software; SITL results are older (not re-run) | section 3 |
| Security review | **Incomplete: AI reviews only, no human review** | section 4 |
| Training guide | Done, labs run word for word on a laptop | [training-r-sec1.md](training-r-sec1.md) |

R-SEC1 shares this repo with R-COM2 (the link) and R-SEC2 (roles, removal, rotation). The test results below cover the whole repo at this commit. The docs here are for R-SEC1, and they also cover the R-SEC2 commands (`remove`, `revoke`, `signer`) because the release needs a way to take a lost device out.

## 1. What was tested, and on what

| | |
|---|---|
| Commit | `7ab7ddb45cf0d4e78b266229f0d88266cf6fdb46` (branch `rsec1-release`, based on `rsec2-impl` = open pull request #8, R-SEC2). The docs in this release are one further commit and change no code. |
| Date | 2026-10-26 |
| Machine | Linux x86-64, 2 CPUs, one cargo job at a time (`-j1`) |
| Toolchain | cargo 1.97.0, rustc 1.97.0 (stable); the project's MSRV is 1.89 and was not tested separately |
| Tools | cargo-deny 0.20.2, cargo-audit 0.22.2 (advisory database: 1355 advisories), Python 3.13.17, pymavlink 2.4.50 (venv) |
| Dependencies | `Cargo.lock` as committed (`--locked`); snow 0.10.0 |

## 2. Build

```sh
cargo build -j1 --locked --bins --examples
```

Result: finished, no warnings.

## 3. Test results

All run on this commit on 2026-10-26.

| Check | Command | Result |
|---|---|---|
| Unit and integration tests | `cargo test -j1 --locked` | **309 passed, 0 failed.** `src/lib.rs` 255, `oasa-link` 10, `oasa-pair` 0, `tests/link_sim.rs` 29, `tests/pair_cli.rs` 15, doc-tests 0 |
| Lint | `cargo clippy -j1 --locked --all-targets -- -D warnings` | Clean |
| Format | `cargo fmt --check` | Clean |
| Pairing end to end | `PYTHON=<venv>/bin/python scripts/e2e.sh` | **Passed: 19 checks, 0 failed** (`All end-to-end checks passed.`): attacker rejected, code never on the command line, signed commands accepted, unsigned and wrong-key ignored, pymavlink interop both ways, second ground station, a key the autopilot did not take is never saved, permissions, rotation and its failure cases |
| Link end to end | `PYTHON=<venv>/bin/python scripts/link-e2e.sh` | **Passed: 31 checks, 0 failed.** Real `oasa-link` processes over localhost UDP, including the MAVLink guard |
| Licenses, bans, sources | `cargo deny --locked check` | `advisories ok, bans ok, licenses ok, sources ok`. 11 warnings, all duplicate versions of a crate (for example `blake2`, `curve25519-dalek`, `syn`); no failure |
| Known vulnerabilities | `cargo audit` | Exit 0; 92 crate dependencies scanned against the RustSec database; no vulnerabilities reported |
| Guide | the `sh` blocks of section 2 of [guide-pairing.md](guide-pairing.md), extracted and run | Worked verbatim after one fix (see below) |
| Training | the `sh` blocks of [training-r-sec1.md](training-r-sec1.md) from section 2 on, extracted and run | Worked verbatim; the output matches the "Expected" text |

Fix found by running the guide: the stand-in autopilot is in `target/debug/examples/`, not on `PATH`. (The unsigned check exits 2 on purpose, so the guide's blocks are not meant to run under `set -e`.) Also checked by hand: the error texts in the guide's table, apart from the ones the guide does not quote.

CI (`.github/workflows/ci.yml`) runs fmt, clippy, tests, deny, audit, both end-to-end scripts and the oasa-lab suite `l1-oasa-link` on every pull request. The lab suite was not run here.

### Real PX4 and ArduPilot simulators (SITL): not re-run

These take 20 minutes or more to build, so they were **not re-run on this commit**. The results below are from [sitl.md](sitl.md) and are older.

| Autopilot | Result | When | Against |
|---|---|---|---|
| PX4 (`px4_sitl_sih`) | 11 of 11 pairing checks pass | 2026-10-23 | PX4 `d4d4c154`, oasa-pair before R-SEC2 |
| ArduPilot (ArduCopter) | 24 of 24 pairing checks pass | 2026-10-23 | ArduPilot `2badacc9a607`, oasa-pair before R-SEC2 |
| PX4 with signing-key rotation | 39 of 39 pass | run 2026-10-23, again 2026-10-24 | same PX4 build |
| ArduPilot with signing-key rotation | 42 of 42 pass | run 2026-10-23, again 2026-10-24 | same ArduPilot build |

The commits that those runs used are not the commit above. Re-run `scripts/sitl/px4-sitl-test.sh` and `scripts/sitl/ardupilot-sitl-test.sh` on the release commit before the node is called done.

### Not tested

- Real autopilot hardware, a real companion computer, and real radios.
- Armed-vehicle behaviour: both autopilots refuse key changes while armed (checked in SITL); nothing was flown.
- Signing-key rotation through `oasa-pair` on real autopilots (SITL only).
- A serial link between the companion and autopilot (UDP and TCP only).
- Long runs. MSRV 1.89 as a separate build.

## 4. Security review

### Done

| Review | Who | Result |
|---|---|---|
| R-SEC1 code and design review | Independent AI reviewer (not the author) | No High findings. Four Medium findings, all fixed: a pairing jam (a stranger holding the drone's pairing open), autopilot lockout on a failed key load, a second ground station overwriting the first's key, and the pairing code on the command line |
| R-SEC2 reviews | Two independent AI reviews | Findings applied; see "design reviews 1 and 2" and "code review 1 and 2" in [oasa-sec-v0-rotation.md](oasa-sec-v0-rotation.md) |
| Dependency gates | `cargo deny`, `cargo audit` | Pass (section 3) |
| Hostile-input tests | In the test suite (simulated attacker, replays, corruption, forged codes and replies) | Pass |
| Design rules | [AGENTS.md](../AGENTS.md) | No custom crypto: Noise via `snow`, X25519 only. Secrets are wiped (`zeroize`) and never printed |

The AI review reports themselves are not stored in this repo. This record repeats their results as given in the project's build log; they have not been re-checked here.

Of the crypto library: `snow` was reviewed by **Trail of Bits** (checked 2026-10-26). 1Password's post on [strengthening snow](https://1password.com/blog/strengthening-snow-for-the-open-source-community) says Trail of Bits reviewed it "through a combination of manual review and automated testing over four engineer-weeks", with 10 findings (one medium, one low, eight informational) and 8 of 10 resolved at the time of the post (one was a nonce-handling bug, another an invalid-PSK-index panic). The post gives no version or date; the report's filename suggests March 2024, which is **unconfirmed**, and may predate the snow 0.10.0 used here. That review covers `snow`, not this code.

### Still missing

- **A human security review of this code. Required before the node is done.** AI reviews do not replace it. SECURITY.md and the design docs still say "not independently reviewed".
- Tests on real hardware, and with an armed vehicle (section 3).
- Old SITL results re-run on the release commit.
- Known limits in [oasa-sec-v0-pairing.md](oasa-sec-v0-pairing.md#6-known-limits-v0): `snow` does not wipe its own handshake state, file ownership is not checked, there is no on-drone confirm button, and PX4 accepts the first key unsigned until a drone is paired.
- Safety notes that depend on the operator, listed in the guide: ArduPilot SERIAL0 is always trusted, PX4's secure bootloader ships a public test key, and a removed operator's key works until the signer has run.

## 5. Before this node is released

1. Human security review: findings fixed or accepted in writing.
2. Merge pull request #8 (R-SEC2), then rebase this branch and re-run section 3 on the merge commit.
3. Re-run both SITL scripts on that commit, and record the results here.
4. A person who did not write the docs follows the guide and runs the training labs.
5. If possible, one real autopilot and companion computer.
6. Update the "Prototype" notice only when the review and tests say so.
