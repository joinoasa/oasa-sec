# Testing against PX4 and ArduPilot SITL

`oasa-pair` is checked against the real autopilot software, running as a simulator (SITL, software in the loop). Two scripts do it. They are **not in CI**: the builds take 20 to 25 minutes.

The test scripts need `pymavlink` (`pip install pymavlink`, or point `PYTHON` at a venv python, as with `scripts/e2e.sh`) and a built `oasa-pair`:

```sh
cargo build --locked --bins --examples
```

## PX4

Tested with PX4-Autopilot commit `d4d4c154` (master, 2026-10-23), target `px4_sitl_sih` (headless), airframe `10040 sihsim_quadx`.

**Build** (about 25 min on 2 cores):

```sh
git clone --depth 1 --recurse-submodules https://github.com/PX4/PX4-Autopilot.git
```

- The clone can fail on three `boards/modalai/voxl2/*` submodules hosted on gitlab.com (403 behind some proxies). They don't matter for SITL. Update every other submodule by hand (`git submodule update --init --depth 1 <path>`), then `export GIT_SUBMODULES_ARE_EVIL=1` so `Tools/check_submodules.sh` doesn't stop the build.
- Some shallow submodules may end up with an empty worktree: `git -C <path> reset --hard HEAD`. `src/modules/mavlink/mavlink` also needs its own nested `pymavlink` submodule (`git submodule update --init --depth 1` inside it), or ninja fails on `mavgen.py`.
- `pip install empy` fails to build a wheel. Use `pip install empy==3.3.4`, plus `kconfiglib pyros-genmsg lark cerberus pyulog`.
- Then `make px4_sitl_sih`. The binary is `build/px4_sitl_sih/bin/px4`.

**Ports** (all localhost): onboard (companion) link UDP **14580**, GCS link **18570**. The system is 1, the autopilot component 1. Pair over 14580: `--autopilot udpout:127.0.0.1:14580 --target 1:1`. PX4 keeps its key in `fs/mavlink/mavlink-signing-key.bin` under its working directory (`/mavlink/mavlink-signing-key.bin` on the autopilot).

**Run:**

```sh
PX4_DIR=~/PX4-Autopilot scripts/sitl/px4-sitl-test.sh
```

It starts and stops its own PX4 in a temporary folder and takes about 2 minutes.

### PX4 results (d4d4c154, 2026-10-23)

11 of 11 checks pass, with no changes to `oasa-pair`.

| Check | Result |
|---|---|
| Pairing: drone loads the key into PX4 and verifies it with a signed command | Pass |
| (d) PX4's stored key equals the ground station's key | Pass |
| (a) Signed command from `oasa-pair command` on 14580 and 18570 | Acknowledged |
| (b) Unsigned command on both ports | Ignored |
| (c) Command signed with a wrong key on both ports | Ignored |
| (f) Unsigned `SETUP_SIGNING` (new key, zero key) | Refused; key unchanged, original key still works |
| (e) After a PX4 restart: signed command | Acknowledged (key persisted) |
| (e) After a PX4 restart: unsigned command | Ignored |

Not tested: the armed case, signed key rotation, PX4's list of messages allowed unsigned.

## ArduPilot

Tested with ArduPilot commit `2badacc9a607b2d45c42f28006e68a4424192fe3` (master, 2026-10-22), ArduCopter SITL.

**Build** (about 17 min on 2 cores):

```sh
git clone --recurse-submodules https://github.com/ArduPilot/ardupilot.git
cd ardupilot
./waf configure --board sitl
./waf copter
```

- If `pip install empy` fails to build, use `empy==3.3.4`. Also needed: `pymavlink pexpect future`.
- The binary is `build/sitl/bin/arducopter`.

**Run SITL by hand** (the script does this itself):

```sh
arducopter --model + --speedup 1 --serial0 tcp:5780 \
  --defaults Tools/autotest/default_params/copter.parm -I2
```

- **Always give `--serial0 tcp:PORT`.** Without it SERIAL0 is `tcp:...:wait` and SITL blocks at boot until something connects.
- With `-I2` the ports are SERIAL0 5780, SERIAL1 **5782**, SERIAL2 5783. (Instance N: 5760 + 10N, then +2 and +3.)
- **Pair over SERIAL1 or higher**, never SERIAL0: `--autopilot tcpout:127.0.0.1:5782 --target 1:1`. See the design doc, section 5. Use TCP serial ports; UDP client links were not tested.
- ArduPilot keeps the key in `eeprom.bin` in its working directory.

**Run the test:**

```sh
ARDUPILOT_DIR=~/ardupilot scripts/sitl/ardupilot-sitl-test.sh
```

It takes about 8 minutes: it restarts SITL several times, waits through ArduPilot's signing timestamp window, and sleeps 70 s once. `INST` (default 2) and `LISTEN` (default 7410) change the ports.

### ArduPilot results (2badacc9a607, 2026-10-23)

24 of 24 checks pass, with no changes to the pairing protocol. Pairing is over SERIAL1.

| Check | Result |
|---|---|
| Baseline, no key yet: unsigned command on SERIAL1 | Acknowledged (no key means open, as in PX4) |
| Pairing: drone loads the key and verifies it with a signed command | Pass |
| (a) Signed command from `oasa-pair command` and from pymavlink | Acknowledged |
| (b) Unsigned command on SERIAL1 and SERIAL2 | Ignored |
| (c) Command signed with a wrong key on SERIAL1 | Ignored |
| (f) SERIAL0: unsigned and wrong-key commands | **Acknowledged.** SERIAL0 never authenticates (ArduPilot's design for USB) |
| Outgoing frames on SERIAL0, 1 and 2 once keyed | All signed |
| Restart: `oasa-pair command` (retries up to 75 s) | Acknowledged; unsigned still ignored; key persisted |
| (e) Unsigned `SETUP_SIGNING` on SERIAL1 | Dropped; original key still works, attacker key doesn't |
| (e3) Signed `SETUP_SIGNING` on SERIAL1 | Rotates the key; old key dead |
| (g) Fresh drone pairs against an already-keyed autopilot | Fails safely; nothing saved; the error lists the likely causes |
| (e2) Unsigned `SETUP_SIGNING` on **SERIAL0** | **Replaces the key**, and it persists across restart |

**Timestamp window.** After a restart, ArduPilot sets its signing timestamp to the stored value plus 60 s and refuses a new signed stream until the clock catches up, up to about a minute. In an earlier run both `oasa-pair` and pymavlink were refused for 34 s after a restart. In the latest run the first command after the restart got through in 2 s, so the window varies with how long and how often the simulator ran before (the stored value is saved every 30 s and ratchets forward). `oasa-pair command` retries for `--wait` seconds (default 75) so it covers either case; the late-answer retry is also covered by `scripts/e2e.sh`. Not tested: the armed case, GPS time effects, UDP client links.

## Helpers

Test tools only, in `tests/sitl/`: `px4_client.py` (send a signed or unsigned command), `px4_setup.py` (send `SETUP_SIGNING`), `approbe.py` (same for ArduPilot, plus a check that frames are signed).
