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

## What the autopilots do with key changes (2026-10-23)

Checked by hand against the same builds as above (PX4 `d4d4c154`, ArduPilot `2badacc9a607`), directly on the autopilots, not through the tunnel. Built to decide what the MAVLink guard in `oasa-link` must block ([link doc](oasa-sec-v0-link.md) section 7). Each result is a run of pymavlink against a fresh simulator; the probe scripts were throwaway and are not kept, but `l1-mavlink-sitl` in [oasa-lab](https://github.com/joinoasa/oasa-lab) repeats the guard cases through the tunnel.

### PX4

| Question | Result |
|---|---|
| Does a **signed** `SETUP_SIGNING` change the key once keyed? | **Yes, on both ports.** Signed with key 1, new key 2 on 14580: key file became key 2, key 1 stopped working. Then new key 3 on 18570: same. |
| Does an all-zero `SETUP_SIGNING` (zero key, zero timestamp) matter? | **Signed with the current key it turns signing off**: the key file became all zero and an unsigned command was then acknowledged. Unsigned, it is refused (earlier section, check f). |
| Does PX4 sign what it sends once keyed? | **Yes.** On 14580, 1698 frames counted from the raw datagrams, all signed (flag set), none unsigned. |
| Signing parameters? | **None.** 1027 parameters; the only names containing `SIGN` are `ADSB_CALLSIGN_1` and `_2`; `MAV_*` are `COMP_ID`, `FWDEXTSP`, `HASH_CHK_EN`, `HB_FORW_EN`, `PROTO_VER`, `RADIO_TOUT`, `SIK_RADIO_ID`, `SYS_ID`, `TYPE`, `USEHILGPS`. The source has no signing setting either (`mavlink_params.yaml`). So no `PARAM_SET` can turn signing off. |
| FTP enabled in SITL? | **Yes**, on 14580 and 18570. The FTP root is PX4's working folder, so the key is `/fs/mavlink/mavlink-signing-key.bin`. |
| Can FTP **read** the key? | **Yes.** A signed FTP open and read of that path returned the 40-byte key file (first 32 bytes equal the key in use). |
| Can FTP **write** the key? | **Yes.** A signed FTP create and write of that path replaced the key file. After a PX4 restart, PX4 used the new key. (Writes are allowed under `./fs/`, which holds the key.) |
| Unsigned FTP? | Ignored once keyed. |
| Signed `SETUP_SIGNING` while armed? | **Refused.** Armed in SIH, signed `SETUP_SIGNING` with a new key: key file unchanged, the old key still worked, the new one did not. |
| An unsigned MAVLink 1 command to a keyed PX4? | Not answered. |

Why FTP matters: any peer that can send signed FTP can read the key out of the drone or replace it, and the next restart makes the replacement real.

### ArduPilot

| Question | Result |
|---|---|
| Signed `SETUP_SIGNING` while armed? | **Refused.** The autopilot sent `ERROR: Won't setup signing when armed`; the old key kept working and the new one did not. After disarming, the same message was accepted. |
| All-zero `SETUP_SIGNING`, signed? | Turns signing off (an unsigned command was then acknowledged). |
| Does ArduPilot sign what it sends once keyed? | **Yes.** On SERIAL1 4 of 4 frames and on SERIAL2 7 of 7 were signed, none unsigned (a short count; the earlier section counted every link). |
| Signing parameters? | No parameter has `SIGN` in its name apart from the unrelated `SIM_ARSPD_SIGN`. But **`MAV<n>_OPTIONS` bit 0 turns signing off for that link**: in the code (`GCS_MAVLINK::load_signing_key`) the bit is `MAVLINK2_SIGNING_DISABLED`, although the parameter text says "Accept unsigned MAVLink2 messages". Signed `PARAM_SET` of `MAV2_OPTIONS` and `MAV3_OPTIONS` to 1 had no effect at once; after a restart, unsigned commands were acknowledged on SERIAL1 and SERIAL2. (`MAV1_OPTIONS` alone changed nothing on those two ports; `MAV_OPTIONS` is a different setting.) It also takes effect at the next key load. |
| FTP? | Not tested. ArduPilot keeps its key in storage, not in a file. |

### The guard: an allowlist

The first version of the guard was a block list built from the results above. It is now an **allowlist** (2026-10-23): a block list only stops what we thought of, and every other message, command or parameter reaches the autopilot. The tables are in the [link doc](oasa-sec-v0-link.md) section 7. In short:

| Rule | Because |
|---|---|
| `SETUP_SIGNING` (256) is always dropped | Both autopilots take a signed one: it replaces the key, and an all-zero one turns signing off |
| `FILE_TRANSFER_PROTOCOL` (110) dropped, unless `--allow-mavlink-ftp` | PX4 FTP reads and replaces the key file |
| `PARAM_SET` (23) and `PARAM_EXT_SET` (323) dropped, unless `--allow-param NAME` | `MAV<n>_OPTIONS` turns ArduPilot signing off after a restart, and any parameter can change what the vehicle does. Names starting `MAV_SIGN` or `MAV<n>_OPTIONS` can never be allowed |
| Messages not in the default list dropped (`--allow-msg ID` widens) | A ground station needs a small set to monitor and fly |
| Commands not in the default list dropped (`--allow-command ID` widens) | `COMMAND_LONG`, `COMMAND_INT` and mission items can reboot, calibrate, write storage, move servos or terminate flight |
| Mission messages for the geofence (type 1), rally points (2) and all types (255) dropped, unless `--allow-fence-rally` (never 255) | A clear-all, or a count of 0, of those types erases the fence or rally points on both autopilots |
| `GPS_INJECT_DATA` and `GPS_RTCM_DATA` dropped, unless `--allow-rtk` | Raw bytes to the GPS receiver, which could reconfigure it |
| Frames of the wrong length dropped | MAVLink 1 sends exactly the base length, MAVLink 2 at most the longest; anything else is not what the autopilot's parser expects |
| Every allowed frame's CRC is checked | A frame with a wrong CRC is dropped, so what the guard read is what the autopilot reads |

Both autopilots refuse key changes while armed, so the key rules matter on the ground. The other rules apply in flight too.

Checked: the lab suite `l1-mavlink-sitl` flies both autopilots through the tunnel with the default allowlist (arm, takeoff, hold, mission upload and run, RTL, land) and repeats each drop case, including a geofence clear. `tests/interop/mavguard_diff.py` compares the guard with pymavlink on every message of the common dialect plus damaged and batched datagrams: where the guard passes a datagram, pymavlink reads the same frame boundaries and ids. `cargo mutants` on `src/mavguard.rs` (not in CI): 133 mutants, 124 caught, 2 unviable, 1 timeout, 6 missed. Five of the six are equivalent: `<` against `<=` on header-length guards whose next check fails the same way, and `|` against `^` where the bits never overlap. The sixth (the RTK match arm) now has a test.

Still possible with the default list: `SET_MODE`, `RC_CHANNELS_OVERRIDE`, `MANUAL_CONTROL` and offboard setpoints steer the vehicle. That is what a paired ground station is for. Signing keys and the pairing decide who may send them; the guard only limits what the paired station can ask for.
