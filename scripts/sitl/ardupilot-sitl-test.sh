#!/usr/bin/env bash
# Check oasa-pair against a real ArduCopter SITL (headless). Test tool only.
# See docs/sitl.md for how to build ArduPilot SITL. Takes about 8 minutes
# (it waits out ArduPilot's signing timestamp window and a 70 s key check).
#
# Needs: ARDUPILOT_DIR (an ardupilot checkout built with
#        `./waf configure --board sitl && ./waf copter`),
#        `cargo build --locked --bins --examples`, and pymavlink
#        (set PYTHON to a venv python if needed).
# Run from anywhere: ARDUPILOT_DIR=~/ardupilot scripts/sitl/ardupilot-sitl-test.sh
# Optional: INST (SITL instance, default 2; ports are 5760 + 10*INST), LISTEN (pairing port).
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
ARDUPILOT_DIR=${ARDUPILOT_DIR:?set ARDUPILOT_DIR to your ardupilot checkout}
PYTHON=${PYTHON:-python3}
OASA=$ROOT/target/debug/oasa-pair
HELP=$ROOT/tests/sitl
SITL_BIN=$ARDUPILOT_DIR/build/sitl/bin/arducopter
INST=${INST:-2}
BASE=$((5760 + 10 * INST))
P0=$BASE; P1=$((BASE + 2)); P2=$((BASE + 3))   # SERIAL0 (channel 0, "USB"), SERIAL1, SERIAL2
LISTEN=${LISTEN:-7410}

[ -x "$OASA" ] || { echo "build first: cargo build --locked --bins --examples"; exit 2; }
[ -x "$SITL_BIN" ] || { echo "ArduPilot SITL not built: $SITL_BIN (./waf copter)"; exit 2; }
$PYTHON -I -c 'from pymavlink import mavutil' 2>/dev/null \
  || { echo "pymavlink is not importable by $PYTHON (pip install pymavlink)"; exit 2; }

T=$(mktemp -d); mkdir "$T/sitl"
SITL_PID=; DRONE_PID=
PASS=0; FAILS=0
cleanup() {
  [ -n "$DRONE_PID" ] && kill "$DRONE_PID" 2> /dev/null
  [ -n "$SITL_PID" ] && kill "$SITL_PID" 2> /dev/null
  [ -n "$SITL_PID" ] && wait "$SITL_PID" 2> /dev/null
  rm -rf "$T"
}
trap cleanup EXIT

# check NAME EXPECTED ACTUAL, where each is "ACK" or "no-ACK" (or any word).
check() {
  if [ "$2" = "$3" ]; then echo "PASS  $1 ($3)"; PASS=$((PASS + 1)); else echo "FAIL  $1 (expected $2, got $3)"; FAILS=$((FAILS + 1)); fi
}

PROBE="$PYTHON -I $HELP/approbe.py"
ack() { "$@" > /dev/null 2>&1 && echo ACK || echo no-ACK; }
# oasa-pair command with a short --wait, so negative checks don't take 75 s.
oack() { ack "$OASA" command --dir "$T/gcs" --to "tcpout:127.0.0.1:$1" --wait "${2:-4}"; }

# --serial0 tcp:PORT matters: without it SERIAL0 waits for a client and SITL blocks at boot.
start_sitl() {
  ( cd "$T/sitl" && exec "$SITL_BIN" --model + --speedup 1 --serial0 tcp:$P0 \
      --defaults "$ARDUPILOT_DIR/Tools/autotest/default_params/copter.parm" -I$INST --sysid 1 \
      >> "$T/sitl.log" 2>&1 ) &
  SITL_PID=$!
  for _ in $(seq 100); do (exec 3<> /dev/tcp/127.0.0.1/$P1) 2> /dev/null && break; sleep 0.3; done
  sleep 3
}
stop_sitl() { kill "$SITL_PID" 2> /dev/null; wait "$SITL_PID" 2> /dev/null; SITL_PID=; sleep 1; }

start_sitl
for d in drone gcs; do "$OASA" init --dir "$T/$d" > /dev/null; done

echo "== baseline: no key yet, so an unsigned command on SERIAL1 works"
check baseline-unsigned-serial1 ACK "$(ack $PROBE cmd $P1 none)"

echo "== pairing over SERIAL1 (tcpout:127.0.0.1:$P1)"
"$OASA" drone --dir "$T/drone" --name drone-1 --listen 127.0.0.1:$LISTEN --wait 60 \
  --autopilot tcpout:127.0.0.1:$P1 --target 1:1 > "$T/drone.log" 2>&1 &
DRONE_PID=$!
for _ in $(seq 50); do grep -q 'OASA1-' "$T/drone.log" && break; sleep 0.1; done
CODE=$(grep -o 'OASA1-[A-Z2-7]*' "$T/drone.log")
echo "$CODE" | "$OASA" ground --dir "$T/gcs" --name gcs-1 --connect 127.0.0.1:$LISTEN --code - > "$T/gcs.log" 2>&1
wait "$DRONE_PID"; DRONE_PID=
FP=$("$OASA" init --dir "$T/drone" | awk '{print $3}')
GKEY=$T/gcs/signing-keys/$FP.bin
if [ -f "$GKEY" ] && [ -f "$T/drone/mavlink-signing-key.bin" ]; then
  check pairing-key-accepted-by-ArduPilot yes yes
else
  check pairing-key-accepted-by-ArduPilot yes no; cat "$T/drone.log" "$T/gcs.log"; exit 1
fi
head -c 32 /dev/urandom > "$T/wrong.bin"; head -c 8 /dev/zero >> "$T/wrong.bin"

echo "== (a) signed command with the paired key"
check a-oasa-pair-signed-serial1 ACK "$(oack $P1 10)"
check a-pymavlink-signed-serial1 ACK "$(ack $PROBE cmd $P1 "$GKEY")"
echo "== (b) unsigned command on SERIAL1 and SERIAL2"
check b-unsigned-serial1 no-ACK "$(ack $PROBE cmd $P1 none)"
check b-unsigned-serial2 no-ACK "$(ack $PROBE cmd $P2 none)"
echo "== (c) wrong key"
check c-wrongkey-serial1 no-ACK "$(ack $PROBE cmd $P1 "$T/wrong.bin")"
echo "== (f) SERIAL0 never authenticates (ArduPilot design: USB is trusted)"
check f-unsigned-serial0 ACK "$(ack $PROBE cmd $P0 none)"
check f-wrongkey-serial0 ACK "$(ack $PROBE cmd $P0 "$T/wrong.bin")"
echo "== outgoing frames are signed on every link once a key is set"
for p in $P0 $P1 $P2; do
  line=$($PROBE rx $p "$GKEY"); n=${line#*frames=}; n=${n%% *}; sg=${line##*signed=}
  [ "$n" -gt 0 ] 2> /dev/null && check "telemetry-signed-port-$p" yes "$([ "$n" = "$sg" ] && echo yes || echo no)" \
    || check "telemetry-signed-port-$p" yes "no-frames"
done

echo "== restart: oasa-pair command keeps trying through ArduPilot's timestamp window"
# After a restart ArduPilot may refuse a new signed stream for up to a minute (how long
# varies with how long it ran before); command must keep trying and get through.
stop_sitl; start_sitl; t0=$(date +%s)
r=$(ack "$OASA" command --dir "$T/gcs" --to tcpout:127.0.0.1:$P1 --wait 75)
echo "     first ACK after restart: $(($(date +%s) - t0)) s"
check restart-oasa-pair-command-within-75s ACK "$r"
check restart-unsigned-ignored no-ACK "$(ack $PROBE cmd $P1 none)"
check restart-key-persisted ACK "$(ack $PROBE cmd $P1 "$GKEY")"

echo "== (e) unsigned SETUP_SIGNING on SERIAL1 is dropped"
ATT=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
$PYTHON -I -c "import sys;open(sys.argv[2],'wb').write(bytes.fromhex(sys.argv[1])+bytes(8))" "$ATT" "$T/att.bin"
$PROBE setup $P1 none "$ATT"
check e-original-key-still-works ACK "$(ack $PROBE cmd $P1 "$GKEY")"
check e-attacker-key-refused no-ACK "$(ack $PROBE cmd $P1 "$T/att.bin")"

echo "== (e3) signed SETUP_SIGNING on SERIAL1 rotates the key (R-SEC2 can build on this)"
NEW=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
$PYTHON -I -c "import sys;open(sys.argv[2],'wb').write(bytes.fromhex(sys.argv[1])+bytes(8))" "$NEW" "$T/new.bin"
# The timestamp window can make ArduPilot refuse a new signed stream, so send again until it takes.
r=no-ACK
for _ in $(seq 20); do
  $PROBE setup $P1 "$GKEY" "$NEW" > /dev/null
  r=$(ack $PROBE cmd $P1 "$T/new.bin"); [ "$r" = ACK ] && break
  sleep 3
done
check e3-new-key-works ACK "$r"
check e3-old-key-dead no-ACK "$(ack $PROBE cmd $P1 "$GKEY")"

echo "== (g) a fresh drone can't pair with an already-keyed autopilot, and saves nothing"
for d in drone2 gcs2; do "$OASA" init --dir "$T/$d" > /dev/null; done
"$OASA" drone --dir "$T/drone2" --name drone-2 --listen 127.0.0.1:$LISTEN --wait 30 \
  --autopilot tcpout:127.0.0.1:$P1 --target 1:1 > "$T/drone2.log" 2>&1 &
DRONE_PID=$!
for _ in $(seq 50); do grep -q 'OASA1-' "$T/drone2.log" && break; sleep 0.1; done
C2=$(grep -o 'OASA1-[A-Z2-7]*' "$T/drone2.log")
echo "$C2" | "$OASA" ground --dir "$T/gcs2" --name gcs-2 --connect 127.0.0.1:$LISTEN --code - > "$T/gcs2.log" 2>&1
wait "$DRONE_PID"; DRONE_PID=
check g-no-key-saved yes "$([ -e "$T/drone2/mavlink-signing-key.bin" ] && echo no || echo yes)"
check g-error-names-causes yes "$(grep -q 'Likely causes' "$T/drone2.log" && echo yes || echo no)"

echo "== (e2) unsigned SETUP_SIGNING on SERIAL0 replaces the key (design: physical access = control)"
stop_sitl; start_sitl
$PROBE setup $P0 none "$ATT"
sleep 70   # let the signing timestamp window pass
check e2-attacker-key-active-after-serial0-setup ACK "$(ack $PROBE cmd $P1 "$T/att.bin")"
check e2-rotated-key-dead no-ACK "$(ack $PROBE cmd $P1 "$T/new.bin")"
stop_sitl; start_sitl; sleep 5
for _ in $(seq 20); do [ "$(ack $PROBE cmd $P1 "$T/att.bin")" = ACK ] && break; sleep 4; done
check e2-attacker-key-persists-after-restart ACK "$(ack $PROBE cmd $P1 "$T/att.bin")"

echo "$PASS passed, $FAILS failed"
[ "$FAILS" = 0 ]
