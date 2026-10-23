#!/usr/bin/env bash
# Check oasa-pair against a real PX4 SITL (SIH, headless). Test tool only.
# See docs/sitl.md for how to build PX4 SITL.
#
# Needs: PX4_DIR (a PX4-Autopilot checkout built with `make px4_sitl_sih`),
#        `cargo build --locked --bins --examples`, and pymavlink
#        (set PYTHON to a venv python if needed).
# Run from anywhere: PX4_DIR=~/PX4-Autopilot scripts/sitl/px4-sitl-test.sh
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
PX4_DIR=${PX4_DIR:?set PX4_DIR to your PX4-Autopilot checkout}
PYTHON=${PYTHON:-python3}
OASA=$ROOT/target/debug/oasa-pair
HELP=$ROOT/tests/sitl
BLD=$PX4_DIR/build/px4_sitl_sih
LISTEN=${LISTEN:-7400}   # drone's pairing port
AP=14580                 # PX4 onboard (companion) link; the GCS link is 18570

[ -x "$OASA" ] || { echo "build first: cargo build --locked --bins --examples"; exit 2; }
[ -x "$BLD/bin/px4" ] || { echo "PX4 SITL not built: $BLD/bin/px4 (make px4_sitl_sih)"; exit 2; }
$PYTHON -I -c 'from pymavlink import mavutil' 2>/dev/null \
  || { echo "pymavlink is not importable by $PYTHON (pip install pymavlink)"; exit 2; }

W=$(mktemp -d); RUN=$W/run; mkdir -p "$RUN"
PX4_PID=; DRONE_PID=
PASS=0; FAILS=0
ok()  { echo "PASS  $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL  $1"; FAILS=$((FAILS + 1)); }

start_px4() {
  ( cd "$RUN" && PX4_SYS_AUTOSTART=10040 PX4_SIMULATOR=sihsim PX4_SIM_MODEL=sihsim_quadx \
      exec "$BLD/bin/px4" -d "$BLD/etc" -s etc/init.d-posix/rcS -t "$PX4_DIR/test_data" -w . \
      >> px4.log 2>&1 < /dev/null ) &
  PX4_PID=$!
  sleep 12
}
stop_px4() {
  [ -n "$PX4_PID" ] && kill "$PX4_PID" 2>/dev/null
  [ -n "$PX4_PID" ] && wait "$PX4_PID" 2>/dev/null
  PX4_PID=; sleep 1
}
cleanup() {
  [ -n "$DRONE_PID" ] && kill "$DRONE_PID" 2>/dev/null
  stop_px4
  rm -rf "$W"
}
trap cleanup EXIT

PY="$PYTHON -I $HELP/px4_client.py"
SETUP="$PYTHON -I $HELP/px4_setup.py"
K=$RUN/fs/mavlink/mavlink-signing-key.bin   # PX4's stored key

start_px4
"$OASA" init --dir "$W/drone" > /dev/null; "$OASA" init --dir "$W/gcs" > /dev/null

"$OASA" drone --dir "$W/drone" --name drone-1 --listen 127.0.0.1:$LISTEN --wait 60 \
  --autopilot udpout:127.0.0.1:$AP --target 1:1 > "$W/drone.log" 2>&1 &
DRONE_PID=$!
for _ in $(seq 50); do grep -q 'OASA1-' "$W/drone.log" && break; sleep 0.1; done
CODE=$(grep -o 'OASA1-[A-Z2-7]*' "$W/drone.log")
if echo "$CODE" | "$OASA" ground --dir "$W/gcs" --name gcs-1 --connect 127.0.0.1:$LISTEN --code - > /dev/null \
   && wait "$DRONE_PID"; then
  ok "pairing; PX4 accepted the key"
else
  bad "pairing"; cat "$W/drone.log"
fi
DRONE_PID=

GK=$(ls "$W"/gcs/signing-keys/*.bin 2> /dev/null | head -n1)
if [ -n "$GK" ] && cmp -s <(head -c32 "$K") <(head -c32 "$GK"); then
  ok "(d) PX4 key file matches the pairing key"
else
  bad "(d) PX4 key file does not match the pairing key"
fi

for p in $AP 18570; do
  "$OASA" command --dir "$W/gcs" --to udpout:127.0.0.1:$p > /dev/null \
    && ok "(a) signed command acknowledged on $p" || bad "(a) signed command on $p"
  $PY none 127.0.0.1 $p > /dev/null; [ $? = 2 ] && ok "(b) unsigned command ignored on $p" || bad "(b) unsigned on $p"
  head -c 40 /dev/urandom > "$W/wrong.bin"
  $PY "$W/wrong.bin" 127.0.0.1 $p > /dev/null; [ $? = 2 ] && ok "(c) wrong-key command ignored on $p" || bad "(c) wrong key on $p"
done

before=$(md5sum < "$K")
$SETUP "$(printf 'ab%.0s' $(seq 32))" $AP > /dev/null
$SETUP zero $AP > /dev/null; sleep 1
if [ "$before" = "$(md5sum < "$K")" ] \
   && "$OASA" command --dir "$W/gcs" --to udpout:127.0.0.1:$AP > /dev/null; then
  ok "(f) unsigned SETUP_SIGNING (new key, zero key) refused; key unchanged"
else
  bad "(f) unsigned SETUP_SIGNING changed the key"
fi

stop_px4; start_px4
"$OASA" command --dir "$W/gcs" --to udpout:127.0.0.1:$AP > /dev/null \
  && ok "(e) signed command works after PX4 restart" || bad "(e) signed command after restart"
$PY none 127.0.0.1 $AP > /dev/null; [ $? = 2 ] && ok "(e) unsigned still ignored after restart" || bad "(e) unsigned after restart"

echo "$PASS passed, $FAILS failed"
[ "$FAILS" = 0 ]
