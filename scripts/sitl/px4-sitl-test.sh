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
  [ -n "${KEEP:-}" ] && echo "kept $W" || rm -rf "$W"
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

# ---- Signing-key rotation (R-SEC2 phase B) ----------------------------------
# The signer talks to PX4 through a gate (tests/sitl/udp_gate.py) that can drop what PX4 says, or the
# key change itself. Plain commands and the arm helper use the other port (18570), so they do not
# take PX4's onboard link away from the signer (PX4 answers whoever spoke last).
GCS_PORT=18570
GATE_PORT=14680
MODE=$W/gate.mode
CMD() { "$OASA" command --dir "$1" --to udpout:127.0.0.1:$GCS_PORT --wait "${2:-8}" > /dev/null 2>&1; }
wait_n() { # secs pattern file n
  local i
  for i in $(seq $(($1 * 10))); do [ "$(grep -c -- "$2" "$3" 2> /dev/null)" -ge "$4" ] && return 0; sleep 0.1; done
  return 1
}
cnt() { grep -c -- "$1" "$2" 2> /dev/null; }
# Wait until pattern $2 shows up in file $3 more often than $4 times (a count taken before the step).
wait_more() { wait_n "$1" "$2" "$3" $(($4 + 1)); }
# Wait until no rotation is pending or half done (a request can ask for one extra rotation).
settle() {
  local i
  for i in $(seq 1200); do
    [ ! -e "$W/drone/mavlink-signing-key.next" ] && [ ! -s "$W/drone/rotation-pending" ] && return 0
    sleep 0.1
  done
  return 1
}
same_key() { cmp -s <(head -c32 "$1") <(head -c32 "$2"); }
DK=$W/drone/mavlink-signing-key.bin
G1KEY=$(ls "$W"/gcs/signing-keys/*.bin | head -n1); cp "$G1KEY" "$W/gcs1-old.bin"
DFP=$(basename "$G1KEY" .bin)

# A second operator, then the links: the drone's oasa-link to it hands it every new key.
"$OASA" init --dir "$W/gcs2" > /dev/null
"$OASA" drone --dir "$W/drone" --name drone-1 --listen 127.0.0.1:$LISTEN --wait 60 \
  --autopilot udpout:127.0.0.1:$AP --target 1:1 > "$W/drone2.log" 2>&1 &
DRONE_PID=$!
for _ in $(seq 50); do grep -q 'OASA1-' "$W/drone2.log" && break; sleep 0.1; done
CODE2=$(grep -o 'OASA1-[A-Z2-7]*' "$W/drone2.log")
echo "$CODE2" | "$OASA" ground --dir "$W/gcs2" --name gcs-2 --connect 127.0.0.1:$LISTEN --code - > /dev/null \
  && wait "$DRONE_PID" && ok "second operator pairs (shares the existing key)" || bad "second pairing"
DRONE_PID=
LINK=$ROOT/target/debug/oasa-link
"$LINK" --dir "$W/drone" --peer gcs-2 --bind 127.0.0.1:7501 --plain-listen 127.0.0.1:7511 --plain-send 127.0.0.1:7512 \
  --duration 3000 > "$W/dlink.log" 2>&1 &
DLINK=$!
"$LINK" --dir "$W/gcs2" --peer drone-1 --bind 127.0.0.1:7502 --remote 127.0.0.1:7501 --initiate \
  --plain-listen 127.0.0.1:7521 --plain-send 127.0.0.1:7522 --duration 3000 > "$W/glink.log" 2>&1 &
GLINK=$!
$PYTHON -I "$HELP/udp_gate.py" $GATE_PORT $AP "$MODE" > "$W/gate.log" 2>&1 &
GATE=$!
trap 'kill $DLINK $GLINK $GATE $SIGNER 2> /dev/null; cleanup' EXIT
wait_n 15 session_established "$W/dlink.log" 1 && ok "drone and operator 2 have a link session" || bad "no link session"

start_signer() { # logfile
  "$OASA" signer --dir "$W/drone" --autopilot udpout:127.0.0.1:$GATE_PORT --target 1:1 > "$1" 2>&1 &
  SIGNER=$!
}
op2_has() { # wait until operator 2 holds the drone's key (and generation $1)
  local i
  for i in $(seq 200); do
    same_key "$DK" "$W/gcs2/signing-keys/$DFP.bin" && [ "$(cat "$W/gcs2/signing-keys/$DFP.gen" 2> /dev/null)" = "$1" ] && return 0
    sleep 0.1
  done
  return 1
}

# 1. Armed: the signer waits. An operator is removed meanwhile; after disarm the key changes.
$PYTHON -I "$HELP/arm.py" "$G1KEY" 127.0.0.1 $GCS_PORT arm > /dev/null && ok "PX4 armed (signed command)" || bad "could not arm PX4"
start_signer "$W/signer1.log"
sleep 2
"$OASA" remove --dir "$W/drone" gcs-1 > /dev/null
before=$(md5sum < "$K")
wait_n 20 rotation_waiting_armed "$W/signer1.log" 1 && ok "armed: the signer reports the rotation as waiting" || bad "armed: no waiting report"
sleep 5
if [ "$before" = "$(md5sum < "$K")" ] && ! grep -q rotation_started "$W/signer1.log"; then
  ok "armed: nothing was sent while PX4 is armed; the key is unchanged"
else
  bad "armed: the signer acted while armed"
fi
$PYTHON -I "$HELP/arm.py" "$W/gcs1-old.bin" 127.0.0.1 $GCS_PORT disarm > /dev/null || bad "could not disarm"
wait_n 60 rotation_done "$W/signer1.log" 1 && ok "disarmed: the rotation ran" || bad "disarmed: no rotation"
same_key "$DK" "$K" && ok "PX4's key file is the drone's new key" || bad "PX4 key differs from the drone's key"
[ "$(cat "$W/drone/mavlink-signing-gen")" = 1 ] && ok "generation 1 issued and saved" || bad "generation"
CMD "$W/gcs" 5 && bad "the removed operator's old key still works on PX4" || ok "the removed operator's old key is dead"
op2_has 1 && ok "operator 2 received the new key from the drone's link" || bad "operator 2 never got the new key"
CMD "$W/gcs2" 20 && ok "operator 2's new key works on PX4" || bad "operator 2's new key does not work"
CMD "$W/drone" 20 && ok "the drone's own new key works" || bad "drone key"

# 2. Lost COMMAND_ACK. Only acknowledgments are lost: PX4 signs its heartbeats, so the signer
#    settles it by listening.
settle
D0=$(cnt rotation_done "$W/signer1.log")
echo acks > "$MODE"
"$OASA" rotate-signing --dir "$W/drone" > /dev/null
wait_more 60 rotation_done "$W/signer1.log" $D0 && ok "lost COMMAND_ACKs: recovered (settled by listening)" || bad "lost acks not recovered"
rm -f "$MODE"
settle
same_key "$DK" "$K" && op2_has "$(cat "$W/drone/mavlink-signing-key.gen")" && CMD "$W/gcs2" 20 && ok "after lost acks: PX4, the drone and operator 2 agree" || bad "keys disagree after lost acks"

# 3. Everything PX4 says is lost for 25 s: nothing to listen to, so the signer asks under both
#    keys until one answers (up to 75 s).
settle
S0=$(cnt rotation_started "$W/signer1.log"); D0=$(cnt rotation_done "$W/signer1.log")
echo all > "$MODE"
"$OASA" rotate-signing --dir "$W/drone" > /dev/null
wait_more 30 rotation_started "$W/signer1.log" $S0 || bad "the rotation did not start"
sleep 25
rm -f "$MODE"
wait_more 80 rotation_done "$W/signer1.log" $D0 && ok "autopilot silent for 25 s after the key change: probing finds the key and finishes" || bad "probe did not recover"
settle
same_key "$DK" "$K" && op2_has "$(cat "$W/drone/mavlink-signing-key.gen")" && ok "after probing: PX4, the drone and operator 2 agree" || bad "keys disagree after probing"

# 4. Neither key answers for the whole probe: both files stay, rotation_stuck, and a new ask resolves it.
settle
T0=$(cnt rotation_stuck "$W/signer1.log"); D0=$(cnt rotation_done "$W/signer1.log")
sleep 3   # the signer needs a fresh (signed) heartbeat before it will start, so let one through first
echo all > "$MODE"
"$OASA" rotate-signing --dir "$W/drone" > /dev/null
wait_more 130 rotation_stuck "$W/signer1.log" $T0 && ok "silent for the whole probe: rotation_stuck reported" || bad "no rotation_stuck"
if [ -e "$W/drone/mavlink-signing-key.next" ] && [ -e "$DK" ] && same_key "$W/drone/mavlink-signing-key.next" "$K"; then
  ok "stuck: both key files kept; PX4 holds the pending one"
else
  bad "stuck: key files wrong"
fi
rm -f "$MODE"
"$OASA" rotate-signing --dir "$W/drone" > /dev/null
wait_more 60 rotation_done "$W/signer1.log" $D0 && ok "stuck: asked again, the signer worked out the key and finished" || bad "stuck was not resolved"
same_key "$DK" "$K" && [ ! -e "$W/drone/mavlink-signing-key.next" ] && ok "stuck: resolved, no pending key left" || bad "stuck: leftovers"

# 5. Power loss between SETUP_SIGNING and the commit: kill the signer right after it started.
settle
S0=$(cnt rotation_started "$W/signer1.log")
echo all > "$MODE"
"$OASA" rotate-signing --dir "$W/drone" > /dev/null
wait_more 30 rotation_started "$W/signer1.log" $S0 || bad "the rotation did not start"
sleep 2
kill -9 "$SIGNER"; wait "$SIGNER" 2> /dev/null
if [ -e "$W/drone/mavlink-signing-key.next" ] && same_key "$W/drone/mavlink-signing-key.next" "$K"; then
  ok "signer killed after SETUP_SIGNING: PX4 has the new key, the drone still has the old one and .next"
else
  bad "power-loss state is not what was expected"
fi
rm -f "$MODE"
start_signer "$W/signer2.log"
wait_n 120 rotation_done "$W/signer2.log" 1 && ok "restarted signer works out the key and finishes the rotation" || bad "restart did not settle the key"
same_key "$DK" "$K" && [ ! -e "$W/drone/mavlink-signing-key.next" ] && CMD "$W/drone" 20 && ok "after the restart: drone key = PX4 key, and it works" || bad "keys after restart"

# 6. PX4 never sees the key change (dropped on the way): the old key stays, the new one is dropped,
#    and the retry uses a new generation.
settle
echo setup > "$MODE"
"$OASA" rotate-signing --dir "$W/drone" > /dev/null
wait_n 60 rotation_rolled_back "$W/signer2.log" 1 && ok "key change lost: rolled back, old key kept" || bad "no rollback"
[ ! -e "$W/drone/mavlink-signing-key.next" ] && same_key "$DK" "$K" && CMD "$W/drone" 20 && ok "after the rollback the old key still works" || bad "state after rollback"
rm -f "$MODE"
wait_n 90 rotation_done "$W/signer2.log" 2 && ok "retry after the rollback finished"
settle || bad "no retry"

# 7. Generations: each number issued once, in order, and the saved highest matches.
gens=$(grep -h rotation_started "$W"/signer1.log "$W"/signer2.log | sed -E 's/.*"generation":([0-9]+).*/\1/')
sorted=$(printf '%s\n' $gens | sort -n | uniq)
if [ "$gens" = "$sorted" ] && [ "$(printf '%s\n' $gens | wc -l)" -ge 6 ] \
   && [ "$(tail -n1 <<< "$gens")" = "$(cat "$W/drone/mavlink-signing-gen")" ]; then
  ok "generations never reused: $(echo $gens | tr '\n' ' ')"
else
  bad "generations: $(echo $gens | tr '\n' ' ')"
fi
op2_has "$(cat "$W/drone/mavlink-signing-key.gen")" && ok "operator 2 ends on the drone's current generation" || bad "operator 2 behind"
kill $SIGNER $DLINK $GLINK $GATE 2> /dev/null

echo "$PASS passed, $FAILS failed"
[ "$FAILS" = 0 ]
