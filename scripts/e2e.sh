#!/usr/bin/env bash
# End-to-end check for oasa-pair, with no hardware: a stand-in autopilot,
# a drone, two ground stations, an attacker, and pymavlink as an independent
# MAVLink implementation. Test tool only.
# Run from the repo root after `cargo build --bins --examples`.
set -euo pipefail

B=target/debug
PYTHON=${PYTHON:-python3}
T=$(mktemp -d)
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$T"; }
trap cleanup EXIT
pass() { echo "PASS  $1"; }
fail() {
  echo "FAIL  $1"
  local f msg="$1"
  for f in "$T"/*.log; do [ -e "$f" ] && { echo "--- $f"; cat "$f"; }; done
  # Also surface the failure and the log tails as GitHub Actions annotations.
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    for f in "$T"/*.log; do
      [ -e "$f" ] || continue
      msg+="%0A--- $(basename "$f") (last 30 lines)"
      msg+="%0A$(tail -n 30 "$f" | head -c 3000 | sed 's/%/%25/g; s/\r//g' | awk '{printf "%s%%0A", $0}')"
    done
    echo "::error title=e2e::${msg}"
  fi
  exit 1
}
PY="$PYTHON -I tests/interop/pymavlink_check.py"

# Wait up to $1 seconds for grep pattern $2 to appear in file $3.
wait_for() {
  local secs=$1 pat=$2 file=$3 i
  for i in $(seq $((secs * 10))); do grep -q -- "$pat" "$file" 2>/dev/null && return 0; sleep 0.1; done
  return 1
}
# Wait up to $1 seconds for something to listen on TCP port $2 (without connecting to it).
wait_tcp_listen() {
  local secs=$1 hex i
  hex=$(printf '%04X' "$2")
  for i in $(seq $((secs * 10))); do
    { cat /proc/net/tcp /proc/net/tcp6 2>/dev/null || true; } \
      | awk -v h=":$hex" '$4=="0A" && $2 ~ h"$" {f=1} END{exit !f}' && return 0
    sleep 0.1
  done
  return 1
}

# Warm up pymavlink: the first import on a fresh machine can take a while.
$PYTHON -I -c 'import os; os.environ["MAVLINK20"]="1"; from pymavlink import mavutil' \
  || { echo "pymavlink is not importable by $PYTHON (pip install pymavlink)"; fail "pymavlink import failed"; }
# Expect the pymavlink client to get no ACK: exit code 2, nothing else.
expect_no_ack() { set +e; $PY client "$1" "$2" >/dev/null 2>&1; local rc=$?; set -e; [ "$rc" = 2 ]; }
key32() { head -c 32 "$1" | od -An -tx1; }

start_drone() { # dir name logfile [extra args...]
  local dir=$1 name=$2 log=$3; shift 3
  $B/oasa-pair drone --dir "$dir" --name "$name" --listen 127.0.0.1:7400 --wait 30 "$@" > "$log" 2>&1 &
  DRONE=$!
  wait_for 30 'OASA1-' "$log" || fail "drone did not show a code"
  wait_tcp_listen 30 7400 || fail "drone is not listening on 7400"
  CODE=$(grep -o 'OASA1-[A-Z2-7]*' "$log") || fail "drone did not show a code"
}

$B/examples/fake_autopilot udpin:127.0.0.1:14540 > "$T/ap.log" 2>&1 & PIDS+=($!)
wait_for 30 "listening" "$T/ap.log" || fail "fake autopilot did not start"
for d in drone gcs gcs2 attacker; do $B/oasa-pair init --dir "$T/$d" >/dev/null; done
DRONE_FP=$($B/oasa-pair init --dir "$T/drone" | awk '{print $3}')

# --- 1. First pairing, with an attacker trying first ---------------------
start_drone "$T/drone" drone-1 "$T/drone.log" --autopilot udpout:127.0.0.1:14540

# The attacker knows the drone's public key (it's in the code) but guesses the secret.
FAKE=$($PYTHON - "$CODE" <<'PY'
import base64, os, sys, hashlib
t = sys.argv[1][6:]
body = bytearray(base64.b32decode(t + "=" * (-len(t) % 8)))
body[33:65] = os.urandom(32)
body[65:] = hashlib.blake2s(b"OASA-SEC v0 code checksum" + bytes(body[:65])).digest()[:4]
print("OASA1-" + base64.b32encode(bytes(body)).decode().rstrip("="))
PY
)
echo "$FAKE" | $B/oasa-pair ground --dir "$T/attacker" --name evil --connect 127.0.0.1:7400 --code - >/dev/null 2>&1 \
  && fail "attacker without the secret was able to pair"
wait_for 10 "Pairing attempt failed: encryption or authentication failed" "$T/drone.log" \
  || fail "drone did not reject the attacker for the right reason"
pass "attacker without the secret is rejected by the handshake"

$B/oasa-pair ground --dir "$T/gcs" --name gcs-1 --connect 127.0.0.1:7400 --code "$CODE" >/dev/null 2>&1 \
  && fail "accepted the pairing code on the command line"
pass "pairing code on the command line is refused"

echo "$CODE" | $B/oasa-pair ground --dir "$T/gcs" --name gcs-1 --connect 127.0.0.1:7400 --code - \
  --expect-drone WRONG-WRON-GWRO-NGWR >/dev/null 2>&1 && fail "paired with an unexpected drone"
pass "--expect-drone refuses a code for a different drone"

echo "$CODE" | $B/oasa-pair ground --dir "$T/gcs" --name gcs-1 --connect 127.0.0.1:7400 --code - \
  --expect-drone "$DRONE_FP" >/dev/null || fail "ground station could not pair"
wait "$DRONE" || fail "drone pairing failed"
grep -q "accepted the new key (checked with a signed command)" "$T/drone.log" \
  || fail "drone did not verify the key with the autopilot"
pass "first ground station pairs; drone loads and verifies the key in the autopilot"

GKEY="$T/gcs/signing-keys/$DRONE_FP.bin"
[ "$(key32 "$GKEY")" = "$(key32 "$T/drone/mavlink-signing-key.bin")" ] || fail "keys differ"
grep -q "gcs-1" "$T/drone/trusted-peers.v1" || fail "drone did not save the ground station"
grep -q "evil" "$T/drone/trusted-peers.v1" && fail "drone saved the attacker"
pass "both sides hold the same key; only the real ground station is saved"

# --- 2. Signed commands --------------------------------------------------
$B/oasa-pair command --dir "$T/gcs" --to udpout:127.0.0.1:14540 >/dev/null || fail "signed command not acknowledged"
pass "autopilot accepts a signed command"
expect_no_ack none 14540 || fail "autopilot accepted an unsigned command"
pass "autopilot ignores an unsigned command (sent by pymavlink)"
mkdir -p "$T/wrong" && chmod 700 "$T/wrong" && head -c 40 /dev/urandom > "$T/wrong/k.bin" && chmod 600 "$T/wrong/k.bin"
expect_no_ack "$T/wrong/k.bin" 14540 || fail "autopilot accepted the wrong key"
pass "autopilot ignores a command signed with the wrong key"
$PY client "$GKEY" 14540 >/dev/null || fail "pymavlink-signed command not accepted"
pass "Rust verifies pymavlink's signatures"

$PY autopilot "$GKEY" 14541 > "$T/py.log" 2>&1 & PY_AP=$!
wait_for 30 "pymavlink autopilot on" "$T/py.log" || fail "pymavlink autopilot did not start"
$B/oasa-pair command --dir "$T/gcs" --to udpout:127.0.0.1:14541 >/dev/null || fail "no signed ACK from pymavlink"
wait "$PY_AP" || fail "pymavlink rejected our signature"
pass "pymavlink verifies our signatures, and we verify its ACK"

# The autopilot may answer late (ArduPilot refuses signed commands for up to a minute after a
# reboot): command keeps trying, says so after a few seconds, and succeeds once it answers.
$B/oasa-pair command --dir "$T/gcs" --to udpout:127.0.0.1:14542 --wait 40 > "$T/late.log" 2>&1 & LATE=$!
sleep 7
$PY autopilot "$GKEY" 14542 > "$T/py-late.log" 2>&1 & PY_LATE=$!
wait "$LATE" || fail "command gave up before the late autopilot answered"
wait "$PY_LATE" || fail "late pymavlink autopilot rejected our signature"
grep -q "Still trying" "$T/late.log" || fail "command did not say it was still trying"
pass "command keeps trying until a late autopilot answers"

# --- 3. A second ground station joins ------------------------------------
start_drone "$T/drone" drone-1 "$T/drone2.log" --autopilot udpout:127.0.0.1:14540
echo "$CODE" | $B/oasa-pair ground --dir "$T/gcs2" --name gcs-2 --connect 127.0.0.1:7400 --code - >/dev/null \
  || fail "second ground station could not pair"
wait "$DRONE" || fail "second pairing failed"
[ "$(key32 "$T/gcs2/signing-keys/$DRONE_FP.bin")" = "$(key32 "$GKEY")" ] || fail "second ground station got a different key"
$B/oasa-pair command --dir "$T/gcs" --to udpout:127.0.0.1:14540 >/dev/null || fail "first ground station was locked out"
$B/oasa-pair command --dir "$T/gcs2" --to udpout:127.0.0.1:14540 >/dev/null || fail "second ground station can't command"
pass "second ground station gets the same key; neither is locked out"

# --- 4. If the autopilot doesn't take the key, nothing is saved ----------
$B/oasa-pair init --dir "$T/drone-b" >/dev/null
start_drone "$T/drone-b" drone-b "$T/drone-b.log" --autopilot udpout:127.0.0.1:14599  # nothing listening
echo "$CODE" | $B/oasa-pair ground --dir "$T/gcs" --name gcs-1 --connect 127.0.0.1:7400 --code - >/dev/null 2>&1 \
  && fail "ground station reported success though the autopilot never took the key"
kill "$DRONE" 2>/dev/null || true; wait "$DRONE" 2>/dev/null || true
[ -e "$T/drone-b/mavlink-signing-key.bin" ] && fail "drone saved a key the autopilot doesn't have"
ls "$T/gcs/signing-keys" | grep -qv "$DRONE_FP" && fail "ground station saved a key for the failed drone"
grep -q "Likely causes" "$T/drone-b.log" || fail "the failure did not name its likely causes"
pass "a key the autopilot didn't accept is never saved on either side"

# --- 5. File permissions -------------------------------------------------
for f in "$T/drone/identity.key" "$T/drone/mavlink-signing-key.bin" "$T/drone/trusted-peers.v1" \
         "$T/gcs/identity.key" "$GKEY" "$T/gcs/trusted-peers.v1"; do
  [ "$(stat -c %a "$f")" = 600 ] || fail "$f is not owner-only"
done
[ "$(stat -c %a "$T/gcs/signing-keys")" = 700 ] || fail "key folder is not owner-only"
pass "key files are 600 and the key folder is 700"

echo "All end-to-end checks passed."
