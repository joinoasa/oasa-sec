#!/usr/bin/env bash
# End-to-end check for oasa-link over real UDP on localhost, with no hardware:
# a ground station, a drone, and an untrusted third device. Test tool only.
# Run from the repo root after `cargo build --locked --bins`.
set -euo pipefail

B=target/debug
PYTHON=${PYTHON:-python3}
CHECK="$PYTHON -I tests/interop/link_check.py"
T=$(mktemp -d)
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$T"; }
trap cleanup EXIT
pass() { echo "PASS  $1"; }
fail() {
  echo "FAIL  $1"
  local f
  for f in "$T"/*.log; do [ -e "$f" ] && { echo "--- $f"; tail -n 40 "$f"; }; done
  if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::error title=link-e2e::$1"; fi
  exit 1
}

# Ports on localhost (encrypted, plain in, plain out) for each process.
D_ENC=7701; D_IN=7711; D_OUT=7712   # drone, a responder
G_ENC=7702; G_IN=7721; G_OUT=7722   # ground station, the initiator
E_ENC=7703; E_IN=7731; E_OUT=7732   # untrusted third device
G2_ENC=7704                         # the ground station again, from a new port

wait_for() { # secs pattern file
  local i
  for i in $(seq $(($1 * 10))); do grep -q -- "$2" "$3" 2>/dev/null && return 0; sleep 0.1; done
  return 1
}
pubkey() { $B/oasa-pair show --dir "$1" | sed -E 's/.*"public_key":"([0-9a-f]{64})".*/\1/'; }
n() { $CHECK count "$@"; }
jstat() { $CHECK stat "$@"; }

# --- identities and trust (oasa-pair init + show + trust) ----------------
for d in gcs drone evil; do $B/oasa-pair init --dir "$T/$d" --name "$d" >/dev/null; done
$B/oasa-pair trust --dir "$T/gcs" --name drone --key "$(pubkey "$T/drone")" >/dev/null
$B/oasa-pair trust --dir "$T/drone" --name gcs --key "$(pubkey "$T/gcs")" >/dev/null
# The untrusted device knows both public keys (they are not secret) but neither trusts it.
$B/oasa-pair trust --dir "$T/evil" --name drone --key "$(pubkey "$T/drone")" >/dev/null
$B/oasa-pair trust --dir "$T/evil" --name gcs --key "$(pubkey "$T/gcs")" >/dev/null
pass "identities made and trusted with oasa-pair show / trust"

# --- 1. A session, traffic both ways, a rekey, an untrusted device -------
$B/oasa-link --dir "$T/drone" --peer gcs --bind 127.0.0.1:$D_ENC \
  --plain-listen 127.0.0.1:$D_IN --plain-send 127.0.0.1:$D_OUT \
  --duration 40 > "$T/drone.log" 2>&1 & DRONE=$!; PIDS+=($DRONE)
sleep 0.5
$B/oasa-link --dir "$T/gcs" --peer drone --bind 127.0.0.1:$G_ENC --remote 127.0.0.1:$D_ENC --initiate \
  --plain-listen 127.0.0.1:$G_IN --plain-send 127.0.0.1:$G_OUT \
  --rekey-secs 4 --keepalive-secs 3 --duration 17 > "$T/gcs.log" 2>&1 & GCS=$!; PIDS+=($GCS)
$B/oasa-link --dir "$T/evil" --peer drone --bind 127.0.0.1:$E_ENC --remote 127.0.0.1:$D_ENC --initiate \
  --plain-listen 127.0.0.1:$E_IN --plain-send 127.0.0.1:$E_OUT \
  --duration 17 > "$T/evil.log" 2>&1 & EVIL=$!; PIDS+=($EVIL)
wait_for 15 session_established "$T/gcs.log" || fail "ground station never got a session"
wait_for 15 session_established "$T/drone.log" || fail "drone never got a session"
pass "handshake over UDP: both sides log session_established"

# The drone's side sends from its plain input to the ground station's plain output and back.
$CHECK traffic 60 0.2 $G_IN $G_OUT $D_IN $D_OUT oversize > "$T/traffic.log" || { cat "$T/traffic.log"; fail "marked packets were not delivered exactly once"; }
cat "$T/traffic.log"
pass "60 marked packets each way delivered exactly once, unchanged"

# While that ran: spray junk at the drone; it must not answer.
$CHECK junk $D_ENC 300 || fail "the drone answered junk"
pass "random packets to the drone get no reply"

wait "$GCS" || fail "ground station did not exit 0 after --duration"
wait "$EVIL" || fail "untrusted device did not exit 0 after --duration"
$CHECK check "$T/gcs.log" && $CHECK check "$T/drone.log" && $CHECK check "$T/evil.log" || fail "log lines are not the agreed JSON"
pass "ground station exits 0 at --duration with stats; all log lines are valid JSON"

[ "$(n "$T/gcs.log" rekey)" -ge 2 ] || fail "ground station did not rekey"
[ "$(n "$T/gcs.log" session_established)" -ge 3 ] || fail "no new sessions after rekeys"
pass "rekeys happened during the run and traffic kept flowing"

[ "$(jstat "$T/gcs.log" sent)" = 60 ] && [ "$(jstat "$T/gcs.log" delivered)" = 60 ] || fail "ground station stats do not match traffic"
[ "$(jstat "$T/gcs.log" drops.too_large)" = 1 ] || fail "oversized plaintext was not dropped with a reason"
pass "stats match what was sent; oversized plaintext dropped as too_large"

# The untrusted device: the drone counted it, and it received nothing at all.
[ "$(n "$T/drone.log" drop untrusted_peer)" -ge 1 ] || fail "drone did not log untrusted_peer"
[ "$(n "$T/evil.log" session_established)" = 0 ] || fail "untrusted device got a session"
[ "$(jstat "$T/evil.log" received)" = 0 ] || fail "untrusted device received data"
[ "$(n "$T/evil.log" drop)" = 0 ] || fail "untrusted device got packets back (even ones it dropped)"
[ "$(n "$T/evil.log" handshake_sent)" -ge 2 ] || fail "untrusted device did not try twice"
pass "untrusted device: counted as untrusted_peer, got no reply of any kind"

# --- 2. The ground station restarts from a new port (roaming) ------------
$B/oasa-link --dir "$T/gcs" --peer drone --bind 127.0.0.1:$G2_ENC --remote 127.0.0.1:$D_ENC --initiate \
  --plain-listen 127.0.0.1:$G_IN --plain-send 127.0.0.1:$G_OUT \
  --counter-bytes 4 --duration 14 > "$T/gcs2.log" 2>&1 & GCS2=$!; PIDS+=($GCS2)
wait_for 12 session_established "$T/gcs2.log" || fail "restarted ground station never got a session"
sleep 0.5
$CHECK traffic 20 0.1 $G_IN $G_OUT $D_IN $D_OUT > "$T/traffic2.log" || { cat "$T/traffic2.log"; fail "traffic after the restart was lost"; }
cat "$T/traffic2.log"
wait "$GCS2" || fail "restarted ground station did not exit 0"
pass "after a restart from a new port the drone follows it (timestamp file kept the handshake fresh)"

# --- 3. SIGTERM prints stats and exits 0; the drone's totals add up ------
kill -TERM "$DRONE"
wait "$DRONE" || fail "drone did not exit 0 on SIGTERM"
[ "$(jstat "$T/drone.log" delivered)" = 80 ] || fail "drone delivered $(jstat "$T/drone.log" delivered), expected 80"
[ "$(jstat "$T/drone.log" sent)" = 80 ] || fail "drone sent $(jstat "$T/drone.log" sent), expected 80"
[ "$(jstat "$T/drone.log" drops.bad_header)" -ge 1 ] || fail "drone did not count junk as bad_header"
[ "$(jstat "$T/drone.log" drops.untrusted_peer)" -ge 1 ] || fail "drone stats miss untrusted_peer"
pass "SIGTERM: stats printed, exit 0; drone totals 80 sent / 80 delivered; junk and untrusted counted"

# --- 4. Files and secrets ------------------------------------------------
[ "$(jstat "$T/drone.log" received)" = 80 ] || fail "received count"
for f in "$T"/gcs/link-timestamp-* "$T"/drone/link-timestamp-*; do
  [ "$(stat -c %a "$f")" = 600 ] || fail "$f is not owner-only"
done
KEY=$(od -An -tx1 -v "$T/gcs/identity.key" | tr -d ' \n')
grep -q "$KEY" "$T"/*.log && fail "a private key is in a log"
pass "timestamp files are 600 and no private key is in any log"

echo "All link end-to-end checks passed."
