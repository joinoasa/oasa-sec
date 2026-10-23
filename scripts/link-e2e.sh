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
fp_of() { $B/oasa-pair show --dir "$T/$1" | sed -E 's/.*"fingerprint":"([^"]+)".*/\1/'; }
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
  --duration 120 > "$T/drone.log" 2>&1 & DRONE=$!; PIDS+=($DRONE)
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

# Drop lines are limited, and nothing is lost from the count: every drop is
# either a printed line or part of a drops_suppressed total. The clock second
# in the timestamp can straddle two windows, so allow up to 20 in one.
PER_SECOND=$($CHECK drops "$T/drone.log") || fail "drop lines and suppressed counts do not add up to the stats"
[ "$PER_SECOND" -le 20 ] || fail "drone printed $PER_SECOND drop lines in one second"
[ "$(n "$T/drone.log" drops_suppressed)" -ge 1 ] || fail "no drops_suppressed line after the junk burst"
pass "drop log limited (at most $PER_SECOND lines in a second); printed + suppressed == stats"

# Plaintext from anywhere is not accepted by default.
if $B/oasa-link --dir "$T/gcs" --peer drone --bind 127.0.0.1:7790 --plain-listen 0.0.0.0:7791 \
  --plain-send 127.0.0.1:7792 --duration 1 >"$T/lan.log" 2>&1; then fail "--plain-listen 0.0.0.0 was accepted"; fi
grep -q loopback "$T/lan.log" || fail "no loopback message"
pass "--plain-listen on a non-loopback address is refused"

# --- 4. Files and secrets ------------------------------------------------
[ "$(jstat "$T/drone.log" received)" = 80 ] || fail "received count"
for f in "$T"/gcs/link-timestamp-* "$T"/drone/link-timestamp-*; do
  [ "$(stat -c %a "$f")" = 600 ] || fail "$f is not owner-only"
done
KEY=$(od -An -tx1 -v "$T/gcs/identity.key" | tr -d ' \n')
grep -q "$KEY" "$T"/*.log && fail "a private key is in a log"
pass "timestamp files are 600 and no private key is in any log"

# --- 5. The MAVLink guard on a drone ------------------------------------
# A device dir with mavlink-signing-key.bin is a drone: the guard is on by default.
# (The file only has to exist here; its bytes are random and never printed.)
grep -q '"event":"mavlink_guard","state":"off"' "$T/drone.log" || fail "a device without the autopilot key should start with the guard off"
grep -q '"event":"hint".*mavlink-signing-key.bin' "$T/drone.log" || fail "no hint about the guard being off"
for d in gcsg dronek; do $B/oasa-pair init --dir "$T/$d" --name "$d" >/dev/null; done
$B/oasa-pair trust --dir "$T/gcsg" --name dronek --key "$(pubkey "$T/dronek")" >/dev/null
$B/oasa-pair trust --dir "$T/dronek" --name gcsg --key "$(pubkey "$T/gcsg")" >/dev/null
head -c 40 /dev/urandom > "$T/dronek/mavlink-signing-key.bin"; chmod 600 "$T/dronek/mavlink-signing-key.bin"
DK_ENC=7741; DK_IN=7751; DK_OUT=7752; GK_ENC=7742; GK_IN=7761; GK_OUT=7762

guard_run() { # name mode [drone flags...]
  local name=$1 mode=$2 want; shift 2
  $B/oasa-link --dir "$T/dronek" --peer gcsg --bind 127.0.0.1:$DK_ENC \
    --plain-listen 127.0.0.1:$DK_IN --plain-send 127.0.0.1:$DK_OUT --mtu 400 --duration 40 "$@" > "$T/$name-drone.log" 2>&1 & local DK=$!; PIDS+=($DK)
  sleep 0.5
  $B/oasa-link --dir "$T/gcsg" --peer dronek --bind 127.0.0.1:$GK_ENC --remote 127.0.0.1:$DK_ENC --initiate \
    --plain-listen 127.0.0.1:$GK_IN --plain-send 127.0.0.1:$GK_OUT --mtu 400 --duration 40 > "$T/$name-gcs.log" 2>&1 & local GK=$!; PIDS+=($GK)
  wait_for 15 session_established "$T/$name-gcs.log" || fail "$name: no session"
  $CHECK guard $GK_IN $DK_OUT "$mode" $DK_IN > "$T/$name-guard.out" 2>&1 || { cat "$T/$name-guard.out"; [ -n "${GITHUB_ACTIONS:-}" ] && echo "::error title=$name guard::$(tr "\n" "|" < "$T/$name-guard.out" | cut -c1-900)"; fail "$name: wrong datagrams reached the autopilot side"; }
  cat "$T/$name-guard.out"
  want=$(sed -n 's/^blocked //p' "$T/$name-guard.out")
  kill -TERM "$DK" "$GK"; wait "$DK" "$GK" || fail "$name: a link did not exit 0"
  $CHECK check "$T/$name-drone.log" || fail "$name: drone log lines are not the agreed JSON"
  local got; got=$(jstat "$T/$name-drone.log" drops.mavlink_blocked 2>/dev/null || echo 0)
  [ "$got" = "$want" ] || fail "$name: drops.mavlink_blocked is $got, expected $want"
}

guard_run guard default
grep -q '"event":"mavlink_guard","state":"on","ftp":false' "$T/guard-drone.log" || fail "the guard did not start on for a drone"
! grep -q '"warning"' "$T/guard-drone.log" || fail "the default guard printed a warning"
grep -q '"reason":"mavlink_blocked","why":"setup_signing","msgid":256' "$T/guard-drone.log" || fail "no log line naming SETUP_SIGNING (256)"
grep -q '"reason":"mavlink_blocked","why":"ftp","msgid":110' "$T/guard-drone.log" || fail "no log line naming FTP (110)"
grep -q '"reason":"mavlink_blocked","why":"command_not_allowed","msgid":76,"command":246' "$T/guard-drone.log" || fail "no log line naming the refused command (246)"
grep -q '"reason":"mavlink_blocked","why":"msg_not_allowed","msgid":33' "$T/guard-drone.log" || fail "no log line for a message not on the list"
grep -q '"reason":"mavlink_blocked","why":"param_write","msgid":23' "$T/guard-drone.log" || fail "no log line for a parameter write"
grep -q '"reason":"mavlink_blocked","why":"bad_crc"' "$T/guard-drone.log" || fail "no log line for a bad CRC"
grep -q '"reason":"mavlink_blocked","why":"mission_type","msgid":45,"mission_type":1' "$T/guard-drone.log" || fail "no log line for a fence clear"
grep -q '"reason":"mavlink_blocked","why":"mission_type","msgid":45,"mission_type":255' "$T/guard-drone.log" || fail "no log line for a clear of all types"
grep -q '"reason":"mavlink_blocked","why":"msg_not_allowed","msgid":233' "$T/guard-drone.log" || fail "no log line for RTK data"
grep -q '"reason":"mavlink_blocked","why":"malformed"' "$T/guard-drone.log" || fail "no log line for a malformed datagram"
[ "$($CHECK drops "$T/guard-drone.log")" -le 20 ] || fail "guard drop lines are not rate limited with the others"
pass "decrypted packets leave from the --plain-listen port, so replies come back through the tunnel"
pass "guard on by default for a drone: only whole, CRC-valid, allowlisted frames pass (arm, takeoff, RTL, mission items, batches); SETUP_SIGNING, FTP, parameter writes, reboot commands, other messages, bad CRCs and junk are dropped with their ids logged"

guard_run guardftp ftp --allow-mavlink-ftp
grep -q '"event":"warning".*FILE_TRANSFER_PROTOCOL' "$T/guardftp-drone.log" || fail "--allow-mavlink-ftp printed no warning"
pass "--allow-mavlink-ftp lets FTP through, logs a warning, and nothing else changes"

guard_run guardwide wide --allow-msg 33 --allow-command 246 --allow-param mpc_xy_vel_max --allow-rtk --allow-fence-rally
for w in "GPS_RTCM_DATA (233) are allowed" "geofence and rally mission messages" "message 33 is allowed" "command 246 is allowed" "writes to parameter MPC_XY_VEL_MAX are allowed"; do
  grep -q "\"event\":\"warning\".*$w" "$T/guardwide-drone.log" || fail "no warning for: $w"
done
pass "--allow-msg, --allow-command and --allow-param each widen exactly one thing and each log a warning; signing parameters stay blocked"

guard_run guardoff off --no-mavlink-guard
grep -q '"event":"warning"' "$T/guardoff-drone.log" || fail "--no-mavlink-guard printed no warning"
pass "--no-mavlink-guard prints a warning and lets everything through"

for bad in "--no-mavlink-guard --allow-msg 33" "--allow-msg 256" "--allow-param MAV_SIGN_CFG" "--allow-command 99999" "--no-mavlink-guard --allow-rtk" "--no-mavlink-guard --allow-fence-rally"; do
  if $B/oasa-link --dir "$T/dronek" --peer gcsg --bind 127.0.0.1:7791 --plain-listen 127.0.0.1:7792 \
    --plain-send 127.0.0.1:7793 --duration 1 $bad >"$T/bad.log" 2>&1; then fail "oasa-link accepted: $bad"; fi
done
pass "widening flags that make no sense or ask for something that can never be allowed are refused"

if $B/oasa-link --dir "$T/dronek" --peer gcsg --bind 127.0.0.1:7791 --plain-listen 127.0.0.1:7792 \
  --plain-send 127.0.0.1:7793 --duration 1 --mavlink-guard --no-mavlink-guard >"$T/both.log" 2>&1; then fail "both guard flags were accepted"; fi
pass "--mavlink-guard together with --no-mavlink-guard is refused"

# --- 6. The guard against pymavlink -------------------------------------
cargo build --release --example mavguard_check >/dev/null 2>&1 || fail "could not build examples/mavguard_check"
$PYTHON -I tests/interop/mavguard_diff.py --n 3000 || fail "the guard and pymavlink disagree"
pass "guard and pymavlink agree on frame boundaries, ids and CRCs for everything the guard passes"

# --- 7. Removal (R-SEC2) -------------------------------------------------
wait_exit() { # pid secs: set EXIT_RC to the exit code, or "running" if it did not exit in time.
  # Not for use in $(...): wait only works in the shell that started the process.
  local i
  EXIT_RC=running
  for i in $(seq $(($2 * 10))); do
    if ! kill -0 "$1" 2>/dev/null; then EXIT_RC=0; wait "$1" || EXIT_RC=$?; return 0; fi
    sleep 0.1
  done
}
link() { # logname dir peer encport [flags...]: plain ports are enc+100 (in) and enc+200 (out)
  local name=$1 dir=$2 peer=$3 p=$4; shift 4
  $B/oasa-link --dir "$T/$dir" --peer "$peer" --bind 127.0.0.1:$p \
    --plain-listen 127.0.0.1:$((p+100)) --plain-send 127.0.0.1:$((p+200)) --duration 90 "$@" > "$T/$name.log" 2>&1 &
  LAST=$!; PIDS+=($LAST)
}
trust_as() { # dir name peerdir role
  $B/oasa-pair trust --dir "$T/$1" --name "$2" --key "$(pubkey "$T/$3")" --role "$4" >/dev/null
}
for d in rg rd rg2 rd2; do $B/oasa-pair init --dir "$T/$d" --name "$d" >/dev/null; done

# 7a. A removal mid-run: the link to the removed device ends with exit code 3.
trust_as rd rg rg operator; trust_as rg rd rd peer
link rd rd rg 7810; RD=$LAST
link rg rg rd 7811 --remote 127.0.0.1:7810 --initiate; RG=$LAST
wait_for 15 session_established "$T/rd.log" || fail "removal test: no session"
wait_for 15 session_established "$T/rg.log" || fail "removal test: ground station has no session"
$B/oasa-pair remove --dir "$T/rd" rg > "$T/remove.out" 2>&1 || { cat "$T/remove.out"; fail "oasa-pair remove failed"; }
wait_exit "$RD" 5; [ "$EXIT_RC" = 3 ] || fail "the drone's link did not exit with code 3 after its peer was removed"
grep -q '"event":"peer_removed".*"why":"removed"' "$T/rd.log" || fail "no peer_removed line"
$CHECK check "$T/rd.log" || fail "removal log lines are not the agreed JSON"
[ "$(jstat "$T/rd.log" delivered)" = 0 ] || fail "stats after peer_removed"
pass "oasa-pair remove: the running oasa-link logs peer_removed and exits with code 3 within seconds (file watch, no restart)"
if $B/oasa-link --dir "$T/rd" --peer rg --bind 127.0.0.1:7812 --plain-listen 127.0.0.1:7912 \
  --plain-send 127.0.0.1:8012 --duration 1 >"$T/again.log" 2>&1; then fail "a removed peer was accepted again"; fi
if $B/oasa-pair trust --dir "$T/rd" --name rg --key "$(pubkey "$T/rg")" >"$T/retrust.out" 2>&1; then fail "trust accepted a removed key"; fi
grep -q "removed" "$T/retrust.out" || fail "no explanation when trusting a removed key"
$B/oasa-pair removed --dir "$T/rd" | grep -q "by hand" || fail "removed does not list the tombstone"
[ "$(stat -c %a "$T/rd/removed")" = 600 ] && [ "$(stat -c %a "$T/rd/trusted-peers.v1")" = 600 ] || fail "removal files are not owner-only"
kill -TERM "$RG" 2>/dev/null || true
pass "a removed key cannot be started with, trusted or paired again; tombstone file is 600"

# 7b. SIGHUP reloads at once (even with nothing changed), and a removal by SIGHUP exits 3.
trust_as rd2 rg2 rg2 operator; trust_as rg2 rd2 rd2 peer
link rd2 rd2 rg2 7813; RD2=$LAST
link rg2 rg2 rd2 7814 --remote 127.0.0.1:7813 --initiate; RG2=$LAST
wait_for 15 session_established "$T/rd2.log" || fail "SIGHUP test: no session"
kill -HUP "$RD2"
wait_for 2 trust_reloaded "$T/rd2.log" || fail "SIGHUP did not reload the trust files"
$B/oasa-pair remove --dir "$T/rd2" rg2 >/dev/null
kill -HUP "$RD2"
wait_exit "$RD2" 3; [ "$EXIT_RC" = 3 ] || fail "SIGHUP after a removal did not end the link with code 3"
kill -TERM "$RG2" 2>/dev/null || true
pass "SIGHUP reloads at once; after a removal it ends the link with code 3"

# 7c. A revoke travels from an admin to a device, and on to the device's other link.
for d in adm dev dev3 vic vic2; do $B/oasa-pair init --dir "$T/$d" --name "$d" >/dev/null; done
trust_as dev adm adm admin; trust_as dev vic vic peer; trust_as dev vic2 vic2 peer
trust_as adm dev dev peer; trust_as adm vic vic peer; trust_as adm vic2 vic2 peer
trust_as vic dev dev peer
trust_as dev3 adm adm peer; trust_as adm dev3 dev3 peer   # dev3 does not list adm as admin
link devA dev adm 7820; DEVA=$LAST          # dev, talking to the admin
link devV dev vic 7821; DEVV=$LAST          # dev, talking to the device that will be revoked
link vic vic dev 7822 --remote 127.0.0.1:7821 --initiate; VIC=$LAST
link adm adm dev 7823 --remote 127.0.0.1:7820 --initiate; ADM=$LAST
link dev3 dev3 adm 7824; DEV3=$LAST
link adm3 adm dev3 7825 --remote 127.0.0.1:7824 --initiate; ADM3=$LAST
for f in devA devV vic adm dev3 adm3; do wait_for 15 session_established "$T/$f.log" || fail "revoke test: $f has no session"; done
$B/oasa-pair revoke --dir "$T/adm" vic > "$T/revoke.out" 2>&1 || { cat "$T/revoke.out"; fail "oasa-pair revoke failed"; }
wait_exit "$DEVV" 8; [ "$EXIT_RC" = 3 ] || fail "the revoke did not reach the device (its link to the revoked peer is still running)"
grep -q '"event":"removal_entry".*"detail":"removed"' "$T/devA.log" || fail "the device logged no removal_entry"
$B/oasa-pair removed --dir "$T/dev" | grep -q "by admin" || fail "the device has no tombstone naming the admin"
! $B/oasa-pair peers --dir "$T/dev" | grep -q " vic$" || fail "the revoked device is still in the device's list"
pass "revoke: an admin's entry reaches the device over the link, tombstones the key there, and the device's other oasa-link (to the revoked peer) exits with code 3"
# A device that does not list the sender as admin applies nothing and says so.
sleep 1
[ ! -e "$T/dev3/removed" ] || fail "a device applied a removal from a sender that is not its admin"
grep -q '"event":"not_admin_here"' "$T/adm3.log" || fail "the sender was not told NOT_ADMIN"
pass "a device that does not list the sender as admin answers NOT_ADMIN and changes nothing"

# The admin is offline when it revokes the next device, and catches up when it reconnects.
kill -TERM "$ADM"; wait "$ADM" || fail "admin link did not exit 0"
$B/oasa-pair revoke --dir "$T/adm" vic2 >/dev/null
VIC2FP=$(fp_of vic2)
! $B/oasa-pair removed --dir "$T/dev" | grep -q "$VIC2FP" || fail "vic2 was removed on the device before the admin reconnected"
link adm_b adm dev 7826 --remote 127.0.0.1:7820 --initiate
wait_for 15 session_established "$T/adm_b.log" || fail "the admin could not reconnect"
for i in $(seq 100); do $B/oasa-pair removed --dir "$T/dev" | grep -q "$VIC2FP" && break; sleep 0.1; done
$B/oasa-pair removed --dir "$T/dev" | grep -q "$VIC2FP" || fail "the admin came back online but the device never got the entry"
[ "$(grep -c '"event":"removal_entry"' "$T/devA.log")" -ge 2 ] || fail "the device logged too few removal entries"
pass "an admin that was offline when it revoked catches the device up as soon as the link is back"

# Every log line is the agreed JSON, nothing secret is printed, control is counted apart.
kill -TERM "$DEVA" "$VIC" "$ADM3" "$DEV3" 2>/dev/null || true
wait "$DEVA" || fail "device link did not exit 0 on SIGTERM"
$CHECK check "$T/devA.log" && $CHECK check "$T/adm_b.log" || fail "removal log lines are not the agreed JSON"
[ "$(jstat "$T/devA.log" control_received)" -ge 4 ] || fail "control messages not counted"
[ "$(jstat "$T/devA.log" delivered)" = 0 ] || fail "a control message reached the application side"
KEY=$(od -An -tx1 -v "$T/adm/identity.key" | tr -d ' \n')
grep -q "$KEY" "$T"/*.log && fail "a private key is in a log"
for f in "$T"/dev/removed "$T"/adm/removal-log "$T"/dev/removal-sync/*; do
  [ "$(stat -c %a "$f")" = 600 ] || fail "$f is not owner-only"
done
pass "control messages are counted apart and never reach the application side; removal files are 600"

echo "All link end-to-end checks passed."
