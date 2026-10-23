#!/usr/bin/env bash
# End-to-end check for oasa-pair, with no hardware:
# stand-in autopilot, drone, ground station, an attacker, and pymavlink.
# Test tool only. Run from the repo root after `cargo build --bins --examples`.
set -euo pipefail

B=target/debug
T=$(mktemp -d)
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$T"; }
trap cleanup EXIT
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; exit 1; }
PY="python3 -I tests/interop/pymavlink_check.py"

$B/examples/fake_autopilot udpin:127.0.0.1:14540 > "$T/ap.log" 2>&1 & PIDS+=($!)
$B/oasa-pair init --dir "$T/drone" >/dev/null
$B/oasa-pair init --dir "$T/gcs" >/dev/null
$B/oasa-pair init --dir "$T/attacker" >/dev/null

$B/oasa-pair drone --dir "$T/drone" --name drone-1 --listen 127.0.0.1:7400 \
  --autopilot udpout:127.0.0.1:14540 --wait 30 > "$T/drone.log" 2>&1 & DRONE=$!
for _ in $(seq 50); do grep -q 'OASA1-' "$T/drone.log" && break; sleep 0.1; done
CODE=$(grep -o 'OASA1-[A-Z2-7]*' "$T/drone.log")

# An attacker who knows the drone's public key but never saw the code.
FAKE=$(python3 - "$CODE" <<'PY'
import base64, os, sys, hashlib
body = bytearray(base64.b32decode(sys.argv[1][6:] + "=" * (-len(sys.argv[1][6:]) % 8)))
body[33:65] = os.urandom(32)  # guess the secret
h = hashlib.blake2s(b"OASA-SEC v0 code checksum" + bytes(body[:65])).digest()[:4]
body[65:] = h
print("OASA1-" + base64.b32encode(bytes(body)).decode().rstrip("="))
PY
)
if $B/oasa-pair ground --dir "$T/attacker" --name evil --connect 127.0.0.1:7400 --code "$FAKE" >/dev/null 2>&1; then
  fail "attacker without the code was able to pair"
fi
pass "attacker without the secret is rejected"

$B/oasa-pair ground --dir "$T/gcs" --name gcs-1 --connect 127.0.0.1:7400 --code "$CODE" >/dev/null \
  || fail "ground station could not pair"
wait "$DRONE" || fail "drone pairing failed"
pass "ground station pairs with the real code after a failed attack"

# Compare the 32-byte keys (the 8-byte timestamps after them differ).
[ "$(head -c 32 "$T/gcs/mavlink-signing-key.bin" | od -An -tx1)" = "$(head -c 32 "$T/drone/mavlink-signing-key.bin" | od -An -tx1)" ] \
  || fail "drone and ground station have different signing keys"
pass "both sides hold the same signing key"

grep -q "gcs-1" "$T/drone/trusted-peers" || fail "drone did not save the ground station"
grep -q "evil" "$T/drone/trusted-peers" && fail "drone saved the attacker"
pass "drone trusts the ground station and not the attacker"

sleep 0.5
grep -q "signing key set" "$T/ap.log" || fail "autopilot did not get SETUP_SIGNING"
$B/oasa-pair command --dir "$T/gcs" --to udpout:127.0.0.1:14540 >/dev/null || fail "signed command not acknowledged"
pass "autopilot accepts a signed command"

$PY client none 14540 >/dev/null && fail "autopilot accepted an unsigned command"
pass "autopilot ignores an unsigned command (sent by pymavlink)"

mkdir -p "$T/wrong" && head -c 40 /dev/urandom > "$T/wrong/mavlink-signing-key.bin" && chmod 600 "$T/wrong/mavlink-signing-key.bin"
$PY client "$T/wrong/mavlink-signing-key.bin" 14540 >/dev/null && fail "autopilot accepted the wrong key"
pass "autopilot ignores a command signed with the wrong key"

$PY client "$T/gcs/mavlink-signing-key.bin" 14540 >/dev/null || fail "pymavlink-signed command not accepted"
pass "pymavlink-signed command is accepted (Rust verifies pymavlink)"

$PY autopilot "$T/drone/mavlink-signing-key.bin" 14541 > "$T/py.log" 2>&1 & PY_AP=$!
sleep 1.5
$B/oasa-pair command --dir "$T/gcs" --to udpout:127.0.0.1:14541 >/dev/null || fail "no signed ACK from pymavlink"
wait "$PY_AP" || fail "pymavlink rejected our signature"
pass "pymavlink accepts our signed command and we accept its signed ACK"

for f in identity.key mavlink-signing-key.bin trusted-peers; do
  for d in drone gcs; do
    [ "$(stat -c %a "$T/$d/$f")" = 600 ] || fail "$d/$f is not owner-only"
  done
done
pass "key files are owner-only (600)"

echo "All end-to-end checks passed."
