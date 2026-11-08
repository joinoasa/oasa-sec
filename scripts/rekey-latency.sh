#!/usr/bin/env bash
# How long data waits at a rekey: two oasa-link processes over localhost UDP,
# 100 messages a second each way, a rekey every REKEY_SECS (default 3), for
# SECONDS_RUN (default 30). Prints the one-way delay per direction (median, 99th
# percentile, largest). Test tool only; not run in CI.
#
# Slow storage makes the difference: every handshake saves its timestamp
# with two fsyncs. SLOW_FSYNC_MS=N (needs a C compiler) delays every fsync
# in both processes by N ms, like a slow SD card or eMMC.
#
#   cargo build --release --bins
#   SLOW_FSYNC_MS=50 scripts/rekey-latency.sh
#   BIN=/path/to/other/build SLOW_FSYNC_MS=50 scripts/rekey-latency.sh
set -euo pipefail

B=${BIN:-target/release}
SECS=${SECONDS_RUN:-30}
REKEY=${REKEY_SECS:-3}
PYTHON=${PYTHON:-python3}
HERE=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d)
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$T"; }
trap cleanup EXIT

PRELOAD=
if [ -n "${SLOW_FSYNC_MS:-}" ]; then
  cat > "$T/slowsync.c" <<'EOF'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <time.h>
static void nap(void) {
    const char *s = getenv("SLOW_FSYNC_MS");
    long ms = s ? atol(s) : 0;
    struct timespec t = {ms / 1000, (ms % 1000) * 1000000L};
    nanosleep(&t, 0);
}
int fsync(int fd) { static int (*r)(int); if (!r) r = dlsym(RTLD_NEXT, "fsync"); nap(); return r(fd); }
int fdatasync(int fd) { static int (*r)(int); if (!r) r = dlsym(RTLD_NEXT, "fdatasync"); nap(); return r(fd); }
EOF
  cc -shared -fPIC -O2 -o "$T/slowsync.so" "$T/slowsync.c" -ldl
  PRELOAD="$T/slowsync.so"
  export SLOW_FSYNC_MS
fi

for d in a b; do "$B/oasa-pair" init --dir "$T/$d" --name "$d" >/dev/null; done
pk() { "$B/oasa-pair" show --dir "$1" | sed -E 's/.*"public_key":"([0-9a-f]{64})".*/\1/'; }
"$B/oasa-pair" trust --dir "$T/a" --name b --key "$(pk "$T/b")" >/dev/null
"$B/oasa-pair" trust --dir "$T/b" --name a --key "$(pk "$T/a")" >/dev/null

LD_PRELOAD=$PRELOAD "$B/oasa-link" --dir "$T/b" --peer a --bind 127.0.0.1:7901 \
  --plain-listen 127.0.0.1:7911 --plain-send 127.0.0.1:7912 \
  --duration $((SECS + 8)) > "$T/b.log" 2>&1 & PIDS+=($!)
sleep 0.3
LD_PRELOAD=$PRELOAD "$B/oasa-link" --dir "$T/a" --peer b --bind 127.0.0.1:7902 --remote 127.0.0.1:7901 --initiate \
  --plain-listen 127.0.0.1:7921 --plain-send 127.0.0.1:7922 --rekey-secs "$REKEY" \
  --duration $((SECS + 6)) > "$T/a.log" 2>&1 & PIDS+=($!)
sleep 2
$PYTHON -I "$HERE/tests/interop/rekey_latency.py" "$SECS" 100 7921 7922 7911 7912
wait
echo "rekeys: initiator $(grep -c '"event":"rekey"' "$T/a.log"), responder $(grep -c '"event":"rekey"' "$T/b.log")"
