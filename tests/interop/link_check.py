"""Helpers for scripts/link-e2e.sh: send marked UDP packets, listen for what
comes out, spray junk, and read oasa-link's JSON lines. Test tool only."""
import json
import os
import random
import socket
import sys
import threading
import time

LOCAL = "127.0.0.1"


def udp(port=0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((LOCAL, port))
    return s


def listen(sock, store, stop):
    sock.settimeout(0.2)
    while not stop.is_set():
        try:
            data, _ = sock.recvfrom(70000)
        except socket.timeout:
            continue
        store.append(data)


def traffic(args):
    """traffic N INTERVAL A_IN A_OUT B_IN B_OUT [oversize]: both sides send N
    marked packets; each must arrive exactly once, unchanged."""
    n, interval = int(args[0]), float(args[1])
    a_in, a_out, b_in, b_out = (int(x) for x in args[2:6])
    oversize = len(args) > 6 and args[6] == "oversize"
    got_a, got_b = [], []  # what comes out at A's and B's plaintext output
    stop = threading.Event()
    ra, rb = udp(a_out), udp(b_out)
    for sock, store in ((ra, got_a), (rb, got_b)):
        threading.Thread(target=listen, args=(sock, store, stop), daemon=True).start()
    tx = udp()
    run = os.urandom(4).hex()
    sent_a = [f"A->B {run} {i:04d} ".encode() + os.urandom(12).hex().encode() for i in range(n)]
    sent_b = [f"B->A {run} {i:04d} ".encode() + os.urandom(20).hex().encode() for i in range(n)]
    for i in range(n):
        tx.sendto(sent_a[i], (LOCAL, a_in))
        tx.sendto(sent_b[i], (LOCAL, b_in))
        time.sleep(interval)
    if oversize:
        # Larger than MTU minus overhead: must be dropped, never delivered.
        tx.sendto(b"BIG " + b"x" * 200, (LOCAL, a_in))
    time.sleep(1.0)
    stop.set()
    time.sleep(0.3)
    ok = True
    for name, sent, got in (("A->B", sent_a, got_b), ("B->A", sent_b, got_a)):
        missing = [p for p in sent if got.count(p) == 0]
        dups = [p for p in sent if got.count(p) > 1]
        foreign = [p for p in got if p not in sent]
        print(f"{name}: sent {len(sent)} delivered {len(sent) - len(missing)} "
              f"duplicates {len(dups)} foreign {len(foreign)}")
        ok = ok and not missing and not dups and not foreign
    return 0 if ok else 2


def listen_only(args):
    """listen_only PORT SECONDS: count what arrives; print the count."""
    sock = udp(int(args[0]))
    got, stop = [], threading.Event()
    threading.Thread(target=listen, args=(sock, got, stop), daemon=True).start()
    time.sleep(float(args[1]))
    stop.set()
    print(len(got))
    return 0


def junk(args):
    """junk TARGET_PORT N: send random packets (some with real-looking headers)
    and fail if anything at all comes back."""
    target, n = int(args[0]), int(args[1])
    s = udp()
    rng = random.Random(1234)
    for _ in range(n):
        size = rng.randrange(0, 141)
        pkt = bytearray(rng.randbytes(size))
        if size and rng.random() < 0.5:
            pkt[0] = rng.choice([0x10, 0x20, 0x30, 0x38, 0x01, 0xFF])
        s.sendto(bytes(pkt), (LOCAL, target))
        time.sleep(0.002)
    s.settimeout(1.0)
    try:
        s.recvfrom(1000)
    except socket.timeout:
        return 0
    print("got a reply to junk")
    return 3


def lines(path):
    out = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))  # every line must be valid JSON
    return out


def stat(args):
    """stat FILE FIELD: print a field of the final stats line (drops.NAME ok)."""
    ev = lines(args[0])
    last = ev[-1]
    assert last["event"] == "stats", "last line is not stats"
    v = last
    for part in args[1].split("."):
        v = v[part]
    print(v)
    return 0


def count(args):
    """count FILE EVENT [REASON]: how many such events."""
    n = 0
    for e in lines(args[0]):
        if e["event"] == args[1] and (len(args) < 3 or e.get("reason") == args[2]):
            n += 1
    print(n)
    return 0


def drops_add_up(args):
    """drops_add_up FILE: printed drop lines + suppressed counts == stats drops.
    Prints the largest number of drop lines in any one second."""
    ev = lines(args[0])
    stats = ev[-1]
    assert stats["event"] == "stats", "last line is not stats"
    total = sum(stats["drops"].values())
    printed = [e for e in ev if e["event"] == "drop"]
    held_back = sum(e["count"] for e in ev if e["event"] == "drops_suppressed")
    assert len(printed) + held_back == total, (len(printed), held_back, total)
    per_second = {}
    for e in printed:
        per_second[e["ts"][:19]] = per_second.get(e["ts"][:19], 0) + 1
    print(max(per_second.values(), default=0))
    return 0


def check_lines(args):
    """check_lines FILE: every line is JSON with a UTC timestamp; nothing secret."""
    for e in lines(args[0]):
        assert e["ts"].endswith("Z") and len(e["ts"]) == 24, e
        assert e["event"] in ("handshake_sent", "session_established", "rekey",
                              "drop", "drops_suppressed", "hint", "stats", "error"), e
    return 0


if __name__ == "__main__":
    cmds = {"traffic": traffic, "listen": listen_only, "junk": junk, "stat": stat,
            "count": count, "check": check_lines, "drops": drops_add_up}
    sys.exit(cmds[sys.argv[1]](sys.argv[2:]))
