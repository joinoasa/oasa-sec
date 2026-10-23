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


def _crc(data, extra):
    from pymavlink import mavutil  # noqa: F401  (sets up the dialects)
    from pymavlink.generator.mavcrc import x25crc
    c = x25crc()
    c.accumulate(data)
    c.accumulate(bytes([extra]))
    return c.crc.to_bytes(2, "little")


def mav(msgid, payload, signed=False, v1=False, bad_crc=False):
    """A MAVLink frame with the real CRC (CRC_EXTRA from pymavlink's common dialect)."""
    from pymavlink.dialects.v20 import common
    extra = common.mavlink_map[msgid].crc_extra
    if v1:
        body = bytes([len(payload), 1, 255, 190, msgid]) + payload
        tail = b""
    else:
        body = bytes([len(payload), 1 if signed else 0, 0, 1, 255, 190]) + msgid.to_bytes(3, "little") + payload
        tail = b"\x5a" * 13 if signed else b""
    crc = _crc(body, extra)
    if bad_crc:
        crc = bytes([crc[0] ^ 1, crc[1]])
    return bytes([0xFE if v1 else 0xFD]) + body + crc + tail


def param_set(name):
    return bytes(4) + bytes([1, 1]) + name.encode().ljust(16, b"\0") + b"\x09"


def command_long(cmd, signed=False):
    # Seven floats, then the 16-bit command, target ids, confirmation.
    return mav(76, bytes(28) + cmd.to_bytes(2, "little") + bytes([1, 1, 0]), signed=signed)


def mission_item_int(cmd):
    # Seven 4-byte values, seq, command, then target ids, frame, current, autocontinue.
    return mav(73, bytes(28) + (0).to_bytes(2, "little") + cmd.to_bytes(2, "little") + bytes([1, 1, 3, 0, 1]))


def guard(args):
    """guard IN_PORT OUT_PORT MODE: send MAVLink datagrams into the ground
    station's plaintext input and compare what comes out of the drone's
    plaintext output with what the allowlist should let through. Prints
    `blocked N` (how many the guard should have stopped). MODE: default,
    ftp (--allow-mavlink-ftp), wide (--allow-msg 33 --allow-command 246
    --allow-param MPC_XY_VEL_MAX) or off (no guard)."""
    a_in, b_out, mode = int(args[0]), int(args[1]), args[2]
    b_in_port = int(args[3]) if len(args) > 3 else None
    hb = mav(0, bytes(9))
    ping = mav(4, bytes(14))
    ftp = mav(110, bytes(251), signed=True)
    gpi = mav(33, bytes(28), signed=True)
    reboot = command_long(246, signed=True)
    param_ok = mav(23, param_set("MPC_XY_VEL_MAX"), signed=True)
    clear_normal = mav(45, bytes([1, 1]))  # MISSION_CLEAR_ALL, the normal mission (type cut)
    clear_fence = mav(45, bytes([1, 1, 1]))
    clear_all = mav(45, bytes([1, 1, 255]))
    rtk = mav(233, bytes([0, 4]) + bytes(180))
    always_blocked = {
        "clear_all_types": clear_all,
        "too_long": mav(0, bytes(10)),  # HEARTBEAT is at most 9 bytes
        "setup_signing": mav(256, bytes(range(42)), signed=True),
        "setup_signing_v2": mav(256, bytes(42)),
        "param_set_sign": mav(23, param_set("MAV_SIGN_CFG")),
        "param_set_opts": mav(23, param_set("MAV2_OPTIONS"), signed=True),
        "mission_reboot": mission_item_int(246),
        "bad_crc": mav(0, bytes(9), bad_crc=True),
        "batched_with_setup_signing": hb + mav(256, bytes(42)) + hb,
        "junk": b"not mavlink at all",
        "cut_short": hb[:-3],
        "stray_byte": hb + b"\x00",
    }
    by_default = {
        "ftp": ftp,
        "global_position_int": gpi,
        "clear_fence": clear_fence,
        "rtk": rtk,
        "command_reboot": reboot,
        "param_set_ok": param_ok,
    }
    passing = {
        "heartbeat": hb,
        "clear_mission": clear_normal,
        "arm": command_long(400, signed=True),
        "takeoff": command_long(22),
        "mission_item": mission_item_int(16),
        "batched_ok": hb + ping + command_long(20, signed=True),
        "v1_ping": mav(4, bytes(14), v1=True),
    }
    send = {**passing, **always_blocked, **by_default}
    allowed_now = {"default": set(), "ftp": {"ftp"},
                   "wide": {"clear_fence", "rtk", "global_position_int", "command_reboot", "mission_reboot", "param_set_ok"}}.get(mode, set())
    if mode == "off":
        expect_pass = set(send)
    else:
        expect_pass = set(passing) | allowed_now
    expect_blocked = set(send) - expect_pass
    print(f"blocked {len(expect_blocked)}")
    got, froms, stop = [], [], threading.Event()
    rb = udp(b_out)

    def collect():
        rb.settimeout(0.2)
        while not stop.is_set():
            try:
                data, frm = rb.recvfrom(70000)
            except socket.timeout:
                continue
            got.append(data)
            froms.append(frm[1])

    threading.Thread(target=collect, daemon=True).start()
    tx = udp()
    for name, d in send.items():
        tx.sendto(d, (LOCAL, a_in))
        time.sleep(0.1)
    time.sleep(1.0)
    stop.set()
    time.sleep(0.3)
    by_bytes = {v: k for k, v in send.items()}
    names = sorted(by_bytes.get(g, "?") for g in got)
    print(f"{mode}: delivered {names}")
    if b_in_port is not None and set(froms) != {b_in_port}:
        print(f"packets came from ports {sorted(set(froms))}, expected only {b_in_port} (the --plain-listen port)")
        return 3
    return 0 if names == sorted(expect_pass) else 2


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
            pkt[0] = rng.choice([0x11, 0x21, 0x31, 0x39, 0x01, 0xFF])
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
                              "drop", "drops_suppressed", "hint", "stats", "error",
                              "mavlink_guard", "warning"), e
    return 0


if __name__ == "__main__":
    cmds = {"traffic": traffic, "listen": listen_only, "junk": junk, "stat": stat,
            "count": count, "guard": guard, "check": check_lines, "drops": drops_add_up}
    sys.exit(cmds[sys.argv[1]](sys.argv[2:]))
