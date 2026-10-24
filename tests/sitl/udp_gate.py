"""Test tool only. A UDP go-between that breaks the link on purpose, so the signer's recovery can be tested.

usage: udp_gate.py LISTEN_PORT TARGET_PORT CONTROLFILE

The client (oasa-pair signer) talks to LISTEN_PORT; this forwards to 127.0.0.1:TARGET_PORT (PX4) and
sends PX4's frames back to the client. CONTROLFILE holds a mode, read on every packet (missing or empty: pass everything):
  all    drop everything PX4 sends back (a silent autopilot, a lost link)
  acks   drop PX4 datagrams that hold a COMMAND_ACK (msgid 77)
  setup  drop client datagrams that hold SETUP_SIGNING (msgid 256), so PX4 never sees the key change
"""
import os, select, socket, sys

listen, target, control = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
client_side = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_side.bind(("127.0.0.1", listen))
px4_side = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
px4_side.bind(("127.0.0.1", 0))
client = None


def mode():
    try:
        return open(control).read().strip()
    except OSError:
        return ""


def msgids(d):
    ids, i = [], 0
    while i + 10 <= len(d):
        if d[i] != 0xFD:
            break
        n, incompat = d[i + 1], d[i + 2]
        ids.append(d[i + 7] | d[i + 8] << 8 | d[i + 9] << 16)
        i += 10 + n + 2 + (13 if incompat & 1 else 0)
    return ids


print("gate ready", flush=True)
while True:
    r, _, _ = select.select([client_side, px4_side], [], [])
    for s in r:
        d, addr = s.recvfrom(4096)
        m = mode()
        if s is client_side:
            client = addr
            if m == "setup" and 256 in msgids(d):
                continue
            px4_side.sendto(d, ("127.0.0.1", target))
        elif client is not None:
            if m == "all" or (m == "acks" and 77 in msgids(d)):
                continue
            client_side.sendto(d, client)
