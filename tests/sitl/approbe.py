"""Test tool only. pymavlink probe for ArduPilot SITL signing tests. Test tool only.
  approbe.py cmd  TCPPORT KEY|none          send REQUEST_MESSAGE(148), exit 0 if ACK, 2 if none
  approbe.py setup TCPPORT SIGKEY|none NEWKEYHEX   send SETUP_SIGNING (signed with SIGKEY or unsigned); exit 0
  approbe.py rx   TCPPORT KEY|none          report whether received frames are signed (3s)
KEY is a 40-byte file (32 key + 8 ts) or 'none'."""
import os, sys, time
os.environ["MAVLINK20"] = "1"
from pymavlink import mavutil
mode, port, key = sys.argv[1], int(sys.argv[2]), sys.argv[3]
c = mavutil.mavlink_connection(f"tcp:127.0.0.1:{port}", source_system=254, source_component=190, dialect="common")
if key != "none":
    k = open(key, "rb").read()[:32]
    c.setup_signing(k, sign_outgoing=True, allow_unsigned_callback=lambda m, i: True)
    c.mav.signing.allow_unsigned_callback = lambda m, i: True
if mode == "cmd":
    end = time.time() + 4
    while time.time() < end:
        c.mav.command_long_send(1, 1, mavutil.mavlink.MAV_CMD_REQUEST_MESSAGE, 0, 148, 0, 0, 0, 0, 0, 0)
        a = c.recv_match(type="COMMAND_ACK", blocking=True, timeout=0.5)
        if a is not None:
            print(f"ACK cmd={a.command} result={a.result}"); sys.exit(0)
    print("no ACK"); sys.exit(2)
elif mode == "setup":
    nk = bytes.fromhex(sys.argv[4])
    ts = int((time.time() - 1420070400) * 1e5)
    c.mav.setup_signing_send(1, 1, list(nk), ts)
    time.sleep(1); print("sent SETUP_SIGNING"); sys.exit(0)
elif mode == "rx":
    n = s = 0; end = time.time() + 3
    while time.time() < end:
        m = c.recv_match(blocking=True, timeout=0.5)
        if m is None: continue
        n += 1
        if m.get_header().incompat_flags & 1: s += 1
    print(f"rx frames={n} signed={s}"); sys.exit(0)
