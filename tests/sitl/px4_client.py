"""Test tool only. Send COMMAND_LONG REQUEST_MESSAGE(148) to PX4, optionally signed. Exit 0 on ACK, 2 on none.
usage: px4_client.py KEYFILE|none HOST PORT [local_port] [sysid compid]"""
import os, sys, time
os.environ["MAVLINK20"] = "1"
from pymavlink import mavutil
key, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
lport = sys.argv[4] if len(sys.argv) > 4 else None
conn = mavutil.mavlink_connection(f"udpout:{host}:{port}", source_system=255, source_component=190, dialect="common")
if key != "none":
    conn.setup_signing(open(key, "rb").read()[:32], sign_outgoing=True,
                       allow_unsigned_callback=lambda m, i: False)
deadline = time.time() + 4
while time.time() < deadline:
    conn.mav.command_long_send(1, 1, mavutil.mavlink.MAV_CMD_REQUEST_MESSAGE, 0, 148, 0, 0, 0, 0, 0, 0)
    ack = conn.recv_match(type="COMMAND_ACK", blocking=True, timeout=0.5)
    if ack is not None:
        print(f"ACK cmd={ack.command} result={ack.result} from {ack.get_srcSystem()}:{ack.get_srcComponent()} signed={bool(ack.get_signed())}")
        sys.exit(0)
print("no ACK"); sys.exit(2)
