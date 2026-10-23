"""Test tool only. Arm or disarm PX4 with a signed command (sent as a ground station).
usage: arm.py KEYFILE HOST PORT arm|disarm   Exit 0 when the autopilot's heartbeat shows the state asked for, else 2."""
import os, sys, time
os.environ["MAVLINK20"] = "1"
from pymavlink import mavutil
key, host, port, what = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
want = what == "arm"
c = mavutil.mavlink_connection(f"udpout:{host}:{port}", source_system=255, source_component=190, dialect="common")
c.setup_signing(open(key, "rb").read()[:32], sign_outgoing=True, allow_unsigned_callback=lambda m, i: False)
end = time.time() + 20
while time.time() < end:
    # 21196 as param2 forces the change past preflight checks (this is a simulator).
    c.mav.command_long_send(1, 1, mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM, 0, 1 if want else 0, 21196, 0, 0, 0, 0, 0)
    m = c.recv_match(type=["HEARTBEAT", "COMMAND_ACK"], blocking=True, timeout=1)
    if m is None or m.get_srcSystem() != 1 or m.get_srcComponent() != 1:
        continue
    # An accepted acknowledgment is enough: a signer may change the key right after a disarm,
    # and then this client (still on the old key) cannot hear the next heartbeat.
    if m.get_type() == "COMMAND_ACK" and m.command == mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM \
            and m.result == mavutil.mavlink.MAV_RESULT_ACCEPTED:
        print("accepted"); sys.exit(0)
    if m.get_type() == "HEARTBEAT" and bool(m.base_mode & mavutil.mavlink.MAV_MODE_FLAG_SAFETY_ARMED) == want:
        print(f"now {'armed' if want else 'disarmed'}"); sys.exit(0)
print("state not reached"); sys.exit(2)
