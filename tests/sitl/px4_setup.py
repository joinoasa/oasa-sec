"""Test tool only. Send SETUP_SIGNING to PX4 sys 1 comp 1, unsigned or signed. usage: px4_setup.py NEWKEYHEX|zero PORT [signkeyfile]"""
import os, sys, time
os.environ["MAVLINK20"] = "1"
from pymavlink import mavutil
newk, port = sys.argv[1], int(sys.argv[2])
c = mavutil.mavlink_connection(f"udpout:127.0.0.1:{port}", source_system=255, source_component=190, dialect="common")
if len(sys.argv) > 3:
    c.setup_signing(open(sys.argv[3],"rb").read()[:32], sign_outgoing=True, allow_unsigned_callback=lambda m,i: False)
key = bytes(32) if newk == "zero" else bytes.fromhex(newk)
ts = 0 if newk == "zero" else int((time.time()-1420070400)*100000)
for _ in range(3):
    c.mav.setup_signing_send(1, 1, list(key), ts); time.sleep(0.2)
print("sent")
