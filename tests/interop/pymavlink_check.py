"""Interop check: pymavlink (the reference MAVLink library) against oasa-pair.

Test tool only. Two modes:

  autopilot KEYFILE PORT       Act as an autopilot with signing on. Rejects
                               unsigned or badly signed messages and answers
                               valid signed COMMAND_LONG with a signed ACK.
                               Exits after the first accepted command.
  client KEYFILE|none PORT     Send a COMMAND_LONG (signed with KEYFILE, or
                               unsigned with "none") and wait 3 s for an ACK.
                               Exit 0 if one arrived, 2 if not (any other
                               exit code means the script itself failed).
"""

import os
import sys
import time

# pymavlink speaks MAVLink 1 (which can't be signed) unless told otherwise.
os.environ["MAVLINK20"] = "1"

from pymavlink import mavutil  # noqa: E402


def load_key(path):
    data = open(path, "rb").read()
    assert len(data) == 40, "signing key file must be 40 bytes"
    return data[:32]


def reject_unsigned(mav, msg_id):
    # Accept nothing unsigned, not even RADIO_STATUS.
    return False


def autopilot(key_path, port):
    conn = mavutil.mavlink_connection(f"udpin:127.0.0.1:{port}", source_system=1, source_component=1, dialect="common")
    conn.setup_signing(load_key(key_path), sign_outgoing=True, allow_unsigned_callback=reject_unsigned)
    print(f"pymavlink autopilot on {port}, signed only", flush=True)
    deadline = time.time() + 20
    while time.time() < deadline:
        msg = conn.recv_match(type="COMMAND_LONG", blocking=True, timeout=1)
        if msg is None:
            continue
        print(f"accepted signed COMMAND_LONG {msg.command} from {msg.get_srcSystem()}:{msg.get_srcComponent()}", flush=True)
        conn.mav.command_ack_send(msg.command, mavutil.mavlink.MAV_RESULT_ACCEPTED)
        return 0
    print("no valid signed command received", flush=True)
    return 1


def client(key_path, port):
    conn = mavutil.mavlink_connection(f"udpout:127.0.0.1:{port}", source_system=255, source_component=190, dialect="common")
    if key_path != "none":
        conn.setup_signing(load_key(key_path), sign_outgoing=True, allow_unsigned_callback=reject_unsigned)
    deadline = time.time() + 3
    while time.time() < deadline:
        conn.mav.command_long_send(1, 1, mavutil.mavlink.MAV_CMD_REQUEST_MESSAGE, 0, 148, 0, 0, 0, 0, 0, 0)
        ack = conn.recv_match(type="COMMAND_ACK", blocking=True, timeout=0.5)
        if ack is not None:
            print(f"ACK {ack.command} result {ack.result}", flush=True)
            return 0
    print("no ACK", flush=True)
    return 2


if __name__ == "__main__":
    mode, key, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
    sys.exit(autopilot(key, port) if mode == "autopilot" else client(key, port))
