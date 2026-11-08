"""Helper for scripts/rekey-latency.sh: two-way traffic through two oasa-link
processes, one-way delay of every message. Test tool only.

usage: rekey_latency.py SECONDS RATE A_IN A_OUT B_IN B_OUT
Sends 32-byte messages at RATE a second each way (A_IN -> B_OUT and
B_IN -> A_OUT), each carrying its number and its send time (monotonic clock,
one machine). Prints one JSON line: per direction the count sent and
received, the median, 99th percentile and largest delay in milliseconds.
"""
import json
import socket
import struct
import sys
import threading
import time

LOCAL = "127.0.0.1"


def main():
    secs, rate = float(sys.argv[1]), float(sys.argv[2])
    a_in, a_out, b_in, b_out = (int(x) for x in sys.argv[3:7])
    start = time.monotonic()
    delays = {"a_to_b": {}, "b_to_a": {}}
    sent = {}

    def receive(port, key):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((LOCAL, port))
        s.settimeout(0.2)
        while time.monotonic() < start + secs + 2:
            try:
                b, _ = s.recvfrom(2048)
            except socket.timeout:
                continue
            now = time.monotonic()
            if len(b) >= 12:
                n, at = struct.unpack("!Id", b[:12])
                delays[key][n] = now - at

    def send(port, key):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        n = 0
        due = time.monotonic()
        while time.monotonic() < start + secs:
            due += 1.0 / rate
            wait = due - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            s.sendto(struct.pack("!Id", n, time.monotonic()) + bytes(20), (LOCAL, port))
            n += 1
        sent[key] = n

    threads = [
        threading.Thread(target=receive, args=(b_out, "a_to_b")),
        threading.Thread(target=receive, args=(a_out, "b_to_a")),
        threading.Thread(target=send, args=(a_in, "a_to_b")),
        threading.Thread(target=send, args=(b_in, "b_to_a")),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    out = {}
    for key, got in delays.items():
        v = sorted(got.values()) or [float("nan")]
        out[key] = {
            "sent": sent[key],
            "received": len(got),
            "p50_ms": round(v[len(v) // 2] * 1000, 2),
            "p99_ms": round(v[min(len(v) - 1, int(len(v) * 0.99))] * 1000, 2),
            "max_ms": round(v[-1] * 1000, 2),
        }
    print(json.dumps(out))


if __name__ == "__main__":
    main()
