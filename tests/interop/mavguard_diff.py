"""Differential test: the Rust MAVLink guard against pymavlink (the reference parser).

Test tool only. Run: python3 -I tests/interop/mavguard_diff.py [--n N] [--seed S]

It builds datagrams with pymavlink (every message of the common dialect, MAVLink 1 and 2,
signed and unsigned, batched), then damages some (bit flips, cuts, junk before and after).
Each datagram goes to `examples/mavguard_check` (built with `cargo build --release --example
mavguard_check`) twice: with the default guard and with `--wide`.

Checks, per datagram:
  A. If the guard passes it, pymavlink must read it as exactly the same frames (message ids
     and lengths) with valid CRCs and no bytes left over.
  B. If pymavlink reads it as whole, valid frames, the guard must not call it `malformed` or
     `bad_crc` (a policy reason is fine).
Exit 0 if they all agree.
"""

import os
import random
import subprocess
import sys

os.environ["MAVLINK20"] = "1"

from pymavlink.dialects.v20 import common as m2  # noqa: E402
from pymavlink.dialects.v10 import common as m1  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "..", "target", "release", "examples", "mavguard_check")
POLICY = {"setup_signing", "param_write", "signing_param", "ftp", "msg_not_allowed", "command_not_allowed"}


class Sink:
    def write(self, b):
        pass


def sample_value(rng, f):
    t = f.type if hasattr(f, "type") else "uint8_t"
    return t


def make_message(mod, rng, cls):
    """A message with random field values, built straight from its field table."""
    args = []
    for name, t, n in zip(cls.fieldnames, cls.fieldtypes, cls.array_lengths):
        base = t.replace("[", " ").split()[0]
        if base == "char":
            v = bytes(rng.choice(b"ABCDEFGHIJKLMNOP_0123456789") for _ in range(rng.randint(0, n or 1)))
            v = v.decode()
        elif "float" in base:
            v = [rng.uniform(-100, 100) for _ in range(n)] if n else rng.uniform(-100, 100)
        else:
            bits = {"uint8_t": 8, "int8_t": 8, "uint16_t": 16, "int16_t": 16, "uint32_t": 32,
                    "int32_t": 32, "uint64_t": 64, "int64_t": 64, "double": 8}.get(base, 8)
            signed = base.startswith("int")
            lo, hi = (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if signed else (0, (1 << bits) - 1)
            pick = lambda: rng.choice([0, 0, 1, hi, rng.randint(lo, hi)])
            v = [pick() for _ in range(n)] if n else pick()
        args.append(v)
    return cls(*args)


def pack_all(rng, signed_ok=True):
    """Yield (name, bytes) frames for every message in both dialects."""
    out = []
    for mod, v2 in ((m2, True), (m1, False)):
        mav = mod.MAVLink(Sink(), srcSystem=1, srcComponent=1)
        for cls in mod.mavlink_map.values():
            if cls.id == 256 and not v2:
                continue
            try:
                msg = make_message(mod, rng, cls)
                buf = msg.pack(mav, force_mavlink1=not v2)
            except Exception:
                continue
            out.append(bytes(buf))
            if v2 and signed_ok:
                # Sign with pymavlink's own signing so the layout is the real one.
                mav.signing.secret_key = bytes(range(32))
                mav.signing.sign_outgoing = True
                mav.signing.link_id = 0
                mav.signing.timestamp = 1000
                try:
                    out.append(bytes(msg.pack(mav)))
                finally:
                    mav.signing.sign_outgoing = False
                    mav.signing.secret_key = None
    return out


def pyread(data):
    """pymavlink's reading of a datagram: [(id, length)] if it is only whole valid frames, else None."""
    mav = m2.MAVLink(None)
    mav.robust_parsing = True
    try:
        msgs = mav.parse_buffer(data) or []
    except Exception:
        return None
    if mav.buf_len() != 0 or not msgs:
        return None
    frames = []
    total = 0
    for m in msgs:
        if m.get_type() in ("BAD_DATA", "UNKNOWN_" ) or m.get_msgId() < 0 or m.get_type().startswith("UNKNOWN"):
            return None  # junk, or an id outside the dialect (no CRC_EXTRA: the guard drops these too)
        b = m.get_msgbuf()
        frames.append((m.get_msgId(), len(b)))
        total += len(b)
    return frames if total == len(data) else None


def run_guard(datagrams, wide):
    args = [BIN] + (["--wide"] if wide else [])
    p = subprocess.run(args, input="\n".join(d.hex() for d in datagrams) + "\n", capture_output=True, text=True, check=True)
    return p.stdout.strip().split("\n")


def damage(rng, d):
    d = bytearray(d)
    k = rng.randint(0, 6)
    if k == 0 and len(d) > 1:
        return bytes(d[: rng.randint(1, len(d) - 1)])
    if k == 1:
        d[rng.randrange(len(d))] ^= 1 << rng.randrange(8)
    elif k == 2:
        d[rng.randrange(len(d))] = rng.randrange(256)
    elif k == 3:
        return bytes(rng.randrange(256) for _ in range(rng.randint(1, 5))) + bytes(d)
    elif k == 4:
        return bytes(d) + bytes(rng.randrange(256) for _ in range(rng.randint(1, 5)))
    elif k == 5 and len(d) > 3:
        d[2] = rng.choice([0, 1, 2, 3, 0x80])  # incompat flags
    else:
        d[1] = rng.randrange(256) if len(d) > 1 else d[0]  # length
    return bytes(d)


def main():
    n = 3000
    seed = 1
    a = sys.argv[1:]
    if "--n" in a:
        n = int(a[a.index("--n") + 1])
    if "--seed" in a:
        seed = int(a[a.index("--seed") + 1])
    rng = random.Random(seed)
    if not os.path.exists(BIN):
        sys.exit("build it first: cargo build --release --example mavguard_check")
    frames = pack_all(rng)
    corpus = list(frames)
    for _ in range(n):
        base = b"".join(rng.choice(frames) for _ in range(rng.choice([1, 1, 1, 2, 3])))
        corpus.append(damage(rng, base) if rng.random() < 0.7 else base)
    corpus.extend([b"", b"\x00", b"\xfd", b"\xfe", b"\xfd" * 20, bytes(300)])
    corpus = [c for c in corpus if c]

    bad = 0
    stats = {"pass": 0, "policy": 0, "invalid": 0, "py_valid": 0}
    for wide in (False, True):
        res = run_guard(corpus, wide)
        assert len(res) == len(corpus), (len(res), len(corpus))
        for d, r in zip(corpus, res):
            py = pyread(d)
            kind, _, rest = r.partition(" ")
            if kind == "pass":
                stats["pass"] += 1
                mine = [tuple(map(int, x.split(":"))) for x in rest.split(",")]
                if py != mine:
                    bad += 1
                    print(f"DISAGREE (guard passed): wide={wide} guard={mine} pymavlink={py} data={d.hex()}")
            else:
                if py is not None:
                    stats["py_valid"] += 1
                    if rest not in POLICY:
                        bad += 1
                        print(f"DISAGREE (guard says {rest}, pymavlink reads whole valid frames {py}): wide={wide} data={d.hex()}")
                    else:
                        stats["policy"] += 1
                else:
                    stats["invalid"] += 1
    print(f"{len(corpus)} datagrams x 2 guards: {stats}, disagreements: {bad}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
