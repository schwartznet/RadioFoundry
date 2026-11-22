#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 The RadioFoundry Authors
"""Auto DMR ID on a PC (docs/spec/auto-dmr-id.md): the DMR ID a radio's Tools > Auto DMR ID gives, from its chip UID.

    tools/dmrid_from_uid.py 401065E42855394B68455CAF        the ID (candidate 0) and the next candidates
    tools/dmrid_from_uid.py --port COM60                     read the UID over the debug link (rfoundry_debug.py chip)
    tools/dmrid_from_uid.py --check UID1 UID2 ...            a fleet: every radio's ID, and any two that collide
    tools/dmrid_from_uid.py --check --file uids.txt          the same, one UID a line (# comments allowed)
    tools/dmrid_from_uid.py --self-test                      the formula against the shared vectors

The UID is the 24 hex digits rfoundry_debug.py chip prints after "uid" (the high word first). The ID of candidate k is
BASE + (the first 4 octets of SHA-256(UID) as a big-endian number) % SPAN for k 0, and of SHA-256(UID || k) for k 1
to 255: what core/support/auto_dmr_id.c computes. --base and --span must match the build's CONFIG_AUTO_DMR_ID_BASE and
_SPAN (default 4670000 and 10000).
"""
import argparse
import hashlib
import os
import sys

BASE_DEFAULT = 4670000
SPAN_DEFAULT = 10000
DMR_ID_MAX = 16776415
VECTORS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests", "vectors", "auto-dmr-id.txt")


def parse_uid(text):
    s = text.strip().replace(" ", "").replace(":", "").replace("-", "")
    if s.lower().startswith("0x"):
        s = s[2:]
    if len(s) != 24:
        raise ValueError(f"a UID is 24 hex digits (96 bits), got {len(s)}: {text!r}")
    return bytes.fromhex(s)


def auto_dmr_id(uid, k=0, base=BASE_DEFAULT, span=SPAN_DEFAULT):
    """The ID of candidate k (0..255) for a 12-octet UID."""
    if len(uid) != 12 or not 0 <= k <= 255:
        raise ValueError("12-octet UID and candidate 0..255")
    if span <= 0:
        return 0
    h = hashlib.sha256(uid + (bytes([k]) if k else b"")).digest()
    return base + int.from_bytes(h[:4], "big") % span


def read_uid(port):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import rfoundry_debug  # noqa: E402  (the debug link client beside this file)
    link = rfoundry_debug.DebugLink(port)
    u0, u1, u2 = link.chip()["uid"]
    if (u0, u1, u2) == (0, 0, 0):
        raise SystemExit("dmrid_from_uid: the radio reports no UID")
    return bytes.fromhex(f"{u2:08X}{u1:08X}{u0:08X}")


def self_test():
    n = 0
    with open(VECTORS, encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].split()
            if not line:
                continue
            uid, k, base, span, want = line[0], int(line[1]), int(line[2]), int(line[3]), int(line[4])
            got = auto_dmr_id(parse_uid(uid), k, base, span)
            if got != want:
                print(f"FAIL {uid} k={k}: {got}, want {want}")
                return 1
            n += 1
    print(f"dmrid_from_uid: {n} vectors pass")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("uids", nargs="*", help="UIDs, 24 hex digits each")
    ap.add_argument("--port", help="read the UID from a radio over the debug link (COMx, /dev/ttyACMx)")
    ap.add_argument("--file", help="UIDs one a line (with --check)")
    ap.add_argument("--check", action="store_true", help="a fleet: the IDs and any collisions")
    ap.add_argument("--candidates", type=int, default=4, help="candidates shown for one radio (default 4)")
    ap.add_argument("--base", type=int, default=BASE_DEFAULT)
    ap.add_argument("--span", type=int, default=SPAN_DEFAULT)
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    if a.base < 1 or a.span < 1 or a.base + a.span - 1 > DMR_ID_MAX:
        ap.error(f"--base and --span must give IDs 1 to {DMR_ID_MAX}")
    uids = [parse_uid(u) for u in a.uids]
    if a.file:
        with open(a.file, encoding="utf-8") as f:
            uids += [parse_uid(l.split("#", 1)[0]) for l in f if l.split("#", 1)[0].strip()]
    if a.port:
        uids.append(read_uid(a.port))
    if not uids:
        ap.error("give a UID, --file or --port")
    if not a.check:
        for uid in uids:
            print(f"uid {uid.hex().upper()}")
            for k in range(max(1, a.candidates)):
                print(f"  candidate {k}: {auto_dmr_id(uid, k, a.base, a.span)}")
        return 0
    # A fleet: candidate 0 each; a collision gets the next candidate on every radio after the first that has the ID,
    # as their users would press # on the radio
    taken = {}
    clash = False
    seen = set()
    for uid in uids:
        if uid in seen:
            print(f"{uid.hex().upper()}  listed twice: skipped")
            continue
        seen.add(uid)
        k = 0
        first = auto_dmr_id(uid, 0, a.base, a.span)
        while auto_dmr_id(uid, k, a.base, a.span) in taken and k < 255:
            k += 1
        i = auto_dmr_id(uid, k, a.base, a.span)
        note = ""
        if k:
            clash = True
            note = f"  (candidate 0 {first} is {taken[first].hex().upper()}'s: use candidate {k})"
        taken[i] = uid
        print(f"{uid.hex().upper()}  {i}  candidate {k}{note}")
    print("collisions: none" if not clash else "collisions: resolved above with later candidates")
    return 0


if __name__ == "__main__":
    sys.exit(main())
