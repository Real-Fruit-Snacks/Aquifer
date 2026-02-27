#!/usr/bin/env python3
"""Patch UPX signatures from a packed ELF binary.

Replaces all UPX magic bytes and info strings to prevent trivial
identification by 'file', YARA rules, or EDR heuristics.

The packed binary remains functional — UPX decompression stubs use
the p_info/p_filter structures at fixed offsets, not the ASCII magic.
Only the cosmetic markers are patched.

Usage:
    python3 scripts/patch_upx.py <binary>
"""

import sys
import os

PATCHES = [
    # (find_bytes, replace_bytes, description)
    (b"UPX!", b"\x00\x00\x00\x00", "UPX magic (header + trailer)"),
    (b"UPX executable packer", b"                     ", "UPX info string"),
    (b"http://upx.sf.net", b"                 ", "UPX URL"),
    (b"$Id: UPX", b"$Id:    ", "UPX version ID"),
    (b"the UPX Team", b"            ", "UPX team credit"),
    (b"Copyright (C) 1996-2024", b"                       ", "UPX copyright"),
]


def patch_binary(path: str) -> int:
    with open(path, "rb") as f:
        data = bytearray(f.read())

    total = 0
    for find, replace, desc in PATCHES:
        count = 0
        idx = 0
        while True:
            idx = data.find(find, idx)
            if idx == -1:
                break
            data[idx : idx + len(replace)] = replace
            idx += len(replace)
            count += 1
        if count:
            print(f"  Patched {count}x: {desc}")
            total += count

    # Also patch lowercase "upx" references (but not inside compressed data)
    # Only patch in the info/note region (last 16KB of file)
    tail_start = max(0, len(data) - 16384)
    idx = tail_start
    count = 0
    while True:
        idx = data.find(b"upx.", idx)
        if idx == -1 or idx < tail_start:
            break
        data[idx : idx + 4] = b"   ."
        idx += 4
        count += 1
    if count:
        print(f"  Patched {count}x: lowercase upx references")
        total += count

    if total == 0:
        print("  No UPX signatures found (already clean or not UPX-packed)")
        return 0

    with open(path, "wb") as f:
        f.write(data)

    print(f"  Total: {total} patches applied to {path}")
    return total


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <binary>", file=sys.stderr)
        sys.exit(1)

    path = sys.argv[1]
    if not os.path.isfile(path):
        print(f"Error: {path} not found", file=sys.stderr)
        sys.exit(1)

    print(f"Patching UPX signatures in {path}...")
    patch_binary(path)


if __name__ == "__main__":
    main()
