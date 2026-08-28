#!/usr/bin/env python3
"""Patch one field (vmaddr or vmsize) of one LC_SEGMENT_64, in place.

Grown vmsize (past filesize) reserves address space with no real file
content backing it -- same BSS-style mechanism __PAGEZERO already uses.
Moved vmaddr relocates a segment to make room for a neighbor's reservation
-- only safe for a segment nothing else references via a hardcoded
PC-relative offset (__LINKEDIT qualifies: dyld always reads its location
fresh from the load command; __TEXT/__DATA/__DATA_CONST do NOT -- see the
2026-08-28 discussion in NOTES.md for why moving one of those would break
existing adrp/add references baked into the compiled code).

Doesn't touch fileoff/filesize, and doesn't move any other byte in the
file -- unlike inserting a whole new load command (which would require
shifting every other load command's own file offsets, deliberately
avoided here).

The binary needs an ad-hoc re-sign afterward (`codesign -s - -f <path>`),
same as strip_lc_load_dylib.py -- this script does not do that for you.
"""
import struct
import sys

LC_SEGMENT_64 = 0x19
FIELD_OFFSET = {"vmaddr": 24, "vmsize": 32}  # bytes into segment_command_64


def patch(path: str, segname: str, field: str, new_value: int) -> bool:
    target = segname.encode("ascii").ljust(16, b"\0")
    field_off = FIELD_OFFSET[field]
    with open(path, "r+b") as f:
        data = bytearray(f.read())
        _, _, _, _, ncmds, _, _, _ = struct.unpack_from("<IiiIIIII", data, 0)
        off = 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", data, off)
            if cmd == LC_SEGMENT_64:
                name = bytes(data[off + 8:off + 24])
                if name == target:
                    old_value, = struct.unpack_from("<Q", data, off + field_off)
                    struct.pack_into("<Q", data, off + field_off, new_value)
                    f.seek(0)
                    f.write(data)
                    print(f"{segname}.{field}: 0x{old_value:x} -> 0x{new_value:x}")
                    return True
            off += cmdsize
    return False


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(f"usage: {sys.argv[0]} <mach-o binary, patched in place> <segname> <field>=<hex-value>\n"
                  f"  field is 'vmaddr' or 'vmsize'")
    field, _, value = sys.argv[3].partition("=")
    if field not in FIELD_OFFSET or not value:
        sys.exit(f"bad field spec {sys.argv[3]!r} -- expected vmaddr=0x... or vmsize=0x...")
    ok = patch(sys.argv[1], sys.argv[2], field, int(value, 16))
    if not ok:
        sys.exit(f"segment {sys.argv[2]!r} not found")
    print("remember to re-sign: codesign -s - -f", sys.argv[1])
