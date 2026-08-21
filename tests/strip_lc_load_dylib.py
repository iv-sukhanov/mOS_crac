#!/usr/bin/env python3
"""Neutralize every LC_LOAD_DYLIB command in a Mach-O64 binary in place.

ld64 refuses to produce a dynamic executable with zero dylib dependencies
("dynamic executables or dylibs must link with libSystem.dylib") -- no
override flag exists. Workaround: link normally with -lSystem to pass that
check, then patch the resulting binary's LC_LOAD_DYLIB command(s) so dyld's
load-command parser no longer recognizes them (cmdsize is left untouched so
the parser still skips over the right number of bytes; the cmd field is
zeroed, which isn't a defined command type, so unknown-command handling
just ignores it). The binary needs an ad-hoc re-sign afterward (`codesign
-s - -f <path>`) since arm64 macOS refuses to exec an unsigned/mis-signed
binary -- this script does not do that for you.

See docs/006-freestanding-restore-driver.md and NOTES.md (2026-08-21) for
why this exists and what it found: the patched binary DOES launch and run
with zero declared dylibs, but dyld loads libSystem into it anyway,
regardless -- this doesn't get you what the freestanding-driver plan needed.
"""
import struct
import sys

LC_LOAD_DYLIB = 0xC


def strip(path: str) -> int:
    with open(path, "r+b") as f:
        data = bytearray(f.read())
        _, _, _, _, ncmds, _, _, _ = struct.unpack_from("<IiiIIIII", data, 0)
        off = 32  # sizeof(mach_header_64)
        patched = 0
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", data, off)
            if cmd == LC_LOAD_DYLIB:
                struct.pack_into("<I", data, off, 0)
                patched += 1
            off += cmdsize
        f.seek(0)
        f.write(data)
    return patched


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(f"usage: {sys.argv[0]} <mach-o binary, patched in place>")
    n = strip(sys.argv[1])
    print(f"neutralized {n} LC_LOAD_DYLIB command(s) in {sys.argv[1]}")
    print("remember to re-sign: codesign -s - -f", sys.argv[1])
