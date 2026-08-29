#!/usr/bin/env python3
"""Append an ordinary LC_LOAD_DYLIB command to a thin ARM64 Mach-O."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0x0C


def align(value: int, boundary: int) -> int:
    return (value + boundary - 1) & ~(boundary - 1)


def inject_load_dylib(data: bytes, dylib_path: str) -> bytes:
    if b"\0" in dylib_path.encode("utf-8"):
        raise ValueError("Dylib path contains NUL")
    if len(data) < 32:
        raise ValueError("Mach-O header is truncated")
    magic, cpu_type, _cpu_subtype, _file_type, ncmds, sizeofcmds, _flags, _reserved = \
        struct.unpack_from("<IiiIIIII", data, 0)
    if magic != MH_MAGIC_64 or cpu_type != CPU_TYPE_ARM64:
        raise ValueError("Expected a thin little-endian ARM64 Mach-O")

    command_offset = 32
    first_section_offset = len(data)
    existing_paths: list[str] = []
    for _ in range(ncmds):
        if command_offset + 8 > len(data):
            raise ValueError("Mach-O load command table is truncated")
        command, command_size = struct.unpack_from("<II", data, command_offset)
        if command_size < 8 or command_offset + command_size > len(data):
            raise ValueError("Invalid Mach-O load command size")
        if command == LC_LOAD_DYLIB and command_size >= 24:
            name_offset = struct.unpack_from("<I", data, command_offset + 8)[0]
            if 24 <= name_offset < command_size:
                raw = data[command_offset + name_offset:command_offset + command_size]
                existing_paths.append(raw.split(b"\0", 1)[0].decode("utf-8", "replace"))
        if command == LC_SEGMENT_64 and command_size >= 72:
            section_count = struct.unpack_from("<I", data, command_offset + 64)[0]
            section_offset = command_offset + 72
            if section_offset + section_count * 80 > command_offset + command_size:
                raise ValueError("Invalid Mach-O section table")
            for index in range(section_count):
                offset = struct.unpack_from("<I", data, section_offset + index * 80 + 48)[0]
                if offset:
                    first_section_offset = min(first_section_offset, offset)
        command_offset += command_size

    load_end = 32 + sizeofcmds
    if command_offset != load_end:
        raise ValueError("Mach-O sizeofcmds does not match its load commands")
    if dylib_path in existing_paths:
        return data

    encoded = dylib_path.encode("utf-8") + b"\0"
    command_size = align(24 + len(encoded), 8)
    if load_end + command_size > first_section_offset:
        raise ValueError(
            f"Insufficient Mach-O header slack: need {command_size}, "
            f"have {first_section_offset - load_end}"
        )
    if any(data[load_end:load_end + command_size]):
        raise ValueError("Mach-O header slack is not zero-filled")

    result = bytearray(data)
    command = struct.pack("<IIIIII", LC_LOAD_DYLIB, command_size, 24, 0, 0, 0)
    command += encoded
    command += b"\0" * (command_size - len(command))
    result[load_end:load_end + command_size] = command
    struct.pack_into("<II", result, 16, ncmds + 1, sizeofcmds + command_size)
    return bytes(result)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("dylib_path")
    args = parser.parse_args()
    patched = inject_load_dylib(args.input.read_bytes(), args.dylib_path)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(patched)
    print(f"input_bytes={args.input.stat().st_size}")
    print(f"output_bytes={args.output.stat().st_size}")
    print(f"dependency={args.dylib_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
