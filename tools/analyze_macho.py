#!/usr/bin/env python3
"""Small LIEF/Capstone helper for repeatable ARM64 Mach-O RVA analysis."""

from __future__ import annotations

import argparse
import bisect
import re
import sys
from pathlib import Path

import lief
from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG


def parse_int(value: str) -> int:
    return int(value, 0)


def c_string(binary: lief.MachO.Binary, address: int, limit: int = 240) -> str | None:
    section = binary.section_from_virtual_address(address)
    if section is None or section.name not in {"__cstring", "__objc_methname", "__objc_classname"}:
        return None
    raw = bytes(binary.get_content_from_virtual_address(address, limit))
    value = raw.split(b"\0", 1)[0]
    if not value or any(byte < 0x20 or byte >= 0x7F for byte in value):
        return None
    return value.decode("ascii", "replace")


def symbol_index(binary: lief.MachO.Binary) -> tuple[list[int], dict[int, list[str]]]:
    by_address: dict[int, list[str]] = {}
    for symbol in binary.symbols:
        if symbol.value:
            by_address.setdefault(symbol.value, []).append(symbol.name)
    return sorted(by_address), by_address


def nearest_symbol(addresses: list[int], symbols: dict[int, list[str]], address: int) -> str | None:
    index = bisect.bisect_right(addresses, address) - 1
    if index < 0:
        return None
    base = addresses[index]
    name = symbols[base][0]
    return name if base == address else f"{name}+0x{address - base:x}"


def function_end(binary: lief.MachO.Binary, start: int, fallback_size: int) -> int:
    text = binary.get_section("__text")
    text_end = text.virtual_address + text.size
    starts = sorted({fn.address for fn in binary.functions if start < fn.address <= text_end})
    return starts[0] if starts else min(start + fallback_size, text_end)


def disassemble(binary: lief.MachO.Binary, start: int, size: int | None, max_size: int) -> None:
    addresses, symbols = symbol_index(binary)
    end = start + size if size is not None else function_end(binary, start, max_size)
    end = min(end, start + max_size)
    content = bytes(binary.get_content_from_virtual_address(start, end - start))

    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    decoder.detail = True
    known_addresses: dict[int, int] = {}

    print(f"\n## {start:#x}-{end:#x} {nearest_symbol(addresses, symbols, start) or ''}")
    for insn in decoder.disasm(content, start):
        annotations: list[str] = []
        ops = insn.operands

        if insn.mnemonic in {"adr", "adrp"} and len(ops) == 2:
            if ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_IMM:
                known_addresses[ops[0].reg] = ops[1].imm
        elif insn.mnemonic == "add" and len(ops) >= 3:
            if ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_REG and ops[2].type == ARM64_OP_IMM:
                base = known_addresses.get(ops[1].reg)
                if base is not None:
                    resolved = base + ops[2].imm
                    known_addresses[ops[0].reg] = resolved
                    text = c_string(binary, resolved)
                    if text is not None:
                        annotations.append(f"string={text!r}")
                    symbol = nearest_symbol(addresses, symbols, resolved)
                    if symbol and "+0x" not in symbol:
                        annotations.append(f"symbol={symbol}")
        elif insn.mnemonic == "mov" and len(ops) == 2:
            if ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_REG:
                if ops[1].reg in known_addresses:
                    known_addresses[ops[0].reg] = known_addresses[ops[1].reg]

        if insn.mnemonic in {"b", "bl"} and ops and ops[0].type == ARM64_OP_IMM:
            target = ops[0].imm
            symbol = nearest_symbol(addresses, symbols, target)
            if symbol:
                annotations.append(f"target={symbol}")

        for op in ops:
            if op.type == ARM64_OP_MEM and op.mem.base in known_addresses:
                resolved = known_addresses[op.mem.base] + op.mem.disp
                text = c_string(binary, resolved)
                if text is not None:
                    annotations.append(f"mem-string={text!r}")

        suffix = f" ; {'; '.join(dict.fromkeys(annotations))}" if annotations else ""
        print(f"{insn.address:08x}: {insn.mnemonic:<8} {insn.op_str:<34}{suffix}")


def print_filtered_strings(path: Path, pattern: str) -> None:
    regex = re.compile(pattern, re.IGNORECASE)
    for match in re.finditer(rb"[ -~]{4,}", path.read_bytes()):
        value = match.group().decode("ascii", "replace")
        if regex.search(value):
            print(f"{match.start():#x} {value}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--rva", action="append", type=parse_int, default=[])
    parser.add_argument("--size", type=parse_int)
    parser.add_argument("--max-size", type=parse_int, default=0x10000)
    parser.add_argument("--strings", metavar="REGEX")
    args = parser.parse_args()

    binary = lief.parse(str(args.binary))
    if not isinstance(binary, lief.MachO.Binary):
        print("Expected a thin Mach-O binary", file=sys.stderr)
        return 2

    print(f"file={args.binary}")
    print(f"cpu={binary.header.cpu_type.name} type={binary.header.file_type.name} imagebase={binary.imagebase:#x}")
    if binary.encryption_info is not None:
        info = binary.encryption_info
        print(f"cryptid={info.crypt_id} cryptoff={info.crypt_offset:#x} cryptsize={info.crypt_size:#x}")

    if args.strings:
        print_filtered_strings(args.binary, args.strings)
    for address in args.rva:
        disassemble(binary, address, args.size, args.max_size)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
