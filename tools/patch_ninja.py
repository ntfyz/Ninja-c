#!/usr/bin/env python3
"""Make missing autoplay WASM a clean no-op in the original ARM64 Ninja binary."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


EXPECTED_SHA256 = "92064543def9b01d6793e1df0f47fe302b43891fcae671757cd3b00f6a563526"
AUTOPLAY_UNAUTHORIZED_BRANCH_RVA = 0x37034

# Original: b AutoPlay::StopForInvalidSession (0x368d8). That cleanup is reached
# every frame after a match starts when the optional WASM payload is absent.
# Replacement: b AutoPlay::Update epilogue (0x37160), which restores the full
# frame normally and leaves gameplay running with autoplay disabled.
EXPECTED_AUTOPLAY_BRANCH = bytes.fromhex("29feff17")
AUTOPLAY_NOOP_BRANCH = bytes.fromhex("4b000014")


def patch_ninja(source: Path, output: Path) -> None:
    original = source.read_bytes()
    digest = hashlib.sha256(original).hexdigest()
    if digest != EXPECTED_SHA256:
        raise SystemExit(
            f"Unexpected source Ninja SHA256: {digest}\nExpected: {EXPECTED_SHA256}"
        )
    start = AUTOPLAY_UNAUTHORIZED_BRANCH_RVA
    if original[start : start + 4] != EXPECTED_AUTOPLAY_BRANCH:
        raise SystemExit("AutoPlay unauthorized branch does not match analyzed ARM64 build")

    patched = bytearray(original)
    patched[start : start + 4] = AUTOPLAY_NOOP_BRANCH
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(patched)
    print(f"source_sha256={digest}")
    print(f"patched_rva=0x{start:x}")
    print(f"output={output}")
    print(f"changed_bytes={sum(a != b for a, b in zip(original, patched))}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    patch_ninja(args.source, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
