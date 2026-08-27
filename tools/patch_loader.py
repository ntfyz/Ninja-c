#!/usr/bin/env python3
"""Patch only the auth entry points in the original ARM64 loader binary."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


EXPECTED_SHA256 = "5f5d25197a2461a3441b5be54584102f55e8d436b8ecf90d838a19160eceaa1a"
LOGIN_RVA = 0x845C
SESSION_VALID_RVA = 0x8700

# ninja_loader_login(username, password, result): zero the 96-byte result,
# accept exactly "1" / "1", then set success=1, generation=1, message="ok".
LOGIN_PATCH = bytes.fromhex(
    "e90302aa490300b43f7d00a93f7d01a93f7d02a93f7d03a9"
    "3f7d04a93f7d05a9600200b4410200b40a0040395fc50071"
    "e10100540a044039aa0100352a0040395fc5007141010054"
    "2a0440390a0100352a0080522a0100b92a0080d22a0d00f9"
    "ea6d8d522a4100793f890039c0035fd6"
)

# mov w0, #1; ret
SESSION_VALID_PATCH = bytes.fromhex("20008052c0035fd6")

# Guards make applying the patch to a different loader fail closed.
EXPECTED_LOGIN_PREFIX = bytes.fromhex(
    "ff0303d1fa6707a9f85f08a9f65709a9f44f0aa9fd7b0ba9"
    "fdc30291e8190090086140f9080140f9a8831bf8420c00b4"
)
EXPECTED_SESSION_PREFIX = bytes.fromhex("ff8300d1fd7b01a9")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def patch_loader(source: Path, output: Path) -> None:
    original = source.read_bytes()
    digest = sha256(original)
    if digest != EXPECTED_SHA256:
        raise SystemExit(
            f"Unexpected source loader SHA256: {digest}\n"
            f"Expected: {EXPECTED_SHA256}"
        )
    if original[LOGIN_RVA : LOGIN_RVA + len(EXPECTED_LOGIN_PREFIX)] != EXPECTED_LOGIN_PREFIX:
        raise SystemExit("Login function prefix does not match the analyzed ARM64 build")
    if (
        original[SESSION_VALID_RVA : SESSION_VALID_RVA + len(EXPECTED_SESSION_PREFIX)]
        != EXPECTED_SESSION_PREFIX
    ):
        raise SystemExit("Session-valid function prefix does not match the analyzed ARM64 build")

    patched = bytearray(original)
    patched[LOGIN_RVA : LOGIN_RVA + len(LOGIN_PATCH)] = LOGIN_PATCH
    patched[SESSION_VALID_RVA : SESSION_VALID_RVA + len(SESSION_VALID_PATCH)] = SESSION_VALID_PATCH

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(patched)
    output.chmod(0o755)

    changed = [index for index, pair in enumerate(zip(original, patched)) if pair[0] != pair[1]]
    print(f"source={source}")
    print(f"output={output}")
    print(f"size={len(patched)}")
    print(f"changed_bytes={len(changed)}")
    print(f"changed_range=0x{min(changed):x}-0x{max(changed):x}")
    print(f"sha256={sha256(patched)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    patch_loader(args.source, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
