#!/usr/bin/env python3
"""Patch only the auth entry points in the original ARM64 loader binary."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


EXPECTED_SHA256 = "5f5d25197a2461a3441b5be54584102f55e8d436b8ecf90d838a19160eceaa1a"
LOGIN_RVA = 0x845C
SESSION_VALID_RVA = 0x8700
GUARD_FAILED_RVA = 0xD6D4
APPDOME_WATCHDOG_RVA = 0xEC10

# ninja_loader_login(username, password, result): zero the 96-byte result,
# accept exactly "1" / "1", set a coherent offline expiry/generation both in
# the result and in the loader's security globals, then return message="ok".
LOGIN_PATCH = bytes.fromhex(
    "e90302aac90400b43f7d00a93f7d01a93f7d02a93f7d03a9"
    "3f7d04a93f7d05a9e00300b4c10300b40a0040395fc50071"
    "610300540a0440392a0300352a0040395fc50071c1020054"
    "2a0440398a0200352a0080522a0100b9eaff9f52eaffaf72"
    "2a0500f92a0900f92a0080d22a0d00f90b1a00906be12d91"
    "6a0100f9eaff9f52eaffaf726a0500f92a0080526a410039"
    "ea6d8d522a4100793f890039c0035fd6"
)

# mov w0, #1; ret
SESSION_VALID_PATCH = bytes.fromhex("20008052c0035fd6")

# Keep gdl_guard_start because it also orchestrates loading ninja.framework.
# Its failure callback normally invalidates the module, sends a heartbeat to
# the retired server, and logs out. For the coherent offline session it must be
# a no-op so a native-guard report cannot block the frame loop on old network IO.
GUARD_FAILED_PATCH = bytes.fromhex("c0035fd6")  # ret

# Platform startup already applies the Appdome memory patch, installs signal/
# syscall hooks, runs several early one-shot scans, and starts detection_watcher.
# This additional worker sleeps for only 1 ms and repeatedly rewrites matching
# thread PCs after its first 1000 iterations. On this build it can eventually
# classify a live game/Ninja worker as a protection thread and freeze the app.
APPDOME_WATCHDOG_PATCH = bytes.fromhex("00008052c0035fd6")  # mov w0, #0; ret

# Guards make applying the patch to a different loader fail closed.
EXPECTED_LOGIN_PREFIX = bytes.fromhex(
    "ff0303d1fa6707a9f85f08a9f65709a9f44f0aa9fd7b0ba9"
    "fdc30291e8190090086140f9080140f9a8831bf8420c00b4"
)
EXPECTED_SESSION_PREFIX = bytes.fromhex("ff8300d1fd7b01a9")
EXPECTED_GUARD_FAILED_PREFIX = bytes.fromhex("ffc300d1f44f01a9")
EXPECTED_APPDOME_WATCHDOG_PREFIX = bytes.fromhex("ffc301d1f85f03a9")


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
    if (
        original[GUARD_FAILED_RVA : GUARD_FAILED_RVA + len(EXPECTED_GUARD_FAILED_PREFIX)]
        != EXPECTED_GUARD_FAILED_PREFIX
    ):
        raise SystemExit("Guard-failure callback prefix does not match the analyzed ARM64 build")
    if (
        original[
            APPDOME_WATCHDOG_RVA : APPDOME_WATCHDOG_RVA
            + len(EXPECTED_APPDOME_WATCHDOG_PREFIX)
        ]
        != EXPECTED_APPDOME_WATCHDOG_PREFIX
    ):
        raise SystemExit("Appdome watchdog prefix does not match the analyzed ARM64 build")

    patched = bytearray(original)
    patched[LOGIN_RVA : LOGIN_RVA + len(LOGIN_PATCH)] = LOGIN_PATCH
    patched[SESSION_VALID_RVA : SESSION_VALID_RVA + len(SESSION_VALID_PATCH)] = SESSION_VALID_PATCH
    patched[GUARD_FAILED_RVA : GUARD_FAILED_RVA + len(GUARD_FAILED_PATCH)] = GUARD_FAILED_PATCH
    patched[
        APPDOME_WATCHDOG_RVA : APPDOME_WATCHDOG_RVA + len(APPDOME_WATCHDOG_PATCH)
    ] = APPDOME_WATCHDOG_PATCH

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
