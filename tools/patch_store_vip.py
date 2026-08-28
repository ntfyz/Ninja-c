#!/usr/bin/env python3
"""Patch the supplied CheatiOSShare IPA to use api.ntfyz.xyz KeyAuth,
prefill key 1, retain four game cards, and keep feature access compatible.

v1.6 changes vs v1.5:
  - Restore the real LicenseGateStore bootstrap/revalidation and key changing.
  - Route the shared API base URL to https://api.ntfyz.xyz.
  - Keep response compatibility and the secondary feature-access compatibility
    patch while primary key activation/status is validated by the cPanel API.
"""

from __future__ import annotations

import argparse
import hashlib
import plistlib
import struct
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path


EXPECTED_IPA_SHA256 = "127f911509b2dc441f78b250603838bbf7d15cdc3861d971352314e169a13c84"
EXPECTED_BINARY_SHA256 = "8469ae1a34db849c5252f504cfa66322bacd303b861e2b42089526941548e909"
EXPECTED_PATCHED_BINARY_SHA256 = "10a03c0875f0a5301c2bf7308c0cfd7e3fb379911fd035ff8c6f54b99a0ef2f0"
EXPECTED_EXECUTABLE = "CheatiOSShare"
OUTPUT_SHORT_VERSION = "1.6"
OUTPUT_BUILD_VERSION = "106"


@dataclass(frozen=True)
class Patch:
    name: str
    offset: int
    expected: bytes
    replacement: bytes


PATCHES = (
    # Shared obfuscated base URL storage. The original value is
    # https://patches.cheatiosvip.net; the cPanel adapter redirects non-key
    # PatchHub calls back there while handling api/keys/* locally.
    Patch("api_base_url_count", 0x1CDC08,
          bytes.fromhex("1f00000000000000"),
          bytes.fromhex("1500000000000000")),
    Patch("api_base_url_xor_4b", 0x1CDC18,
          bytes.fromhex("233f3f3b387164643b2a3f28232e386528232e2a3f2224383d223b65252e3f"),
          bytes.fromhex("233f3f3b387164642a3b2265253f2d32316533323100000000000000000000")),

    # KeyEntryView starts with "1", but the user can replace it with a real
    # cPanel key and the normal keychain/bootstrap path remains intact.
    # KeyEntryView State<String>: Swift small-string for "1".
    Patch("default_key_1", 0x80650,
          bytes.fromhex("ffe300390800fcd2ff2301a9"),
          bytes.fromhex("290680520820fcd2e92301a9")),
    Patch("key_focus_false", 0x806A0,
          bytes.fromhex("e8e34039"),
          bytes.fromhex("08008052")),

    # Force registerVisitor and fetchGames to ALWAYS take the skip/init
    # path by replacing their conditional branches with unconditional ones.
    #
    # registerVisitor sentinel check at 0x6a3c-0x6a40:
    #   cmn x8, #1
    #   b.ne 0x6a50        <- if sentinel != -1, branch to init+proceed
    # We replace b.ne with b 0x6a50 so init ALWAYS runs regardless of
    # sentinel value.  The skip path calls 0x153f38 (device state init)
    # then converges with the proceed path at 0x6a44.
    Patch("registerVisitor_always_init", 0x6a40,
          bytes.fromhex("81000054"),
          bytes.fromhex("04000014")),

    # fetchGames sentinel check at 0x6e28-0x6e2c:
    #   cmn x8, #1
    #   b.ne 0x70ec        <- if sentinel != -1, branch to init+proceed
    # Same logic: always call 0x153f4c (fetchGames init) then proceed.
    Patch("fetchGames_always_init", 0x6e2c,
          bytes.fromhex("01160054"),
          bytes.fromhex("b0000014")),

    # PatchHubService.verifyResponse(data:httpResponse:) at 0x6873C.
    # The cPanel compatibility response intentionally does not reproduce the
    # old server's embedded response-signature format; JSON status is still
    # parsed by LicenseKeyService.result(from:statusCode:).
    Patch("verifyResponse_always_true", 0x6873C,
          bytes.fromhex("fc6fbaa9fa6701a9"),
          bytes.fromhex("20008052c0035fd6")),

    # PatchHubService.verifyAccess(licenseKey:) is async and returns Bool.
    # The old PatchHub does not know cPanel-issued keys, so this secondary
    # feature check resumes true after the primary key gate has authenticated.
    #   mov w0, #1
    #   ldr x1, [x22, #8]
    #   br  x1
    Patch("verifyAccess_always_true", 0x6AB4C,
          bytes.fromhex("bd0344b2ff8300d1fd7b01a9"),
          bytes.fromhex("20008052c10640f920001fd6")),
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def locate_app(entries: list[str]) -> str:
    candidates = sorted(
        name[: -len("Info.plist")]
        for name in entries
        if name.startswith("Payload/")
        and name.count("/") == 2
        and name.endswith(".app/Info.plist")
    )
    if len(candidates) != 1:
        raise SystemExit(f"Expected exactly one app bundle, found {candidates}")
    return candidates[0]


def macho_cryptid(binary: bytes) -> int:
    if binary[:4] != bytes.fromhex("cffaedfe"):
        raise SystemExit("Expected a little-endian 64-bit Mach-O executable")
    ncmds = struct.unpack_from("<I", binary, 16)[0]
    command_offset = 32
    for _ in range(ncmds):
        command, command_size = struct.unpack_from("<II", binary, command_offset)
        if command_size < 8 or command_offset + command_size > len(binary):
            raise SystemExit("Malformed Mach-O load-command table")
        if command == 0x2C:  # LC_ENCRYPTION_INFO_64
            return struct.unpack_from("<I", binary, command_offset + 16)[0]
        command_offset += command_size
    raise SystemExit("LC_ENCRYPTION_INFO_64 is missing")


def patch_binary(original: bytes) -> bytes:
    digest = sha256(original)
    if digest != EXPECTED_BINARY_SHA256:
        raise SystemExit(
            f"Unexpected CheatiOSShare SHA256: {digest}\nExpected: {EXPECTED_BINARY_SHA256}"
        )
    cryptid = macho_cryptid(original)
    if cryptid != 0:
        raise SystemExit(f"Source executable is encrypted (cryptid={cryptid})")

    patched = bytearray(original)
    for patch in PATCHES:
        actual = bytes(patched[patch.offset : patch.offset + len(patch.expected)])
        if actual != patch.expected:
            raise SystemExit(
                f"{patch.name} source mismatch at 0x{patch.offset:x}: "
                f"{actual.hex()} != {patch.expected.hex()}"
            )
        patched[patch.offset : patch.offset + len(patch.replacement)] = patch.replacement
    return bytes(patched)


def should_strip(name: str) -> bool:
    return (
        "/_CodeSignature/" in name
        or "/SC_Info/" in name
        or name.endswith("/embedded.mobileprovision")
    )


def build(input_ipa: Path, output_ipa: Path) -> None:
    source_digest = sha256(input_ipa.read_bytes())
    if source_digest != EXPECTED_IPA_SHA256:
        raise SystemExit(
            f"Unexpected source IPA SHA256: {source_digest}\nExpected: {EXPECTED_IPA_SHA256}"
        )

    output_ipa.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(input_ipa, "r") as source:
        bad_entry = source.testzip()
        if bad_entry is not None:
            raise SystemExit(f"Corrupt source IPA entry: {bad_entry}")
        app_prefix = locate_app(source.namelist())
        plist_name = app_prefix + "Info.plist"
        plist = plistlib.loads(source.read(plist_name))
        executable = plist.get("CFBundleExecutable")
        if executable != EXPECTED_EXECUTABLE:
            raise SystemExit(f"Unexpected CFBundleExecutable: {executable!r}")
        executable_name = app_prefix + executable
        original_binary = source.read(executable_name)
        patched_binary = patch_binary(original_binary)

        plist["CFBundleShortVersionString"] = OUTPUT_SHORT_VERSION
        plist["CFBundleVersion"] = OUTPUT_BUILD_VERSION
        patched_plist = plistlib.dumps(plist, fmt=plistlib.FMT_BINARY, sort_keys=False)

        with tempfile.NamedTemporaryFile(
            prefix=output_ipa.stem + "-", suffix=".ipa", dir=output_ipa.parent, delete=False
        ) as temporary:
            temporary_path = Path(temporary.name)
        try:
            with zipfile.ZipFile(
                temporary_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
            ) as destination:
                for entry in source.infolist():
                    if should_strip(entry.filename):
                        continue
                    if entry.filename == executable_name:
                        destination.writestr(entry, patched_binary)
                    elif entry.filename == plist_name:
                        destination.writestr(entry, patched_plist)
                    else:
                        destination.writestr(entry, source.read(entry.filename))
            temporary_path.replace(output_ipa)
        finally:
            temporary_path.unlink(missing_ok=True)

    verify(output_ipa)
    print(f"source_ipa_sha256={source_digest}")
    print(f"source_binary_sha256={sha256(original_binary)}")
    print(f"patched_binary_sha256={sha256(patched_binary)}")
    for patch in PATCHES:
        print(f"patch={patch.name}@0x{patch.offset:x}:{patch.replacement.hex()}")
    print(f"version={OUTPUT_SHORT_VERSION} ({OUTPUT_BUILD_VERSION})")
    print(f"output={output_ipa}")
    print(f"output_sha256={sha256(output_ipa.read_bytes())}")


def verify(ipa: Path) -> None:
    with zipfile.ZipFile(ipa, "r") as archive:
        bad_entry = archive.testzip()
        if bad_entry is not None:
            raise SystemExit(f"Corrupt output IPA entry: {bad_entry}")
        names = archive.namelist()
        app_prefix = locate_app(names)
        plist_name = app_prefix + "Info.plist"
        plist = plistlib.loads(archive.read(plist_name))
        executable_name = app_prefix + str(plist.get("CFBundleExecutable", ""))
        binary = archive.read(executable_name)
        if macho_cryptid(binary) != 0:
            raise SystemExit("Output executable cryptid is not zero")
        for patch in PATCHES:
            actual = binary[patch.offset : patch.offset + len(patch.replacement)]
            if actual != patch.replacement:
                raise SystemExit(f"Output verification failed for {patch.name}")
        patched_digest = sha256(binary)
        if patched_digest != EXPECTED_PATCHED_BINARY_SHA256:
            raise SystemExit(
                f"Unexpected patched executable SHA256: {patched_digest}\n"
                f"Expected: {EXPECTED_PATCHED_BINARY_SHA256}"
            )
        if plist.get("CFBundleShortVersionString") != OUTPUT_SHORT_VERSION:
            raise SystemExit("Output short version was not updated")
        if plist.get("CFBundleVersion") != OUTPUT_BUILD_VERSION:
            raise SystemExit("Output build version was not updated")
        forbidden = [name for name in names if should_strip(name)]
        if forbidden:
            raise SystemExit(f"Signed material remains in unsigned IPA: {forbidden}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_ipa", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build(args.input_ipa, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
