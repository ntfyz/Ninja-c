#!/usr/bin/env python3
"""Replace loader.framework in an IPA and emit an unsigned IPA."""

from __future__ import annotations

import argparse
import hashlib
import plistlib
import shutil
import stat
import tempfile
import zipfile
from pathlib import Path


def directory_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name.rstrip("/") + "/")
    info.create_system = 3
    info.external_attr = (stat.S_IFDIR | 0o755) << 16
    return info


def file_info(name: str, executable: bool = False) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name)
    info.create_system = 3
    mode = 0o755 if executable else 0o644
    info.external_attr = (stat.S_IFREG | mode) << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


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


def patch_app_plist(data: bytes) -> bytes:
    plist = plistlib.loads(data)
    transport = dict(plist.get("NSAppTransportSecurity", {}))
    transport["NSAllowsArbitraryLoads"] = True
    transport["NSAllowsLocalNetworking"] = True
    plist["NSAppTransportSecurity"] = transport
    return plistlib.dumps(plist, fmt=plistlib.FMT_BINARY, sort_keys=False)


def repack(input_ipa: Path, loader_binary: Path, loader_plist: Path, output_ipa: Path) -> None:
    binary_data = loader_binary.read_bytes()
    if binary_data[:4] not in {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"}:
        raise SystemExit(f"Replacement loader is not a 64-bit Mach-O: {loader_binary}")
    plist_data = loader_plist.read_bytes()
    plistlib.loads(plist_data)

    output_ipa.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(input_ipa, "r") as source:
        app_prefix = locate_app(source.namelist())
        app_plist = app_prefix + "Info.plist"
        loader_prefix = app_prefix + "Frameworks/loader.framework/"

        with tempfile.NamedTemporaryFile(
            prefix=output_ipa.stem + "-", suffix=".ipa", dir=output_ipa.parent, delete=False
        ) as temporary:
            temporary_path = Path(temporary.name)
        try:
            with zipfile.ZipFile(
                temporary_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6
            ) as destination:
                for original in source.infolist():
                    name = original.filename
                    if name.startswith(loader_prefix):
                        continue
                    if "/_CodeSignature/" in name or name.endswith("/_CodeSignature/"):
                        continue
                    if name == app_prefix + "embedded.mobileprovision":
                        continue
                    if name == app_plist:
                        destination.writestr(original, patch_app_plist(source.read(original)))
                        continue
                    if original.is_dir():
                        destination.writestr(original, b"")
                        continue
                    with source.open(original, "r") as reader, destination.open(original, "w") as writer:
                        shutil.copyfileobj(reader, writer, length=1024 * 1024)

                destination.writestr(directory_info(loader_prefix), b"")
                destination.writestr(file_info(loader_prefix + "Info.plist"), plist_data)
                destination.writestr(
                    file_info(loader_prefix + "loader", executable=True), binary_data
                )
            temporary_path.replace(output_ipa)
        finally:
            temporary_path.unlink(missing_ok=True)

    digest = hashlib.sha256(output_ipa.read_bytes()).hexdigest()
    print(f"output={output_ipa}")
    print(f"size={output_ipa.stat().st_size}")
    print(f"sha256={digest}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_ipa", type=Path)
    parser.add_argument("--loader-binary", type=Path, required=True)
    parser.add_argument("--loader-plist", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    repack(args.input_ipa, args.loader_binary, args.loader_plist, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
