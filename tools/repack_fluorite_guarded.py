#!/usr/bin/env python3
"""Move the original Fluorite loader to fg.framework and add the KeyAuth wrapper."""

from __future__ import annotations

import argparse
import hashlib
import plistlib
import shutil
import stat
import tempfile
import zipfile
from pathlib import Path


SOURCE_SHA256 = "71291c75ad65a3bef6166452b5ef5ecb7fd1ac9378920f5099e5b486441a37f2"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def item(name: str, executable: bool = False, compression: int = zipfile.ZIP_DEFLATED) -> zipfile.ZipInfo:
    result = zipfile.ZipInfo(name)
    result.create_system = 3
    result.compress_type = compression
    result.external_attr = (stat.S_IFREG | (0o755 if executable else 0o644)) << 16
    return result


def add_size_padding(archive: Path, app: str, target_size: int) -> None:
    current_size = archive.stat().st_size
    if current_size > target_size:
        raise SystemExit(f"Repacked IPA is larger than source: {current_size} > {target_size}")
    if current_size == target_size:
        return
    name = app + ".fluorite_size_pad"
    overhead = 76 + 2 * len(name.encode("utf-8"))
    payload_size = target_size - current_size - overhead
    if payload_size < 0:
        raise SystemExit(f"Not enough room for exact-size ZIP padding: delta={target_size-current_size}")
    with zipfile.ZipFile(archive, "a", allowZip64=True) as destination:
        padding = item(name, compression=zipfile.ZIP_STORED)
        with destination.open(padding, "w") as writer:
            zeroes = b"\0" * (1024 * 1024)
            remaining = payload_size
            while remaining:
                block = zeroes[: min(remaining, len(zeroes))]
                writer.write(block)
                remaining -= len(block)
    if archive.stat().st_size != target_size:
        raise SystemExit(f"Exact-size padding failed: {archive.stat().st_size} != {target_size}")


def repack(source: Path, wrapper: Path, wrapper_plist: Path, guard: Path,
           guard_plist: Path, output: Path) -> None:
    if sha256_file(source) != SOURCE_SHA256:
        raise SystemExit("Input IPA is not the supplied Fluorite 56.28.2 2.5.1 sample")
    wrapper_data = wrapper.read_bytes()
    guard_data = guard.read_bytes()
    if wrapper_data[:4] != b"\xcf\xfa\xed\xfe" or guard_data[:4] != b"\xcf\xfa\xed\xfe":
        raise SystemExit("Wrapper and guard must be thin ARM64 Mach-O binaries")
    wrapper_info = wrapper_plist.read_bytes()
    guard_info = guard_plist.read_bytes()
    plistlib.loads(wrapper_info)
    plistlib.loads(guard_info)

    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(source) as src:
        apps = [name[:-len("Info.plist")] for name in src.namelist()
                if name.startswith("Payload/") and name.count("/") == 2 and name.endswith(".app/Info.plist")]
        if len(apps) != 1:
            raise SystemExit(f"Expected exactly one app bundle, got {apps}")
        app = apps[0]
        old_prefix = app + "Frameworks/libloader.framework/"
        pool_name = app + "pool"
        resources_name = app + "fluorite_resources.tar.lz4"
        source_pool = src.read(pool_name)
        source_resources = src.read(resources_name)

        with tempfile.NamedTemporaryFile(dir=output.parent, suffix=".ipa", delete=False) as temporary:
            temp = Path(temporary.name)
        try:
            with zipfile.ZipFile(temp, "w", compression=zipfile.ZIP_DEFLATED,
                                 compresslevel=9, allowZip64=True) as dst:
                for entry in src.infolist():
                    name = entry.filename
                    if name.startswith(old_prefix):
                        continue
                    if "/_CodeSignature/" in name or name.endswith("embedded.mobileprovision"):
                        continue
                    if entry.is_dir():
                        dst.writestr(entry, b"")
                    else:
                        with src.open(entry) as reader, dst.open(entry, "w") as writer:
                            shutil.copyfileobj(reader, writer, 1024 * 1024)

                dst.writestr(item(old_prefix + "Info.plist"), wrapper_info)
                dst.writestr(item(old_prefix + "libloader", executable=True), wrapper_data)
                guard_prefix = app + "Frameworks/fg.framework/"
                dst.writestr(item(guard_prefix + "Info.plist"), guard_info)
                dst.writestr(item(guard_prefix + "fg", executable=True), guard_data)

            add_size_padding(temp, app, source.stat().st_size)
            with zipfile.ZipFile(temp) as built:
                if built.testzip() is not None:
                    raise SystemExit("ZIP integrity verification failed")
                if built.read(pool_name) != source_pool:
                    raise SystemExit("Main pool binary changed")
                if built.read(resources_name) != source_resources:
                    raise SystemExit("fluorite_resources.tar.lz4 changed")
                expected = {
                    old_prefix + "libloader",
                    app + "Frameworks/fg.framework/fg",
                    resources_name,
                    app + ".fluorite_size_pad",
                }
                missing = expected.difference(built.namelist())
                if missing:
                    raise SystemExit(f"Missing output entries: {sorted(missing)}")
            temp.replace(output)
        finally:
            temp.unlink(missing_ok=True)

    print(f"output={output}")
    print(f"size={output.stat().st_size}")
    print(f"source_size={source.stat().st_size}")
    print(f"pool_sha256={sha256_bytes(source_pool)}")
    print(f"fluorite_resources_sha256={sha256_bytes(source_resources)}")
    print(f"sha256={sha256_file(output)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_ipa", type=Path)
    parser.add_argument("--wrapper-binary", type=Path, required=True)
    parser.add_argument("--wrapper-plist", type=Path, required=True)
    parser.add_argument("--guard-binary", type=Path, required=True)
    parser.add_argument("--guard-plist", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    repack(args.input_ipa, args.wrapper_binary, args.wrapper_plist,
           args.guard_binary, args.guard_plist, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
