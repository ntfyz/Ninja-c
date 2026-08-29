#!/usr/bin/env python3
"""Create an unsigned Fluorite IPA without changing pool, loader, or resources."""

from __future__ import annotations

import argparse
import hashlib
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


def item(name: str, compression: int = zipfile.ZIP_DEFLATED) -> zipfile.ZipInfo:
    result = zipfile.ZipInfo(name)
    result.create_system = 3
    result.compress_type = compression
    result.external_attr = (stat.S_IFREG | 0o644) << 16
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
                block = zeroes[:min(remaining, len(zeroes))]
                writer.write(block)
                remaining -= len(block)
    if archive.stat().st_size != target_size:
        raise SystemExit(f"Exact-size padding failed: {archive.stat().st_size} != {target_size}")


def repack(source: Path, output: Path) -> None:
    if sha256_file(source) != SOURCE_SHA256:
        raise SystemExit("Input IPA is not the supplied Fluorite 56.28.2 2.5.1 sample")
    output.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(source) as src:
        apps = [name[:-len("Info.plist")] for name in src.namelist()
                if name.startswith("Payload/") and name.count("/") == 2
                and name.endswith(".app/Info.plist")]
        if len(apps) != 1:
            raise SystemExit(f"Expected exactly one app bundle, got {apps}")
        app = apps[0]
        protected_names = {
            "pool": app + "pool",
            "libloader": app + "Frameworks/libloader.framework/libloader",
            "fluorite_resources": app + "fluorite_resources.tar.lz4",
        }
        protected = {label: src.read(name) for label, name in protected_names.items()}

        with tempfile.NamedTemporaryFile(dir=output.parent, suffix=".ipa", delete=False) as temporary:
            temp = Path(temporary.name)
        try:
            with zipfile.ZipFile(temp, "w", compression=zipfile.ZIP_DEFLATED,
                                 compresslevel=9, allowZip64=True) as dst:
                for entry in src.infolist():
                    name = entry.filename
                    if "/_CodeSignature/" in name or name.endswith("embedded.mobileprovision"):
                        continue
                    if entry.is_dir():
                        dst.writestr(entry, b"")
                    else:
                        with src.open(entry) as reader, dst.open(entry, "w") as writer:
                            shutil.copyfileobj(reader, writer, 1024 * 1024)

            add_size_padding(temp, app, source.stat().st_size)
            with zipfile.ZipFile(temp) as built:
                if built.testzip() is not None:
                    raise SystemExit("ZIP integrity verification failed")
                for label, name in protected_names.items():
                    if built.read(name) != protected[label]:
                        raise SystemExit(f"Protected Fluorite component changed: {label}")
                names = built.namelist()
                if any(".app/Frameworks/keyguard.framework/" in name or
                       ".app/Frameworks/fg.framework/" in name for name in names):
                    raise SystemExit("Unexpected wrapper framework remains in output")
            temp.replace(output)
        finally:
            temp.unlink(missing_ok=True)

    print(f"output={output}")
    print(f"size={output.stat().st_size}")
    print(f"source_size={source.stat().st_size}")
    for label, data in protected.items():
        print(f"{label}_sha256={sha256_bytes(data)}")
    print(f"sha256={sha256_file(output)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_ipa", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    repack(args.input_ipa, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
