#!/usr/bin/env python3
"""Replace selected framework binaries while preserving all other IPA entries."""

from __future__ import annotations

import argparse
import hashlib
import shutil
import tempfile
import zipfile
from pathlib import Path


def locate_framework_binary(entries: list[str], framework: str) -> str:
    matches = sorted(
        name
        for name in entries
        if name.startswith("Payload/")
        and name.endswith(f".app/Frameworks/{framework}.framework/{framework}")
    )
    if len(matches) != 1:
        raise SystemExit(f"Expected exactly one {framework} binary, found {matches}")
    return matches[0]


def patch_ipa(input_ipa: Path, loader_binary: Path, ninja_binary: Path, output_ipa: Path) -> None:
    replacements = {"loader": loader_binary.read_bytes(), "ninja": ninja_binary.read_bytes()}
    for framework, data in replacements.items():
        if data[:4] not in {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"}:
            raise SystemExit(f"Patched {framework} is not a 64-bit Mach-O")

    output_ipa.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(input_ipa, "r") as source:
        entry_replacements = {
            locate_framework_binary(source.namelist(), framework): data
            for framework, data in replacements.items()
        }
        with tempfile.NamedTemporaryFile(
            prefix=output_ipa.stem + "-",
            suffix=".ipa",
            dir=output_ipa.parent,
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)

        try:
            with zipfile.ZipFile(temporary_path, "w", allowZip64=True) as destination:
                for info in source.infolist():
                    if info.filename in entry_replacements:
                        destination.writestr(info, entry_replacements[info.filename])
                    elif info.is_dir():
                        destination.writestr(info, b"")
                    else:
                        with source.open(info, "r") as reader, destination.open(info, "w") as writer:
                            shutil.copyfileobj(reader, writer, length=1024 * 1024)
            temporary_path.replace(output_ipa)
        finally:
            temporary_path.unlink(missing_ok=True)

    digest = hashlib.sha256(output_ipa.read_bytes()).hexdigest()
    for name in sorted(entry_replacements):
        print(f"patched_entry={name}")
    print(f"output={output_ipa}")
    print(f"size={output_ipa.stat().st_size}")
    print(f"sha256={digest}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_ipa", type=Path)
    parser.add_argument("--loader-binary", type=Path, required=True)
    parser.add_argument("--ninja-binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    patch_ipa(args.input_ipa, args.loader_binary, args.ninja_binary, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
