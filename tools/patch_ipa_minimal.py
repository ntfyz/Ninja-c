#!/usr/bin/env python3
"""Replace only loader.framework/loader while preserving all other IPA entries."""

from __future__ import annotations

import argparse
import hashlib
import shutil
import tempfile
import zipfile
from pathlib import Path


def locate_loader(entries: list[str]) -> str:
    matches = sorted(
        name
        for name in entries
        if name.startswith("Payload/")
        and name.endswith(".app/Frameworks/loader.framework/loader")
    )
    if len(matches) != 1:
        raise SystemExit(f"Expected exactly one loader binary, found {matches}")
    return matches[0]


def patch_ipa(input_ipa: Path, loader_binary: Path, output_ipa: Path) -> None:
    loader_data = loader_binary.read_bytes()
    if loader_data[:4] not in {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"}:
        raise SystemExit(f"Patched loader is not a 64-bit Mach-O: {loader_binary}")

    output_ipa.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(input_ipa, "r") as source:
        loader_name = locate_loader(source.namelist())
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
                    if info.filename == loader_name:
                        destination.writestr(info, loader_data)
                    elif info.is_dir():
                        destination.writestr(info, b"")
                    else:
                        with source.open(info, "r") as reader, destination.open(info, "w") as writer:
                            shutil.copyfileobj(reader, writer, length=1024 * 1024)
            temporary_path.replace(output_ipa)
        finally:
            temporary_path.unlink(missing_ok=True)

    digest = hashlib.sha256(output_ipa.read_bytes()).hexdigest()
    print(f"loader_entry={loader_name}")
    print(f"output={output_ipa}")
    print(f"size={output_ipa.stat().st_size}")
    print(f"sha256={digest}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_ipa", type=Path)
    parser.add_argument("--loader-binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    patch_ipa(args.input_ipa, args.loader_binary, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
