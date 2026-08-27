#!/usr/bin/env python3
"""Package online auth loader plus the renamed original guard and patched Ninja."""

from __future__ import annotations

import argparse
import hashlib
import plistlib
import shutil
import stat
import tempfile
import zipfile
from pathlib import Path


def info(name: str, executable: bool = False) -> zipfile.ZipInfo:
    item = zipfile.ZipInfo(name)
    item.create_system = 3
    item.compress_type = zipfile.ZIP_DEFLATED
    item.external_attr = (stat.S_IFREG | (0o755 if executable else 0o644)) << 16
    return item


def repack(source_ipa: Path, loader: Path, loader_plist: Path, guard: Path,
           guard_plist: Path, ninja: Path, output: Path) -> None:
    binaries = {"loader": loader.read_bytes(), "guard": guard.read_bytes(), "ninja": ninja.read_bytes()}
    for name, data in binaries.items():
        if data[:4] not in {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"}:
            raise SystemExit(f"{name} is not ARM64 Mach-O")
    loader_info = loader_plist.read_bytes(); plistlib.loads(loader_info)
    guard_info = guard_plist.read_bytes(); plistlib.loads(guard_info)
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(source_ipa) as src:
        apps = [n[:-len("Info.plist")] for n in src.namelist()
                if n.startswith("Payload/") and n.count("/") == 2 and n.endswith(".app/Info.plist")]
        if len(apps) != 1: raise SystemExit(f"Expected one app: {apps}")
        app = apps[0]; loader_prefix = app + "Frameworks/loader.framework/"
        ninja_name = app + "Frameworks/ninja.framework/ninja"
        with tempfile.NamedTemporaryFile(dir=output.parent, suffix=".ipa", delete=False) as tmp:
            temp = Path(tmp.name)
        try:
            with zipfile.ZipFile(temp, "w", allowZip64=True) as dst:
                for entry in src.infolist():
                    name = entry.filename
                    if name.startswith(loader_prefix) or name == ninja_name: continue
                    if "/_CodeSignature/" in name or name.endswith("embedded.mobileprovision"): continue
                    if entry.is_dir(): dst.writestr(entry, b"")
                    else:
                        with src.open(entry) as reader, dst.open(entry, "w") as writer:
                            shutil.copyfileobj(reader, writer, 1024 * 1024)
                dst.writestr(info(loader_prefix + "Info.plist"), loader_info)
                dst.writestr(info(loader_prefix + "loader", True), binaries["loader"])
                guard_prefix = app + "Frameworks/guard.framework/"
                dst.writestr(info(guard_prefix + "Info.plist"), guard_info)
                dst.writestr(info(guard_prefix + "guard", True), binaries["guard"])
                original_ninja = next(e for e in src.infolist() if e.filename == ninja_name)
                dst.writestr(original_ninja, binaries["ninja"])
            temp.replace(output)
        finally: temp.unlink(missing_ok=True)
    print(f"output={output}")
    print(f"sha256={hashlib.sha256(output.read_bytes()).hexdigest()}")


def main() -> int:
    p=argparse.ArgumentParser(description=__doc__); p.add_argument("input_ipa",type=Path)
    for name in ("loader_binary","loader_plist","guard_binary","guard_plist","ninja_binary"):
        p.add_argument("--"+name.replace("_","-"),type=Path,required=True)
    p.add_argument("--output",type=Path,required=True); a=p.parse_args()
    repack(a.input_ipa,a.loader_binary,a.loader_plist,a.guard_binary,a.guard_plist,a.ninja_binary,a.output)
    return 0


if __name__ == "__main__": raise SystemExit(main())
