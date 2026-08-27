#!/usr/bin/env python3
"""Split a large IPA for Git storage or join it from a checked-in manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def split_file(source: Path, output_dir: Path, chunk_size: int) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    parts: list[dict[str, object]] = []
    with source.open("rb") as stream:
        index = 0
        while block := stream.read(chunk_size):
            part_name = f"{source.name}.part{index:03d}"
            part_path = output_dir / part_name
            part_path.write_bytes(block)
            parts.append({"name": part_name, "size": len(block), "sha256": sha256(part_path)})
            index += 1
    manifest = {
        "filename": source.name,
        "size": source.stat().st_size,
        "sha256": sha256(source),
        "parts": parts,
    }
    manifest_path = output_dir / f"{source.name}.parts.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(manifest_path)
    return manifest_path


def join_file(manifest_path: Path, output: Path) -> None:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as destination:
        for part in manifest["parts"]:
            part_path = manifest_path.parent / part["name"]
            if part_path.stat().st_size != part["size"] or sha256(part_path) != part["sha256"]:
                raise SystemExit(f"Part verification failed: {part_path}")
            with part_path.open("rb") as source:
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    destination.write(block)
    if output.stat().st_size != manifest["size"] or sha256(output) != manifest["sha256"]:
        output.unlink(missing_ok=True)
        raise SystemExit("Joined IPA verification failed")
    print(output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    split = subcommands.add_parser("split")
    split.add_argument("source", type=Path)
    split.add_argument("output_dir", type=Path)
    split.add_argument("--chunk-size", type=int, default=32 * 1024 * 1024)
    join = subcommands.add_parser("join")
    join.add_argument("manifest", type=Path)
    join.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.command == "split":
        split_file(args.source, args.output_dir, args.chunk_size)
    else:
        join_file(args.manifest, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
