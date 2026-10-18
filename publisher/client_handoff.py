#!/usr/bin/env python3
"""Verify the exact protected client artifact before any secret is exposed."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import shutil
import stat
import sys


PAYLOADS = ("client_handoff.py", "create_pull.py", "package_request.py")
INVENTORY = frozenset((*PAYLOADS, "SHA256SUMS"))
CHECKSUM = re.compile(r"([0-9a-f]{64})  ([A-Za-z0-9_]+\.py)")
DECIMAL = re.compile(r"[1-9][0-9]*")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify(directory: Path) -> None:
    root_status = directory.lstat()
    if not stat.S_ISDIR(root_status.st_mode) or directory.is_symlink():
        raise ValueError("publisher client root is not a real directory")
    entries = {entry.name: entry for entry in directory.iterdir()}
    if set(entries) != INVENTORY:
        raise ValueError("publisher client file inventory is not exact")
    for name, path in entries.items():
        status = path.lstat()
        if not stat.S_ISREG(status.st_mode) or path.is_symlink():
            raise ValueError(f"publisher client entry is not a regular file: {name}")
        if stat.S_IMODE(status.st_mode) != 0o644:
            raise ValueError(f"publisher client mode is not 0644: {name}")
        limit = 4096 if name == "SHA256SUMS" else 256 * 1024
        if not 0 < status.st_size <= limit:
            raise ValueError(f"publisher client size is unsafe: {name}")

    records: dict[str, str] = {}
    manifest = entries["SHA256SUMS"].read_text(encoding="ascii")
    if not manifest.endswith("\n"):
        raise ValueError("publisher client checksum manifest is not canonical")
    for line in manifest.splitlines():
        match = CHECKSUM.fullmatch(line)
        if match is None or match.group(2) in records:
            raise ValueError("publisher client checksum record is malformed")
        records[match.group(2)] = match.group(1)
    if tuple(records) != PAYLOADS:
        raise ValueError("publisher client checksum inventory is not exact")
    for name, expected in records.items():
        if _sha256(entries[name]) != expected:
            raise ValueError(f"publisher client checksum mismatch: {name}")


def create(source: Path, directory: Path, github_output: Path, run_attempt: str) -> None:
    """Create and report an exact, checksum-bound publisher client handoff."""

    if DECIMAL.fullmatch(run_attempt) is None:
        raise ValueError("publisher run attempt is not canonical")
    if directory.exists() or directory.is_symlink():
        raise ValueError("publisher client output must be new")
    directory.mkdir(mode=0o755)
    for name in PAYLOADS:
        source_path = source / name
        status = source_path.lstat()
        if not stat.S_ISREG(status.st_mode) or source_path.is_symlink():
            raise ValueError(f"publisher client source is not a regular file: {name}")
        destination = directory / name
        shutil.copyfile(source_path, destination)
        destination.chmod(0o644)
    manifest = directory / "SHA256SUMS"
    manifest.write_text(
        "".join(f"{_sha256(directory / name)}  {name}\n" for name in PAYLOADS),
        encoding="ascii",
    )
    manifest.chmod(0o644)
    verify(directory)
    with github_output.open("a", encoding="utf-8") as output:
        output.write(f"publisher_attempt={run_attempt}\n")
        output.write(f"publisher_checksum={_sha256(manifest)}\n")
        output.write(f"publisher_verifier_checksum={_sha256(directory / PAYLOADS[0])}\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--create-from", type=Path)
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--run-attempt")
    args = parser.parse_args()
    try:
        creating = args.create_from is not None
        if creating != (args.github_output is not None and args.run_attempt is not None):
            raise ValueError("create mode requires source, GitHub output, and run attempt")
        if creating:
            create(args.create_from, args.directory, args.github_output, args.run_attempt)
        else:
            verify(args.directory)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"client-handoff: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
