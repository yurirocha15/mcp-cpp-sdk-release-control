#!/usr/bin/env python3
"""Build the exact ConanCenter recipe folder from signed release inputs.

A first submission reproduces the production tree that the source release
validated.  A later version is merged into the upstream recipe only when that
recipe still has the exact layout this broker writes; anything else fails
closed for a maintainer to resolve by hand.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import sys


VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
DIGEST = re.compile(r"[0-9a-f]{64}")
SHA = re.compile(r"[0-9a-f]{40}")
SOURCE_URL = "https://github.com/yurirocha15/mcp-cpp-sdk/releases/download"
CONFIG_ENTRY = "conan-recipe-config-entry.json"
CONANDATA_ENTRY = "conan-recipe-conandata-entry.json"
RECIPE_FILES = {
    "all/conanfile.py": "conan-recipe-conanfile.py",
    "all/test_package/CMakeLists.txt": "conan-recipe-test-CMakeLists.txt",
    "all/test_package/conanfile.py": "conan-recipe-test-conanfile.py",
    "all/test_package/test_package.cpp": "conan-recipe-test-test_package.cpp",
}
MANAGED_FILES = frozenset({"config.yml", "all/conandata.yml", *RECIPE_FILES})
_CONFIG_ENTRY = re.compile(r'  "([^"\n]+)":\n    folder: all\n')
_SOURCE_ENTRY = re.compile(
    r'  "([^"\n]+)":\n    url: "(https://[^"\n]+)"\n    sha256: "([0-9a-f]{64})"\n'
)


def _strict_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"JSON document repeats field: {key}")
        result[key] = value
    return result


def _read_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_strict_pairs)


def tree_sha256(root: Path) -> str:
    """Digest a recipe tree exactly as the source release validation does."""

    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("recipe tree contains a symbolic link")
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix().encode("utf-8")
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _regular_files(root: Path) -> dict[str, Path]:
    files: dict[str, Path] = {}
    for path in sorted(root.rglob("*")):
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise ValueError(f"upstream recipe has a non-regular entry: {path.relative_to(root)}")
        files[path.relative_to(root).as_posix()] = path
    return files


def _parse_entries(text: str, header: str, pattern: re.Pattern[str], label: str) -> list[tuple[str, ...]]:
    if not text.startswith(header):
        raise ValueError(f"upstream {label} does not start with {header.strip()!r}")
    body = text[len(header):]
    entries = []
    position = 0
    while position < len(body):
        match = pattern.match(body, position)
        if match is None:
            raise ValueError(f"upstream {label} has content this broker does not manage")
        entries.append(match.groups())
        position = match.end()
    if not entries:
        raise ValueError(f"upstream {label} lists no versions")
    versions = [entry[0] for entry in entries]
    if len(versions) != len(set(versions)):
        raise ValueError(f"upstream {label} repeats a version")
    return entries


def _signed_entries(inputs: Path, version: str) -> tuple[str, str]:
    config = _read_json(inputs / CONFIG_ENTRY)
    source = _read_json(inputs / CONANDATA_ENTRY)
    url = f"{SOURCE_URL}/v{version}/mcp-cpp-sdk-{version}.tar.gz"
    if config != {"schema_version": 1, "version": version, "folder": "all"}:
        raise ValueError("signed Conan config entry is not exact")
    if (
        not isinstance(source, dict)
        or set(source) != {"schema_version", "version", "url", "sha256"}
        or source.get("schema_version") != 1
        or source.get("version") != version
        or source.get("url") != url
        or not isinstance(source.get("sha256"), str)
        or DIGEST.fullmatch(source["sha256"]) is None
    ):
        raise ValueError("signed Conan source entry is not exact")
    return url, source["sha256"]


def assemble(*, inputs: Path, version: str, upstream: Path | None, output: Path) -> str:
    """Write the recipe folder to ``output`` and return ``new`` or ``existing``."""

    if VERSION.fullmatch(version) is None:
        raise ValueError("version is not a canonical stable version")
    url, sha256 = _signed_entries(inputs, version)
    config_entry = f'  "{version}":\n    folder: all\n'
    source_entry = f'  "{version}":\n    url: "{url}"\n    sha256: "{sha256}"\n'
    config = "versions:\n" + config_entry
    conandata = "sources:\n" + source_entry
    state = "new"
    if upstream is not None:
        files = _regular_files(upstream)
        if set(files) != MANAGED_FILES:
            raise ValueError("upstream recipe layout differs from the managed layout")
        old_config = files["config.yml"].read_text(encoding="utf-8")
        old_conandata = files["all/conandata.yml"].read_text(encoding="utf-8")
        configured = _parse_entries(old_config, "versions:\n", _CONFIG_ENTRY, "config.yml")
        sourced = _parse_entries(old_conandata, "sources:\n", _SOURCE_ENTRY, "conandata.yml")
        if [entry[0] for entry in configured] != [entry[0] for entry in sourced]:
            raise ValueError("upstream config.yml and conandata.yml list different versions")
        if version in {entry[0] for entry in configured}:
            raise ValueError(f"upstream recipe already lists version {version}")
        config = "versions:\n" + config_entry + old_config[len("versions:\n"):]
        conandata = "sources:\n" + source_entry + old_conandata[len("sources:\n"):]
        state = "existing"
    output.mkdir(parents=True, exist_ok=False)
    (output / "all/test_package").mkdir(parents=True)
    (output / "config.yml").write_text(config, encoding="utf-8", newline="\n")
    (output / "all/conandata.yml").write_text(conandata, encoding="utf-8", newline="\n")
    for destination, name in RECIPE_FILES.items():
        source = inputs / name
        if source.is_symlink() or not source.is_file() or not source.stat().st_size:
            raise ValueError(f"signed recipe input is empty or unsafe: {name}")
        (output / destination).write_bytes(source.read_bytes())
    return state


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--upstream", type=Path)
    parser.add_argument("--base-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    args = parser.parse_args()
    try:
        if SHA.fullmatch(args.base_commit) is None:
            raise ValueError("upstream base commit is malformed")
        state = assemble(
            inputs=args.inputs, version=args.version, upstream=args.upstream, output=args.output
        )
        metadata = {
            "schema_version": 1,
            "version": args.version,
            "state": state,
            "base_commit": args.base_commit,
            "tree_sha256": tree_sha256(args.output),
        }
        args.metadata.write_text(
            json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        print(f"assemble-recipe: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
