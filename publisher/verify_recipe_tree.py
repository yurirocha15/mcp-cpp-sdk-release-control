#!/usr/bin/env python3
"""Reject unsafe or incomplete ConanCenter recipe trees."""

from __future__ import annotations

import argparse
import ast
from pathlib import Path
import json
import re
import stat
import sys


ALLOWED_NAMES = {
    "config.yml",
    "conandata.yml",
    "conanfile.py",
    "CMakeLists.txt",
    "test_package.cpp",
}
ALLOWED_SUFFIXES = {".patch", ".py", ".txt", ".yml", ".yaml", ".cmake", ".cpp", ".hpp"}
TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
DIGEST = re.compile(r"[0-9a-f]{64}")


def _declared_requirements(conanfile: Path) -> list[str]:
    tree = ast.parse(conanfile.read_text(encoding="utf-8"), filename=str(conanfile))
    references = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "requires":
            continue
        if not node.args or not isinstance(node.args[0], ast.Constant) or not isinstance(node.args[0].value, str):
            raise ValueError("Conan recipe requirement must be an exact string literal")
        references.append(node.args[0].value)
    if not references or len(references) != len(set(references)):
        raise ValueError("Conan recipe requirements are empty or duplicated")
    return sorted(references)


def verify(
    root: Path, *, version: str, source_url: str, source_sha256: str, release_manifest: Path
) -> None:
    if not root.is_dir() or root.is_symlink():
        raise ValueError("recipe root is not a real directory")
    files = []
    for path in sorted(root.rglob("*")):
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise ValueError(f"recipe contains a non-regular entry: {path.relative_to(root)}")
        if mode & 0o111:
            raise ValueError(f"recipe contains an executable file: {path.relative_to(root)}")
        if path.name not in ALLOWED_NAMES and path.suffix not in ALLOWED_SUFFIXES:
            raise ValueError(f"recipe contains an unapproved file type: {path.relative_to(root)}")
        files.append(path)
    if not files:
        raise ValueError("recipe tree is empty")
    if not any(path.name == "conanfile.py" for path in files):
        raise ValueError("recipe tree has no conanfile.py")
    if not any("test_package" in path.parts and path.name == "conanfile.py" for path in files):
        raise ValueError("recipe tree has no test_package/conanfile.py")
    config = (root / "config.yml").read_text(encoding="utf-8")
    if not config.startswith(f'versions:\n  "{version}":\n    folder: all\n'):
        raise ValueError("config.yml does not list this release as its newest version")
    conandata = (root / "all/conandata.yml").read_text(encoding="utf-8")
    if not conandata.startswith(
        f'sources:\n  "{version}":\n    url: "{source_url}"\n    sha256: "{source_sha256}"\n'
    ):
        raise ValueError("conandata.yml does not bind this release's signed source archive")
    combined = "\n".join(path.read_text(encoding="utf-8") for path in files)
    if "license" not in combined:
        raise ValueError("recipe tree declares no license")
    if "http://" in combined:
        raise ValueError("recipe tree contains an insecure source URL")
    manifest = json.loads(release_manifest.read_text(encoding="utf-8"))
    requirements = manifest.get("conan_requirements")
    if (
        not isinstance(requirements, list)
        or not requirements
        or any(
            not isinstance(reference, str)
            or not reference
            or reference != reference.strip()
            or reference.count("/") != 1
            for reference in requirements
        )
        or requirements != sorted(set(requirements))
    ):
        raise ValueError("release manifest Conan requirements are missing or noncanonical")
    recipe_requirements = _declared_requirements(root / "all/conanfile.py")
    if recipe_requirements != requirements:
        raise ValueError("recipe requirements differ from the signed exact requirement set")


def _source_identity(manifest: object, tag: str) -> tuple[str, str, str]:
    match = TAG.fullmatch(tag)
    if match is None:
        raise ValueError("source tag is not a canonical stable release")
    version = tag[1:]
    name = f"mcp-cpp-sdk-{version}.tar.gz"
    payloads = manifest.get("payloads") if isinstance(manifest, dict) else None
    if not isinstance(payloads, list):
        raise ValueError("release manifest payloads are malformed")
    matches = [
        item
        for item in payloads
        if isinstance(item, dict) and item.get("name") == name
    ]
    if (
        len(matches) != 1
        or not isinstance(matches[0].get("sha256"), str)
        or DIGEST.fullmatch(matches[0]["sha256"]) is None
    ):
        raise ValueError("release manifest source archive identity is not exact")
    url = f"https://github.com/yurirocha15/mcp-cpp-sdk/releases/download/{tag}/{name}"
    return version, url, matches[0]["sha256"]


def verify_assembled(root: Path, *, tag: str, release_manifest: Path) -> None:
    """Verify an assembled recipe folder against the signed source identity."""

    manifest = json.loads(release_manifest.read_text(encoding="utf-8"))
    version, source_url, source_sha256 = _source_identity(manifest, tag)
    verify(
        root,
        version=version,
        source_url=source_url,
        source_sha256=source_sha256,
        release_manifest=release_manifest,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tree", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--release-manifest", type=Path, required=True)
    args = parser.parse_args()
    try:
        verify_assembled(args.tree, tag=args.tag, release_manifest=args.release_manifest)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        print(f"verify-recipe-tree: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
