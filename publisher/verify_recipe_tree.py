#!/usr/bin/env python3
"""Reject unsafe or incomplete ConanCenter recipe trees."""

from __future__ import annotations

import argparse
import ast
import hashlib
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
RECIPE_PREFIX = "recipes/mcp-cpp-sdk/"


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
    combined = "\n".join(path.read_text(encoding="utf-8") for path in files)
    for required in (version, source_url, source_sha256, "license"):
        if required not in combined:
            raise ValueError(f"recipe tree does not bind required release value: {required}")
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


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


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


def verify_handoff(
    root: Path,
    *,
    tag: str,
    tree_archive: Path,
    tree_sha256: str,
    diff: Path,
    release_manifest: Path,
) -> None:
    """Verify the fetched fork tree, diff boundary, and signed source binding."""

    if DIGEST.fullmatch(tree_sha256) is None or _sha256(tree_archive) != tree_sha256:
        raise ValueError("recipe tree archive digest does not match the dispatch")
    changed: list[str] = []
    for line in diff.read_text(encoding="utf-8").splitlines():
        fields = line.split("\t")
        if len(fields) != 2 or fields[0] not in {"A", "D", "M"}:
            raise ValueError("recipe diff contains a malformed or renamed entry")
        path = fields[1]
        if not path.startswith(RECIPE_PREFIX) or path == RECIPE_PREFIX:
            raise ValueError("fork changes files outside the package recipe")
        changed.append(path)
    if not changed or len(changed) != len(set(changed)):
        raise ValueError("recipe diff is empty or duplicated")
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
    parser.add_argument("--tree-archive", type=Path, required=True)
    parser.add_argument("--tree-sha256", required=True)
    parser.add_argument("--diff", type=Path, required=True)
    parser.add_argument("--release-manifest", type=Path, required=True)
    args = parser.parse_args()
    try:
        verify_handoff(
            args.tree,
            tag=args.tag,
            tree_archive=args.tree_archive,
            tree_sha256=args.tree_sha256,
            diff=args.diff,
            release_manifest=args.release_manifest,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        print(f"verify-recipe-tree: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
