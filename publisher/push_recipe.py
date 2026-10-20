#!/usr/bin/env python3
"""Push one verified recipe folder to the ConanCenter fork as a review branch.

The client only talks to fixed GitHub API routes for the fork and its
upstream.  It creates a single commit on top of the upstream commit that the
credential-free job verified, changing nothing outside the recipe folder, and
accepts an existing branch only when it already holds exactly that change.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import sys
from typing import Mapping
from urllib.parse import quote, urlencode


API_HOST = "api.github.com"
FORK = "yurirocha15/conan-center-index"
UPSTREAM = "conan-io/conan-center-index"
BASE_BRANCH = "master"
PACKAGE = "mcp-cpp-sdk"
RECIPE_PATH = f"recipes/{PACKAGE}"
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
TIMEOUT_SECONDS = 30
SHA = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
DECIMAL = re.compile(r"[1-9][0-9]*")
VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")


class PushError(ValueError):
    """Raised when the fork push is not provably exact."""


@dataclass(frozen=True)
class Response:
    status: int
    value: object


class Client:
    def __init__(self, token: str) -> None:
        if not token or len(token) > 8192 or any(c.isspace() for c in token):
            raise PushError("GitHub token is missing or malformed")
        self._token = token

    def request(
        self,
        method: str,
        path: str,
        expected: set[int],
        body: Mapping[str, object] | None = None,
    ) -> Response:
        if not path.startswith("/repos/") or "//" in path or ".." in path:
            raise PushError("GitHub API route is outside the fixed repository API")
        encoded = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._token}",
            "User-Agent": "mcp-cpp-sdk-release-control/2",
            "X-GitHub-Api-Version": "2026-03-10",
        }
        if encoded is not None:
            headers["Content-Type"] = "application/json"
        connection = http.client.HTTPSConnection(API_HOST, timeout=TIMEOUT_SECONDS)
        request_id = "missing"
        try:
            connection.request(method, path, body=encoded, headers=headers)
            response = connection.getresponse()
            request_id = response.getheader("X-GitHub-Request-Id", "missing")
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise PushError(f"{method} {path}: response exceeds limit; request_id={request_id}")
            if response.status not in expected:
                raise PushError(
                    f"{method} {path}: unexpected HTTP {response.status}; request_id={request_id}"
                )
            return Response(response.status, json.loads(raw) if raw else None)
        except (OSError, http.client.HTTPException, json.JSONDecodeError) as error:
            raise PushError(
                f"{method} {path}: {type(error).__name__}; request_id={request_id}"
            ) from error
        finally:
            connection.close()


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise PushError(f"{label} is not a JSON object")
    return value


def recipe_files(directory: Path) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise PushError("recipe folder contains a symbolic link")
        if path.is_file():
            files[path.relative_to(directory).as_posix()] = path.read_bytes()
    if not files:
        raise PushError("recipe folder is empty")
    return files


def git_tree_sha(files: Mapping[str, bytes]) -> str:
    """Return the Git object ID of the tree holding exactly ``files``."""

    children: dict[str, dict[str, bytes]] = {}
    entries: list[tuple[str, bytes, bytes]] = []
    for path, content in files.items():
        head, _, rest = path.partition("/")
        if rest:
            children.setdefault(head, {})[rest] = content
        else:
            blob = hashlib.sha1(b"blob %d\0" % len(content) + content).digest()
            entries.append((head, b"100644", blob))
    for name, nested in children.items():
        entries.append((name + "/", b"40000", bytes.fromhex(git_tree_sha(nested))))
    body = b"".join(
        mode + b" " + name.rstrip("/").encode("utf-8") + b"\0" + object_id
        for name, mode, object_id in sorted(entries, key=lambda entry: entry[0].encode())
    )
    return hashlib.sha1(b"tree %d\0" % len(body) + body).hexdigest()


def pull_title(version: str, state: str) -> str:
    if state == "new":
        return f"{PACKAGE}/{version}: new recipe"
    return f"{PACKAGE}: add version {version}"


def pull_body(*, version: str, commit: str, request_uuid: str) -> str:
    return (
        "### Summary\n"
        f"Changes to recipe:  **{PACKAGE}/{version}**\n\n"
        "#### Motivation\n"
        f"Publish the stable {PACKAGE}/{version} SDK release through ConanCenter.\n\n"
        "#### Details\n"
        f"Source commit: `{commit}`\n\n"
        f"Release request: `{request_uuid}`\n\n"
        "---\n\n"
        "- [x] Read the [contributing guidelines]"
        "(https://github.com/conan-io/conan-center-index/blob/master/CONTRIBUTING.md)\n"
        "- [x] Checked that this PR is not a duplicate: [list of PRs by recipe]"
        "(https://github.com/conan-io/conan-center-index/discussions/24240)\n"
        "- [ ] If this is a bug fix, please link related issue or provide bug details\n"
        "- [x] Tested locally with at least one configuration using a recent version of Conan\n"
    )


def _subtree_sha(client: Client, tree_sha: str, path: str) -> str | None:
    current = tree_sha
    for part in path.split("/"):
        tree = _mapping(
            client.request("GET", f"/repos/{FORK}/git/trees/{current}", {200}).value, "Git tree"
        )
        if tree.get("truncated") is not False:
            raise PushError("Git tree listing is truncated")
        matches = [
            item
            for item in tree.get("tree", [])
            if isinstance(item, Mapping) and item.get("path") == part
        ]
        if not matches:
            return None
        if len(matches) != 1 or matches[0].get("type") != "tree":
            raise PushError(f"{path} is not a single directory")
        current = str(matches[0].get("sha"))
    return current


def _verify_repositories(client: Client, *, fork_id: int, fork_owner_id: int, upstream_id: int) -> None:
    fork = _mapping(client.request("GET", f"/repos/{FORK}", {200}).value, "fork repository")
    parent = _mapping(fork.get("parent"), "fork parent")
    owner = _mapping(fork.get("owner"), "fork owner")
    if (
        fork.get("id") != fork_id
        or fork.get("full_name") != FORK
        or fork.get("fork") is not True
        or fork.get("archived") is not False
        or owner.get("id") != fork_owner_id
        or parent.get("id") != upstream_id
        or parent.get("full_name") != UPSTREAM
    ):
        raise PushError("fork or upstream identity differs from configuration")


def _ensure_base(client: Client, base_commit: str) -> None:
    """Make the verified upstream base commit available in the fork."""

    path = f"/repos/{FORK}/git/commits/{base_commit}"
    if client.request("GET", path, {200, 404, 422}).status == 200:
        return
    owner, name = FORK.split("/")
    compare = _mapping(
        client.request(
            "GET",
            f"/repos/{UPSTREAM}/compare/{BASE_BRANCH}...{owner}:{name}:{BASE_BRANCH}",
            {200},
        ).value,
        "fork comparison",
    )
    if compare.get("ahead_by") != 0:
        raise PushError("fork master has commits that are not upstream; sync it by hand")
    client.request(
        "POST", f"/repos/{FORK}/merge-upstream", {200}, {"branch": BASE_BRANCH}
    )
    if client.request("GET", path, {200, 404, 422}).status != 200:
        raise PushError("verified upstream base commit is not available in the fork")


def _branch_matches(client: Client, *, branch: str, expected_recipe: str) -> bool:
    owner, name = FORK.split("/")
    compare = _mapping(
        client.request(
            "GET",
            f"/repos/{UPSTREAM}/compare/{BASE_BRANCH}...{owner}:{name}:{quote(branch, safe='/')}",
            {200},
        ).value,
        "branch comparison",
    )
    files = compare.get("files")
    if (
        compare.get("ahead_by") != 1
        or not isinstance(files, list)
        or not files
        or any(
            not isinstance(item, Mapping)
            or not str(item.get("filename", "")).startswith(RECIPE_PATH + "/")
            for item in files
        )
    ):
        return False
    head = _mapping(
        client.request("GET", f"/repos/{FORK}/git/ref/heads/{quote(branch, safe='/')}", {200}).value,
        "branch reference",
    )
    commit_sha = str(_mapping(head.get("object"), "branch object").get("sha"))
    commit = _mapping(
        client.request("GET", f"/repos/{FORK}/git/commits/{commit_sha}", {200}).value, "commit"
    )
    tree = str(_mapping(commit.get("tree"), "commit tree").get("sha"))
    return _subtree_sha(client, tree, RECIPE_PATH) == expected_recipe


def push(
    client: Client,
    *,
    files: Mapping[str, bytes],
    version: str,
    state: str,
    base_commit: str,
    fork_id: int,
    fork_owner_id: int,
    upstream_id: int,
) -> tuple[str, bool]:
    """Create or prove the review branch; return its name and whether it was created."""

    branch = f"package/{PACKAGE}-{version}"
    expected_recipe = git_tree_sha(files)
    _verify_repositories(client, fork_id=fork_id, fork_owner_id=fork_owner_id, upstream_id=upstream_id)
    ref_path = f"/repos/{FORK}/git/ref/heads/{quote(branch, safe='/')}"
    if client.request("GET", ref_path, {200, 404}).status == 200:
        if not _branch_matches(client, branch=branch, expected_recipe=expected_recipe):
            raise PushError(f"fork branch {branch} exists with different content; delete it first")
        return branch, False

    _ensure_base(client, base_commit)
    base = _mapping(
        client.request("GET", f"/repos/{FORK}/git/commits/{base_commit}", {200}).value,
        "base commit",
    )
    base_tree = str(_mapping(base.get("tree"), "base tree").get("sha"))
    if state == "new" and _subtree_sha(client, base_tree, RECIPE_PATH) is not None:
        raise PushError("upstream gained this recipe after verification; rerun the workflow")
    entries = []
    for path, content in sorted(files.items()):
        blob = _mapping(
            client.request(
                "POST",
                f"/repos/{FORK}/git/blobs",
                {201},
                {"content": base64.b64encode(content).decode("ascii"), "encoding": "base64"},
            ).value,
            "blob",
        )
        entries.append(
            {"path": f"{RECIPE_PATH}/{path}", "mode": "100644", "type": "blob", "sha": blob.get("sha")}
        )
    tree = _mapping(
        client.request(
            "POST", f"/repos/{FORK}/git/trees", {201}, {"base_tree": base_tree, "tree": entries}
        ).value,
        "tree",
    )
    tree_sha = str(tree.get("sha"))
    if _subtree_sha(client, tree_sha, RECIPE_PATH) != expected_recipe:
        raise PushError("GitHub stored a recipe tree that differs from the verified folder")
    commit = _mapping(
        client.request(
            "POST",
            f"/repos/{FORK}/git/commits",
            {201},
            {"message": pull_title(version, state), "tree": tree_sha, "parents": [base_commit]},
        ).value,
        "commit",
    )
    client.request(
        "POST",
        f"/repos/{FORK}/git/refs",
        {201},
        {"ref": f"refs/heads/{branch}", "sha": commit.get("sha")},
    )
    if not _branch_matches(client, branch=branch, expected_recipe=expected_recipe):
        raise PushError("fork branch readback differs from the verified recipe")
    return branch, True


def compare_link(*, branch: str, title: str, body: str) -> str:
    owner, name = FORK.split("/")
    query = urlencode({"quick_pull": "1", "title": title, "body": body})
    return (
        f"https://github.com/{UPSTREAM}/compare/{BASE_BRANCH}..."
        f"{owner}:{name}:{quote(branch, safe='/')}?{query}"
    )


def _positive(value: str, label: str) -> int:
    if DECIMAL.fullmatch(value) is None:
        raise PushError(f"{label} is not a positive canonical decimal")
    return int(value)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recipe", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--expected-tree-sha256", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--request-uuid", required=True)
    parser.add_argument("--fork-repository-id", required=True)
    parser.add_argument("--fork-owner-id", required=True)
    parser.add_argument("--upstream-repository-id", required=True)
    parser.add_argument("--summary", type=Path, required=True)
    args = parser.parse_args()
    try:
        metadata = _mapping(json.loads(args.metadata.read_text(encoding="utf-8")), "metadata")
        version = str(metadata.get("version"))
        state = str(metadata.get("state"))
        base_commit = str(metadata.get("base_commit"))
        if (
            set(metadata) != {"schema_version", "version", "state", "base_commit", "tree_sha256"}
            or metadata.get("schema_version") != 1
            or VERSION.fullmatch(version) is None
            or state not in {"new", "existing"}
            or SHA.fullmatch(base_commit) is None
            or DIGEST.fullmatch(args.expected_tree_sha256) is None
            or metadata.get("tree_sha256") != args.expected_tree_sha256
            or SHA.fullmatch(args.source_commit) is None
        ):
            raise PushError("recipe metadata differs from the verified handoff")
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from assemble_recipe import tree_sha256

        if tree_sha256(args.recipe) != args.expected_tree_sha256:
            raise PushError("recipe folder differs from the verified handoff")
        files = recipe_files(args.recipe)
        branch, created = push(
            Client(os.environ.get("GH_TOKEN", "")),
            files=files,
            version=version,
            state=state,
            base_commit=base_commit,
            fork_id=_positive(args.fork_repository_id, "fork repository ID"),
            fork_owner_id=_positive(args.fork_owner_id, "fork owner ID"),
            upstream_id=_positive(args.upstream_repository_id, "upstream repository ID"),
        )
        title = pull_title(version, state)
        link = compare_link(
            branch=branch,
            title=title,
            body=pull_body(version=version, commit=args.source_commit, request_uuid=args.request_uuid),
        )
        with args.summary.open("a", encoding="utf-8") as summary:
            summary.write(
                f"## ConanCenter recipe branch {'created' if created else 'already present'}\n\n"
                f"Branch `{branch}` on `{FORK}` holds `{PACKAGE}/{version}` "
                f"({state} recipe).\n\n"
                f"[Open the ConanCenter pull request]({link}) — title and body are prefilled.\n"
            )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        print(f"push-recipe: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
