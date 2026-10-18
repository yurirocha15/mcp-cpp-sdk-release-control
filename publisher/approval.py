#!/usr/bin/env python3
"""Verify public Conan authorization and render the approval summary."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

if __package__:
    from . import package_request
else:
    import package_request


SHA = re.compile(r"[0-9a-f]{40}")


def recipe_identity(
    git_directory: Path,
    *,
    fork_head: str,
    ref: str = "refs/heads/upstream-master",
) -> tuple[str, str]:
    if (
        not git_directory.is_dir()
        or not ref.startswith("refs/heads/")
        or SHA.fullmatch(fork_head) is None
    ):
        raise package_request.PackageRequestError(
            "upstream recipe Git input is malformed"
        )
    merge_base = subprocess.run(
        ["git", "-C", str(git_directory), "merge-base", ref, fork_head],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout.strip()
    if SHA.fullmatch(merge_base) is None:
        raise package_request.PackageRequestError("recipe branch has no canonical merge base")
    path = f"recipes/{package_request.PACKAGE}"
    advanced = subprocess.run(
        [
            "git",
            "-C",
            str(git_directory),
            "diff",
            "--quiet",
            merge_base,
            ref,
            "--",
            path,
        ],
        check=False,
        timeout=30,
    )
    if advanced.returncode == 1:
        raise package_request.PackageRequestError(
            "upstream recipe changed after the fork branch diverged"
        )
    if advanced.returncode != 0:
        raise package_request.PackageRequestError("could not compare upstream recipe state")
    result = subprocess.run(
        [
            "git",
            "-C",
            str(git_directory),
            "cat-file",
            "-e",
            f"{ref}:{path}",
        ],
        check=False,
        capture_output=True,
        timeout=30,
    )
    if result.returncode == 0:
        object_type = subprocess.run(
            ["git", "-C", str(git_directory), "cat-file", "-t", f"{ref}:{path}"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.strip()
        if object_type != "tree":
            raise package_request.PackageRequestError("upstream recipe path is not a tree")
        tree = subprocess.run(
            ["git", "-C", str(git_directory), "rev-parse", f"{ref}:{path}"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.strip()
        if SHA.fullmatch(tree) is None:
            raise package_request.PackageRequestError("upstream recipe tree is malformed")
        return "existing", tree
    if result.returncode == 128:
        return "new", "absent"
    raise package_request.PackageRequestError(
        "could not determine upstream recipe state"
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--repository-id", required=True)
    parser.add_argument("--fork-repository", required=True, type=Path)
    parser.add_argument("--fork-repository-id", required=True)
    parser.add_argument("--fork-owner-id", required=True)
    parser.add_argument("--issue", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--git-directory", required=True, type=Path)
    parser.add_argument("--recipe-diff", required=True, type=Path)
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--github-output", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--source-run-id", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--recipe-tree-sha256", required=True)
    parser.add_argument("--fork-branch", required=True)
    parser.add_argument("--fork-head", required=True)
    parser.add_argument("--request-uuid", required=True)
    for field in package_request.IssueIdentity.__dataclass_fields__:
        parser.add_argument(f"--{field.replace('_', '-')}", required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        version = package_request.version_from_tag(args.tag)
        repository = json.loads(args.repository.read_text(encoding="utf-8"))
        fork_repository = json.loads(
            args.fork_repository.read_text(encoding="utf-8")
        )
        issue = json.loads(args.issue.read_text(encoding="utf-8"))
        identity = package_request.IssueIdentity(
            **{
                field: getattr(args, field)
                for field in package_request.IssueIdentity.__dataclass_fields__
            }
        )
        package_request.verify_repository(
            repository, repository_id=args.repository_id
        )
        package_request.verify_fork(
            fork_repository,
            repository_id=args.fork_repository_id,
            owner_id=args.fork_owner_id,
            upstream_repository_id=args.repository_id,
        )
        package_request.verify_issue(issue, version=version, identity=identity)
        state, upstream_recipe_tree = recipe_identity(
            args.git_directory, fork_head=args.fork_head
        )
        title = package_request.pull_title(version, state)
        diff = args.recipe_diff.read_text(encoding="utf-8")
        if not diff or "```" in diff:
            raise package_request.PackageRequestError(
                "recipe diff is empty or unsafe for the summary"
            )
        with args.summary.open("a", encoding="utf-8") as summary:
            summary.write(
                "## Approved ConanCenter operation\n\n"
                f"- Source: {args.tag} at {args.source_commit}\n"
                f"- Immutable release ID: {args.release_id}\n"
                f"- Source workflow run: {args.source_run_id}\n"
                f"- Release manifest SHA-256: {args.manifest_sha256}\n"
                f"- Recipe tree SHA-256: {args.recipe_tree_sha256}\n"
                f"- Head: yurirocha15:{args.fork_branch} at {args.fork_head}\n"
                f"- Base: {package_request.UPSTREAM}:master\n"
                f"- Title: {title}\n"
                f"- Issue closure: fixes #{identity.number}\n"
                f"- Request: {args.request_uuid}\n\n"
                "### Complete allow-listed recipe diff\n\n"
                f"```text\n{diff}```\n"
            )
        with args.github_output.open("a", encoding="utf-8") as output:
            output.write(f"recipe_state={state}\n")
            output.write(f"upstream_recipe_tree={upstream_recipe_tree}\n")
    except (
        json.JSONDecodeError,
        OSError,
        subprocess.SubprocessError,
        UnicodeError,
        package_request.PackageRequestError,
    ) as error:
        print(f"conan-approval: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
