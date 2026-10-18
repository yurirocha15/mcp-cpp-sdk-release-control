#!/usr/bin/env python3
"""Verify the immutable source release and workflow run behind a Conan request."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
import json
import re
import subprocess
import sys
import time


DECIMAL = re.compile(r"[1-9][0-9]*")
SHA = re.compile(r"[0-9a-f]{40}")
TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
PENDING = frozenset({"in_progress", "pending", "queued", "requested", "waiting"})
SOURCE_REPOSITORY = "yurirocha15/mcp-cpp-sdk"


def verify_repository(value: object, *, repository_id: str, owner_id: str) -> None:
    """Require the one public, active source repository identity."""

    if DECIMAL.fullmatch(repository_id) is None or DECIMAL.fullmatch(owner_id) is None:
        raise ValueError("source repository identity is malformed")
    if not isinstance(value, Mapping):
        raise ValueError("source repository response is malformed")
    owner = value.get("owner")
    if (
        value.get("id") != int(repository_id)
        or value.get("full_name") != SOURCE_REPOSITORY
        or value.get("private") is not False
        or value.get("archived") is not False
        or value.get("disabled") is not False
        or value.get("default_branch") != "main"
        or not isinstance(owner, Mapping)
        or owner.get("id") != int(owner_id)
        or owner.get("login") != "yurirocha15"
        or owner.get("type") != "User"
    ):
        raise ValueError("source repository identity does not match")


def verify_release(value: object, *, tag: str, release_id: str) -> None:
    """Require the exact immutable, published stable GitHub Release."""

    if TAG.fullmatch(tag) is None or DECIMAL.fullmatch(release_id) is None:
        raise ValueError("source release identity is malformed")
    if (
        not isinstance(value, Mapping)
        or value.get("id") != int(release_id)
        or value.get("tag_name") != tag
        or value.get("draft") is not False
        or value.get("prerelease") is not False
        or value.get("immutable") is not True
    ):
        raise ValueError("source release identity does not match")


def verify_completed_run(
    value: object, *, run_id: str, workflow_head_sha: str, repository_id: str
) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError("source workflow run response is malformed")
    if DECIMAL.fullmatch(run_id) is None or DECIMAL.fullmatch(repository_id) is None:
        raise ValueError("source workflow identity is malformed")
    if SHA.fullmatch(workflow_head_sha) is None:
        raise ValueError("source workflow head is malformed")
    repository = value.get("repository")
    if not isinstance(repository, Mapping):
        raise ValueError("source workflow repository identity is missing")
    expected = {
        "id": int(run_id),
        "event": "workflow_dispatch",
        "status": "completed",
        "conclusion": "success",
        "head_sha": workflow_head_sha,
        "head_branch": "main",
        "path": ".github/workflows/release.yml",
    }
    for field, wanted in expected.items():
        if value.get(field) != wanted:
            raise ValueError(f"source workflow {field} does not match the dispatch")
    if repository.get("id") != int(repository_id):
        raise ValueError("source workflow repository ID does not match")
    return dict(value)


def poll(
    fetch: Callable[[], object],
    *,
    run_id: str,
    workflow_head_sha: str,
    repository_id: str,
    timeout_seconds: int = 3600,
    interval_seconds: int = 20,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, object]:
    if not 60 <= timeout_seconds <= 3600 or not 1 <= interval_seconds <= 60:
        raise ValueError("source workflow polling bounds are unsafe")
    deadline = monotonic() + timeout_seconds
    while True:
        value = fetch()
        if not isinstance(value, Mapping) or not isinstance(value.get("status"), str):
            raise ValueError("source workflow run response is malformed")
        status = value["status"]
        if status == "completed":
            return verify_completed_run(
                value,
                run_id=run_id,
                workflow_head_sha=workflow_head_sha,
                repository_id=repository_id,
            )
        if status not in PENDING:
            raise ValueError(f"source workflow entered unexpected status: {status}")
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise TimeoutError("source workflow did not complete within 60 minutes")
        sleep(min(interval_seconds, remaining))


def _fetch(path: str) -> object:
    result = subprocess.run(
        [
            "gh",
            "api",
            "-H",
            "X-GitHub-Api-Version: 2026-03-10",
            path,
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return json.loads(result.stdout)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--workflow-head-sha", required=True)
    parser.add_argument("--repository-id", required=True)
    parser.add_argument("--owner-id", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=3600)
    args = parser.parse_args()
    try:
        verify_repository(
            _fetch(f"/repos/{SOURCE_REPOSITORY}"),
            repository_id=args.repository_id,
            owner_id=args.owner_id,
        )
        verify_release(
            _fetch(f"/repos/{SOURCE_REPOSITORY}/releases/tags/{args.tag}"),
            tag=args.tag,
            release_id=args.release_id,
        )
        poll(
            lambda: _fetch(f"/repos/{SOURCE_REPOSITORY}/actions/runs/{args.run_id}"),
            run_id=args.run_id,
            workflow_head_sha=args.workflow_head_sha,
            repository_id=args.repository_id,
            timeout_seconds=args.timeout_seconds,
        )
    except (
        json.JSONDecodeError,
        OSError,
        subprocess.CalledProcessError,
        TimeoutError,
        ValueError,
    ) as error:
        print(f"source-run: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
