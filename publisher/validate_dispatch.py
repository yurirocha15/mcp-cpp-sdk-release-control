#!/usr/bin/env python3
"""Validate and normalize the broker's fixed workflow_dispatch contract."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys
from uuid import UUID


FIELDS = (
    "source_tag",
    "source_commit_sha",
    "source_workflow_head_sha",
    "provider_control_sha",
    "github_release_id",
    "source_workflow_run_id",
    "release_manifest_sha256",
    "fork_branch",
    "fork_head_sha",
    "recipe_tree_sha256",
    "request_uuid",
)
STABLE_TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
SHA = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
DECIMAL = re.compile(r"0|[1-9][0-9]*")


def validate(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != set(FIELDS):
        raise ValueError("dispatch must contain exactly the approved fields")
    normalized: dict[str, str] = {}
    for field in FIELDS:
        item = value[field]
        if not isinstance(item, str) or not item or len(item) > 160:
            raise ValueError(f"{field} is not a bounded non-empty string")
        if any(character.isspace() or ord(character) < 0x20 for character in item):
            raise ValueError(f"{field} contains whitespace or control characters")
        normalized[field] = item

    match = STABLE_TAG.fullmatch(normalized["source_tag"])
    if match is None:
        raise ValueError("source_tag is not a canonical stable tag")
    version = normalized["source_tag"][1:]
    expected_branch = f"package/mcp-cpp-sdk-{version}"
    recovery = re.compile(re.escape(expected_branch) + r"-r[1-9][0-9]*")
    if normalized["fork_branch"] != expected_branch and recovery.fullmatch(normalized["fork_branch"]) is None:
        raise ValueError("fork_branch does not match source_tag")
    for field in (
        "source_commit_sha",
        "source_workflow_head_sha",
        "provider_control_sha",
        "fork_head_sha",
    ):
        if SHA.fullmatch(normalized[field]) is None:
            raise ValueError(f"{field} is not a lowercase full commit SHA")
    for field in ("release_manifest_sha256", "recipe_tree_sha256"):
        if DIGEST.fullmatch(normalized[field]) is None:
            raise ValueError(f"{field} is not a lowercase SHA-256")
    for field in ("github_release_id", "source_workflow_run_id"):
        if DECIMAL.fullmatch(normalized[field]) is None:
            raise ValueError(f"{field} is not a canonical decimal ID")
    try:
        request_id = UUID(normalized["request_uuid"])
    except ValueError as error:
        raise ValueError("request_uuid is invalid") from error
    if str(request_id) != normalized["request_uuid"]:
        raise ValueError("request_uuid is not canonical lowercase")
    return normalized


def main() -> int:
    try:
        request = json.loads(os.environ["DISPATCH_JSON"])
        normalized = validate(request)
        output_path = Path(os.environ["GITHUB_OUTPUT"])
        with output_path.open("a", encoding="utf-8") as output:
            for field in FIELDS:
                output.write(f"{field}={normalized[field]}\n")
    except (KeyError, OSError, json.JSONDecodeError, ValueError) as error:
        print(f"validate-dispatch: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
