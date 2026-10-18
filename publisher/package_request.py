#!/usr/bin/env python3
"""Verify the exact ConanCenter authorization issue and PR metadata policy."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import re


UPSTREAM = "conan-io/conan-center-index"
FORK = "yurirocha15/conan-center-index"
PACKAGE = "mcp-cpp-sdk"
PROJECT_URL = "https://github.com/yurirocha15/mcp-cpp-sdk"
REQUIRED_LABEL = "library request"
VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
DECIMAL = re.compile(r"[1-9][0-9]*")
HEX64 = re.compile(r"[0-9a-f]{64}")
TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
NODE = re.compile(r"[A-Za-z0-9_-]{4,128}")
LOGIN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
SECTIONS = (
    "Package Name/Version",
    "Webpage",
    "Source code",
    "Description of the library/tool",
)


class PackageRequestError(ValueError):
    """Raised when authorization or generated PR metadata is not exact."""


@dataclass(frozen=True)
class IssueIdentity:
    number: str
    issue_id: str
    node_id: str
    created_at: str
    body_sha256: str
    author_id: str
    author_node_id: str
    author_login: str
    author_type: str
    label_id: str
    label_node_id: str
    label_name: str

    def validate(self) -> None:
        for field in ("number", "issue_id", "author_id", "label_id"):
            if DECIMAL.fullmatch(getattr(self, field)) is None:
                raise PackageRequestError(f"package request {field} is malformed")
        for field in ("node_id", "author_node_id", "label_node_id"):
            if NODE.fullmatch(getattr(self, field)) is None:
                raise PackageRequestError(f"package request {field} is malformed")
        if TIMESTAMP.fullmatch(self.created_at) is None:
            raise PackageRequestError("package request creation time is malformed")
        if HEX64.fullmatch(self.body_sha256) is None:
            raise PackageRequestError("package request body digest is malformed")
        if LOGIN.fullmatch(self.author_login) is None or self.author_type != "User":
            raise PackageRequestError("package request author identity is malformed")
        if self.label_name != REQUIRED_LABEL:
            raise PackageRequestError("package request label is not the official template label")


def version_from_tag(tag: str) -> str:
    if TAG.fullmatch(tag) is None:
        raise PackageRequestError("source tag is not a canonical stable tag")
    return tag[1:]


def verify_repository(value: object, *, repository_id: str) -> None:
    if DECIMAL.fullmatch(repository_id) is None or not isinstance(value, Mapping):
        raise PackageRequestError("ConanCenter repository identity is malformed")
    owner = value.get("owner")
    if (
        value.get("id") != int(repository_id)
        or value.get("full_name") != UPSTREAM
        or value.get("name") != "conan-center-index"
        or value.get("fork") is not False
        or value.get("archived") is not False
        or value.get("disabled") is not False
        or value.get("default_branch") != "master"
        or not isinstance(owner, Mapping)
        or owner.get("login") != "conan-io"
        or owner.get("type") != "Organization"
    ):
        raise PackageRequestError("ConanCenter repository identity changed")


def verify_fork(
    value: object,
    *,
    repository_id: str,
    owner_id: str,
    upstream_repository_id: str,
) -> None:
    if any(
        DECIMAL.fullmatch(identity) is None
        for identity in (repository_id, owner_id, upstream_repository_id)
    ) or not isinstance(value, Mapping):
        raise PackageRequestError("ConanCenter fork identity is malformed")
    owner = value.get("owner")
    parent = value.get("parent")
    if (
        value.get("id") != int(repository_id)
        or value.get("full_name") != FORK
        or value.get("name") != "conan-center-index"
        or value.get("fork") is not True
        or value.get("archived") is not False
        or value.get("disabled") is not False
        or value.get("default_branch") != "master"
        or not isinstance(owner, Mapping)
        or owner.get("id") != int(owner_id)
        or owner.get("login") != "yurirocha15"
        or owner.get("type") != "User"
        or not isinstance(parent, Mapping)
        or parent.get("id") != int(upstream_repository_id)
        or parent.get("full_name") != UPSTREAM
    ):
        raise PackageRequestError("ConanCenter fork identity changed")


def _sections(body: str) -> dict[str, str]:
    positions: list[tuple[str, int, int]] = []
    for heading in SECTIONS:
        matches = list(re.finditer(rf"(?m)^### {re.escape(heading)}\s*$", body))
        if len(matches) != 1:
            raise PackageRequestError(f"package request body must contain one {heading!r} section")
        positions.append((heading, matches[0].start(), matches[0].end()))
    if [item[1] for item in positions] != sorted(item[1] for item in positions):
        raise PackageRequestError("package request body sections are out of order")
    values: dict[str, str] = {}
    for index, (heading, _, end) in enumerate(positions):
        next_start = positions[index + 1][1] if index + 1 < len(positions) else len(body)
        values[heading] = body[end:next_start].strip()
    return values


def verify_issue(value: object, *, version: str, identity: IssueIdentity) -> None:
    identity.validate()
    if VERSION.fullmatch(version) is None or not isinstance(value, Mapping):
        raise PackageRequestError("package request response or version is malformed")
    expected_number = int(identity.number)
    if (
        value.get("id") != int(identity.issue_id)
        or value.get("node_id") != identity.node_id
        or value.get("number") != expected_number
        or value.get("repository_url") != f"https://api.github.com/repos/{UPSTREAM}"
        or value.get("html_url") != f"https://github.com/{UPSTREAM}/issues/{identity.number}"
        or value.get("state") != "open"
        or value.get("state_reason") is not None
        or value.get("title") != f"[request] {PACKAGE}/{version}"
        or value.get("created_at") != identity.created_at
        or "pull_request" in value
    ):
        raise PackageRequestError("package request immutable identity or open state changed")
    body = value.get("body")
    if not isinstance(body, str) or not body or len(body.encode("utf-8")) > 65536:
        raise PackageRequestError("package request body is missing or oversized")
    if hashlib.sha256(body.encode("utf-8")).hexdigest() != identity.body_sha256:
        raise PackageRequestError("package request body digest changed")
    sections = _sections(body)
    if sections["Package Name/Version"] != f"{PACKAGE}/{version}":
        raise PackageRequestError("package request body names another package or version")
    if (
        sections["Webpage"] != PROJECT_URL
        or sections["Source code"] != PROJECT_URL
    ):
        raise PackageRequestError("package request project URLs are not exact")
    if not sections["Description of the library/tool"]:
        raise PackageRequestError("package request body has an empty required section")
    user = value.get("user")
    if (
        not isinstance(user, Mapping)
        or user.get("id") != int(identity.author_id)
        or user.get("node_id") != identity.author_node_id
        or user.get("login") != identity.author_login
        or user.get("type") != identity.author_type
    ):
        raise PackageRequestError("package request author identity changed")
    labels = value.get("labels")
    if not isinstance(labels, list) or len(labels) != 1 or not isinstance(labels[0], Mapping):
        raise PackageRequestError("package request labels are not exact")
    label = labels[0]
    if (
        label.get("id") != int(identity.label_id)
        or label.get("node_id") != identity.label_node_id
        or label.get("name") != identity.label_name
    ):
        raise PackageRequestError("package request label identity changed")


def pull_title(version: str, state: str) -> str:
    if VERSION.fullmatch(version) is None or state not in {"new", "existing"}:
        raise PackageRequestError("pull request title inputs are malformed")
    if state == "new":
        return f"{PACKAGE}/{version}: new recipe"
    return f"{PACKAGE}: add version {version}"


def pull_body(*, version: str, issue: str, commit: str, request_uuid: str) -> str:
    if VERSION.fullmatch(version) is None or DECIMAL.fullmatch(issue) is None:
        raise PackageRequestError("pull request body inputs are malformed")
    return (
        "### Summary\n"
        f"Changes to recipe:  **{PACKAGE}/{version}**\n\n"
        "#### Motivation\n"
        f"Publish the stable {PACKAGE}/{version} SDK release through ConanCenter.\n\n"
        f"fixes #{issue}\n\n"
        "#### Details\n"
        f"Source commit: `{commit}`\n\n"
        f"Release request: `{request_uuid}`\n\n"
        "---\n\n"
        "- [x] Read the [contributing guidelines]"
        "(https://github.com/conan-io/conan-center-index/blob/master/CONTRIBUTING.md)\n"
        "- [x] Checked that this PR is not a duplicate: [list of PRs by recipe]"
        "(https://github.com/conan-io/conan-center-index/discussions/24240)\n"
        "- [ ] If this is a bug fix, please link related issue or provide bug details\n"
        "- [x] Tested locally with at least one configuration using a recent version of Conan\n\n"
        "---\n\n"
        "Add a :+1: reaction to pull requests you find "
        "[important](https://github.com/conan-io/conan-center-index/pulls?"
        "q=is%3Aopen+sort%3Areactions-%2B1-desc) to help the team prioritize, thanks!\n"
    )


def identity_from_mapping(value: Mapping[str, str]) -> IssueIdentity:
    return IssueIdentity(
        number=value["PACKAGE_REQUEST_ISSUE"],
        issue_id=value["PACKAGE_REQUEST_ISSUE_ID"],
        node_id=value["PACKAGE_REQUEST_ISSUE_NODE_ID"],
        created_at=value["PACKAGE_REQUEST_ISSUE_CREATED_AT"],
        body_sha256=value["PACKAGE_REQUEST_ISSUE_BODY_SHA256"],
        author_id=value["PACKAGE_REQUEST_ISSUE_AUTHOR_ID"],
        author_node_id=value["PACKAGE_REQUEST_ISSUE_AUTHOR_NODE_ID"],
        author_login=value["PACKAGE_REQUEST_ISSUE_AUTHOR_LOGIN"],
        author_type=value["PACKAGE_REQUEST_ISSUE_AUTHOR_TYPE"],
        label_id=value["PACKAGE_REQUEST_ISSUE_LABEL_ID"],
        label_node_id=value["PACKAGE_REQUEST_ISSUE_LABEL_NODE_ID"],
        label_name=value["PACKAGE_REQUEST_ISSUE_LABEL_NAME"],
    )
