#!/usr/bin/env python3
"""Create the one exact ConanCenter PR through fixed GitHub API routes."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
from types import ModuleType
import urllib.parse
from uuid import UUID


def _load_package_request() -> ModuleType:
    path = Path(__file__).with_name("package_request.py")
    spec = importlib.util.spec_from_file_location(
        "_mcp_cpp_sdk_conan_package_request", path
    )
    if spec is None or spec.loader is None:
        raise ImportError("could not create the exact package request policy loader")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


package_request = _load_package_request()


API_HOST = "api.github.com"
BOT_LOGIN = "mcp-cpp-sdk-release-bot"
BASE_BRANCH = "master"
MAX_RESPONSE_BYTES = 1024 * 1024
TIMEOUT_SECONDS = 30
SHA = re.compile(r"[0-9a-f]{40}")
DECIMAL = re.compile(r"[1-9][0-9]*")


class PullCreationError(ValueError):
    """Raised when the fixed PR operation is not provably safe."""


@dataclass(frozen=True)
class ApiResult:
    value: object
    status: int
    headers: Mapping[str, str]

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


class Client:
    def __init__(self, token: str) -> None:
        if not token or len(token) > 8192:
            raise PullCreationError("GitHub token is missing or malformed")
        self._token = token

    def request(
        self,
        operation: str,
        method: str,
        path: str,
        expected: set[int],
        body: Mapping[str, object] | None = None,
    ) -> ApiResult:
        if not path.startswith("/") or "//" in path or not expected:
            raise PullCreationError(f"{operation}: API route is malformed")
        encoded = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._token}",
            "User-Agent": "mcp-cpp-sdk-release-control/2",
            "X-GitHub-Api-Version": "2026-03-10",
        }
        if encoded is not None:
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(encoded))
        connection = http.client.HTTPSConnection(API_HOST, timeout=TIMEOUT_SECONDS)
        request_id = "missing"
        try:
            connection.request(method, path, body=encoded, headers=headers)
            response = connection.getresponse()
            request_id = response.getheader("X-GitHub-Request-Id", "missing")
            if 300 <= response.status < 400:
                raise PullCreationError(f"{operation}: redirect rejected; request_id={request_id}")
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise PullCreationError(
                    f"{operation}: response exceeds limit; request_id={request_id}"
                )
            if response.status not in expected:
                raise PullCreationError(
                    f"{operation}: unexpected HTTP status class "
                    f"{response.status // 100}xx; request_id={request_id}"
                )
            value = json.loads(raw)
            response_headers = {name.lower(): value for name, value in response.getheaders()}
            return ApiResult(value=value, status=response.status, headers=response_headers)
        except (OSError, http.client.HTTPException, json.JSONDecodeError) as error:
            raise PullCreationError(
                f"{operation}: {type(error).__name__}; request_id={request_id}"
            ) from error
        finally:
            connection.close()


@dataclass(frozen=True)
class Configuration:
    tag: str
    commit: str
    branch: str
    head_sha: str
    request_uuid: str
    bot_user_id: str
    upstream_repository_id: str
    fork_repository_id: str
    fork_owner_id: str
    recipe_state: str
    upstream_recipe_tree: str
    issue: package_request.IssueIdentity

    @classmethod
    def from_environment(cls, environment: Mapping[str, str]) -> "Configuration":
        configuration = cls(
            tag=environment["SOURCE_TAG"],
            commit=environment["SOURCE_COMMIT_SHA"],
            branch=environment["FORK_BRANCH"],
            head_sha=environment["FORK_HEAD_SHA"],
            request_uuid=environment["REQUEST_UUID"],
            bot_user_id=environment["BOT_USER_ID"],
            upstream_repository_id=environment["UPSTREAM_REPOSITORY_ID"],
            fork_repository_id=environment["FORK_REPOSITORY_ID"],
            fork_owner_id=environment["FORK_OWNER_ID"],
            recipe_state=environment["RECIPE_STATE"],
            upstream_recipe_tree=environment["UPSTREAM_RECIPE_TREE"],
            issue=package_request.identity_from_mapping(environment),
        )
        configuration.validate()
        return configuration

    @property
    def version(self) -> str:
        return package_request.version_from_tag(self.tag)

    @property
    def expected_branch(self) -> str:
        return f"package/{package_request.PACKAGE}-{self.version}"

    @property
    def recovery(self) -> bool:
        return re.fullmatch(
            re.escape(self.expected_branch) + r"-r[1-9][0-9]*", self.branch
        ) is not None

    def validate(self) -> None:
        package_request.version_from_tag(self.tag)
        if SHA.fullmatch(self.commit) is None or SHA.fullmatch(self.head_sha) is None:
            raise PullCreationError("source or fork commit is malformed")
        if self.branch != self.expected_branch and not self.recovery:
            raise PullCreationError("fork branch does not match the source version")
        for identity in (
            self.bot_user_id,
            self.upstream_repository_id,
            self.fork_repository_id,
            self.fork_owner_id,
        ):
            if DECIMAL.fullmatch(identity) is None:
                raise PullCreationError("repository or machine identity is malformed")
        try:
            request_id = UUID(self.request_uuid)
        except ValueError as error:
            raise PullCreationError("release request UUID is malformed") from error
        if str(request_id) != self.request_uuid:
            raise PullCreationError("release request UUID is not canonical")
        if self.recipe_state not in {"new", "existing"}:
            raise PullCreationError("verified upstream recipe state is malformed")
        if (
            self.recipe_state == "new"
            and self.upstream_recipe_tree != "absent"
        ) or (
            self.recipe_state == "existing"
            and SHA.fullmatch(self.upstream_recipe_tree) is None
        ):
            raise PullCreationError("verified upstream recipe tree is malformed")
        self.issue.validate()


def _permissions_are_read_only(value: object) -> bool:
    return value == {
        "admin": False,
        "maintain": False,
        "push": False,
        "triage": False,
        "pull": True,
    }


def _verify_repositories(fork: object, upstream: object, config: Configuration) -> None:
    package_request.verify_repository(upstream, repository_id=config.upstream_repository_id)
    package_request.verify_fork(
        fork,
        repository_id=config.fork_repository_id,
        owner_id=config.fork_owner_id,
        upstream_repository_id=config.upstream_repository_id,
    )
    if (
        not isinstance(fork, Mapping)
        or not _permissions_are_read_only(fork.get("permissions"))
        or not isinstance(upstream, Mapping)
        or not _permissions_are_read_only(upstream.get("permissions"))
    ):
        raise PullCreationError("repository identity or machine authority changed")


def _exact_pulls(value: object, *, branch: str) -> list[Mapping[str, object]]:
    if not isinstance(value, list):
        raise PullCreationError("pull request search response is malformed")
    return [
        pull
        for pull in value
        if isinstance(pull, Mapping)
        and isinstance(pull.get("head"), Mapping)
        and pull["head"].get("label") == f"yurirocha15:{branch}"
        and isinstance(pull.get("base"), Mapping)
        and pull["base"].get("ref") == BASE_BRANCH
        and isinstance(pull["base"].get("repo"), Mapping)
        and pull["base"]["repo"].get("full_name") == package_request.UPSTREAM
    ]


def _pull_query(branch: str) -> str:
    return urllib.parse.urlencode(
        (
            ("state", "all"),
            ("head", f"yurirocha15:{branch}"),
            ("base", BASE_BRANCH),
            ("per_page", "100"),
            ("page", "1"),
        )
    )


def _find_pulls(client: Client, branch: str, operation: str) -> list[Mapping[str, object]]:
    result = client.request(
        operation,
        "GET",
        f"/repos/{package_request.UPSTREAM}/pulls?{_pull_query(branch)}",
        {200},
    )
    if 'rel="next"' in result.header("link"):
        raise PullCreationError(f"{operation}: pagination is ambiguous")
    exact = _exact_pulls(result.value, branch=branch)
    if len(exact) > 1:
        raise PullCreationError(f"{operation}: pull request identity is ambiguous")
    return exact


def _expected_pull(config: Configuration) -> tuple[str, str]:
    return (
        package_request.pull_title(config.version, config.recipe_state),
        package_request.pull_body(
            version=config.version,
            issue=config.issue.number,
            commit=config.commit,
            request_uuid=config.request_uuid,
        ),
    )


def _verify_pull_identity(
    value: object,
    *,
    config: Configuration,
    title: str,
    body: str,
    expected_base_sha: str | None,
) -> str:
    if not isinstance(value, Mapping):
        raise PullCreationError("pull request response is malformed")
    number = value.get("number")
    pull_id = value.get("id")
    node_id = value.get("node_id")
    user = value.get("user")
    head = value.get("head")
    base = value.get("base")
    head_repository = head.get("repo") if isinstance(head, Mapping) else None
    base_repository = base.get("repo") if isinstance(base, Mapping) else None
    base_sha = base.get("sha") if isinstance(base, Mapping) else None
    if (
        not isinstance(number, int)
        or number <= 0
        or not isinstance(pull_id, int)
        or pull_id <= 0
        or not isinstance(node_id, str)
        or package_request.NODE.fullmatch(node_id) is None
        or value.get("url")
        != f"https://api.github.com/repos/{package_request.UPSTREAM}/pulls/{number}"
        or value.get("html_url")
        != f"https://github.com/{package_request.UPSTREAM}/pull/{number}"
        or value.get("draft") is not False
        or value.get("title") != title
        or value.get("body") != body
        or value.get("maintainer_can_modify") is not False
        or not isinstance(user, Mapping)
        or user.get("login") != BOT_LOGIN
        or str(user.get("id")) != config.bot_user_id
        or user.get("type") != "User"
        or not isinstance(head, Mapping)
        or head.get("label") != f"yurirocha15:{config.branch}"
        or head.get("ref") != config.branch
        or head.get("sha") != config.head_sha
        or not isinstance(head_repository, Mapping)
        or head_repository.get("id") != int(config.fork_repository_id)
        or head_repository.get("full_name") != package_request.FORK
        or not isinstance(base, Mapping)
        or base.get("ref") != BASE_BRANCH
        or not isinstance(base_sha, str)
        or SHA.fullmatch(base_sha) is None
        or (expected_base_sha is not None and base_sha != expected_base_sha)
        or not isinstance(base_repository, Mapping)
        or base_repository.get("id") != int(config.upstream_repository_id)
        or base_repository.get("full_name") != package_request.UPSTREAM
    ):
        raise PullCreationError("pull request identity does not match")
    return str(value["html_url"])


def _verify_existing(pull: Mapping[str, object], config: Configuration) -> str:
    title, body = _expected_pull(config)
    url = _verify_pull_identity(
        pull,
        config=config,
        title=title,
        body=body,
        expected_base_sha=None,
    )
    if pull.get("state") == "open" and pull.get("merged_at") is None:
        return url
    merged_at = pull.get("merged_at")
    if pull.get("state") == "closed" and isinstance(merged_at, str) and merged_at:
        return url
    raise PullCreationError("matching pull request is closed and unmerged")


def _verify_created_pull(
    value: object,
    *,
    config: Configuration,
    title: str,
    body: str,
    upstream_head_sha: str,
) -> str:
    url = _verify_pull_identity(
        value,
        config=config,
        title=title,
        body=body,
        expected_base_sha=upstream_head_sha,
    )
    if (
        not isinstance(value, Mapping)
        or value.get("state") != "open"
        or value.get("merged_at") is not None
    ):
        raise PullCreationError("created pull request is not open and unmerged")
    return url


def _tree(value: object, *, expected_sha: str, operation: str) -> list[Mapping[str, object]]:
    if not isinstance(value, Mapping):
        raise PullCreationError(f"{operation}: Git tree response is malformed")
    entries = value.get("tree")
    if (
        value.get("sha") != expected_sha
        or value.get("truncated") is not False
        or not isinstance(entries, list)
        or any(not isinstance(entry, Mapping) for entry in entries)
    ):
        raise PullCreationError(f"{operation}: Git tree identity is incomplete")
    return entries


def _one_tree_entry(
    entries: list[Mapping[str, object]], *, path: str, required: bool
) -> str | None:
    matches = [entry for entry in entries if entry.get("path") == path]
    if not matches and not required:
        return None
    if len(matches) != 1:
        raise PullCreationError(f"upstream Git tree has ambiguous path: {path}")
    entry = matches[0]
    sha = entry.get("sha")
    if (
        entry.get("type") != "tree"
        or entry.get("mode") != "040000"
        or not isinstance(sha, str)
        or SHA.fullmatch(sha) is None
    ):
        raise PullCreationError(f"upstream Git tree path is malformed: {path}")
    return sha


def _upstream_recipe_tree(client: Client) -> tuple[str, str]:
    reference = client.request(
        "get-upstream-master",
        "GET",
        f"/repos/{package_request.UPSTREAM}/git/ref/heads/{BASE_BRANCH}",
        {200},
    ).value
    reference_object = reference.get("object") if isinstance(reference, Mapping) else None
    if (
        not isinstance(reference, Mapping)
        or reference.get("ref") != f"refs/heads/{BASE_BRANCH}"
        or not isinstance(reference_object, Mapping)
        or reference_object.get("type") != "commit"
        or SHA.fullmatch(str(reference_object.get("sha", ""))) is None
    ):
        raise PullCreationError("upstream master reference is malformed")
    commit_sha = str(reference_object["sha"])
    commit = client.request(
        "get-upstream-commit",
        "GET",
        f"/repos/{package_request.UPSTREAM}/git/commits/{commit_sha}",
        {200},
    ).value
    commit_tree = commit.get("tree") if isinstance(commit, Mapping) else None
    if (
        not isinstance(commit, Mapping)
        or commit.get("sha") != commit_sha
        or not isinstance(commit_tree, Mapping)
        or SHA.fullmatch(str(commit_tree.get("sha", ""))) is None
    ):
        raise PullCreationError("upstream master commit is malformed")
    root_sha = str(commit_tree["sha"])
    root_value = client.request(
        "get-upstream-root-tree",
        "GET",
        f"/repos/{package_request.UPSTREAM}/git/trees/{root_sha}",
        {200},
    ).value
    recipes_sha = _one_tree_entry(
        _tree(root_value, expected_sha=root_sha, operation="get-upstream-root-tree"),
        path="recipes",
        required=True,
    )
    if recipes_sha is None:
        raise PullCreationError("upstream recipes tree is missing")
    recipes_value = client.request(
        "get-upstream-recipes-tree",
        "GET",
        f"/repos/{package_request.UPSTREAM}/git/trees/{recipes_sha}",
        {200},
    ).value
    package_sha = _one_tree_entry(
        _tree(
            recipes_value,
            expected_sha=recipes_sha,
            operation="get-upstream-recipes-tree",
        ),
        path=package_request.PACKAGE,
        required=False,
    )
    return commit_sha, "absent" if package_sha is None else package_sha


def create(client: Client, config: Configuration) -> str:
    user_result = client.request("get-user", "GET", "/user", {200})
    user = user_result.value
    if (
        not isinstance(user, Mapping)
        or user.get("login") != BOT_LOGIN
        or str(user.get("id")) != config.bot_user_id
        or user.get("type") != "User"
    ):
        raise PullCreationError("machine identity changed")
    scopes = {
        scope.strip()
        for scope in user_result.header("x-oauth-scopes").split(",")
        if scope.strip()
    }
    if scopes != {"public_repo"}:
        raise PullCreationError("PAT scope is not exactly public_repo")

    fork = client.request(
        "get-fork", "GET", f"/repos/{package_request.FORK}", {200}
    ).value
    upstream = client.request(
        "get-upstream", "GET", f"/repos/{package_request.UPSTREAM}", {200}
    ).value
    try:
        _verify_repositories(fork, upstream, config)
    except package_request.PackageRequestError as error:
        raise PullCreationError(str(error)) from error

    encoded_branch = urllib.parse.quote(config.branch, safe="")
    branch = client.request(
        "get-branch",
        "GET",
        f"/repos/{package_request.FORK}/branches/{encoded_branch}",
        {200},
    ).value
    if not isinstance(branch, Mapping) or not isinstance(branch.get("commit"), Mapping):
        raise PullCreationError("fork branch response is malformed")
    if branch["commit"].get("sha") != config.head_sha:
        raise PullCreationError("fork branch head changed")

    exact = _find_pulls(client, config.branch, "find-pulls")
    if exact:
        return _verify_existing(exact[0], config)

    if config.recovery:
        predecessor = _find_pulls(client, config.expected_branch, "find-original-pull")
        if len(predecessor) != 1:
            raise PullCreationError("recovery requires one predecessor pull request")
        prior = predecessor[0]
        if prior.get("state") != "closed" or prior.get("merged_at") is not None:
            raise PullCreationError("recovery predecessor is not closed and unmerged")

    title, body = _expected_pull(config)
    issue = client.request(
        "recheck-package-request",
        "GET",
        f"/repos/{package_request.UPSTREAM}/issues/{config.issue.number}",
        {200},
    ).value
    try:
        package_request.verify_issue(issue, version=config.version, identity=config.issue)
    except package_request.PackageRequestError as error:
        raise PullCreationError(str(error)) from error

    upstream_head_sha, upstream_recipe_tree = _upstream_recipe_tree(client)
    if upstream_recipe_tree != config.upstream_recipe_tree:
        raise PullCreationError("upstream recipe tree changed after public verification")

    created = client.request(
        "create-pull",
        "POST",
        f"/repos/{package_request.UPSTREAM}/pulls",
        {201},
        {
            "title": title,
            "head": f"yurirocha15:{config.branch}",
            "base": BASE_BRANCH,
            "body": body,
            "maintainer_can_modify": False,
        },
    ).value
    return _verify_created_pull(
        created,
        config=config,
        title=title,
        body=body,
        upstream_head_sha=upstream_head_sha,
    )


def main() -> int:
    try:
        token = os.environ.pop("CONAN_CENTER_PR_BOT_PAT")
        for name in tuple(os.environ):
            if name.lower() in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}:
                os.environ.pop(name, None)
        url = create(Client(token), Configuration.from_environment(os.environ))
        print(f"ConanCenter pull request: {url}")
    except (KeyError, package_request.PackageRequestError, PullCreationError) as error:
        print(f"create-pull: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
