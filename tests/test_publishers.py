from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from publisher.approval import recipe_identity
from publisher.client_handoff import PAYLOADS, create as create_client_handoff, verify as verify_client_handoff
from publisher.create_pull import ApiResult, Configuration, create
from publisher.package_request import (
    IssueIdentity,
    pull_body,
    pull_title,
    verify_issue,
    verify_fork,
    verify_repository,
)
from publisher.scan_repository_secrets import find_sensitive_paths
from publisher.source_run import poll, verify_release, verify_repository as verify_source_repository
from publisher.validate_dispatch import validate
from publisher.verify_recipe_tree import verify as verify_recipe, verify_handoff
from publisher.verify_release_bundle import sha256, verify as verify_bundle


ISSUE_BODY = """### Package Name/Version

mcp-cpp-sdk/0.2.0

### Webpage

https://github.com/yurirocha15/mcp-cpp-sdk

### Source code

https://github.com/yurirocha15/mcp-cpp-sdk

### Description of the library/tool

A C++ SDK for the Model Context Protocol.
"""


def issue_identity() -> IssueIdentity:
    return IssueIdentity(
        number="42",
        issue_id="101",
        node_id="I_kwDOExample",
        created_at="2026-07-19T01:02:03Z",
        body_sha256=hashlib.sha256(ISSUE_BODY.encode()).hexdigest(),
        author_id="202",
        author_node_id="U_kwDOExample",
        author_login="release-owner",
        author_type="User",
        label_id="303",
        label_node_id="LA_kwDOExample",
        label_name="library request",
    )


def issue_response() -> dict[str, object]:
    return {
        "id": 101,
        "node_id": "I_kwDOExample",
        "number": 42,
        "repository_url": "https://api.github.com/repos/conan-io/conan-center-index",
        "html_url": "https://github.com/conan-io/conan-center-index/issues/42",
        "state": "open",
        "state_reason": None,
        "title": "[request] mcp-cpp-sdk/0.2.0",
        "created_at": "2026-07-19T01:02:03Z",
        "body": ISSUE_BODY,
        "user": {
            "id": 202,
            "node_id": "U_kwDOExample",
            "login": "release-owner",
            "type": "User",
        },
        "labels": [
            {
                "id": 303,
                "node_id": "LA_kwDOExample",
                "name": "library request",
            }
        ],
    }


class DispatchTests(unittest.TestCase):
    def test_stable_request(self) -> None:
        request = {
            "source_tag": "v0.2.0",
            "source_commit_sha": "0" * 40,
            "source_workflow_head_sha": "4" * 40,
            "provider_control_sha": "5" * 40,
            "github_release_id": "1",
            "source_workflow_run_id": "2",
            "release_manifest_sha256": "1" * 64,
            "fork_branch": "package/mcp-cpp-sdk-0.2.0",
            "fork_head_sha": "2" * 40,
            "recipe_tree_sha256": "3" * 64,
            "request_uuid": "00000000-0000-0000-0000-000000000001",
        }
        self.assertEqual(validate(request), request)

    def test_rejects_rc(self) -> None:
        with self.assertRaises(ValueError):
            validate({"source_tag": "v0.2.0-rc.1"})


class SecretScanTests(unittest.TestCase):
    def test_tracked_control_repository_contains_no_secret_shapes(self) -> None:
        root = Path(__file__).resolve().parents[1]
        self.assertEqual(find_sensitive_paths(root), [])


class SourceRunTests(unittest.TestCase):
    def test_binds_source_repository_and_immutable_release(self) -> None:
        verify_source_repository(
            {
                "id": 88,
                "full_name": "yurirocha15/mcp-cpp-sdk",
                "private": False,
                "archived": False,
                "disabled": False,
                "default_branch": "main",
                "owner": {"id": 99, "login": "yurirocha15", "type": "User"},
            },
            repository_id="88",
            owner_id="99",
        )
        release = {
            "id": 77,
            "tag_name": "v0.2.0",
            "draft": False,
            "prerelease": False,
            "immutable": True,
        }
        verify_release(release, tag="v0.2.0", release_id="77")
        with self.assertRaises(ValueError):
            verify_release({**release, "draft": True}, tag="v0.2.0", release_id="77")

    def test_waits_for_source_release_for_one_hour(self) -> None:
        clock = [0.0]
        responses = iter(
            [
                {"status": "queued"},
                {"status": "waiting"},
                {
                    "id": 77,
                    "event": "workflow_dispatch",
                    "status": "completed",
                    "conclusion": "success",
                    "head_sha": "a" * 40,
                    "head_branch": "main",
                    "path": ".github/workflows/release.yml",
                    "repository": {"id": 88},
                },
            ]
        )

        result = poll(
            lambda: next(responses),
            run_id="77",
            workflow_head_sha="a" * 40,
            repository_id="88",
            timeout_seconds=3600,
            interval_seconds=20,
            monotonic=lambda: clock[0],
            sleep=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
        )
        self.assertEqual(result["conclusion"], "success")
        self.assertEqual(clock[0], 40)


class PackageRequestTests(unittest.TestCase):
    def test_binds_exact_upstream_and_authorization_issue(self) -> None:
        verify_repository(
            {
                "id": 909,
                "full_name": "conan-io/conan-center-index",
                "name": "conan-center-index",
                "fork": False,
                "archived": False,
                "disabled": False,
                "default_branch": "master",
                "owner": {"login": "conan-io", "type": "Organization"},
            },
            repository_id="909",
        )
        verify_issue(issue_response(), version="0.2.0", identity=issue_identity())

        for field, value in (
            ("title", "[request] another/0.2.0"),
            ("state", "closed"),
            ("body", ISSUE_BODY.replace("mcp-cpp-sdk/0.2.0", "mcp-cpp-sdk/0.3.0")),
        ):
            changed = issue_response()
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify_issue(changed, version="0.2.0", identity=issue_identity())

        changed = issue_response()
        changed_body = ISSUE_BODY.replace(
            "https://github.com/yurirocha15/mcp-cpp-sdk\n\n### Source code",
            "https://github.com/yurirocha15/mcp-cpp-sdk/\n\n### Source code",
        )
        changed["body"] = changed_body
        changed_identity = replace(
            issue_identity(),
            body_sha256=hashlib.sha256(changed_body.encode()).hexdigest(),
        )
        with self.assertRaisesRegex(ValueError, "project URLs are not exact"):
            verify_issue(changed, version="0.2.0", identity=changed_identity)

    def test_binds_exact_fork_owner_parent_and_state(self) -> None:
        fork = {
            "id": 808,
            "full_name": "yurirocha15/conan-center-index",
            "name": "conan-center-index",
            "fork": True,
            "archived": False,
            "disabled": False,
            "default_branch": "master",
            "owner": {"id": 707, "login": "yurirocha15", "type": "User"},
            "parent": {
                "id": 909,
                "full_name": "conan-io/conan-center-index",
            },
        }
        verify_fork(
            fork,
            repository_id="808",
            owner_id="707",
            upstream_repository_id="909",
        )
        mutations = (
            ("default_branch", "main"),
            ("archived", True),
            ("disabled", True),
            ("owner", {"id": 706, "login": "yurirocha15", "type": "User"}),
            (
                "parent",
                {"id": 908, "full_name": "conan-io/conan-center-index"},
            ),
        )
        for field, value in mutations:
            changed = dict(fork)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify_fork(
                    changed,
                    repository_id="808",
                    owner_id="707",
                    upstream_repository_id="909",
                )

    def test_current_conan_center_title_and_body_rules(self) -> None:
        self.assertEqual(pull_title("0.2.0", "new"), "mcp-cpp-sdk/0.2.0: new recipe")
        self.assertEqual(pull_title("0.3.0", "existing"), "mcp-cpp-sdk: add version 0.3.0")
        body = pull_body(
            version="0.2.0",
            issue="42",
            commit="a" * 40,
            request_uuid="00000000-0000-0000-0000-000000000001",
        )
        self.assertIn("### Summary", body)
        self.assertIn("#### Motivation", body)
        self.assertIn("#### Details", body)
        self.assertIn("fixes #42", body)
        self.assertEqual(body.count("- [x]"), 3)
        self.assertEqual(body.count("- [ ]"), 1)


class ApprovalTests(unittest.TestCase):
    def test_rejects_a_branch_stale_for_the_recipe_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            subprocess.run(["git", "init", "-q", str(repository)], check=True)
            subprocess.run(
                ["git", "-C", str(repository), "config", "user.name", "test"],
                check=True,
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repository),
                    "config",
                    "user.email",
                    "test@example.invalid",
                ],
                check=True,
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repository),
                    "config",
                    "commit.gpgsign",
                    "false",
                ],
                check=True,
            )
            recipe = repository / "recipes/mcp-cpp-sdk"
            recipe.mkdir(parents=True)
            (recipe / "config.yml").write_text("versions: {}\n")
            subprocess.run(["git", "-C", str(repository), "add", "."], check=True)
            subprocess.run(
                ["git", "-C", str(repository), "commit", "-qm", "base"],
                check=True,
            )
            fork_head = subprocess.run(
                ["git", "-C", str(repository), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            subprocess.run(
                ["git", "-C", str(repository), "branch", "upstream-master"],
                check=True,
            )

            state, tree = recipe_identity(
                repository,
                fork_head=fork_head,
                ref="refs/heads/upstream-master",
            )
            self.assertEqual(state, "existing")
            self.assertRegex(tree, r"[0-9a-f]{40}")

            subprocess.run(
                ["git", "-C", str(repository), "checkout", "-q", "upstream-master"],
                check=True,
            )
            (recipe / "config.yml").write_text("versions:\n  0.2.0: all\n")
            subprocess.run(["git", "-C", str(repository), "add", "."], check=True)
            subprocess.run(
                ["git", "-C", str(repository), "commit", "-qm", "upstream change"],
                check=True,
            )
            with self.assertRaisesRegex(ValueError, "changed after.*diverged"):
                recipe_identity(
                    repository,
                    fork_head=fork_head,
                    ref="refs/heads/upstream-master",
                )


class ClientHandoffTests(unittest.TestCase):
    def _write_valid_handoff(self, root: Path) -> None:
        for name in PAYLOADS:
            path = root / name
            path.write_text(f"# {name}\n")
            path.chmod(0o644)
        manifest = "".join(
            f"{hashlib.sha256((root / name).read_bytes()).hexdigest()}  {name}\n"
            for name in PAYLOADS
        )
        (root / "SHA256SUMS").write_text(manifest, encoding="ascii")
        (root / "SHA256SUMS").chmod(0o644)

    def test_rejects_import_injection_and_unsafe_entries(self) -> None:
        for injection in (
            "extension",
            "subdirectory",
            "payload_directory",
            "payload_symlink",
            "executable_mode",
            "oversized_payload",
        ):
            with (
                self.subTest(injection=injection),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                self._write_valid_handoff(root)
                verify_client_handoff(root)
                if injection == "extension":
                    (root / "package_request.so").write_bytes(b"injected")
                elif injection == "subdirectory":
                    (root / "__pycache__").mkdir()
                elif injection == "payload_directory":
                    (root / "package_request.py").unlink()
                    (root / "package_request.py").mkdir()
                elif injection == "payload_symlink":
                    (root / "package_request.py").unlink()
                    os.symlink(root / "create_pull.py", root / "package_request.py")
                elif injection == "executable_mode":
                    (root / "package_request.py").chmod(0o755)
                else:
                    (root / "package_request.py").write_bytes(b"x" * (256 * 1024 + 1))
                with self.assertRaises(ValueError):
                    verify_client_handoff(root)

    def test_create_emits_verified_attempt_bound_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            for name in PAYLOADS:
                (source / name).write_text(f"# {name}\n", encoding="utf-8")
            output = root / "publisher-client"
            github_output = root / "github-output"
            create_client_handoff(source, output, github_output, "3")
            verify_client_handoff(output)
            values = dict(
                line.split("=", 1)
                for line in github_output.read_text(encoding="utf-8").splitlines()
            )
            self.assertEqual(values["publisher_attempt"], "3")
            self.assertEqual(len(values["publisher_checksum"]), 64)
            self.assertEqual(len(values["publisher_verifier_checksum"]), 64)


class FakeClient:
    def __init__(self, results: dict[str, ApiResult]) -> None:
        self.results = results
        self.calls: list[tuple[str, str, str, object]] = []

    def request(
        self,
        operation: str,
        method: str,
        path: str,
        expected: set[int],
        body: object = None,
    ) -> ApiResult:
        self.calls.append((operation, method, path, body))
        return self.results[operation]


class PullCreationTests(unittest.TestCase):
    def test_rechecks_issue_and_upstream_snapshot_before_creation(self) -> None:
        identity = issue_identity()
        config = Configuration(
            tag="v0.2.0",
            commit="a" * 40,
            branch="package/mcp-cpp-sdk-0.2.0",
            head_sha="b" * 40,
            request_uuid="00000000-0000-0000-0000-000000000001",
            bot_user_id="404",
            upstream_repository_id="909",
            fork_repository_id="808",
            fork_owner_id="707",
            recipe_state="new",
            upstream_recipe_tree="absent",
            issue=identity,
        )
        expected_body = pull_body(
            version="0.2.0",
            issue="42",
            commit="a" * 40,
            request_uuid=config.request_uuid,
        )
        client = FakeClient(
            {
                "get-user": ApiResult(
                    {"login": "mcp-cpp-sdk-release-bot", "id": 404, "type": "User"},
                    200,
                    {"x-oauth-scopes": "public_repo"},
                ),
                "get-fork": ApiResult(
                    {
                        "id": 808,
                        "full_name": "yurirocha15/conan-center-index",
                        "name": "conan-center-index",
                        "fork": True,
                        "archived": False,
                        "disabled": False,
                        "default_branch": "master",
                        "owner": {
                            "id": 707,
                            "login": "yurirocha15",
                            "type": "User",
                        },
                        "parent": {
                            "id": 909,
                            "full_name": "conan-io/conan-center-index",
                        },
                        "permissions": {
                            "admin": False,
                            "maintain": False,
                            "push": False,
                            "triage": False,
                            "pull": True,
                        },
                    },
                    200,
                    {},
                ),
                "get-upstream": ApiResult(
                    {
                        "id": 909,
                        "full_name": "conan-io/conan-center-index",
                        "name": "conan-center-index",
                        "fork": False,
                        "archived": False,
                        "disabled": False,
                        "default_branch": "master",
                        "owner": {"login": "conan-io", "type": "Organization"},
                        "permissions": {
                            "admin": False,
                            "maintain": False,
                            "push": False,
                            "triage": False,
                            "pull": True,
                        },
                    },
                    200,
                    {},
                ),
                "get-branch": ApiResult({"commit": {"sha": "b" * 40}}, 200, {}),
                "find-pulls": ApiResult([], 200, {}),
                "get-upstream-master": ApiResult(
                    {
                        "ref": "refs/heads/master",
                        "object": {"type": "commit", "sha": "c" * 40},
                    },
                    200,
                    {},
                ),
                "get-upstream-commit": ApiResult(
                    {"sha": "c" * 40, "tree": {"sha": "d" * 40}}, 200, {}
                ),
                "get-upstream-root-tree": ApiResult(
                    {
                        "sha": "d" * 40,
                        "truncated": False,
                        "tree": [
                            {
                                "path": "recipes",
                                "type": "tree",
                                "mode": "040000",
                                "sha": "e" * 40,
                            }
                        ],
                    },
                    200,
                    {},
                ),
                "get-upstream-recipes-tree": ApiResult(
                    {"sha": "e" * 40, "truncated": False, "tree": []},
                    200,
                    {},
                ),
                "recheck-package-request": ApiResult(issue_response(), 200, {}),
                "create-pull": ApiResult(
                    {
                        "id": 606,
                        "node_id": "PR_kwDOExample",
                        "number": 1,
                        "url": "https://api.github.com/repos/conan-io/conan-center-index/pulls/1",
                        "html_url": "https://github.com/conan-io/conan-center-index/pull/1",
                        "draft": False,
                        "maintainer_can_modify": False,
                        "user": {
                            "login": "mcp-cpp-sdk-release-bot",
                            "id": 404,
                            "type": "User",
                        },
                        "head": {
                            "label": "yurirocha15:package/mcp-cpp-sdk-0.2.0",
                            "ref": "package/mcp-cpp-sdk-0.2.0",
                            "sha": "b" * 40,
                            "repo": {
                                "id": 808,
                                "full_name": "yurirocha15/conan-center-index",
                            },
                        },
                        "base": {
                            "ref": "master",
                            "sha": "c" * 40,
                            "repo": {
                                "id": 909,
                                "full_name": "conan-io/conan-center-index",
                            },
                        },
                        "title": "mcp-cpp-sdk/0.2.0: new recipe",
                        "body": expected_body,
                        "state": "open",
                    },
                    201,
                    {},
                ),
            }
        )

        self.assertEqual(
            create(client, config),
            "https://github.com/conan-io/conan-center-index/pull/1",
        )
        self.assertEqual(
            [call[0] for call in client.calls[-6:]],
            [
                "recheck-package-request",
                "get-upstream-master",
                "get-upstream-commit",
                "get-upstream-root-tree",
                "get-upstream-recipes-tree",
                "create-pull",
            ],
        )
        payload = client.calls[-1][3]
        self.assertEqual(payload["title"], "mcp-cpp-sdk/0.2.0: new recipe")
        self.assertEqual(payload["body"], expected_body)

        fork = client.results["get-fork"].value
        self.assertIsInstance(fork, dict)
        fork["permissions"]["push"] = True
        with self.assertRaisesRegex(ValueError, "machine authority changed"):
            create(client, config)
        fork["permissions"]["push"] = False

        created = client.results["create-pull"].value
        self.assertIsInstance(created, dict)
        original = deepcopy(created)
        client.results["find-pulls"] = ApiResult([deepcopy(original)], 200, {})
        self.assertEqual(
            create(client, config),
            "https://github.com/conan-io/conan-center-index/pull/1",
        )
        for mutation in ("draft", "head-repo", "base-repo", "url"):
            existing = deepcopy(original)
            if mutation == "draft":
                existing["draft"] = True
            elif mutation == "head-repo":
                existing["head"]["repo"]["id"] = 807
            elif mutation == "base-repo":
                existing["base"]["repo"]["id"] = 908
            else:
                existing["html_url"] = "https://github.com/conan-io/other/pull/1"
            client.results["find-pulls"] = ApiResult([existing], 200, {})
            with self.subTest(mutation=mutation), self.assertRaisesRegex(
                ValueError, "identity does not match"
            ):
                create(client, config)

        client.results["find-pulls"] = ApiResult([], 200, {})
        created = deepcopy(original)
        created["base"]["sha"] = "f" * 40
        client.results["create-pull"] = ApiResult(created, 201, {})
        with self.assertRaisesRegex(ValueError, "identity does not match"):
            create(client, config)


class RecipeTests(unittest.TestCase):
    def test_recipe_binds_source_and_locked_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "recipe"
            (root / "all/test_package").mkdir(parents=True)
            source_url = "https://github.com/yurirocha15/mcp-cpp-sdk/releases/download/v0.2.0/mcp-cpp-sdk-0.2.0.tar.gz"
            digest = "1" * 64
            conanfile_source = (
                'license = "MIT"\n'
                'def requirements(self):\n'
                '    self.requires("boost/1.86.0")\n'
                '    self.requires("nlohmann_json/3.12.0")\n'
                '    self.requires("openssl/3.6.3")\n'
            )
            (root / "all/conanfile.py").write_text(conanfile_source)
            (root / "all/conandata.yml").write_text(f'0.2.0:\n  url: "{source_url}"\n  sha256: "{digest}"\n')
            (root / "all/test_package/conanfile.py").write_text("# test_package\n")
            manifest = Path(directory) / "manifest.json"
            manifest.write_text(json.dumps({
                "conan_requirements": [
                    "boost/1.86.0", "nlohmann_json/3.12.0", "openssl/3.6.3"
                ],
                "payloads": [
                    {
                        "name": "mcp-cpp-sdk-0.2.0.tar.gz",
                        "sha256": digest,
                    }
                ],
            }))
            verify_recipe(
                root,
                version="0.2.0",
                source_url=source_url,
                source_sha256=digest,
                release_manifest=manifest,
            )
            archive = Path(directory) / "recipe.tar"
            archive.write_bytes(b"exact recipe tree archive")
            archive_digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            diff = Path(directory) / "recipe.diff"
            diff.write_text(
                "M\trecipes/mcp-cpp-sdk/all/conanfile.py\n", encoding="utf-8"
            )
            verify_handoff(
                root,
                tag="v0.2.0",
                tree_archive=archive,
                tree_sha256=archive_digest,
                diff=diff,
                release_manifest=manifest,
            )
            diff.write_text("M\tREADME.md\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "outside the package recipe"):
                verify_handoff(
                    root,
                    tag="v0.2.0",
                    tree_archive=archive,
                    tree_sha256=archive_digest,
                    diff=diff,
                    release_manifest=manifest,
                )

            for conanfile, expected_error in (
                (
                    conanfile_source + '    self.requires("zlib/1.3.1")\n',
                    "differ from the signed exact",
                ),
                (
                    conanfile_source.replace(
                        '    self.requires("openssl/3.6.3")\n', ""
                    ),
                    "differ from the signed exact",
                ),
            ):
                (root / "all/conanfile.py").write_text(conanfile)
                with self.subTest(error=expected_error), self.assertRaisesRegex(ValueError, expected_error):
                    verify_recipe(
                        root,
                        version="0.2.0",
                        source_url=source_url,
                        source_sha256=digest,
                        release_manifest=manifest,
                    )


class ReleaseBundleTests(unittest.TestCase):
    def test_rejects_legacy_incomplete_manifest_before_payload_use(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "release-manifest.json"
            manifest.write_text(
                json.dumps({"schema_version": 1, "tag": "v0.2.0", "commit": "0" * 40}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "complete stable channel set"):
                verify_bundle(
                    root,
                    tag="v0.2.0",
                    commit="0" * 40,
                    manifest_digest=sha256(manifest),
                    primary_fingerprint="A" * 40,
                    artifact_fingerprint="B" * 40,
                    public_key=root / "unused.asc",
                )
