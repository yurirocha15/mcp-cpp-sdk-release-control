from __future__ import annotations

import base64
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from urllib.parse import parse_qs, urlsplit

from publisher.assemble_recipe import assemble, tree_sha256
from publisher.push_recipe import (
    PushError,
    Response,
    compare_link,
    git_tree_sha,
    pull_body,
    push,
    recipe_files,
)
from publisher.scan_repository_secrets import find_sensitive_paths
from publisher.validate_dispatch import (
    expected_request_uuid,
    validate,
    validate_execution_context,
)
from publisher.verify_git_status import verify as verify_git_status
from publisher.verify_recipe_tree import verify_assembled
from publisher.verify_source_release import (
    _verify_publication_contract,
    _verify_recipe_entries,
)
from publisher.verify_source_state import verify as verify_source_state


SOURCE_SHA = "0" * 40
WORKFLOW_SHA = "1" * 40
CONTROL_SHA = "2" * 40
MANIFEST_SHA = "3" * 64
BASE_SHA = "4" * 40
SOURCE_DIGEST = "5" * 64
REQUIREMENTS = ["boost/1.86.0", "nlohmann_json/3.12.0", "openssl/3.6.5"]
CONTROL_REPOSITORY = "yurirocha15/mcp-cpp-sdk-release-control"


def dispatch() -> dict[str, str]:
    return {
        "source_tag": "v0.2.0",
        "source_commit_sha": SOURCE_SHA,
        "source_workflow_head_sha": WORKFLOW_SHA,
        "provider_control_sha": CONTROL_SHA,
        "github_release_id": "1",
        "source_workflow_run_id": "2",
        "release_manifest_sha256": MANIFEST_SHA,
        "request_uuid": expected_request_uuid("v0.2.0", MANIFEST_SHA),
    }


def control_context(ref: str = "refs/tags/release-control-v1") -> dict[str, str]:
    return {
        "GITHUB_REPOSITORY": CONTROL_REPOSITORY,
        "GITHUB_REF": ref,
        "GITHUB_SHA": CONTROL_SHA,
        "GITHUB_WORKFLOW_REF": (
            f"{CONTROL_REPOSITORY}/.github/workflows/conan-center-pr.yml@refs/tags/release-control-v1"
        ),
    }


class DispatchTests(unittest.TestCase):
    def test_accepts_exact_source_request_and_control_context(self) -> None:
        request = dispatch()
        self.assertEqual(validate(request), request)
        validate_execution_context(request, control_context())

    def test_request_uuid_matches_the_source_dispatcher(self) -> None:
        # The source release derives this from "<repository>:<tag>:<manifest>:conan2".
        self.assertEqual(
            expected_request_uuid("v0.2.0", "ab" * 32),
            "4dcc40da-ae35-5654-92b2-b6c82b8ea853",
        )

    def test_rejects_every_missing_or_extra_field(self) -> None:
        request = dispatch()
        for field in tuple(request):
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate({name: value for name, value in request.items() if name != field})
        with self.assertRaises(ValueError):
            validate({**request, "fork_branch": "package/mcp-cpp-sdk-0.2.0"})

    def test_rejects_rc_arbitrary_uuid_and_main_execution(self) -> None:
        request = dispatch()
        with self.assertRaisesRegex(ValueError, "stable"):
            validate({**request, "source_tag": "v0.2.0-rc.1"})
        with self.assertRaisesRegex(ValueError, "does not bind"):
            validate({**request, "request_uuid": "00000000-0000-0000-0000-000000000001"})
        with self.assertRaisesRegex(ValueError, "GITHUB_REF"):
            validate_execution_context(request, control_context("refs/heads/main"))


class SourceStateTests(unittest.TestCase):
    def api(self, workflow_sha: str = WORKFLOW_SHA):
        responses = {
            "repos/yurirocha15/mcp-cpp-sdk": {
                "id": 10,
                "full_name": "yurirocha15/mcp-cpp-sdk",
                "default_branch": "main",
                "archived": False,
                "disabled": False,
                "owner": {"id": 20},
            },
            "repos/yurirocha15/mcp-cpp-sdk/releases/tags/v0.2.0": {
                "id": 30,
                "tag_name": "v0.2.0",
                "draft": False,
                "prerelease": False,
                "immutable": True,
            },
            "repos/yurirocha15/mcp-cpp-sdk/actions/runs/40": {
                "id": 40,
                "status": "completed",
                "conclusion": "success",
                "event": "workflow_dispatch",
                "head_branch": "main",
                "head_sha": workflow_sha,
                "path": ".github/workflows/release.yml",
                "repository": {"id": 10, "full_name": "yurirocha15/mcp-cpp-sdk"},
            },
        }
        return responses.__getitem__

    def verify(self, api) -> None:
        verify_source_state(
            api,
            source_repository_id=10,
            source_owner_id=20,
            source_tag="v0.2.0",
            source_workflow_head_sha=WORKFLOW_SHA,
            github_release_id=30,
            source_workflow_run_id=40,
            sleeper=lambda _: None,
        )

    def test_accepts_the_exact_completed_source_run(self) -> None:
        self.verify(self.api())

    def test_rejects_wrong_workflow_head(self) -> None:
        with self.assertRaisesRegex(ValueError, "workflow run"):
            self.verify(self.api(SOURCE_SHA))


def contract(control_sha: str = CONTROL_SHA, requirements=REQUIREMENTS) -> dict[str, object]:
    return {
        "schema_version": 1,
        "native_targets": [],
        "native_builders": [],
        "channel_targets": {"aur": {}, "homebrew": {}, "chocolatey": {}},
        "destinations": {
            "cloudsmith": {},
            "homebrew": {},
            "chocolatey": {},
            "conan_control": {"repository": CONTROL_REPOSITORY, "repository_id": "60"},
        },
        "conan_requirements": list(requirements),
        "provider_controls": {
            "homebrew": {},
            "chocolatey": {},
            "conan": {
                "repository": CONTROL_REPOSITORY,
                "control_tag": "release-control-v1",
                "control_commit": control_sha,
                "workflow": "conan-center-pr.yml",
            },
        },
    }


SOURCE_URL = (
    "https://github.com/yurirocha15/mcp-cpp-sdk/releases/download/v0.2.0/mcp-cpp-sdk-0.2.0.tar.gz"
)


class SignedPolicyTests(unittest.TestCase):
    def test_contract_binds_destination_control_and_requirements(self) -> None:
        _verify_publication_contract(
            contract(),
            provider_control_sha=CONTROL_SHA,
            publisher_repository_id="60",
            conan_requirements=REQUIREMENTS,
        )
        for candidate, publisher_id, message in (
            (contract(SOURCE_SHA), "60", "control"),
            (contract(), "61", "destination"),
            (contract(requirements=REQUIREMENTS[:2]), "60", "requirements"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                _verify_publication_contract(
                    candidate,
                    provider_control_sha=CONTROL_SHA,
                    publisher_repository_id=publisher_id,
                    conan_requirements=REQUIREMENTS,
                )

    def test_recipe_entries_bind_the_signed_source_archive(self) -> None:
        config = {"schema_version": 1, "version": "0.2.0", "folder": "all"}
        source = {"schema_version": 1, "version": "0.2.0", "url": SOURCE_URL, "sha256": SOURCE_DIGEST}
        arguments = {
            "version": "0.2.0",
            "tag": "v0.2.0",
            "source_name": "mcp-cpp-sdk-0.2.0.tar.gz",
            "source_sha256": SOURCE_DIGEST,
        }
        _verify_recipe_entries(config, source, **arguments)
        with self.assertRaisesRegex(ValueError, "source archive"):
            _verify_recipe_entries(config, {**source, "sha256": "6" * 64}, **arguments)
        with self.assertRaisesRegex(ValueError, "config entry"):
            _verify_recipe_entries({**config, "folder": "other"}, source, **arguments)

    def test_git_status_requires_exact_subkey_and_primary(self) -> None:
        tag = "A" * 40
        primary = "B" * 40
        verify_git_status(f"[GNUPG:] VALIDSIG {tag} 1 2 3 4 5 6 7 8 {primary}", tag, primary)
        with self.assertRaises(ValueError):
            verify_git_status("[GNUPG:] BADSIG dead", tag, primary)


CONANFILE = (
    "class McpCppSdkConan(ConanFile):\n"
    '    license = "Apache-2.0"\n'
    "    def requirements(self):\n"
    + "".join(f'        self.requires("{reference}")\n' for reference in REQUIREMENTS)
)


def write_inputs(directory: Path, version: str = "0.2.0", digest: str = SOURCE_DIGEST) -> Path:
    inputs = directory / f"inputs-{version}"
    inputs.mkdir()
    url = SOURCE_URL.replace("0.2.0", version)
    (inputs / "conan-recipe-config-entry.json").write_text(
        json.dumps({"folder": "all", "schema_version": 1, "version": version})
    )
    (inputs / "conan-recipe-conandata-entry.json").write_text(
        json.dumps({"schema_version": 1, "sha256": digest, "url": url, "version": version})
    )
    (inputs / "conan-recipe-conanfile.py").write_text(CONANFILE)
    (inputs / "conan-recipe-test-CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.20)\n")
    (inputs / "conan-recipe-test-conanfile.py").write_text("# test_package\n")
    (inputs / "conan-recipe-test-test_package.cpp").write_text("int main() {}\n")
    return inputs


def write_manifest(directory: Path, digest: str = SOURCE_DIGEST) -> Path:
    manifest = directory / "release-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "conan_requirements": REQUIREMENTS,
                "payloads": [{"name": "mcp-cpp-sdk-0.2.0.tar.gz", "sha256": digest}],
            }
        )
    )
    return manifest


class AssembleRecipeTests(unittest.TestCase):
    def test_first_submission_is_the_validated_production_tree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = assemble(
                inputs=write_inputs(root), version="0.2.0", upstream=None, output=root / "recipe"
            )
            self.assertEqual(state, "new")
            self.assertEqual(
                (root / "recipe/config.yml").read_text(), 'versions:\n  "0.2.0":\n    folder: all\n'
            )
            self.assertEqual(
                (root / "recipe/all/conandata.yml").read_text(),
                f'sources:\n  "0.2.0":\n    url: "{SOURCE_URL}"\n    sha256: "{SOURCE_DIGEST}"\n',
            )
            self.assertEqual(
                sorted(recipe_files(root / "recipe")),
                [
                    "all/conandata.yml",
                    "all/conanfile.py",
                    "all/test_package/CMakeLists.txt",
                    "all/test_package/conanfile.py",
                    "all/test_package/test_package.cpp",
                    "config.yml",
                ],
            )
            verify_assembled(root / "recipe", tag="v0.2.0", release_manifest=write_manifest(root))

    def test_later_version_is_prepended_to_the_managed_upstream_recipe(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assemble(inputs=write_inputs(root), version="0.2.0", upstream=None, output=root / "old")
            state = assemble(
                inputs=write_inputs(root, "0.3.0", "7" * 64),
                version="0.3.0",
                upstream=root / "old",
                output=root / "new",
            )
            self.assertEqual(state, "existing")
            config = (root / "new/config.yml").read_text()
            self.assertEqual(
                config,
                'versions:\n  "0.3.0":\n    folder: all\n  "0.2.0":\n    folder: all\n',
            )
            conandata = (root / "new/all/conandata.yml").read_text()
            self.assertLess(conandata.index('"0.3.0"'), conandata.index('"0.2.0"'))
            self.assertIn(SOURCE_DIGEST, conandata)

    def test_unmanaged_or_duplicate_upstream_state_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assemble(inputs=write_inputs(root), version="0.2.0", upstream=None, output=root / "old")
            later = write_inputs(root, "0.3.0", "7" * 64)
            with self.assertRaisesRegex(ValueError, "already lists"):
                assemble(
                    inputs=root / "inputs-0.2.0", version="0.2.0", upstream=root / "old", output=root / "a"
                )
            patched = root / "patched"
            subprocess.run(["cp", "-r", str(root / "old"), str(patched)], check=True)
            with (patched / "all/conandata.yml").open("a") as stream:
                stream.write('patches:\n  "0.2.0":\n    - patch_file: "patches/fix.patch"\n')
            with self.assertRaisesRegex(ValueError, "does not manage"):
                assemble(inputs=later, version="0.3.0", upstream=patched, output=root / "b")
            extra = root / "extra"
            subprocess.run(["cp", "-r", str(root / "old"), str(extra)], check=True)
            (extra / "all/patches").mkdir()
            (extra / "all/patches/fix.patch").write_text("--- a\n")
            with self.assertRaisesRegex(ValueError, "layout"):
                assemble(inputs=later, version="0.3.0", upstream=extra, output=root / "c")

    def test_tree_digest_covers_paths_and_contents(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assemble(inputs=write_inputs(root), version="0.2.0", upstream=None, output=root / "recipe")
            first = tree_sha256(root / "recipe")
            (root / "recipe/all/test_package/test_package.cpp").write_text("int main() { return 1; }\n")
            self.assertNotEqual(tree_sha256(root / "recipe"), first)


class RecipeVerificationTests(unittest.TestCase):
    def test_newest_entries_and_requirements_bind_the_release(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assemble(inputs=write_inputs(root), version="0.2.0", upstream=None, output=root / "old")
            assemble(
                inputs=write_inputs(root, "0.3.0", "7" * 64),
                version="0.3.0",
                upstream=root / "old",
                output=root / "new",
            )
            manifest = write_manifest(root)
            verify_assembled(root / "old", tag="v0.2.0", release_manifest=manifest)
            with self.assertRaisesRegex(ValueError, "newest version"):
                verify_assembled(root / "new", tag="v0.2.0", release_manifest=manifest)
            conanfile = root / "old/all/conanfile.py"
            conanfile.write_text(CONANFILE + '        self.requires("zlib/1.3.1")\n')
            with self.assertRaisesRegex(ValueError, "signed exact requirement set"):
                verify_assembled(root / "old", tag="v0.2.0", release_manifest=manifest)


FORK_ID = 100
FORK_OWNER_ID = 200
UPSTREAM_ID = 300


class FakeGitHub:
    """In-memory model of the fork routes push_recipe.py may call."""

    def __init__(self, *, base_in_fork: bool = True, fork_ahead: int = 0) -> None:
        self.base_in_fork = base_in_fork
        self.fork_ahead = fork_ahead
        self.trees: dict[str, list[dict[str, str]]] = {
            "root": [{"path": "recipes", "type": "tree", "sha": "recipes"}],
            "recipes": [{"path": "zlib", "type": "tree", "sha": "zlib"}],
        }
        self.commits: dict[str, dict[str, object]] = {BASE_SHA: {"tree": "root", "parents": []}}
        self.refs: dict[str, str] = {}
        self.writes: list[str] = []
        self.blobs: dict[str, bytes] = {}

    def request(self, method, path, expected, body=None):
        response = self._route(method, path, body)
        if response.status not in expected:
            raise PushError(f"{method} {path}: unexpected HTTP {response.status}")
        return response

    def _route(self, method, path, body):
        fork = "/repos/yurirocha15/conan-center-index"
        if method == "GET" and path == fork:
            return Response(200, {
                "id": FORK_ID, "full_name": "yurirocha15/conan-center-index", "fork": True,
                "archived": False, "owner": {"id": FORK_OWNER_ID},
                "parent": {"id": UPSTREAM_ID, "full_name": "conan-io/conan-center-index"},
            })
        if method == "GET" and path.startswith(f"{fork}/git/commits/"):
            sha = path.rsplit("/", 1)[1]
            if sha == BASE_SHA and not self.base_in_fork:
                return Response(404, None)
            commit = self.commits.get(sha)
            return Response(200, {"sha": sha, "tree": {"sha": commit["tree"]}, "parents": commit["parents"]}) if commit else Response(404, None)
        if method == "GET" and path.startswith(f"{fork}/git/trees/"):
            return Response(200, {"truncated": False, "tree": self.trees[path.rsplit("/", 1)[1]]})
        if method == "GET" and path.startswith(f"{fork}/git/ref/heads/"):
            branch = path[len(f"{fork}/git/ref/heads/"):]
            if branch not in self.refs:
                return Response(404, None)
            return Response(200, {"object": {"sha": self.refs[branch]}})
        if method == "GET" and path.startswith("/repos/conan-io/conan-center-index/compare/master..."):
            head = path.rsplit(":", 1)[1]
            if head == "master":
                return Response(200, {"ahead_by": self.fork_ahead})
            commit = self.commits[self.refs[head]]
            changed = [f"recipes/mcp-cpp-sdk/{name}" for name in commit.get("files", [])]
            return Response(200, {"ahead_by": 1, "files": [{"filename": name} for name in changed]})
        if method == "POST" and path == f"{fork}/merge-upstream":
            self.writes.append("merge-upstream")
            self.base_in_fork = True
            return Response(200, {"merge_type": "fast-forward"})
        if method == "POST" and path == f"{fork}/git/blobs":
            self.writes.append("blob")
            content = base64.b64decode(body["content"])
            sha = subprocess.run(
                ["git", "hash-object", "--stdin"], input=content, capture_output=True, check=True
            ).stdout.decode().strip()
            self.blobs[sha] = content
            return Response(201, {"sha": sha})
        if method == "POST" and path == f"{fork}/git/trees":
            self.writes.append("tree")
            files = {
                entry["path"].removeprefix("recipes/mcp-cpp-sdk/"): self.blobs[entry["sha"]]
                for entry in body["tree"]
            }
            recipe = git_tree_sha(files)
            self.trees[recipe] = []
            self.trees["new-recipes"] = self.trees["recipes"] + [
                {"path": "mcp-cpp-sdk", "type": "tree", "sha": recipe}
            ]
            self.trees["new-root"] = [{"path": "recipes", "type": "tree", "sha": "new-recipes"}]
            self.pending_files = sorted(files)
            return Response(201, {"sha": "new-root"})
        if method == "POST" and path == f"{fork}/git/commits":
            self.writes.append("commit")
            self.commits["new-commit"] = {
                "tree": body["tree"], "parents": body["parents"], "files": self.pending_files,
                "message": body["message"],
            }
            return Response(201, {"sha": "new-commit"})
        if method == "POST" and path == f"{fork}/git/refs":
            self.writes.append("ref")
            self.refs[body["ref"].removeprefix("refs/heads/")] = body["sha"]
            return Response(201, {"ref": body["ref"]})
        raise AssertionError(f"unexpected route {method} {path}")


class PushRecipeTests(unittest.TestCase):
    def files(self) -> dict[str, bytes]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assemble(inputs=write_inputs(root), version="0.2.0", upstream=None, output=root / "recipe")
            return recipe_files(root / "recipe")

    def push(self, client, files=None):
        return push(
            client,
            files=files or self.files(),
            version="0.2.0",
            state="new",
            base_commit=BASE_SHA,
            fork_id=FORK_ID,
            fork_owner_id=FORK_OWNER_ID,
            upstream_id=UPSTREAM_ID,
        )

    def test_git_tree_id_matches_git(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = self.files()
            for path, content in files.items():
                (root / path).parent.mkdir(parents=True, exist_ok=True)
                (root / path).write_bytes(content)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
            expected = subprocess.run(
                ["git", "-C", str(root), "write-tree"], capture_output=True, check=True, text=True
            ).stdout.strip()
            self.assertEqual(git_tree_sha(files), expected)

    def test_creates_one_commit_on_the_verified_base(self) -> None:
        client = FakeGitHub()
        branch, created = self.push(client)
        self.assertEqual((branch, created), ("package/mcp-cpp-sdk-0.2.0", True))
        self.assertEqual(client.writes, ["blob"] * 6 + ["tree", "commit", "ref"])
        commit = client.commits["new-commit"]
        self.assertEqual(commit["parents"], [BASE_SHA])
        self.assertEqual(commit["message"], "mcp-cpp-sdk/0.2.0: new recipe")

    def test_identical_existing_branch_is_accepted_without_writes(self) -> None:
        client = FakeGitHub()
        self.push(client)
        client.writes.clear()
        self.assertEqual(self.push(client), ("package/mcp-cpp-sdk-0.2.0", False))
        self.assertEqual(client.writes, [])

    def test_different_existing_branch_is_refused(self) -> None:
        client = FakeGitHub()
        self.push(client)
        files = dict(self.files())
        files["all/conanfile.py"] += b"# changed\n"
        with self.assertRaisesRegex(PushError, "different content"):
            self.push(client, files)

    def test_missing_base_syncs_only_an_unmodified_fork(self) -> None:
        client = FakeGitHub(base_in_fork=False)
        self.push(client)
        self.assertEqual(client.writes[0], "merge-upstream")
        diverged = FakeGitHub(base_in_fork=False, fork_ahead=2)
        with self.assertRaisesRegex(PushError, "sync it by hand"):
            self.push(diverged)
        self.assertEqual(diverged.writes, [])

    def test_wrong_fork_identity_is_refused_before_writes(self) -> None:
        client = FakeGitHub()
        with self.assertRaisesRegex(PushError, "identity"):
            push(
                client,
                files=self.files(),
                version="0.2.0",
                state="new",
                base_commit=BASE_SHA,
                fork_id=FORK_ID + 1,
                fork_owner_id=FORK_OWNER_ID,
                upstream_id=UPSTREAM_ID,
            )
        self.assertEqual(client.writes, [])

    def test_compare_link_prefills_the_pull_request(self) -> None:
        body = pull_body(version="0.2.0", commit=SOURCE_SHA, request_uuid="u")
        link = urlsplit(
            compare_link(branch="package/mcp-cpp-sdk-0.2.0", title="mcp-cpp-sdk/0.2.0: new recipe", body=body)
        )
        self.assertEqual(
            link.path,
            "/conan-io/conan-center-index/compare/master...yurirocha15:conan-center-index:package/mcp-cpp-sdk-0.2.0",
        )
        query = parse_qs(link.query)
        self.assertEqual(query["title"], ["mcp-cpp-sdk/0.2.0: new recipe"])
        self.assertEqual(query["body"], [body])


class SecretScanTests(unittest.TestCase):
    def test_tracked_control_repository_contains_no_secret_shapes(self) -> None:
        root = Path(__file__).resolve().parents[1]
        self.assertEqual(find_sensitive_paths(root), [])


if __name__ == "__main__":
    unittest.main()
