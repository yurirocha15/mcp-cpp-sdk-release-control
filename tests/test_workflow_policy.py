from __future__ import annotations

import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
FULL_SHA_ACTION = re.compile(r"uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([0-9a-f]{40})(?:\s|$)")


class WorkflowSyntaxTests(unittest.TestCase):
    def test_workflows_have_known_structure(self) -> None:
        for path in WORKFLOWS.glob("*.yml"):
            text = path.read_text()
            self.assertIn("name:", text)
            self.assertIn("on:", text)
            self.assertIn("permissions:", text)
            self.assertIn("jobs:", text)
            self.assertNotIn("\t", text)


class SecurityPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = (WORKFLOWS / "conan-center-pr.yml").read_text()
        self.manifest = json.loads((ROOT / "repository-settings.json").read_text())

    def test_actions_are_full_sha_allowlisted(self) -> None:
        allowed = self.manifest["actions"]["allowed_actions"]
        for path in WORKFLOWS.glob("*.yml"):
            for line in path.read_text().splitlines():
                if "uses:" not in line:
                    continue
                match = FULL_SHA_ACTION.search(line)
                self.assertIsNotNone(match, line)
                self.assertEqual(allowed.get(match.group(1)), match.group(2))

    def test_fork_credential_is_confined_to_the_protected_push_job(self) -> None:
        verify, push = self.workflow.split("\n  push:\n", 1)
        self.assertNotIn("secrets.", verify)
        self.assertNotIn("environment:", verify)
        self.assertIn("    environment: conan-fork-push\n", push)
        self.assertEqual(push.count("secrets.CONAN_FORK_APP_PRIVATE_KEY"), 1)
        token = push.split("actions/create-github-app-token@", 1)[1].split("      - name:", 1)[0]
        self.assertIn("          repositories: conan-center-index\n", token)
        self.assertEqual(
            [line.strip() for line in token.splitlines() if "permission-" in line],
            ["permission-contents: write"],
        )
        self.assertTrue(
            push.rstrip().endswith('--summary "${GITHUB_STEP_SUMMARY}"')
            and "python3 -I -S publisher/push_recipe.py" in push
        )

    def test_dispatch_inputs_match_the_validated_contract(self) -> None:
        from publisher.validate_dispatch import FIELDS

        inputs = self.workflow.split("    inputs:\n", 1)[1].split("\npermissions:", 1)[0]
        declared = re.findall(r"(?m)^      ([a-z0-9_]+):$", inputs)
        self.assertEqual(tuple(declared), FIELDS)
        self.assertEqual(self.workflow.count("required: true"), len(FIELDS))

    def test_jobs_run_only_the_immutable_control_code(self) -> None:
        self.assertIn("test \"${GITHUB_REF}\" = refs/tags/release-control-v1", self.workflow)
        self.assertEqual(
            self.workflow.count("ref: ${{ inputs.provider_control_sha }}")
            + self.workflow.count("ref: ${{ needs.verify.outputs.provider_control_sha }}"),
            2,
        )
        self.assertNotIn("python3 -I -S <<", self.workflow)
        self.assertEqual(self.workflow.count("persist-credentials: false"), 2)

    def test_settings_declare_the_fork_app_boundary(self) -> None:
        environment = self.manifest["environment"]
        self.assertEqual(environment["name"], "conan-fork-push")
        self.assertEqual(environment["deployment_tag"], "release-control-v1")
        self.assertEqual(environment["secrets"], ["CONAN_FORK_APP_PRIVATE_KEY"])
        self.assertEqual(environment["variables"], ["CONAN_FORK_APP_CLIENT_ID"])
        self.assertEqual(
            self.manifest["publisher_app"]["installation_repositories"],
            ["yurirocha15/conan-center-index"],
        )
        for variable in re.findall(r"vars\.([A-Z0-9_]+)", self.workflow):
            self.assertIn(
                variable,
                self.manifest["repository_variables"] + environment["variables"],
            )

if __name__ == "__main__":
    unittest.main()
