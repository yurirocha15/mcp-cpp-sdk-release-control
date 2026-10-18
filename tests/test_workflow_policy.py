from __future__ import annotations

import ast
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

    def test_pat_is_in_one_final_no_checkout_step(self) -> None:
        publish = self.workflow.split("\n  publish:\n", 1)[1]
        self.assertNotIn("actions/checkout", publish)
        self.assertEqual(publish.count("      - name:"), 3)
        self.assertEqual(publish.count("secrets.CONAN_CENTER_PR_BOT_PAT"), 1)
        self.assertTrue(
            publish.rstrip().endswith("run: python3 -I -S publisher-client/create_pull.py")
        )
        secret = publish.index("secrets.CONAN_CENTER_PR_BOT_PAT")
        self.assertLess(
            publish.index("client_handoff.py --directory publisher-client"), secret
        )

    def test_extracted_client_is_valid_stdlib_python(self) -> None:
        source = (ROOT / "publisher/create_pull.py").read_text()
        tree = ast.parse(source)
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])
        self.assertEqual(
            imports,
            {
                "__future__",
                "collections",
                "dataclasses",
                "http",
                "importlib",
                "json",
                "os",
                "pathlib",
                "re",
                "sys",
                "types",
                "urllib",
                "uuid",
            },
        )
        self.assertIn('API_HOST = "api.github.com"', source)

    def test_polling_issue_binding_and_handoff_are_bounded(self) -> None:
        self.assertIn("timeout-minutes: 75", self.workflow)
        self.assertIn("--timeout-seconds 3600", self.workflow)
        self.assertNotIn("python3 -I -S <<", self.workflow)
        self.assertIn("retention-days: 90", self.workflow)
        self.assertIn("PACKAGE_REQUEST_ISSUE_BODY_SHA256", self.workflow)
        client = (ROOT / "publisher/create_pull.py").read_text()
        self.assertLess(
            client.index('"recheck-package-request"'),
            client.index('"create-pull"'),
        )


if __name__ == "__main__":
    unittest.main()
