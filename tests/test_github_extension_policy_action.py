from __future__ import annotations

import unittest
from pathlib import Path

import yaml


class GitHubExtensionPolicyActionTests(unittest.TestCase):
    def test_action_enforces_exact_artifact_policy_and_exports_summary(self) -> None:
        root = Path(__file__).resolve().parents[1]
        action = yaml.safe_load(
            (root / ".github" / "actions" / "extension-policy" / "action.yml").read_text(encoding="utf-8")
        )

        self.assertEqual(action["name"], "GuardRails extension policy")
        self.assertEqual(action["inputs"]["write_lock"]["default"], "false")
        self.assertEqual(action["outputs"]["failed"]["value"], "${{ steps.policy.outputs.failed }}")
        script = action["runs"]["steps"][0]["run"]
        self.assertIn("scripts/policy_gate.py", script)
        self.assertIn("--policy", script)
        self.assertIn("--lock", script)
        self.assertIn("--write-lock", script)
        self.assertIn("GITHUB_OUTPUT", script)
        self.assertIn('"${args[@]}"', script)

    def test_documentation_uses_scoped_action_and_describes_fail_closed_behavior(self) -> None:
        guide = (Path(__file__).resolve().parents[1] / "docs" / "github-extension-policy-action.md").read_text(encoding="utf-8")

        self.assertIn(".github/actions/extension-policy@main", guide)
        self.assertIn("SHA-256", guide)
        self.assertIn("fails the job", guide)
        self.assertIn("write_lock: \"true\"", guide)


if __name__ == "__main__":
    unittest.main()
