from __future__ import annotations

import unittest
from pathlib import Path

import yaml


class GitHubSarifActionTests(unittest.TestCase):
    def test_action_requires_a_path_and_exports_sarif(self) -> None:
        action = yaml.safe_load((Path(__file__).resolve().parents[1] / "action.yml").read_text(encoding="utf-8"))

        self.assertEqual(action["name"], "GuardRails extension scan")
        self.assertTrue(action["inputs"]["path"]["required"])
        self.assertEqual(action["outputs"]["sarif_file"]["value"], "${{ steps.scan.outputs.sarif_file }}")
        script = action["runs"]["steps"][0]["run"]
        self.assertIn("--format sarif", script)
        self.assertIn('"${args[@]}"', script)
        self.assertIn("deep", script)
        self.assertIn("GITHUB_OUTPUT", script)
        self.assertIn('pip install --disable-pip-version-check --no-cache-dir "$GITHUB_ACTION_PATH"', script)

    def test_documented_workflow_uploads_the_action_output(self) -> None:
        guide = (Path(__file__).resolve().parents[1] / "docs" / "github-sarif-action.md").read_text(encoding="utf-8")

        self.assertIn("security-events: write", guide)
        self.assertIn("github/codeql-action/upload-sarif@v3", guide)
        self.assertIn("steps.guardrails.outputs.sarif_file", guide)


if __name__ == "__main__":
    unittest.main()
