from __future__ import annotations

import unittest
from pathlib import Path

import yaml


class GitHubActionSmokeWorkflowTests(unittest.TestCase):
    def test_workflow_exercises_local_action_and_its_sarif_output(self) -> None:
        workflow = yaml.safe_load((Path(__file__).resolve().parents[1] / ".github" / "workflows" / "github-action-smoke.yml").read_text(encoding="utf-8"))

        job = workflow["jobs"]["scan-fixture"]
        action_step = job["steps"][1]
        self.assertEqual(action_step["uses"], "./")
        self.assertEqual(action_step["with"]["path"], "tests/fixtures/benign-formatter")
        validation = job["steps"][2]["run"]
        self.assertIn('payload["version"] == "2.1.0"', validation)
        self.assertIn("GuardRails Scanner", validation)


if __name__ == "__main__":
    unittest.main()
