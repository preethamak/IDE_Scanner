from __future__ import annotations

import unittest
from pathlib import Path

import yaml


class GitHubWorkspaceScanSmokeWorkflowTests(unittest.TestCase):
    def test_workflow_exercises_local_action_and_validates_empty_workspace_outputs(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = yaml.safe_load(
            (root / ".github" / "workflows" / "github-workspace-scan-smoke.yml").read_text(encoding="utf-8")
        )

        job = workflow["jobs"]["scan-empty-workspace"]
        action_step = job["steps"][1]
        self.assertEqual(action_step["uses"], "./.github/actions/workspace-extension-scan")
        self.assertEqual(action_step["with"]["root"], "fixtures/workspace-empty")
        validation = job["steps"][2]["run"]
        self.assertIn("guardrails.workspace-extension-scan.v1", validation)
        self.assertIn("HIGHEST_DECISION", validation)
