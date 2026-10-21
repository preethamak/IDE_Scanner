from __future__ import annotations

import unittest
from pathlib import Path

import yaml


class GitHubMcpAssessmentSmokeWorkflowTests(unittest.TestCase):
    def test_workflow_runs_local_action_and_validates_its_outputs(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = yaml.safe_load(
            (root / ".github" / "workflows" / "github-mcp-assessment-smoke.yml").read_text(encoding="utf-8")
        )

        job = workflow["jobs"]["assess-fixture"]
        action_step = job["steps"][1]
        self.assertEqual(action_step["uses"], "./.github/actions/mcp-assessment")
        self.assertEqual(action_step["with"]["descriptor"], "fixtures/mcp-local-server.json")
        validation = job["steps"][2]["run"]
        self.assertIn("guardrails.mcp-risk-report.v1", validation)
        self.assertIn("COVERAGE_PERCENT", validation)
