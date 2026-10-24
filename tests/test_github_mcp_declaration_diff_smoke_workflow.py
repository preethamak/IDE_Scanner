from __future__ import annotations

import unittest
from pathlib import Path

import yaml


class GitHubMcpDeclarationDiffSmokeWorkflowTests(unittest.TestCase):
    def test_workflow_runs_local_action_and_validates_drift_outputs(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = yaml.safe_load(
            (root / ".github" / "workflows" / "github-mcp-declaration-diff-smoke.yml").read_text(encoding="utf-8"),
        )

        job = workflow["jobs"]["compare-fixtures"]
        action_step = job["steps"][1]
        self.assertEqual(action_step["uses"], "./.github/actions/mcp-declaration-diff")
        self.assertEqual(action_step["with"]["fail-on-drift"], "false")
        validation = job["steps"][2]["run"]
        self.assertIn("guardrails.mcp-declaration-diff.v1", validation)
        self.assertIn("CHANGED_TOOL_COUNT", validation)
