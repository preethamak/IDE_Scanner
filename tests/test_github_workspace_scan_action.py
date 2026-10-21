from __future__ import annotations

import unittest
from pathlib import Path

import yaml


class GitHubWorkspaceScanActionTests(unittest.TestCase):
    def test_action_uses_workspace_cli_and_declares_aggregate_outputs(self) -> None:
        root = Path(__file__).resolve().parents[1]
        action = yaml.safe_load((root / ".github" / "actions" / "workspace-extension-scan" / "action.yml").read_text(encoding="utf-8"))

        self.assertEqual(action["name"], "GuardRails workspace extension scan")
        self.assertEqual(action["inputs"]["profile"]["default"], "standard")
        self.assertEqual(action["outputs"]["highest_decision"]["value"], "${{ steps.scan.outputs.highest_decision }}")
        script = action["runs"]["steps"][0]["run"]
        self.assertIn("ide_scanner.cli workspace", script)
        self.assertIn("--lock", script)
        self.assertIn("highest_decision", script)
        self.assertIn("fail_on", script)
        self.assertIn('"${args[@]}"', script)
