from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import yaml

from ide_scanner.cli import main


class McpCliAndActionTests(unittest.TestCase):
    def test_mcp_cli_writes_a_machine_readable_assessment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            descriptor = root / "server.json"
            output = root / "assessment.json"
            descriptor.write_text(json.dumps({"name": "local-server", "transport": "stdio", "tools": []}), encoding="utf-8")

            self.assertEqual(main(["mcp", "--input", str(descriptor), "--output", str(output)]), 0)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["schema_version"], "guardrails.mcp-risk-report.v1")
            self.assertIn(report["decision"], {"allow", "review", "block", "incomplete"})

    def test_action_records_report_outputs_and_explicit_gate_threshold(self) -> None:
        root = Path(__file__).resolve().parents[1]
        action = yaml.safe_load((root / ".github" / "actions" / "mcp-assessment" / "action.yml").read_text(encoding="utf-8"))

        self.assertEqual(action["name"], "GuardRails MCP assessment")
        self.assertTrue(action["inputs"]["descriptor"]["required"])
        self.assertEqual(action["inputs"]["fail_on"]["default"], "never")
        self.assertEqual(action["outputs"]["decision"]["value"], "${{ steps.assess.outputs.decision }}")
        script = action["runs"]["steps"][0]["run"]
        self.assertIn("ide_scanner.cli mcp", script)
        self.assertIn("coverage_percent", script)
        self.assertIn("fail_on", script)
