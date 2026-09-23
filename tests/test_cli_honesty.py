from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from ide_scanner import cli


class CliHonestyTests(unittest.TestCase):
    def test_terminal_output_path_does_not_crash(self) -> None:
        # Regression: cli._scan_output_format references sys.stdout; sys was
        # previously unimported, crashing every non-piped scan.
        buffer = io.StringIO()
        with patch("sys.stdout.isatty", return_value=True), redirect_stdout(buffer):
            code = cli.main(["scan", "--fixtures", "--format", "terminal"])
        self.assertEqual(code, 0)
        self.assertIn("IDE Scanner security brief", buffer.getvalue())

    def test_jobs_flag_runs_bounded_parallel_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "report.json"
            code = cli.main(["scan", "--fixtures", "--jobs", "2", "--format", "json", "--out", str(output)])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["summary"]["total_extensions"], 9)

    def test_terminal_separates_file_coverage_from_provider_completion(self) -> None:
        report = {
            "extensions": [{
                "extension_id": "example.large",
                "analysis_status": "incomplete",
                "decision": "incomplete",
                "decision_reason": "Required provider semgrep did not complete",
                "analysis_coverage": {
                    "executable_file_coverage_percent": 100,
                    "required_providers_complete": False,
                },
            }],
        }
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            cli._emit_terminal_brief(report)
        output = buffer.getvalue()
        self.assertIn("Executable-file coverage 100%", output)
        self.assertIn("required analysis incomplete", output)
        self.assertNotIn("required analyzers complete", output)

    def test_terminal_includes_a_recorded_evidence_line(self) -> None:
        report = {
            "extensions": [{
                "extension_id": "example.location",
                "analysis_status": "complete",
                "decision": "review",
                "analysis_coverage": {
                    "executable_file_coverage_percent": 100,
                    "required_providers_complete": True,
                },
                "findings": [{
                    "severity": "MEDIUM",
                    "evidence_summary": "Process execution reference",
                    "file_refs": ["src/terminal.js"],
                    "evidence": {"line": 43},
                }],
            }],
        }
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            cli._emit_terminal_brief(report)

        self.assertIn("src/terminal.js:43", buffer.getvalue())

    def test_deep_scan_returns_nonzero_when_report_is_incomplete(self) -> None:
        report = {
            "extensions": [{
                "extension_id": "example.runtime",
                "analysis_status": "incomplete",
                "decision": "incomplete",
            }],
        }
        with patch("ide_scanner.cli.scan_targets", return_value=report):
            code = cli.main(["scan", "--fixtures", "--profile", "deep", "--runtime", "--format", "json"])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
