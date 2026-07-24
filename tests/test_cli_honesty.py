from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
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

    def test_jobs_flag_is_removed_not_a_silent_noop(self) -> None:
        with self.assertRaises(SystemExit):
            cli.main(["scan", "--fixtures", "--jobs", "4"])

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


if __name__ == "__main__":
    unittest.main()
