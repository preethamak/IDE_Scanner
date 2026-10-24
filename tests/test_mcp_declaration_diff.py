from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from ide_scanner import cli
from ide_scanner.mcp.declaration_diff import compare_declaration_reports


def _assessment(*tools: tuple[str, str]) -> dict:
    return {"tools": [{"name": name, "declaration": {"sha256": digest}} for name, digest in tools]}


class McpDeclarationDiffTests(unittest.TestCase):
    def test_compares_added_removed_changed_and_unchanged_tools(self) -> None:
        a = "a" * 64
        b = "b" * 64
        c = "c" * 64
        d = "d" * 64
        with tempfile.TemporaryDirectory() as temp:
            before = Path(temp) / "before.json"
            after = Path(temp) / "after.json"
            before.write_text(json.dumps(_assessment(("stable", a), ("changed", b), ("removed", c))), encoding="utf-8")
            after.write_text(json.dumps(_assessment(("stable", a), ("changed", d), ("added", c))), encoding="utf-8")
            result = compare_declaration_reports(before, after)

        self.assertEqual(result["added"], ["added"])
        self.assertEqual(result["removed"], ["removed"])
        self.assertEqual(result["unchanged"], ["stable"])
        self.assertEqual(result["changed"], [{"name": "changed", "before_sha256": b, "after_sha256": d}])
        self.assertTrue(result["drift_detected"])

    def test_rejects_unfingerprinted_or_duplicate_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            invalid = Path(temp) / "invalid.json"
            valid = Path(temp) / "valid.json"
            invalid.write_text(json.dumps({"tools": [{"name": "missing", "declaration": {}}]}), encoding="utf-8")
            valid.write_text(json.dumps(_assessment(("valid", "a" * 64))), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "no valid declaration SHA-256"):
                compare_declaration_reports(invalid, valid)

    def test_cli_can_fail_a_ci_gate_on_declaration_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            before = Path(temp) / "before.json"
            after = Path(temp) / "after.json"
            before.write_text(json.dumps(_assessment(("tool", "a" * 64))), encoding="utf-8")
            after.write_text(json.dumps(_assessment(("tool", "b" * 64))), encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output), redirect_stderr(io.StringIO()):
                code = cli.main(["mcp-declarations", "--before", str(before), "--after", str(after), "--fail-on-drift"])

        self.assertEqual(code, 1)
        self.assertTrue(json.loads(output.getvalue())["drift_detected"])


if __name__ == "__main__":
    unittest.main()
