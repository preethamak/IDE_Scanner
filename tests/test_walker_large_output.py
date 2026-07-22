from __future__ import annotations

import json
import unittest
from unittest.mock import MagicMock, patch

import ide_scanner.ast_analyzer as ast_analyzer
from ide_scanner.ast_analyzer import analyze_js_source_status, node_available


class WalkerLargeOutputTests(unittest.TestCase):
    @unittest.skipUnless(node_available(), "node runtime required")
    def test_large_findings_payload_is_not_truncated(self) -> None:
        # Regression: walker.js used to call process.exit() immediately after
        # process.stdout.write(), truncating output at the ~64KB pipe buffer.
        # A findings payload larger than that arrived as invalid JSON and the
        # analyzer reported status "malformed", silently dropping a required
        # provider. Each dynamic-call line below emits one finding; enough of
        # them push the serialized JSON well past 64KB.
        lines = [f'win["ev"+"al_{i}"]();' for i in range(4000)]
        source = "\n".join(lines) + "\n"

        findings, status = analyze_js_source_status("big.js", source)

        self.assertEqual(status, "ok")
        self.assertGreater(len(findings), 2000)
        # The output that would have been truncated must round-trip as JSON.
        self.assertGreater(len(json.dumps(findings)), 64 * 1024)

    @unittest.skipUnless(node_available(), "node runtime required")
    def test_typescript_is_unparsed_not_ok(self) -> None:
        # acorn is plain-JS only; TypeScript must surface as a disclosed
        # "unparsed", never as a clean "ok" that falsely claims AST coverage.
        _findings, status = analyze_js_source_status("a.ts", "const x: number = 1;\n")
        self.assertEqual(status, "unparsed")

    def test_walk_error_fails_closed_as_malformed(self) -> None:
        # A crash AFTER a successful parse is a genuine analyzer failure and
        # must fail closed as "malformed", not be mistaken for a benign
        # unparsed file. The walker tags it kind="walk-error".
        fake = MagicMock(
            returncode=0,
            stdout=json.dumps({"error": "walk failed: boom", "kind": "walk-error", "findings": []}),
        )
        with patch.object(ast_analyzer.subprocess, "run", return_value=fake), \
             patch.object(ast_analyzer, "node_available", return_value=True):
            _findings, status = analyze_js_source_status("a.js", "x")
        self.assertEqual(status, "malformed")

    def test_unknown_error_shape_fails_closed(self) -> None:
        # An error payload with no/unknown kind is treated conservatively as
        # malformed rather than silently trusted as unparsed.
        fake = MagicMock(returncode=0, stdout=json.dumps({"error": "weird", "findings": []}))
        with patch.object(ast_analyzer.subprocess, "run", return_value=fake), \
             patch.object(ast_analyzer, "node_available", return_value=True):
            _findings, status = analyze_js_source_status("a.js", "x")
        self.assertEqual(status, "malformed")


if __name__ == "__main__":
    unittest.main()
