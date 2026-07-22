from __future__ import annotations

import unittest

from ide_scanner.agent import _redact_source_previews


class AgentPrivacyTests(unittest.TestCase):
    def _report_with_source(self) -> dict:
        return {
            "extensions": [
                {
                    "extension_id": "ex.one",
                    "artifact_inventory": {
                        "source_previews": [
                            {"path": "extension.js", "content": "SECRET=abc", "content_sha256": "d" * 64, "truncated": False},
                        ]
                    },
                }
            ]
        }

    def test_source_content_removed_by_default(self) -> None:
        report = self._report_with_source()
        count = _redact_source_previews(report)
        self.assertEqual(count, 1)
        preview = report["extensions"][0]["artifact_inventory"]["source_previews"][0]
        self.assertNotIn("content", preview)
        self.assertTrue(preview["redacted"])
        self.assertEqual(preview["path"], "extension.js")
        self.assertEqual(preview["content_sha256"], "d" * 64)

    def test_no_source_previews_is_noop(self) -> None:
        report = {"extensions": [{"extension_id": "ex.two", "artifact_inventory": {}}]}
        self.assertEqual(_redact_source_previews(report), 0)


if __name__ == "__main__":
    unittest.main()
