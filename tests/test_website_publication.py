from __future__ import annotations

import io
import json
import unittest
from unittest.mock import patch

from scripts.publish_website_corpus import published_artifacts, rows_to_dispatch, workflow_command
from scripts.validate_website_publication import validate_rows


class WebsitePublicationTests(unittest.TestCase):
    def test_dispatch_skips_only_same_hash_publication(self) -> None:
        rows = [
            {"extension_id": "publisher.one", "version": "1.0.0", "sha256": "a" * 64},
            {"extension_id": "publisher.two", "version": "2.0.0", "sha256": "b" * 64},
        ]
        pending = rows_to_dispatch(rows, {"publisher.one@1.0.0": "a" * 64, "publisher.two@2.0.0": "c" * 64})
        self.assertEqual([row["extension_id"] for row in pending], ["publisher.two"])

    def test_publications_from_an_older_scanner_build_are_pending_by_default(self) -> None:
        payload = {
            "rows": [
                {
                    "extension_id": "publisher.one",
                    "version": "1.0.0",
                    "sha256": "a" * 64,
                    "scan": {
                        "scanner_build": "old-build",
                        "score_schema_version": "2",
                        "coverage_percent": 100,
                    },
                },
                {
                    "extension_id": "publisher.two",
                    "version": "2.0.0",
                    "sha256": "b" * 64,
                    "scan": {
                        "scanner_build": "current-build",
                        "score_schema_version": "2",
                        "coverage_percent": 100,
                    },
                },
            ]
        }
        with patch("scripts.publish_website_corpus.urllib.request.urlopen", return_value=io.BytesIO(json.dumps(payload).encode())):
            published = published_artifacts("https://example.test/publication", "current-build")
        self.assertEqual(published, {"publisher.two@2.0.0": "b" * 64})

    def test_platform_qualified_artifact_is_dispatched_explicitly(self) -> None:
        command = workflow_command({
            "extension_id": "ms-python.python",
            "version": "1.2.3",
            "target_platform": "darwin-x64",
        })

        self.assertIn("target_platform=darwin-x64", command)

    def test_validator_compares_exact_hash_decision_coverage_and_schema(self) -> None:
        expected = [{"extension_id": "publisher.one", "version": "1.0.0", "sha256": "a" * 64, "frozen_expected_decision": "review"}]
        actual = [{"extension_id": "publisher.one", "version": "1.0.0", "sha256": "a" * 64, "scan": {"decision": "review", "coverage_percent": 100, "score_schema_version": "2"}}]
        self.assertEqual(validate_rows(expected, actual), {"total": 1, "published": 1, "awaiting": [], "mismatches": []})

    def test_validator_reports_missing_and_divergent_rows(self) -> None:
        expected = [
            {"extension_id": "publisher.one", "version": "1.0.0", "sha256": "a" * 64, "frozen_expected_decision": "allow"},
            {"extension_id": "publisher.two", "version": "2.0.0", "sha256": "b" * 64, "frozen_expected_decision": "review"},
        ]
        actual = [{"extension_id": "publisher.one", "version": "1.0.0", "sha256": "a" * 64, "scan": {"decision": "review", "coverage_percent": 99, "score_schema_version": "1"}}]
        result = validate_rows(expected, actual)
        self.assertEqual(result["awaiting"], ["publisher.two@2.0.0"])
        self.assertEqual({item["field"] for item in result["mismatches"]}, {"decision", "coverage", "score_schema"})


if __name__ == "__main__":
    unittest.main()
