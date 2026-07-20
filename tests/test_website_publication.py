from __future__ import annotations

import unittest

from scripts.publish_website_corpus import rows_to_dispatch
from scripts.validate_website_publication import validate_rows


class WebsitePublicationTests(unittest.TestCase):
    def test_dispatch_skips_only_same_hash_publication(self) -> None:
        rows = [
            {"extension_id": "publisher.one", "version": "1.0.0", "sha256": "a" * 64},
            {"extension_id": "publisher.two", "version": "2.0.0", "sha256": "b" * 64},
        ]
        pending = rows_to_dispatch(rows, {"publisher.one@1.0.0": "a" * 64, "publisher.two@2.0.0": "c" * 64})
        self.assertEqual([row["extension_id"] for row in pending], ["publisher.two"])

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
