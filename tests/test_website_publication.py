from __future__ import annotations

import io
import json
import unittest
from unittest.mock import patch

from scripts.publish_website_corpus import (
    github_repository_full_name,
    publication_scan_is_complete,
    published_artifacts,
    rows_to_dispatch,
    verify_clean_worktree,
    workflow_command,
)
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
                        "policy_version": "current-policy",
                        "ruleset_version": "current-ruleset",
                        "score_schema_version": "2",
                        "coverage_percent": 100,
                        "analysis_status": "complete",
                        "analysis_coverage_status": "complete",
                        "required_providers_complete": True,
                        "executable_file_coverage_percent": 100,
                    },
                },
                {
                    "extension_id": "publisher.two",
                    "version": "2.0.0",
                    "sha256": "b" * 64,
                    "scan": {
                        "scanner_build": "current-build",
                        "policy_version": "current-policy",
                        "ruleset_version": "current-ruleset",
                        "score_schema_version": "2",
                        "coverage_percent": 100,
                        "analysis_status": "complete",
                        "analysis_coverage_status": "complete",
                        "required_providers_complete": True,
                        "executable_file_coverage_percent": 100,
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
        }, scanner_build="a" * 40)

        self.assertIn("target_platform=darwin-x64", command)
        self.assertIn(f"scanner_build={'a' * 40}", command)

    def test_dispatch_rejects_non_immutable_scanner_build(self) -> None:
        with self.assertRaises(ValueError):
            workflow_command({"extension_id": "publisher.one", "version": "1.0.0"}, scanner_build="main")

    def test_publication_accepts_https_and_scp_github_origins(self) -> None:
        self.assertEqual(
            github_repository_full_name("https://github.com/preethamak/IDE_Scanner.git"),
            "preethamak/IDE_Scanner",
        )
        self.assertEqual(
            github_repository_full_name("git@github.com:preethamak/IDE_Scanner.git"),
            "preethamak/IDE_Scanner",
        )

    def test_publication_rejects_non_github_origins(self) -> None:
        with self.assertRaises(RuntimeError):
            github_repository_full_name("https://example.test/preethamak/IDE_Scanner.git")

    def test_validator_compares_exact_hash_decision_coverage_and_schema(self) -> None:
        expected = [{"extension_id": "publisher.one", "version": "1.0.0", "sha256": "a" * 64, "frozen_expected_decision": "review"}]
        actual = [{"extension_id": "publisher.one", "version": "1.0.0", "sha256": "a" * 64, "scan": {"decision": "review", "coverage_percent": 100, "score_schema_version": "2", "analysis_status": "complete", "analysis_coverage_status": "complete", "required_providers_complete": True, "executable_file_coverage_percent": 100, "scanner_build": "build", "policy_version": "policy", "ruleset_version": "rules"}}]
        self.assertEqual(validate_rows(expected, actual), {"total": 1, "published": 1, "awaiting": [], "mismatches": []})

    def test_validator_reports_missing_and_divergent_rows(self) -> None:
        expected = [
            {"extension_id": "publisher.one", "version": "1.0.0", "sha256": "a" * 64, "frozen_expected_decision": "allow"},
            {"extension_id": "publisher.two", "version": "2.0.0", "sha256": "b" * 64, "frozen_expected_decision": "review"},
        ]
        actual = [{"extension_id": "publisher.one", "version": "1.0.0", "sha256": "a" * 64, "scan": {"decision": "review", "coverage_percent": 99, "score_schema_version": "1", "analysis_status": "incomplete", "analysis_coverage_status": "incomplete", "required_providers_complete": False, "executable_file_coverage_percent": 99}}]
        result = validate_rows(expected, actual)
        self.assertEqual(result["awaiting"], ["publisher.two@2.0.0"])
        self.assertEqual({item["field"] for item in result["mismatches"]}, {"decision", "coverage", "score_schema", "policy_version", "ruleset_version", "scanner_build", "analysis_status", "coverage_status", "required_providers_complete", "executable_file_coverage"})

    def test_validator_can_bind_rows_to_exact_scanner_build(self) -> None:
        expected = [{"extension_id": "publisher.one", "version": "1.0.0", "sha256": "a" * 64, "frozen_expected_decision": "allow"}]
        actual = [{"extension_id": "publisher.one", "version": "1.0.0", "sha256": "a" * 64, "scan": {"decision": "allow", "coverage_percent": 100, "score_schema_version": "2", "analysis_status": "complete", "analysis_coverage_status": "complete", "required_providers_complete": True, "executable_file_coverage_percent": 100, "scanner_build": "old-build", "policy_version": "policy", "ruleset_version": "rules"}}]
        result = validate_rows(expected, actual, required_scanner_build="current-build")
        self.assertEqual(result["mismatches"], [{"artifact": "publisher.one@1.0.0", "field": "scanner_build", "expected": "current-build", "actual": "old-build"}])

    def test_full_coverage_does_not_hide_incomplete_analysis(self) -> None:
        scan = {
            "score_schema_version": "2",
            "coverage_percent": 100,
            "analysis_status": "incomplete",
            "analysis_coverage_status": "incomplete",
            "required_providers_complete": False,
            "executable_file_coverage_percent": 100,
            "scanner_build": "build",
            "policy_version": "policy",
            "ruleset_version": "rules",
        }
        self.assertFalse(publication_scan_is_complete(scan))

    def test_dispatch_worktree_guard_rejects_tracked_changes(self) -> None:
        with patch("scripts.publish_website_corpus.subprocess.run") as run:
            run.return_value.returncode = 1
            with self.assertRaisesRegex(RuntimeError, "tracked changes"):
                verify_clean_worktree()

    def test_dispatch_worktree_guard_checks_index_after_worktree(self) -> None:
        with patch("scripts.publish_website_corpus.subprocess.run") as run:
            run.side_effect = [type("Result", (), {"returncode": 0})(), type("Result", (), {"returncode": 1})()]
            with self.assertRaisesRegex(RuntimeError, "tracked changes"):
                verify_clean_worktree()
            self.assertEqual(run.call_args_list[1].args[0], ["git", "diff", "--cached", "--quiet"])


if __name__ == "__main__":
    unittest.main()
