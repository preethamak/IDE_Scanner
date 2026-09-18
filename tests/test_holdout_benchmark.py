from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ide_scanner.benchmarks.production import evaluate_holdout_corpus


class HoldoutBenchmarkTests(unittest.TestCase):
    def test_runtime_holdout_requires_safe_allow_and_malicious_block(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corpus_path = self._write(root, "corpus.json", self._corpus())
            report_path = self._write(root, "report.json", self._report())

            result = evaluate_holdout_corpus(corpus_path, report_path)

            self.assertTrue(result["gate"]["passed"])
            self.assertEqual(result["summary"]["required_pass_rate"], 1.0)
            self.assertTrue(result["runtime_evidence"]["runtime_enabled"])
            self.assertEqual(result["rule_matrix"]["trusted-threat-feed-hit"]["fired_on_known_malicious"], 1)

    def test_holdout_fails_when_malicious_artifact_is_only_reviewed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = self._report()
            report["extensions"][1]["decision"] = "review"
            report_path = self._write(root, "report.json", report)

            result = evaluate_holdout_corpus(self._write(root, "corpus.json", self._corpus()), report_path)

            self.assertFalse(result["gate"]["passed"])
            malicious = result["artifacts"][1]
            self.assertTrue(any("not blocked" in item for item in malicious["violations"]))

    def test_holdout_fails_when_runtime_evidence_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = self._report()
            report["corpus_execution"]["runtime_enabled"] = False
            report["corpus_execution"]["profile"] = "quick"

            result = evaluate_holdout_corpus(
                self._write(root, "corpus.json", self._corpus()),
                self._write(root, "report.json", report),
            )

            self.assertFalse(result["gate"]["passed"])
            self.assertFalse(result["gate"]["checks"]["runtime_enabled"])
            self.assertFalse(result["gate"]["checks"]["deep_profile"])

    def test_holdout_fails_on_artifact_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = self._report()
            report["extensions"][0]["artifact_hash"] = "0" * 64

            result = evaluate_holdout_corpus(
                self._write(root, "corpus.json", self._corpus()),
                self._write(root, "report.json", report),
            )

            self.assertFalse(result["gate"]["passed"])
            self.assertTrue(any("SHA-256" in item for item in result["artifacts"][0]["violations"]))

    @staticmethod
    def _corpus() -> dict:
        return {
            "schema_version": "1.0",
            "corpus_id": "holdout",
            "corpus_version": "1",
            "holdout": {
                "status": "fresh-labeled",
                "frozen_before_scan": True,
                "original_bytes_available": True,
            },
            "artifacts": [
                {
                    "extension_id": "safe.extension",
                    "version": "1.0.0",
                    "gate_required": True,
                    "label": "known_safe",
                    "artifact": {"source_type": "pinned_https", "original_bytes_available": True, "sha256": "a" * 64},
                },
                {
                    "extension_id": "bad.extension",
                    "version": "2.0.0",
                    "gate_required": True,
                    "label": "known_malicious",
                    "artifact": {"source_type": "pinned_https", "original_bytes_available": True, "sha256": "b" * 64},
                },
            ],
        }

    @staticmethod
    def _report() -> dict:
        return {
            "scanner_build": "a" * 40,
            "policy_version": "policy",
            "ruleset_version": "rules",
            "corpus_execution": {"runtime_enabled": True, "profile": "deep", "runtime_timeout_seconds": 20},
            "extensions": [
                {
                    "extension_id": "safe.extension",
                    "version": "1.0.0",
                    "analysis_status": "complete",
                    "decision": "allow",
                    "verdict": "clean",
                    "artifact_hash": "a" * 64,
                    "findings": [],
                },
                {
                    "extension_id": "bad.extension",
                    "version": "2.0.0",
                    "analysis_status": "complete",
                    "decision": "block",
                    "verdict": "malicious",
                    "artifact_hash": "b" * 64,
                    "findings": [{"rule_id": "trusted-threat-feed-hit"}],
                },
            ],
        }

    @staticmethod
    def _write(root: Path, name: str, value: dict) -> Path:
        path = root / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path


if __name__ == "__main__":
    unittest.main()
