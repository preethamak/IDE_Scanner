from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.build_publication_accuracy_gate import build_publication_accuracy_gate


BUILD = "a" * 40


def gate(corpus_id: str, *, safe: int = 2, malicious: int = 2, version: str = "1") -> dict:
    return {
        "schema_version": "1.0",
        "corpus_id": corpus_id,
        "corpus_version": version,
        "report_identity": {"scanner_build": BUILD, "policy_version": "policy", "ruleset_version": "rules"},
        "gate": {
            "passed": True,
            "checks": {
                "required_pass_rate": True,
                "safe_block_rate": True,
                "safe_review_rate": True,
                "malicious_allow_rate": True,
                "incomplete_required": True,
            },
        },
        "summary": {
            "total_artifacts": safe + malicious,
            "scanned_artifacts": safe + malicious,
            "not_scanned": 0,
            "required_artifacts": safe + malicious,
            "required_passed": safe + malicious,
            "required_failed": 0,
            "required_pass_rate": 1.0,
            "safe_evaluated": safe,
            "safe_blocks": 0,
            "safe_block_rate": 0.0,
            "safe_reviewed": 0,
            "safe_review_rate": 0.0,
            "malicious_evaluated": malicious,
            "malicious_allows": 0,
            "malicious_allow_rate": 0.0,
            "malicious_blocked": malicious,
            "malicious_block_rate": 1.0,
            "malicious_reviewed": 0,
            "malicious_review_rate": 0.0,
            "malicious_detected": malicious,
            "malicious_detection_rate": 1.0,
            "dynamic_required": malicious,
            "dynamic_not_applicable": safe,
            "incomplete_required": 0,
        },
        "rule_matrix": {},
    }


def holdout_corpus(source_type: str = "vsix") -> dict:
    artifacts = []
    for index in range(5):
        artifact_sha256 = f"{index + 1:x}" * 64
        artifacts.append({
            "extension_id": f"safe.extension{index}",
            "version": f"1.0.{index}",
            "gate_required": True,
            "label": "known_safe",
            "label_evidence": {
                "source_type": "independent_review",
                "source_url": f"https://security.example.org/safe-extension-{index}",
                "retrieved_at": "2026-09-18T00:00:00Z",
                "evidence_scope": "exact-artifact",
                "extension_id": f"safe.extension{index}",
                "version": f"1.0.{index}",
                "artifact_sha256": artifact_sha256,
            },
            "artifact": {"source_type": source_type, "original_bytes_available": True, "sha256": artifact_sha256},
        })
    for index in range(5):
        artifact_sha256 = f"{index + 11:x}" * 64
        artifacts.append({
            "extension_id": f"bad.extension{index}",
            "version": f"9.9.{index}",
            "gate_required": True,
            "label": "known_malicious",
            "label_evidence": {
                "source_type": "independent_threat_report",
                "source_url": f"https://security.example.org/bad-extension-{index}",
                "retrieved_at": "2026-09-18T00:00:00Z",
                "evidence_scope": "exact-artifact",
                "extension_id": f"bad.extension{index}",
                "version": f"9.9.{index}",
                "artifact_sha256": artifact_sha256,
                "advisory_id": f"UNIT-ADVISORY-{index}",
            },
            "artifact": {"source_type": source_type, "original_bytes_available": True, "sha256": artifact_sha256},
        })
    return {
        "schema_version": "1.0",
        "corpus_id": "fresh-holdout",
        "corpus_version": "2026.09.18.1",
        "holdout": {
            "status": "fresh-labeled",
            "frozen_before_scan": True,
            "frozen_at": "2026-09-18T00:00:00Z",
            "original_bytes_available": True,
            "label_source": "independent-adjudication-2026-09-18",
            "provenance": {
                "source_sha256": "a" * 64,
                "advisory_snapshot_sha256": "b" * 64,
                "advisory_snapshot_version": "unit-test.1",
                "malicious_artifacts_with_exact_advisories": 5,
            },
        },
        "artifacts": artifacts,
    }


def holdout_gate() -> dict:
    result = gate("fresh-holdout", safe=5, malicious=5, version="2026.09.18.1")
    result["runtime_evidence"] = {
        "required": True,
        "runtime_enabled": True,
        "profile": "deep",
        "external_syscall_trace": True,
        "runtime_timeout_seconds": 20,
    }
    result["artifacts"] = []
    for index in range(5):
        result["artifacts"].append({
            "extension_id": f"safe.extension{index}",
            "version": f"1.0.{index}",
            "gate_required": True,
            "label": "known_safe",
            "scanned": True,
            "passed": True,
            "gate_passed": True,
            "actual": {
                "analysis_status": "complete",
                "verdict": "clean",
                "decision": "allow",
                "rule_ids": ["filesystem-access"],
                "artifact_sha256": f"{index + 1:x}" * 64,
                "runtime_contract": {
                    "coverage_status": "complete",
                    "required_providers_complete": True,
                    "required": False,
                    "provider_status": "not-applicable",
                    "execution": "policy-gated",
                    "runtime_policy": "capability-gated-v1",
                    "executed": False,
                    "external_syscall_trace": False,
                },
            },
        })
    for index in range(5):
        result["artifacts"].append({
            "extension_id": f"bad.extension{index}",
            "version": f"9.9.{index}",
            "gate_required": True,
            "label": "known_malicious",
            "scanned": True,
            "passed": True,
            "gate_passed": True,
            "actual": {
                "analysis_status": "complete",
                "verdict": "suspicious",
                "decision": "block",
                "rule_ids": ["download-and-execute"],
                "artifact_sha256": f"{index + 11:x}" * 64,
                "runtime_contract": {
                    "coverage_status": "complete",
                    "required_providers_complete": True,
                    "required": True,
                    "provider_status": "completed",
                    "runtime_run_status": "completed",
                    "execution": "controlled-bubblewrap",
                    "runtime_policy": "capability-gated-v1",
                    "executed": True,
                    "external_syscall_trace": True,
                },
            },
        })
    return result


class PublicationAccuracyGateTests(unittest.TestCase):
    def write(self, root: Path, name: str, value: dict) -> Path:
        path = root / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_combines_matching_regression_and_fresh_holdout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            regression = gate("regression")
            behavior = holdout_gate()
            behavior["classification_mode"] = "behavior-only"
            behavior["advisory_snapshot"] = {
                "status": "completed",
                "snapshot_version": "empty.1",
                "sha256": "c" * 64,
                "entry_count": 0,
            }
            result = build_publication_accuracy_gate(
                self.write(root, "regression.json", regression),
                self.write(root, "holdout.json", holdout_gate()),
                self.write(root, "corpus.json", holdout_corpus()),
                self.write(root, "behavior.json", behavior),
            )
        self.assertEqual(result["holdout"]["status"], "fresh-labeled")
        self.assertTrue(result["holdout"]["complete"])
        self.assertEqual(result["holdout"]["label_counts"], {"known_safe": 5, "known_malicious": 5})
        self.assertEqual(result["holdout"]["safe_review_rate"], 0.0)
        self.assertEqual(result["holdout"]["malicious_detection_rate"], 1.0)
        self.assertEqual(result["holdout"]["dynamic_required"], 5)
        self.assertEqual(result["holdout"]["dynamic_not_applicable"], 5)
        self.assertEqual(result["holdout"]["rule_matrix"]["download-and-execute"]["fired_on_known_malicious"], 5)
        self.assertEqual(result["holdout"]["behavior_only"]["status"], "behavior-only")
        self.assertEqual(result["holdout"]["behavior_only"]["malicious_detection_rate"], 1.0)
        self.assertEqual(result["report_identity"]["scanner_build"], BUILD)

    def test_rejects_fixture_only_holdout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "synthetic fixture"):
                build_publication_accuracy_gate(
                    self.write(root, "regression.json", gate("regression")),
                    self.write(root, "holdout.json", holdout_gate()),
                    self.write(root, "corpus.json", holdout_corpus("fixture_directory")),
                )

    def test_rejects_unknown_scanner_build(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            regression = gate("regression")
            regression["report_identity"]["scanner_build"] = "unknown"
            with self.assertRaisesRegex(ValueError, "full 40-character scanner build"):
                build_publication_accuracy_gate(
                    self.write(root, "regression.json", regression),
                    self.write(root, "holdout.json", holdout_gate()),
                    self.write(root, "corpus.json", holdout_corpus()),
                )

    def test_rejects_summary_without_exact_holdout_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            invalid = holdout_gate()
            del invalid["artifacts"]
            with self.assertRaisesRegex(ValueError, "one result row"):
                build_publication_accuracy_gate(
                    self.write(root, "regression.json", gate("regression")),
                    self.write(root, "holdout.json", invalid),
                    self.write(root, "corpus.json", holdout_corpus()),
                )

    def test_rejects_free_form_label_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corpus = holdout_corpus()
            corpus["artifacts"][0]["label_evidence"] = "operator says safe"
            with self.assertRaisesRegex(ValueError, "structured label evidence"):
                build_publication_accuracy_gate(
                    self.write(root, "regression.json", gate("regression")),
                    self.write(root, "holdout.json", holdout_gate()),
                    self.write(root, "corpus.json", corpus),
                )

    def test_rejects_evidence_retrieved_after_holdout_freeze(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corpus = holdout_corpus()
            corpus["holdout"]["frozen_at"] = "2026-09-18T00:00:00Z"
            corpus["artifacts"][0]["label_evidence"]["retrieved_at"] = "2026-09-19T00:00:00Z"
            with self.assertRaisesRegex(ValueError, "retrieved after the holdout was frozen"):
                build_publication_accuracy_gate(
                    self.write(root, "regression.json", gate("regression")),
                    self.write(root, "holdout.json", holdout_gate()),
                    self.write(root, "corpus.json", corpus),
                )

    def test_rejects_unapproved_label_evidence_source_type(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corpus = holdout_corpus()
            corpus["artifacts"][0]["label_evidence"]["source_type"] = "operator_assertion"
            with self.assertRaisesRegex(ValueError, "approved independent source_type"):
                build_publication_accuracy_gate(
                    self.write(root, "regression.json", gate("regression")),
                    self.write(root, "holdout.json", holdout_gate()),
                    self.write(root, "corpus.json", corpus),
                )

    def test_rejects_threat_report_as_known_safe_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corpus = holdout_corpus()
            corpus["artifacts"][0]["label_evidence"]["source_type"] = "independent_threat_report"
            with self.assertRaisesRegex(ValueError, "known_safe label requires independent safety evidence"):
                build_publication_accuracy_gate(
                    self.write(root, "regression.json", gate("regression")),
                    self.write(root, "holdout.json", holdout_gate()),
                    self.write(root, "corpus.json", corpus),
                )

    def test_accepts_independent_threat_report_with_osv_compatible_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corpus = holdout_corpus()
            corpus["artifacts"][5]["label_evidence"]["source_type"] = "independent_threat_report_and_osv_record"
            result = build_publication_accuracy_gate(
                self.write(root, "regression.json", gate("regression")),
                self.write(root, "holdout.json", holdout_gate()),
                self.write(root, "corpus.json", corpus),
            )

            self.assertEqual(result["holdout"]["label_counts"], {"known_safe": 5, "known_malicious": 5})

    def test_rejects_static_only_holdout_from_publication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            invalid = holdout_gate()
            invalid["runtime_evidence"]["required"] = False
            with self.assertRaisesRegex(ValueError, "required deep runtime"):
                build_publication_accuracy_gate(
                    self.write(root, "regression.json", gate("regression")),
                    self.write(root, "holdout.json", invalid),
                    self.write(root, "corpus.json", holdout_corpus()),
                )

    def test_rejects_holdout_without_both_runtime_surfaces(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            invalid = holdout_gate()
            invalid["summary"]["dynamic_required"] = 0
            with self.assertRaisesRegex(ValueError, "both executable-capability"):
                build_publication_accuracy_gate(
                    self.write(root, "regression.json", gate("regression")),
                    self.write(root, "holdout.json", invalid),
                    self.write(root, "corpus.json", holdout_corpus()),
                )

    def test_rejects_holdout_without_external_syscall_trace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            invalid = holdout_gate()
            invalid["runtime_evidence"]["external_syscall_trace"] = False
            with self.assertRaisesRegex(ValueError, "external syscall tracing"):
                build_publication_accuracy_gate(
                    self.write(root, "regression.json", gate("regression")),
                    self.write(root, "holdout.json", invalid),
                    self.write(root, "corpus.json", holdout_corpus()),
                )

    def test_rejects_small_fresh_holdout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            invalid = holdout_gate()
            invalid["summary"]["safe_evaluated"] = 4
            with self.assertRaisesRegex(ValueError, "at least 5 known-safe"):
                build_publication_accuracy_gate(
                    self.write(root, "regression.json", gate("regression")),
                    self.write(root, "holdout.json", invalid),
                    self.write(root, "corpus.json", holdout_corpus()),
                )

    def test_rejects_falsified_holdout_label_counts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            invalid = holdout_gate()
            invalid["summary"]["malicious_evaluated"] = 6
            with self.assertRaisesRegex(ValueError, "summary label counts"):
                build_publication_accuracy_gate(
                    self.write(root, "regression.json", gate("regression")),
                    self.write(root, "holdout.json", invalid),
                    self.write(root, "corpus.json", holdout_corpus()),
                )

    def test_rejects_holdout_row_without_classification_outcome(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            invalid = holdout_gate()
            invalid["artifacts"][0]["actual"].pop("verdict")
            with self.assertRaisesRegex(ValueError, "valid verdict and decision"):
                build_publication_accuracy_gate(
                    self.write(root, "regression.json", gate("regression")),
                    self.write(root, "holdout.json", invalid),
                    self.write(root, "corpus.json", holdout_corpus()),
                )

    def test_rejects_incomplete_holdout_decision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            invalid = holdout_gate()
            invalid["artifacts"][0]["actual"]["decision"] = "incomplete"
            with self.assertRaisesRegex(ValueError, "valid verdict and decision"):
                build_publication_accuracy_gate(
                    self.write(root, "regression.json", gate("regression")),
                    self.write(root, "holdout.json", invalid),
                    self.write(root, "corpus.json", holdout_corpus()),
                )

    def test_rejects_holdout_summary_not_derived_from_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            invalid = holdout_gate()
            invalid["summary"]["malicious_allows"] = 1
            with self.assertRaisesRegex(ValueError, "summary field 'malicious_allows'"):
                build_publication_accuracy_gate(
                    self.write(root, "regression.json", gate("regression")),
                    self.write(root, "holdout.json", invalid),
                    self.write(root, "corpus.json", holdout_corpus()),
                )

    def test_rejects_tampered_noise_metric(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            invalid = holdout_gate()
            invalid["summary"]["safe_review_rate"] = 1.0
            with self.assertRaisesRegex(ValueError, "safe review rate exceeds"):
                build_publication_accuracy_gate(
                    self.write(root, "regression.json", gate("regression")),
                    self.write(root, "holdout.json", invalid),
                    self.write(root, "corpus.json", holdout_corpus()),
                )

    def test_rejects_holdout_without_rule_level_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            invalid = holdout_gate()
            for result in invalid["artifacts"]:
                result["actual"]["rule_ids"] = []
            with self.assertRaisesRegex(ValueError, "at least one labelled rule firing"):
                build_publication_accuracy_gate(
                    self.write(root, "regression.json", gate("regression")),
                    self.write(root, "holdout.json", invalid),
                    self.write(root, "corpus.json", holdout_corpus()),
                )

    def test_rejects_gate_with_missing_required_check(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            regression = gate("regression")
            regression["gate"]["checks"].pop("incomplete_required")
            with self.assertRaisesRegex(ValueError, "missing check"):
                build_publication_accuracy_gate(
                    self.write(root, "regression.json", regression),
                    self.write(root, "holdout.json", holdout_gate()),
                    self.write(root, "corpus.json", holdout_corpus()),
                )

    def test_rejects_gate_with_missing_rate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            regression = gate("regression")
            del regression["summary"]["safe_block_rate"]
            with self.assertRaisesRegex(ValueError, "safe_block_rate must be a number"):
                build_publication_accuracy_gate(
                    self.write(root, "regression.json", regression),
                    self.write(root, "holdout.json", holdout_gate()),
                    self.write(root, "corpus.json", holdout_corpus()),
                )
