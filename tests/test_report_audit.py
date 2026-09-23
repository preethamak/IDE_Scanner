import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
import json

from scripts.audit_report import _load_corrections, _load_labels, audit_report


class ReportAuditTests(unittest.TestCase):
    def test_counts_rule_volume_and_mixed_outcomes(self) -> None:
        result = audit_report({
            "scan_id": "scan-1",
            "scanner_build": "build-1",
            "ruleset_version": "rules-1",
            "extensions": [
                {"extension_id": "publisher.clean", "version": "1.0.0", "verdict": "clean", "findings": [{"rule_id": "dynamic-code-loading", "evidence": {"evidence_class": "weak"}}]},
                {"extension_id": "publisher.review", "version": "1.0.0", "verdict": "review", "findings": [{"rule_id": "dynamic-code-loading", "evidence": {"evidence_class": "weak"}, "actionability": "review"}]},
            ],
        })

        self.assertEqual(result["summary"]["total_extensions"], 2)
        self.assertEqual(result["rule_observations"][0]["rule_id"], "dynamic-code-loading")
        self.assertTrue(result["rule_observations"][0]["mixed_outcome"])
        self.assertEqual(result["rule_observations"][0]["finding_count"], 2)
        self.assertEqual(result["rule_observations"][0]["extension_count"], 2)
        self.assertEqual(result["rule_observations"][0]["actionability_counts"], {"contextual": 1, "review": 1})
        self.assertEqual(result["summary"]["finding_actionability_counts"], {"contextual": 1, "review": 1})
        self.assertEqual(result["summary"]["actionable_finding_count"], 1)
        self.assertEqual(result["summary"]["extensions_with_actionable_findings"], 1)
        self.assertEqual(result["extensions"][0]["actionability_counts"], {"contextual": 1})

    def test_rule_outcomes_are_deduplicated_per_extension(self) -> None:
        result = audit_report({
            "extensions": [
                {
                    "extension_id": "publisher.clean",
                    "version": "1.0.0",
                    "verdict": "clean",
                    "findings": [
                        {"rule_id": "network-access", "evidence": {"evidence_class": "weak"}},
                        {"rule_id": "network-access", "evidence": {"evidence_class": "weak"}},
                    ],
                },
            ],
        })

        observation = result["rule_observations"][0]
        self.assertEqual(observation["finding_count"], 2)
        self.assertEqual(observation["extension_count"], 1)
        self.assertEqual(observation["clean_extension_count"], 1)
        self.assertEqual(observation["review_or_higher_extension_count"], 0)
        self.assertEqual(observation["routing_outcome_counts"], {"clean": 1})
        self.assertEqual(observation["actionability_counts"], {"contextual": 2})

    def test_labels_report_routing_mismatches_without_claiming_malware_accuracy(self) -> None:
        result = audit_report({
            "extensions": [
                {"extension_id": "publisher.allowed", "verdict": "review", "findings": []},
                {"extension_id": "publisher.bad", "verdict": "clean", "findings": []},
            ],
        }, {"publisher.allowed": "allow", "publisher.bad": "malicious"})

        self.assertEqual(result["label_metrics"]["labeled_extensions"], 2)
        self.assertEqual(result["label_metrics"]["false_positive_review_count"], 1)
        self.assertEqual(result["label_metrics"]["false_negative_malware_count"], 1)
        self.assertEqual(len(result["label_metrics"]["mismatches"]), 2)

    def test_labels_are_resolved_by_exact_artifact_before_extension_fallback(self) -> None:
        result = audit_report({
            "extensions": [
                {"extension_id": "publisher.same", "version": "1.0.0", "verdict": "clean", "findings": []},
                {"extension_id": "publisher.same", "version": "2.0.0", "verdict": "review", "findings": []},
            ],
        }, {
            "publisher.same@1.0.0": "allow",
            "publisher.same@2.0.0": "review",
        })

        self.assertEqual(result["label_metrics"]["labeled_extensions"], 2)
        self.assertEqual(result["label_metrics"]["mismatches"], [])

    def test_label_corrections_override_frozen_exact_artifact_labels(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            labels = root / "labels.json"
            labels.write_text(json.dumps({"samples": [{
                "extension_id": "publisher.same",
                "version": "2.0.0",
                "expected_decision": "review",
            }]}), encoding="utf-8")
            corrections = root / "corrections.json"
            corrections.write_text(json.dumps({"corrections": [{
                "extension_id": "publisher.same",
                "version": "2.0.0",
                "corrected_expected_decision": "allow",
            }]}), encoding="utf-8")

            loaded = {**_load_labels(labels), **_load_corrections(corrections)}
            result = audit_report({
                "extensions": [{
                    "extension_id": "publisher.same",
                    "version": "2.0.0",
                    "verdict": "clean",
                    "findings": [],
                }],
            }, loaded)

        self.assertEqual(result["label_metrics"]["labeled_extensions"], 1)
        self.assertEqual(result["label_metrics"]["mismatches"], [])


if __name__ == "__main__":
    unittest.main()
