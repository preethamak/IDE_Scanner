import unittest
from types import SimpleNamespace

from ide_scanner.classification_policy import effective_finding_severity, finding_actionability
from ide_scanner.report_bundle import _rank_findings, _security_dimensions, grade_extension
from ide_scanner.scanner import _classify_findings, _finding


class ClassificationPolicyV3Tests(unittest.TestCase):
    def finding(self, rule_id: str, evidence_class: str, severity: str = "MEDIUM", evidence=None):
        return _finding(
            "example.extension", "1.0.0", rule_id, "test", severity, 0.9,
            "Test evidence.", ["extension.js"], "Review evidence.",
            {"evidence_class": evidence_class, **(evidence or {})},
        )

    def test_capability_power_is_contextual(self) -> None:
        finding = self.finding("process-execution", "capability")
        verdict, _, _, severity, _, risk, _ = _classify_findings([finding])
        self.assertEqual(finding_actionability(finding), "contextual")
        self.assertEqual((verdict, severity, risk), ("clean", "INFO", 0))

    def test_contextual_raw_high_does_not_deduct_from_security_dimension(self) -> None:
        finding = self.finding("process-execution", "capability", "HIGH")
        extension = SimpleNamespace(
            findings=[finding],
            analysis_coverage={"status": "complete", "coverage_percent": 100, "providers": {}},
        )

        dimensions = _security_dimensions(extension)

        self.assertEqual(dimensions["behavior_safety"]["score"], 100)
        self.assertEqual(dimensions["behavior_safety"]["deductions"], [])

    def test_webview_hardening_note_is_low_without_review(self) -> None:
        finding = self.finding("webview-csp-missing", "capability")
        verdict, _, _, severity, _, risk, _ = _classify_findings([finding])
        self.assertEqual(finding_actionability(finding), "low")
        self.assertEqual(effective_finding_severity(finding), "LOW")
        self.assertEqual(verdict, "clean")
        self.assertEqual(severity, "LOW")
        self.assertGreater(risk, 0)

    def test_isolated_credential_state_storage_is_low_without_review(self) -> None:
        finding = self.finding("credential-global-state-storage", "exposure", "HIGH")
        verdict, _, _, severity, _, risk, _ = _classify_findings([finding])
        self.assertEqual(finding_actionability(finding), "low")
        self.assertEqual((verdict, severity), ("clean", "LOW"))
        self.assertGreater(risk, 0)

    def test_credential_network_proximity_is_low_without_dataflow_proof(self) -> None:
        finding = self.finding("credential-source-near-network", "exposure", "HIGH")
        verdict, _, _, severity, _, risk, _ = _classify_findings([finding])
        self.assertEqual(finding_actionability(finding), "low")
        self.assertEqual((verdict, severity), ("clean", "LOW"))
        self.assertGreater(risk, 0)

    def test_isolated_secret_read_is_low_without_exfiltration(self) -> None:
        finding = self.finding("observed-secret-read", "observed", "MEDIUM")
        verdict, _, _, severity, _, risk, _ = _classify_findings([finding])
        self.assertEqual(finding_actionability(finding), "low")
        self.assertEqual((verdict, severity), ("clean", "LOW"))
        self.assertGreater(risk, 0)

    def test_unverified_binary_is_a_low_hardening_note(self) -> None:
        finding = self.finding("binary-without-origin", "provenance")
        verdict, _, _, severity, _, _, _ = _classify_findings([finding])
        self.assertEqual(finding_actionability(finding), "low")
        self.assertEqual((verdict, severity), ("clean", "LOW"))

    def test_packed_artifact_presence_is_contextual(self) -> None:
        finding = self.finding("packed-artifact", "provenance")
        verdict, _, _, severity, _, risk, _ = _classify_findings([finding])
        self.assertEqual(finding_actionability(finding), "contextual")
        self.assertEqual((verdict, severity, risk), ("clean", "INFO", 0))

    def test_unresolved_dependency_range_is_contextual(self) -> None:
        finding = self.finding("vulnerable-npm-dependency", "dependency", "HIGH", {"exact": False})
        verdict, _, _, severity, _, risk, _ = _classify_findings([finding])
        self.assertEqual(finding_actionability(finding), "contextual")
        self.assertEqual((verdict, severity, risk), ("clean", "INFO", 0))

    def test_exact_vulnerable_dependency_requires_review(self) -> None:
        finding = self.finding("vulnerable-npm-dependency", "dependency", "HIGH", {"exact": True})
        verdict, _, _, severity, _, _, _ = _classify_findings([finding])
        self.assertEqual((verdict, severity), ("review", "HIGH"))

    def test_exact_extension_vulnerability_can_block_without_malware_label(self) -> None:
        finding = self.finding(
            "known-vulnerable-extension",
            "vulnerability",
            "HIGH",
            {"exact": True, "policy_action": "block"},
        )
        verdict, _, authority, severity, malware, risk, _ = _classify_findings([finding])
        self.assertEqual(finding_actionability(finding), "block")
        self.assertEqual((verdict, authority, severity), ("review", "none", "HIGH"))
        self.assertEqual(malware, 0)
        self.assertGreater(risk, 0)

    def test_dashboard_grade_ignores_contextual_raw_high_severity(self) -> None:
        finding = self.finding("process-execution", "capability", "HIGH")
        self.assertEqual(grade_extension("review", 30, 0, [finding]), "B")

    def test_dashboard_grade_keeps_actionable_high_severity(self) -> None:
        finding = self.finding("vulnerable-npm-dependency", "dependency", "HIGH", {"exact": True})
        self.assertEqual(grade_extension("review", 30, 0, [finding]), "C")

    def test_report_headlines_rank_actionable_evidence_above_context(self) -> None:
        contextual = self.finding("process-execution", "capability", "HIGH")
        correlated = self.finding("credential-exfiltration-chain", "correlated", "MEDIUM")
        self.assertEqual(
            [item.rule_id for item in _rank_findings([contextual, correlated])],
            ["credential-exfiltration-chain", "process-execution"],
        )


if __name__ == "__main__":
    unittest.main()
