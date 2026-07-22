import unittest

from ide_scanner.classification_policy import effective_finding_severity, finding_actionability
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

    def test_unattributed_binary_requires_low_severity_review(self) -> None:
        finding = self.finding("binary-without-origin", "provenance")
        verdict, _, _, severity, _, _, _ = _classify_findings([finding])
        self.assertEqual(finding_actionability(finding), "review")
        self.assertEqual((verdict, severity), ("review", "LOW"))

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


if __name__ == "__main__":
    unittest.main()
