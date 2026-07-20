import unittest

from ide_scanner.models import ExtensionReport, Finding
from ide_scanner.public_outcomes import apply_public_assessment


class PublicOutcomeTests(unittest.TestCase):
    def test_established_profile_explains_capability_without_overriding_review(self) -> None:
        report = _report()
        apply_public_assessment(report)

        self.assertEqual(report.decision, "review")
        self.assertEqual(report.public_outcome, "expected_capability")
        self.assertEqual(report.provenance["tier"], "established")
        self.assertEqual(report.capability_assessment["unexpected"], [])

    def test_unexpected_capability_stays_investigatory(self) -> None:
        report = _report()
        report.capabilities.append({"id": "credential_input", "evidence": ["extension.js"]})
        apply_public_assessment(report)

        self.assertEqual(report.decision, "review")
        self.assertEqual(report.public_outcome, "investigate")
        self.assertEqual(report.capability_assessment["unexpected"], ["credential_input"])


def _report() -> ExtensionReport:
    artifact_hash = "a" * 64
    verified = Finding(
        finding_id="verified",
        extension_id="dbaeumer.vscode-eslint",
        version="3.0.33",
        rule_id="marketplace-verified-publisher",
        category="reputation",
        severity="INFO",
        confidence=0.95,
        score=0,
        evidence_type="registry",
        evidence_summary="Marketplace metadata reports a verified publisher.",
        evidence={"evidence_class": "reputation", "publisher_verified": True},
    )
    capability = Finding(
        finding_id="process",
        extension_id="dbaeumer.vscode-eslint",
        version="3.0.33",
        rule_id="untrusted-workspace-input-to-process",
        category="execution",
        severity="MEDIUM",
        confidence=0.8,
        score=50,
        evidence_type="static",
        evidence_summary="Configuration reaches process execution.",
        evidence={"evidence_class": "capability"},
    )
    return ExtensionReport(
        instance_id="eslint",
        extension_id="dbaeumer.vscode-eslint",
        name="vscode-eslint",
        publisher="dbaeumer",
        version="3.0.33",
        description="ESLint integration",
        repository="https://github.com/microsoft/vscode-eslint",
        install_path="/tmp/eslint",
        source="vs-marketplace",
        artifact_hash=artifact_hash,
        severity="MEDIUM",
        verdict="review",
        malware_authority="none",
        verdict_reason="Capability needs context.",
        malware_score=0,
        risk_score=51,
        score_details={"confidence": "medium"},
        capabilities=[{"id": "activation", "evidence": []}, {"id": "process_execution", "evidence": ["extension.js"]}],
        artifact_inventory={},
        findings=[verified, capability],
        scanned_files=1,
        decision="review",
        decision_reason="Capability needs context.",
        artifact_identity={"extension_id": "dbaeumer.vscode-eslint", "version": "3.0.33", "sha256": artifact_hash},
        analysis_coverage={"status": "complete", "coverage_percent": 100},
    )


if __name__ == "__main__":
    unittest.main()
