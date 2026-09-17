import unittest

from ide_scanner.models import ExtensionReport, Finding
from ide_scanner.public_outcomes import apply_public_assessment
from ide_scanner.trust_tiers import derive_trust_tier


class TrustTierTests(unittest.TestCase):
    def test_incomplete_analysis_stays_unanalyzed(self) -> None:
        report = _report(decision="incomplete", analysis_status="incomplete")
        assessment = derive_trust_tier(report)

        self.assertEqual(assessment.tier, "unanalyzed")
        self.assertEqual(assessment.label, "Analysis pending")

    def test_clean_complete_analysis_is_analyzed(self) -> None:
        report = _report(decision="allow")
        assessment = derive_trust_tier(report)

        self.assertEqual(assessment.tier, "analyzed")
        self.assertEqual(
            assessment.label,
            "Analyzed \u00b7 capabilities documented",
        )

    def test_expected_capability_without_behavioral_run_is_not_verified(self) -> None:
        report = _report(decision="review")
        apply_public_assessment(report)

        self.assertEqual(report.public_outcome, "expected_capability")
        self.assertEqual(derive_trust_tier(report).tier, "analyzed")

    def test_behavioral_verification_earns_verified(self) -> None:
        report = _report(decision="review")
        report.capability_assessment["behavioral_verification"] = {
            "status": "complete",
            "matches_declaration": True,
        }
        apply_public_assessment(report)

        self.assertEqual(report.public_outcome, "expected_capability")
        assessment = derive_trust_tier(report)
        self.assertEqual(assessment.tier, "verified")
        self.assertIn("matches declaration", assessment.label)

    def test_unexpected_capability_is_attention_and_names_the_count(self) -> None:
        report = _report(decision="review")
        report.capabilities.append({"id": "credential_input", "evidence": ["extension.js"]})
        assessment = derive_trust_tier(report)

        self.assertEqual(assessment.tier, "attention")
        self.assertIn("1 undeclared", assessment.label.lower())

    def test_investigate_outcome_is_attention(self) -> None:
        report = _report(decision="review")
        report.findings.append(_finding("obfuscated-eval", "code", "HIGH", "correlated"))
        apply_public_assessment(report)

        self.assertEqual(report.public_outcome, "investigate")
        self.assertEqual(derive_trust_tier(report).tier, "attention")

    def test_preventive_block_is_attention_not_confirmed_risk(self) -> None:
        report = _report(decision="block")
        assessment = derive_trust_tier(report)

        self.assertEqual(assessment.tier, "attention")

    def test_suspicious_verdict_is_attention(self) -> None:
        report = _report(decision="review", verdict="suspicious")
        assessment = derive_trust_tier(report)

        self.assertEqual(assessment.tier, "attention")

    def test_malicious_verdict_is_confirmed_risk(self) -> None:
        report = _report(decision="block", verdict="malicious", evidence_confidence="confirmed")
        assessment = derive_trust_tier(report)

        self.assertEqual(assessment.tier, "confirmed_risk")
        self.assertIn("evidence", assessment.summary.lower())

    def test_apply_public_assessment_populates_tier_fields(self) -> None:
        report = _report(decision="allow")
        apply_public_assessment(report)

        self.assertEqual(report.trust_tier, "analyzed")
        self.assertTrue(report.trust_tier_label)
        self.assertTrue(report.trust_tier_reason)


def _finding(rule_id: str, category: str, severity: str, evidence_class: str) -> Finding:
    return Finding(
        finding_id=rule_id,
        extension_id="dbaeumer.vscode-eslint",
        version="3.0.33",
        rule_id=rule_id,
        category=category,
        severity=severity,
        confidence=0.8,
        score=50,
        evidence_type="static",
        evidence_summary=f"{rule_id} observed.",
        evidence={"evidence_class": evidence_class},
    )


def _report(
    *,
    decision: str,
    verdict: str = "review",
    analysis_status: str = "complete",
    evidence_confidence: str | None = None,
) -> ExtensionReport:
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
        score=50 if decision != "allow" else 0,
        evidence_type="static",
        evidence_summary="Configuration reaches process execution.",
        evidence={
            "evidence_class": "capability" if decision != "allow" else "weak",
            **({} if evidence_confidence is None else {}),
        },
    )
    kwargs: dict = {}
    if evidence_confidence is not None:
        kwargs["evidence_confidence"] = evidence_confidence
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
        severity="INFO" if decision == "allow" else "MEDIUM",
        verdict=verdict,
        malware_authority="none",
        verdict_reason="Capability needs context.",
        malware_score=0,
        risk_score=51 if decision != "allow" else 0,
        score_details={"confidence": "medium"},
        capabilities=[{"id": "activation", "evidence": []}, {"id": "process_execution", "evidence": ["extension.js"]}],
        artifact_inventory={},
        findings=[verified, capability],
        scanned_files=1,
        decision=decision,
        decision_reason="Capability needs context.",
        artifact_identity={"extension_id": "dbaeumer.vscode-eslint", "version": "3.0.33", "sha256": artifact_hash},
        analysis_coverage={"status": "complete", "coverage_percent": 100},
        analysis_status=analysis_status,
        **kwargs,
    )


if __name__ == "__main__":
    unittest.main()
