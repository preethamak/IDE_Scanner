import unittest

from ide_scanner.models import ExtensionReport, Finding
from ide_scanner.public_outcomes import _repository_owner_match, apply_public_assessment


class RepositoryOwnerMatchTests(unittest.TestCase):
    def test_matches_owner_repo_pair_case_insensitively(self) -> None:
        self.assertTrue(
            _repository_owner_match("https://github.com/Dart-Code/Dart-Code", ["dart-code/dart-code"])
        )

    def test_strips_git_suffix(self) -> None:
        """Marketplace manifests overwhelmingly use ``.git`` URLs; the segment
        comparison must normalize the suffix or every real profile fails."""
        self.assertTrue(
            _repository_owner_match("https://github.com/Dart-Code/Dart-Code.git", ["dart-code/dart-code"])
        )
        self.assertTrue(
            _repository_owner_match("https://github.com/MICROSOFT/vscode-python-environments.GIT", [
                "microsoft/vscode-python-environments"
            ])
        )

    def test_rejects_substring_and_path_spoofs(self) -> None:
        self.assertFalse(
            _repository_owner_match("https://github.com/attacker/dart-code.git", ["dart-code/dart-code"])
        )
        self.assertFalse(
            _repository_owner_match("https://github.com/dart-code/dart-code-extra.git", ["dart-code/dart-code"])
        )
        self.assertFalse(
            _repository_owner_match("https://gitlab.com/dart-code/dart-code.git", ["dart-code/dart-code"])
        )
        self.assertFalse(_repository_owner_match("", ["dart-code/dart-code"]))
        self.assertFalse(_repository_owner_match("https://github.com/dart-code/dart-code.git", []))


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
        self.assertEqual(report.capability_assessment["contract_class"], "formatter_linter")
        self.assertEqual(report.capability_assessment["forbidden_observed"], ["credential_input"])

    def test_unprofiled_theme_is_classified_but_not_established(self) -> None:
        report = _report()
        report.extension_id = "unknown.pretty-theme"
        report.publisher = "unknown"
        report.name = "Pretty Theme"
        report.description = "A color theme"
        report.repository = ""
        apply_public_assessment(report)

        classification = report.capability_assessment["classification"]
        self.assertEqual(classification["primary"], "theme")
        self.assertEqual(report.provenance["tier"], "verified")
        self.assertNotEqual(report.public_outcome, "expected_capability")


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
        artifact_inventory={
            # Established provenance now requires registry hash binding: the
            # scanned VSIX must be the marketplace-served artifact.
            "vsix_signature": {
                "package_integrity": {
                    "matched": True,
                    "expected": artifact_hash,
                    "actual": artifact_hash,
                    "source": "vs-marketplace-version-property",
                },
            },
        },
        findings=[verified, capability],
        scanned_files=1,
        decision="review",
        decision_reason="Capability needs context.",
        artifact_identity={
            "extension_id": "dbaeumer.vscode-eslint",
            "version": "3.0.33",
            "sha256": artifact_hash,
            "original_registry_artifact": True,
        },
        analysis_coverage={"status": "complete", "coverage_percent": 100},
    )


if __name__ == "__main__":
    unittest.main()
