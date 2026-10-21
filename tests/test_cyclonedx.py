from __future__ import annotations

import unittest

from ide_scanner.cyclonedx import build_cyclonedx_bom

class CycloneDxTests(unittest.TestCase):
    def test_cyclonedx_binds_dependencies_to_the_exact_extension_artifact(self) -> None:
        report = {"scan_id": "scan-1", "created_at": "2026-10-22T00:00:00Z", "scanner_build": "a" * 40, "extensions": [{
            "extension_id": "publisher.extension", "version": "1.2.3", "artifact_identity": {"sha256": "B" * 64},
            "decision": "review", "analysis_status": "complete", "analysis_coverage": {"coverage_percent": 91},
            "findings": [
                {"finding_id": "flow-1", "rule_id": "credential-network-flow", "severity": "HIGH", "evidence_summary": "A credential-like value reaches a network request.", "evidence_class": "correlated", "actionability": "review"},
                {"finding_id": "capability-1", "rule_id": "network-capability", "severity": "MEDIUM", "evidence_summary": "Network capability is declared.", "evidence_class": "capability", "actionability": "contextual"},
            ],
            "artifact_inventory": {"dependency_inventory": [{"name": "@scope/tool", "version": "4.5.6", "relationship": "direct"}, {"name": "transitive", "version": "1.0.0", "relationship": "transitive"}]},
        }]}
        bom = build_cyclonedx_bom(report, profile="deep", source="marketplace")
        extension_ref = "pkg:generic/publisher/extension@1.2.3?type=vsix"
        self.assertEqual(bom["bomFormat"], "CycloneDX")
        self.assertEqual(bom["specVersion"], "1.5")
        self.assertEqual(bom["serialNumber"], build_cyclonedx_bom(report)["serialNumber"])
        changed_evidence = json.loads(json.dumps(report))
        changed_evidence["extensions"][0]["findings"][0]["evidence_summary"] = "A different observed credential flow."
        self.assertNotEqual(bom["serialNumber"], build_cyclonedx_bom(changed_evidence)["serialNumber"])
        extension = next(component for component in bom["components"] if component["bom-ref"] == extension_ref)
        self.assertEqual(extension["hashes"], [{"alg": "SHA-256", "content": "b" * 64}])
        self.assertEqual(next(item for item in bom["dependencies"] if item["ref"] == extension_ref)["dependsOn"], ["pkg:npm/%40scope/tool@4.5.6", "pkg:npm/transitive@1.0.0"])
        self.assertEqual(len(bom["vulnerabilities"]), 1)
        vulnerability = bom["vulnerabilities"][0]
        self.assertEqual(vulnerability["affects"], [{"ref": extension_ref}])
        self.assertEqual(vulnerability["ratings"], [{"method": "other", "severity": "high"}])
        self.assertIn({"name": "guardrails:actionability", "value": "review"}, vulnerability["properties"])

    def test_cyclonedx_falls_back_to_resolved_dependency_map_and_rejects_invalid_hashes(self) -> None:
        bom = build_cyclonedx_bom({"extensions": [{"extension_id": "publisher.extension", "version": "1", "artifact_hash": "not-a-hash", "dependencies": {"left-pad": "1.3.0"}}]})
        extension = next(component for component in bom["components"] if component["type"] == "application")
        self.assertEqual(extension["hashes"], [])
        self.assertIn("pkg:npm/left-pad@1.3.0", [component["bom-ref"] for component in bom["components"]])
