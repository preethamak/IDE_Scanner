from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from ide_scanner.scanner import scan_extension


class ExtensionRelationshipTests(unittest.TestCase):
    def test_records_deduplicated_pack_and_dependency_references_as_contextual_evidence(self) -> None:
        with TemporaryDirectory() as temp:
            report = scan_extension(
                Path(temp),
                manifest_override={
                    "publisher": "example",
                    "name": "bundle",
                    "version": "1.0.0",
                    "extensionPack": ["vendor.alpha", "vendor.alpha", "not an extension"],
                    "extensionDependencies": ["vendor.beta", "https://marketplace.visualstudio.com/items?itemName=vendor.beta"],
                },
            )

        self.assertEqual(
            report.artifact_inventory["declared_extension_relationships"],
            [
                {"extension_id": "vendor.beta", "relationship": "extension_dependency"},
                {"extension_id": "vendor.alpha", "relationship": "extension_pack"},
            ],
        )
        finding = next(item for item in report.findings if item.rule_id == "declared-extension-relationships")
        self.assertEqual(finding.evidence["evidence_class"], "capability")
        self.assertFalse(finding.evidence["version_pinned"])
        self.assertEqual(report.verdict, "clean")


if __name__ == "__main__":
    unittest.main()
