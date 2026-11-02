from __future__ import annotations

import unittest

from ide_scanner.sarif import report_to_sarif


class SarifExportTests(unittest.TestCase):
    def test_omits_location_when_the_finding_has_no_file_evidence(self) -> None:
        sarif = report_to_sarif({
            "scan_id": "scan_without_location",
            "extensions": [{
                "extension_id": "publisher.extension",
                "version": "1.2.3",
                "findings": [{"rule_id": "marketplace-removed-malware", "severity": "CRITICAL", "evidence_summary": "Removed by Marketplace."}],
            }],
        })

        result = sarif["runs"][0]["results"][0]
        self.assertEqual(result["level"], "error")
        self.assertNotIn("locations", result)
        self.assertEqual(result["properties"]["extension_id"], "publisher.extension")


if __name__ == "__main__":
    unittest.main()
