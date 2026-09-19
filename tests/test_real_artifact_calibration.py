from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from ide_scanner.scanner import scan_targets


BCAI_ARTIFACT = Path(__file__).parents[1] / "benchmarks" / "external" / "artifacts" / "bcai-rosetta-4.0.37" / "bcai-rosetta-4.0.37.vsix"
BCAI_SHA256 = "b1b9785cdc7be479061f121f282391fba9be013d896d9a54f395621634709216"


class RealArtifactCalibrationTests(unittest.TestCase):
    def test_bcai_rosetta_behavior_is_reviewed_without_threat_intelligence(self) -> None:
        """Keep one independently reported artifact as a reproducible calibration case.

        The empty advisory snapshot is intentional: this test proves that the
        artifact's static behavior still routes to review without depending on
        the exact-hash intelligence entry. It does not claim a first discovery.
        """
        self.assertTrue(BCAI_ARTIFACT.is_file(), BCAI_ARTIFACT)
        with TemporaryDirectory() as directory:
            advisory_path = Path(directory) / "empty-advisories.json"
            advisory_path.write_text(
                json.dumps({"snapshot_version": "empty-test", "entries": []}),
                encoding="utf-8",
            )
            report = scan_targets(
                paths=[BCAI_ARTIFACT],
                online=False,
                include_posture=False,
                extension_advisories_file=advisory_path,
            )

        extension = report["extensions"][0]
        rule_ids = {str(item.get("rule_id")) for item in extension["findings"]}
        self.assertEqual(extension["artifact_hash"], BCAI_SHA256)
        self.assertEqual(extension["extension_id"], "bingcha.bcai-tools")
        self.assertEqual(extension["version"], "4.0.37")
        self.assertEqual(extension["analysis_status"], "complete")
        self.assertEqual(extension["decision"], "review")
        self.assertEqual(extension["verdict"], "review")
        self.assertEqual(extension["malware_score"], 0)
        # The shipped token-proxy file contains connectivity probes using
        # HEAD/CONNECT plus local registry queries. Those are not a download
        # and execute chain; keep this real artifact as a regression against
        # that false-positive shape. The exact advisory remains the
        # authoritative malicious decision in the companion test.
        self.assertNotIn("download-and-execute", rule_ids)
        self.assertIn("dynamic-shell-execution", rule_ids)
        self.assertIn("remote-credential-broker", rule_ids)

    def test_bcai_rosetta_exact_advisory_blocks_the_real_artifact(self) -> None:
        """The independently reported exact artifact remains a confirmed block."""
        self.assertTrue(BCAI_ARTIFACT.is_file(), BCAI_ARTIFACT)
        report = scan_targets(
            paths=[BCAI_ARTIFACT],
            online=False,
            include_posture=False,
        )

        extension = report["extensions"][0]
        self.assertEqual(extension["artifact_hash"], BCAI_SHA256)
        self.assertEqual(extension["decision"], "block")
        self.assertEqual(extension["verdict"], "malicious")
        self.assertEqual(extension["malware_score"], 100)
        self.assertEqual(extension["public_outcome"], "confirmed_threat")
        self.assertTrue(any(item["rule_id"] == "known-malicious-extension" for item in extension["findings"]))


if __name__ == "__main__":
    unittest.main()
