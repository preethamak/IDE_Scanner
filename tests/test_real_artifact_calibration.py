from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from ide_scanner.scanner import scan_targets


BCAI_ARTIFACT = Path(__file__).parents[1] / "benchmarks" / "external" / "artifacts" / "bcai-rosetta-4.0.37" / "bcai-rosetta-4.0.37.vsix"
BCAI_SHA256 = "b1b9785cdc7be479061f121f282391fba9be013d896d9a54f395621634709216"
SAFE_CONTROLS = (
    (
        "nrwl.angular-console",
        "18.94.0",
        Path(__file__).parents[1] / "benchmarks" / "external" / "artifacts" / "public-holdout-2026-09-18" / "nrwl-angular-console-18.94.0.vsix",
        "228a2cf081d4cbea9b91cde14a8f9c4a4d003e7f32431496953fd6bac266f5a3",
    ),
    (
        "streetsidesoftware.code-spell-checker",
        "4.5.6",
        Path(__file__).parents[1] / "benchmarks" / "external" / "artifacts" / "code-spell-checker-4.5.6" / "code-spell-checker-4.5.6.vsix",
        "b271bd7ebc445960ecb3cb730da57f22f55abc7411ac94806ab8fe44df8a5c44",
    ),
    (
        "redhat.vscode-yaml",
        "1.24.0",
        Path(__file__).parents[1] / "benchmarks" / "external" / "artifacts" / "vscode-yaml-1.24.0" / "vscode-yaml-1.24.0-298.vsix",
        "0668758312a7fa6beda259ca5a6849d90c5d519df6415edbe246c135e06d7168",
    ),
    (
        "rust-lang.rust-analyzer",
        "0.3.2971",
        Path(__file__).parents[1] / "benchmarks" / "external" / "artifacts" / "rust-analyzer-no-server-2026-07-13" / "rust-analyzer-no-server.vsix",
        "34ac3f72a70a04d2dea5c900c413a651e58c0e8745851aaf5966a951552e22aa",
    ),
    (
        "ms-python.python",
        "2026.5.2026070801",
        Path(__file__).parents[1] / "benchmarks" / "external" / "artifacts" / "public-holdout-2026-09-18" / "ms-python.python-2026.5.2026070801.vsix",
        "95d8af5d113124f8795a31fffe9eae75fafc7ed4de73ae1a90656cf166aebefa",
    ),
)


class RealArtifactCalibrationTests(unittest.TestCase):
    @unittest.skipUnless(
        all(path.is_file() for _, _, path, _ in SAFE_CONTROLS),
        "exact safe-control VSIX artifacts are not provisioned; run the production-gate artifact setup first",
    )
    def test_exact_safe_controls_stay_clean_and_contextual(self) -> None:
        """Protect the no-noise boundary on independently labelled controls."""
        for extension_id, version, artifact, expected_hash in SAFE_CONTROLS:
            with self.subTest(extension_id=extension_id, version=version):
                report = scan_targets(
                    paths=[artifact],
                    online=False,
                    include_posture=False,
                )
                extension = report["extensions"][0]
                self.assertEqual(extension["artifact_hash"], expected_hash)
                self.assertEqual(extension["extension_id"], extension_id)
                self.assertEqual(extension["version"], version)
                self.assertEqual(extension["analysis_status"], "complete")
                self.assertEqual(extension["decision"], "allow")
                self.assertEqual(extension["verdict"], "clean")
                self.assertEqual(extension["risk_score"], 0)
                self.assertEqual(extension["malware_score"], 0)
                self.assertTrue(extension["findings"])
                self.assertTrue(all(item.get("actionability") == "contextual" for item in extension["findings"]))

    @unittest.skipUnless(
        BCAI_ARTIFACT.is_file(),
        "exact BCAI VSIX is not provisioned; run the production-gate artifact setup first",
    )
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

    @unittest.skipUnless(
        BCAI_ARTIFACT.is_file(),
        "exact BCAI VSIX is not provisioned; run the production-gate artifact setup first",
    )
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
