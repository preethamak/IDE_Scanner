from __future__ import annotations

import hashlib
import gzip
import json
import shutil
import subprocess
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scripts.scan_corpus import _canonical_artifact_sha256, _manifest_targets, _scan_one, _wait_for_worker


class ScanCorpusTests(unittest.TestCase):
    def test_manifest_requires_exact_identity_and_hash(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "example.vsix"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(
                    "extension/package.json",
                    '{"publisher":"example","name":"manifest","version":"1.0.0"}',
                )
            manifest = root / "corpus.json"
            manifest.write_text(json.dumps({
                "schema_version": "guardrails.corpus-manifest.v1",
                "artifacts": [{
                    "path": artifact.name,
                    "extension_id": "example.manifest",
                    "version": "1.0.0",
                    "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                }],
            }), encoding="utf-8")

            targets = _manifest_targets(manifest)
            result = _scan_one(targets[0], timeout=30, profile="quick")

        self.assertEqual(result["extension_id"], "example.manifest")
        self.assertEqual(result["analysis_status"], "complete")
        self.assertTrue(result["artifact_inventory"]["corpus_manifest"]["verified"])

    def test_manifest_identity_mismatch_becomes_incomplete(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "example.vsix"
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr(
                    "extension/package.json",
                    '{"publisher":"example","name":"manifest","version":"1.0.0"}',
                )
            manifest = root / "corpus.json"
            manifest.write_text(json.dumps({
                "schema_version": "guardrails.corpus-manifest.v1",
                "artifacts": [{
                    "path": artifact.name,
                    "extension_id": "attacker.replica",
                    "version": "1.0.0",
                    "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                }],
            }), encoding="utf-8")

            result = _scan_one(_manifest_targets(manifest)[0], timeout=30, profile="quick")

        self.assertEqual(result["decision"], "incomplete")
        self.assertFalse(result["artifact_inventory"]["corpus_manifest"]["verified"])
        self.assertIn("manifest identity check failed", result["artifact_inventory"]["skipped_reason"])

    def test_manifest_hash_failure_becomes_incomplete(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "example.vsix"
            artifact.write_bytes(b"artifact")
            target = {
                "path": str(artifact),
                "type": "vsix",
                "manifest_expected_extension_id": "example.manifest",
                "manifest_expected_version": "1.0.0",
                "manifest_expected_sha256": "0" * 64,
            }
            with patch("scripts.scan_corpus._canonical_artifact_sha256", side_effect=OSError("read failed")):
                result = _scan_one(target, timeout=30, profile="quick")

        self.assertEqual(result["decision"], "incomplete")
        self.assertFalse(result["artifact_inventory"]["corpus_manifest"]["verified"])
        self.assertIn("artifact could not be hashed", result["artifact_inventory"]["skipped_reason"])

    def test_manifest_hash_uses_unwrapped_vsix_identity(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw_vsix = root / "example.vsix"
            with zipfile.ZipFile(raw_vsix, "w") as archive:
                archive.writestr(
                    "extension/package.json",
                    '{"publisher":"example","name":"wrapped","version":"1.0.0"}',
                )
            wrapped = root / "example-wrapped.vsix"
            with raw_vsix.open("rb") as source, gzip.open(wrapped, "wb") as target:
                shutil.copyfileobj(source, target)
            expected_hash = hashlib.sha256(raw_vsix.read_bytes()).hexdigest()
            target = {
                "path": str(wrapped),
                "type": "vsix",
                "manifest_expected_extension_id": "example.wrapped",
                "manifest_expected_version": "1.0.0",
                "manifest_expected_sha256": expected_hash,
            }

            self.assertEqual(_canonical_artifact_sha256(wrapped), expected_hash)
            result = _scan_one(target, timeout=30, profile="quick")

        self.assertEqual(result["analysis_status"], "complete")
        self.assertTrue(result["artifact_inventory"]["corpus_manifest"]["verified"])

    def test_worker_timeout_reaps_stuck_process(self) -> None:
        process = subprocess.Popen(
            ["/usr/bin/python", "-c", "import time; time.sleep(60)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        try:
            self.assertFalse(_wait_for_worker(process, timeout=0.1))
            self.assertIsNotNone(process.poll())
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()


if __name__ == "__main__":
    unittest.main()
