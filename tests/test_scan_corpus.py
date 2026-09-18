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

from scripts.scan_corpus import _canonical_artifact_sha256, _checkpoint_context, _checkpoint_path, _load_checkpoint, _manifest_targets, _parser, _scan_one, _wait_for_worker, _worker_command, _write_checkpoint, run


class ScanCorpusTests(unittest.TestCase):
    def test_parser_exposes_runtime_controls(self) -> None:
        args = _parser().parse_args(["--path", ".", "--out", "report.json", "--runtime", "--runtime-timeout", "30"])
        self.assertTrue(args.runtime)
        self.assertEqual(args.runtime_timeout, 30)

    def test_parser_accepts_deep_runtime_holdout_profile(self) -> None:
        args = _parser().parse_args(["--manifest", "corpus.json", "--profile", "deep", "--runtime", "--out", "report.json"])
        self.assertEqual(args.profile, "deep")
        self.assertTrue(args.runtime)

    def test_deep_profile_rejects_static_only_corpus_runs(self) -> None:
        args = _parser().parse_args(["--manifest", "corpus.json", "--profile", "deep", "--out", "report.json"])
        with self.assertRaisesRegex(ValueError, "deep profile requires --runtime"):
            run(args)

    def test_runtime_controls_reach_each_isolated_worker(self) -> None:
        command = _worker_command(Path("artifact.vsix"), "benchmark", Path("report.json"), runtime=True, runtime_timeout=30)
        self.assertIn("--runtime", command)
        self.assertEqual(command[command.index("--runtime-timeout") + 1], "30")

    def test_runtime_observation_kinds_survive_corpus_aggregation(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"runtime","version":"1.0.0","main":"extension.js"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text("module.exports = { activate() {} };", encoding="utf-8")
            args = _parser().parse_args([
                "--path", str(root),
                "--profile", "deep",
                "--runtime",
                "--out", str(root / "report.json"),
            ])
            extension = {
                "extension_id": "example.runtime",
                "version": "1.0.0",
                "analysis_status": "complete",
                "decision": "allow",
                "verdict": "clean",
                "artifact_hash": "a" * 64,
                "analysis_coverage": {"status": "complete", "coverage_percent": 100},
                "_corpus_dynamic_sandbox": {
                    "runtime_required_ids": ["example.runtime"],
                    "runtime_runs": [{"extension_id": "example.runtime", "status": "completed"}],
                    "observed_kinds": {"example.runtime": ["secret_exfil", "network_attempt"]},
                },
            }
            with patch("scripts.scan_corpus._scan_one", return_value=extension), patch(
                "scripts.scan_corpus.sandbox_preflight", return_value={"status": "ready"},
            ):
                report = run(args)

        dynamic = report["intelligence"]["dynamic_sandbox"]
        self.assertEqual(dynamic["observed_kinds"]["example.runtime"], ["network_attempt", "secret_exfil"])
        self.assertEqual(dynamic["runtime_required_ids"], ["example.runtime"])
        self.assertEqual(dynamic["runtime_runs"][0]["status"], "completed")

    def test_complete_manifest_result_can_be_resumed_from_checkpoint(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = {
                "path": str(root / "example.vsix"),
                "manifest_expected_extension_id": "example.extension",
                "manifest_expected_version": "1.0.0",
                "manifest_expected_sha256": "a" * 64,
            }
            extension = {
                "extension_id": "example.extension",
                "version": "1.0.0",
                "analysis_status": "complete",
                "artifact_hash": "a" * 64,
            }
            checkpoint_dir = root / "checkpoints"
            context = _checkpoint_context("quick", False, 20)
            _write_checkpoint(checkpoint_dir, target, extension, context)
            self.assertTrue(_checkpoint_path(checkpoint_dir, target).is_file())
            self.assertEqual(_load_checkpoint(checkpoint_dir, target, context), extension)

    def test_checkpoint_is_not_reused_for_a_different_scanner_context(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = {
                "path": str(root / "example.vsix"),
                "manifest_expected_extension_id": "example.extension",
                "manifest_expected_version": "1.0.0",
                "manifest_expected_sha256": "a" * 64,
            }
            extension = {"extension_id": "example.extension", "version": "1.0.0", "analysis_status": "complete", "artifact_hash": "a" * 64}
            checkpoint_dir = root / "checkpoints"
            _write_checkpoint(checkpoint_dir, target, extension, _checkpoint_context("quick", False, 20))

            self.assertIsNone(_load_checkpoint(checkpoint_dir, target, _checkpoint_context("benchmark", False, 20)))
            self.assertIsNone(_load_checkpoint(checkpoint_dir, target, _checkpoint_context("quick", True, 20)))

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
