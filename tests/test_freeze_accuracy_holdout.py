from __future__ import annotations

import json
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.freeze_accuracy_holdout import _read_source, freeze_holdout


class FreezeAccuracyHoldoutTests(unittest.TestCase):
    def test_source_requires_frozen_timestamp_and_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.json"
            path.write_text(json.dumps({
                "schema_version": "guardrails.holdout-source.v1",
                "corpus_id": "holdout",
                "corpus_version": "1",
                "holdout": {"status": "fresh-labeled", "label_source": "advisory"},
                "artifacts": [],
            }), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "frozen_at"):
                _read_source(path)

    def test_source_schema_is_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.json"
            path.write_text(json.dumps({"schema_version": "1"}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "schema_version"):
                _read_source(path)

    def test_freezer_writes_hash_pinned_corpus_and_scan_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            safe_bytes = b"safe-vsix"
            bad_bytes = b"bad-vsix"
            source = root / "source.json"
            source.write_text(json.dumps({
                "schema_version": "guardrails.holdout-source.v1",
                "corpus_id": "holdout",
                "corpus_version": "1",
                "holdout": {"status": "fresh-labeled", "label_source": "adjudication", "frozen_at": "2026-09-18T00:00:00Z"},
                "artifacts": [
                    self._source_artifact("safe.ext", "1.0.0", "known_safe", safe_bytes),
                    self._source_artifact("bad.ext", "2.0.0", "known_malicious", bad_bytes),
                ],
            }), encoding="utf-8")
            output_dir = root / "artifacts"
            corpus = root / "holdout-corpus.json"
            manifest = root / "corpus-manifest.json"

            def fake_acquire(_url: str, expected: str, destination: Path) -> Path:
                path = destination / f"download-{expected[:8]}.vsix"
                payload = safe_bytes if expected == hashlib.sha256(safe_bytes).hexdigest() else bad_bytes
                path.write_bytes(payload)
                return path

            with patch("scripts.freeze_accuracy_holdout.acquire_https_vsix", side_effect=fake_acquire):
                result = freeze_holdout(source, output_dir, corpus, manifest)

            self.assertEqual(result["artifacts"], 2)
            corpus_value = json.loads(corpus.read_text(encoding="utf-8"))
            manifest_value = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(corpus_value["holdout"]["status"], "fresh-labeled")
            self.assertEqual(len(corpus_value["artifacts"]), 2)
            self.assertEqual(len(manifest_value["artifacts"]), 2)
            self.assertTrue(all((output_dir / row["path"]).is_file() for row in manifest_value["artifacts"]))

    def test_freezer_can_verify_already_retained_private_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "retained.vsix"
            artifact.write_bytes(b"retained-vsix")
            source = root / "source.json"
            source.write_text(json.dumps({
                "schema_version": "guardrails.holdout-source.v1",
                "corpus_id": "holdout",
                "corpus_version": "2",
                "holdout": {"status": "fresh-labeled", "label_source": "adjudication", "frozen_at": "2026-09-18T00:00:00Z"},
                "artifacts": [
                    {
                        **self._source_artifact("retained.ext", "1.0.0", "known_safe", b"retained-vsix"),
                        "local_path": artifact.name,
                    },
                ],
            }), encoding="utf-8")
            output_dir = root / "artifacts"
            corpus = root / "holdout-corpus.json"
            manifest = root / "corpus-manifest.json"

            with patch("scripts.freeze_accuracy_holdout.acquire_https_vsix") as acquire:
                result = freeze_holdout(source, output_dir, corpus, manifest)

            acquire.assert_not_called()
            self.assertEqual(result["artifacts"], 1)
            frozen = next(output_dir.glob("*.vsix"))
            self.assertEqual(frozen.read_bytes(), b"retained-vsix")

    @staticmethod
    def _source_artifact(extension_id: str, version: str, label: str, payload: bytes) -> dict[str, object]:
        return {
            "extension_id": extension_id,
            "version": version,
            "label": label,
            "artifact_url": "https://artifacts.example.test/package.vsix",
            "sha256": hashlib.sha256(payload).hexdigest(),
            "label_evidence": {
                "source_type": "independent_review" if label == "known_safe" else "independent_threat_report",
                "source_url": "https://evidence.example.test/report",
                "retrieved_at": "2026-09-18T00:00:00Z",
            },
        }


if __name__ == "__main__":
    unittest.main()
