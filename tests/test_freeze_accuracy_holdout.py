from __future__ import annotations

import json
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ide_scanner.artifact_input import ArtifactInputError
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
            self.assertTrue(all((manifest.parent / row["path"]).is_file() for row in manifest_value["artifacts"]))

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

    def test_freezer_falls_back_to_pinned_download_when_private_cache_is_absent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = b"downloaded-vsix"
            source = root / "source.json"
            source.write_text(json.dumps({
                "schema_version": "guardrails.holdout-source.v1",
                "corpus_id": "holdout",
                "corpus_version": "3",
                "holdout": {"status": "fresh-labeled", "label_source": "adjudication", "frozen_at": "2026-09-18T00:00:00Z"},
                "artifacts": [{
                    **self._source_artifact("download.ext", "1.0.0", "known_safe", payload),
                    "local_path": "missing/private-cache.vsix",
                }],
            }), encoding="utf-8")
            output_dir = root / "artifacts"
            corpus = root / "holdout-corpus.json"
            manifest = root / "corpus-manifest.json"

            def fake_acquire(_url: str, expected: str, destination: Path) -> Path:
                self.assertEqual(expected, hashlib.sha256(payload).hexdigest())
                downloaded = destination / "downloaded.vsix"
                downloaded.write_bytes(payload)
                return downloaded

            with patch("scripts.freeze_accuracy_holdout.acquire_https_vsix", side_effect=fake_acquire) as acquire:
                freeze_holdout(source, output_dir, corpus, manifest)

            acquire.assert_called_once()
            self.assertEqual(next(output_dir.glob("*.vsix")).read_bytes(), payload)

    def test_freezer_tries_exact_artifact_mirrors_in_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = b"mirrored-vsix"
            source = root / "source.json"
            source.write_text(json.dumps({
                "schema_version": "guardrails.holdout-source.v1",
                "corpus_id": "holdout",
                "corpus_version": "3-mirror",
                "holdout": {"status": "fresh-labeled", "label_source": "adjudication", "frozen_at": "2026-09-18T00:00:00Z"},
                "artifacts": [{
                    **self._source_artifact("mirror.ext", "1.0.0", "known_safe", payload),
                    "artifact_mirrors": ["https://mirror.example.test/package.vsix"],
                }],
            }), encoding="utf-8")
            output_dir = root / "artifacts"

            def fake_acquire(url: str, expected: str, destination: Path) -> Path:
                if url == "https://artifacts.example.test/package.vsix":
                    raise ArtifactInputError("primary unavailable")
                self.assertEqual(url, "https://mirror.example.test/package.vsix")
                self.assertEqual(expected, hashlib.sha256(payload).hexdigest())
                downloaded = destination / "mirror.vsix"
                downloaded.write_bytes(payload)
                return downloaded

            with patch("scripts.freeze_accuracy_holdout.acquire_https_vsix", side_effect=fake_acquire) as acquire:
                freeze_holdout(source, output_dir, root / "holdout.json", root / "manifest.json")

            self.assertEqual(
                [call.args[0] for call in acquire.call_args_list],
                ["https://artifacts.example.test/package.vsix", "https://mirror.example.test/package.vsix"],
            )
            self.assertEqual(next(output_dir.glob("*.vsix")).read_bytes(), payload)

    def test_source_rejects_invalid_artifact_mirrors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.json"
            source.write_text(json.dumps({
                "schema_version": "guardrails.holdout-source.v1",
                "corpus_id": "holdout",
                "corpus_version": "3-invalid-mirror",
                "holdout": {"status": "fresh-labeled", "label_source": "adjudication", "frozen_at": "2026-09-18T00:00:00Z"},
                "artifacts": [{
                    **self._source_artifact("mirror.ext", "1.0.0", "known_safe", b"mirror"),
                    "artifact_mirrors": ["http://mirror.example.test/package.vsix"],
                }],
            }), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, r"artifact_mirrors\[0\].*public HTTPS"):
                freeze_holdout(source, root / "artifacts", root / "holdout.json", root / "manifest.json")

    def test_freezer_rejects_backend_result_with_wrong_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = b"expected-vsix"
            source = root / "source.json"
            source.write_text(json.dumps({
                "schema_version": "guardrails.holdout-source.v1",
                "corpus_id": "holdout",
                "corpus_version": "3-wrong-backend-digest",
                "holdout": {"status": "fresh-labeled", "label_source": "adjudication", "frozen_at": "2026-09-18T00:00:00Z"},
                "artifacts": [self._source_artifact("wrong.ext", "1.0.0", "known_safe", payload)],
            }), encoding="utf-8")

            def fake_acquire(_url: str, _expected: str, destination: Path) -> Path:
                wrong = destination / "wrong.vsix"
                wrong.write_bytes(b"not-the-pinned-bytes")
                return wrong

            with patch("scripts.freeze_accuracy_holdout.acquire_https_vsix", side_effect=fake_acquire):
                with self.assertRaisesRegex(ValueError, "wrong SHA-256"):
                    freeze_holdout(source, root / "artifacts", root / "holdout.json", root / "manifest.json")

    def test_freezer_resolves_relative_paths_inside_an_explicit_artifact_vault(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vault = root / "private-vault"
            vault.mkdir()
            artifact = vault / "retained.vsix"
            artifact.write_bytes(b"vault-vsix")
            source = root / "source.json"
            source.write_text(json.dumps({
                "schema_version": "guardrails.holdout-source.v1",
                "corpus_id": "holdout",
                "corpus_version": "4",
                "holdout": {"status": "fresh-labeled", "label_source": "adjudication", "frozen_at": "2026-09-18T00:00:00Z"},
                "artifacts": [{
                    **self._source_artifact("vault.ext", "1.0.0", "known_safe", b"vault-vsix"),
                    "local_path": "retained.vsix",
                }],
            }), encoding="utf-8")
            output_dir = root / "artifacts"
            corpus = root / "holdout-corpus.json"
            manifest = root / "corpus-manifest.json"

            with patch("scripts.freeze_accuracy_holdout.acquire_https_vsix") as acquire:
                freeze_holdout(source, output_dir, corpus, manifest, artifact_vault=vault)

            acquire.assert_not_called()
            self.assertEqual(next(output_dir.glob("*.vsix")).read_bytes(), b"vault-vsix")

    def test_freezer_rejects_private_vault_path_escape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vault = root / "private-vault"
            vault.mkdir()
            source = root / "source.json"
            source.write_text(json.dumps({
                "schema_version": "guardrails.holdout-source.v1",
                "corpus_id": "holdout",
                "corpus_version": "5",
                "holdout": {"status": "fresh-labeled", "label_source": "adjudication", "frozen_at": "2026-09-18T00:00:00Z"},
                "artifacts": [{
                    **self._source_artifact("escape.ext", "1.0.0", "known_safe", b"vault-vsix"),
                    "local_path": "../outside.vsix",
                }],
            }), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "escapes the private artifact vault"):
                freeze_holdout(source, root / "artifacts", root / "holdout.json", root / "manifest.json", artifact_vault=vault)

    @staticmethod
    def _source_artifact(extension_id: str, version: str, label: str, payload: bytes) -> dict[str, object]:
        artifact_sha256 = hashlib.sha256(payload).hexdigest()
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
                "evidence_scope": "exact-artifact",
                "extension_id": extension_id,
                "version": version,
                "artifact_sha256": artifact_sha256,
                **({"advisory_id": f"UNIT-{extension_id}-{version}"} if label == "known_malicious" else {}),
            },
        }


if __name__ == "__main__":
    unittest.main()
