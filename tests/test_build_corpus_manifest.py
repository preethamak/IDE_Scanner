from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.build_corpus_manifest import build_manifest


class BuildCorpusManifestTests(unittest.TestCase):
    def test_builds_exact_manifest_from_nested_vsix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "nested" / "example.vsix"
            artifact.parent.mkdir()
            with zipfile.ZipFile(artifact, "w") as archive:
                archive.writestr("extension/package.json", json.dumps({"publisher": "example", "name": "extension", "version": "1.2.3"}))
            output = root / "manifest.json"
            result = build_manifest([root], output)
            manifest = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(result["artifacts"], 1)
            self.assertEqual(manifest["schema_version"], "guardrails.corpus-manifest.v1")
            self.assertEqual(manifest["artifacts"][0]["extension_id"], "example.extension")
            self.assertEqual(manifest["artifacts"][0]["version"], "1.2.3")
            self.assertEqual(len(manifest["artifacts"][0]["sha256"]), 64)

    def test_rejects_duplicate_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("one.vsix", "two.vsix"):
                with zipfile.ZipFile(root / name, "w") as archive:
                    archive.writestr("extension/package.json", json.dumps({"publisher": "example", "name": "extension", "version": "1.0.0"}))
            with self.assertRaisesRegex(ValueError, "duplicate extension identity"):
                build_manifest([root], root / "manifest.json")


if __name__ == "__main__":
    unittest.main()
