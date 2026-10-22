from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from zipfile import ZipFile

from ide_scanner import cli
from ide_scanner.source_provenance import compare_source_to_vsix


class SourceVsixProvenanceTests(unittest.TestCase):
    def test_compares_source_and_packaged_extension_files_without_claiming_equivalence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            source.mkdir()
            (source / "package.json").write_text('{"name":"example"}', encoding="utf-8")
            (source / "shared.js").write_text("same", encoding="utf-8")
            (source / "changed.js").write_text("source", encoding="utf-8")
            (source / "test.js").write_text("source-only", encoding="utf-8")
            vsix = root / "example.vsix"
            with ZipFile(vsix, "w") as archive:
                archive.writestr("extension/package.json", '{"name":"example"}')
                archive.writestr("extension/shared.js", "same")
                archive.writestr("extension/changed.js", "artifact")
                archive.writestr("extension/generated.js", "artifact-only")
                archive.writestr("[Content_Types].xml", "metadata")

            result = compare_source_to_vsix(source, vsix)

            comparison = result["comparison"]
            self.assertEqual(comparison["matching_file_count"], 2)
            self.assertEqual(comparison["changed_file_count"], 1)
            self.assertEqual(comparison["changed_files"][0]["path"], "changed.js")
            self.assertEqual(comparison["source_only_files"], ["test.js"])
            self.assertEqual(comparison["artifact_only_files"], ["generated.js"])
            self.assertEqual(result["artifact"]["ignored_member_count"], 1)

    def test_cli_writes_source_comparison_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            source.mkdir()
            (source / "package.json").write_text("{}", encoding="utf-8")
            vsix = root / "example.vsix"
            with ZipFile(vsix, "w") as archive:
                archive.writestr("extension/package.json", "{}")
            output = root / "comparison.json"

            self.assertEqual(cli.main(["provenance", "--source", str(source), "--vsix", str(vsix), "--out", str(output)]), 0)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["comparison"]["matching_file_count"], 1)

    def test_rejects_ambiguous_duplicate_payload_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            source.mkdir()
            vsix = root / "example.vsix"
            with ZipFile(vsix, "w") as archive:
                archive.writestr("extension/package.json", "first")
                archive.writestr("extension/package.json", "second")

            with self.assertRaisesRegex(ValueError, "duplicate"):
                compare_source_to_vsix(source, vsix)

    def test_cli_reports_invalid_provenance_input_without_a_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            error = StringIO()
            with redirect_stderr(error), self.assertRaises(SystemExit) as stopped:
                cli.main(["provenance", "--source", temp, "--vsix", str(Path(temp) / "missing.vsix")])
            self.assertEqual(stopped.exception.code, 2)
            self.assertIn("requires a .vsix file", error.getvalue())
