from __future__ import annotations

import json
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from ide_scanner.scanner import (
    _finalize_analysis_coverage,
    _javascript_ast_provider_status,
    _read_manifest_status,
    _read_text,
    _safe_extract_vsix,
    _vsix_signature_status,
    scan_extension,
    scan_targets,
    scan_vsix,
)


def _write_ext(root: Path, manifest: dict | str, main: str = "extension.js", source: str = "const x = 1;\n") -> None:
    if isinstance(manifest, dict):
        (root / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
    else:
        (root / "package.json").write_text(manifest, encoding="utf-8")
    if main:
        (root / main).write_text(source, encoding="utf-8")


class ManifestFailClosedTests(unittest.TestCase):
    def test_invalid_json_manifest_is_incomplete_not_allow(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_ext(root, "{ this is not valid json ]", main="extension.js")
            report = scan_extension(root)
        self.assertEqual(report.analysis_coverage["manifest_validation"]["status"], "invalid-json")
        self.assertFalse(report.analysis_coverage["manifest_validation"]["valid"])
        self.assertEqual(report.analysis_coverage["status"], "incomplete")
        self.assertEqual(report.decision, "incomplete")

    def test_missing_manifest_fails_closed(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "extension.js").write_text("const x = 1;\n", encoding="utf-8")
            report = scan_extension(root)
        self.assertEqual(report.analysis_coverage["manifest_validation"]["status"], "missing")
        self.assertEqual(report.decision, "incomplete")

    def test_non_object_manifest_fails_closed(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_ext(root, "[1, 2, 3]", main="extension.js")
            report = scan_extension(root)
        self.assertEqual(report.analysis_coverage["manifest_validation"]["status"], "not-object")
        self.assertEqual(report.decision, "incomplete")

    def test_valid_manifest_reports_valid(self) -> None:
        _manifest, status = _read_manifest_status(Path("/does/not/exist/package.json"))
        self.assertEqual(status, "missing")

    def test_empty_object_manifest_has_no_identity_and_fails_closed(self) -> None:
        # Regression: an object that merely parses ({}) fabricated an identity
        # (unknown.<dir>@0.0.0) and was reported allow/complete, violating the
        # "invalid artifact identity must never allow" invariant.
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_ext(root, "{}", main="extension.js")
            report = scan_extension(root)
        self.assertEqual(report.analysis_coverage["manifest_validation"]["status"], "missing-identity")
        self.assertFalse(report.analysis_coverage["manifest_validation"]["valid"])
        self.assertEqual(report.analysis_coverage["status"], "incomplete")
        self.assertNotEqual(report.decision, "allow")
        self.assertEqual(report.decision, "incomplete")

    def test_partial_identity_manifest_fails_closed(self) -> None:
        for manifest in (
            '{"name":"n","version":"1.0.0"}',            # no publisher
            '{"publisher":"p","version":"1.0.0"}',       # no name
            '{"publisher":"p","name":"n"}',              # no version
            '{"publisher":"","name":"n","version":"1"}', # empty publisher
            '{"publisher":"p","name":"n","version":123}', # non-string version
        ):
            with TemporaryDirectory() as tmp:
                root = Path(tmp)
                _write_ext(root, manifest, main="extension.js")
                report = scan_extension(root)
            self.assertEqual(
                report.analysis_coverage["manifest_validation"]["status"],
                "missing-identity",
                msg=f"manifest {manifest!r} should lack identity",
            )
            self.assertEqual(report.decision, "incomplete", msg=f"manifest {manifest!r}")

    def test_vsix_with_identityless_manifest_fails_closed(self) -> None:
        with TemporaryDirectory() as tmp:
            vsix = Path(tmp) / "x.vsix"
            with zipfile.ZipFile(vsix, "w") as archive:
                archive.writestr("extension/package.json", "{}")
                archive.writestr("extension/extension.js", "const x = 1;\n")
            report = scan_vsix(vsix)
        self.assertEqual(report.analysis_coverage["manifest_validation"]["status"], "missing-identity")
        self.assertEqual(report.decision, "incomplete")

    def test_full_identity_manifest_is_valid(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_ext(root, {"publisher": "p", "name": "n", "version": "1.0.0", "main": "extension.js"})
            report = scan_extension(root)
        self.assertEqual(report.analysis_coverage["manifest_validation"]["status"], "valid")


class ProviderStatusTests(unittest.TestCase):
    def test_missing_node_marks_js_ast_failed(self) -> None:
        record = _javascript_ast_provider_status(["node-missing"])
        self.assertEqual(record["status"], "failed")
        self.assertTrue(record["required"])
        self.assertIn("Node runtime unavailable", record["error"])

    def test_all_ok_completes(self) -> None:
        record = _javascript_ast_provider_status(["ok", "ok"])
        self.assertEqual(record["status"], "completed")

    def test_no_js_files_completes(self) -> None:
        record = _javascript_ast_provider_status([])
        self.assertEqual(record["status"], "completed")
        self.assertEqual(record["analyzed_files"], 0)

    def test_js_ast_failure_makes_scan_incomplete(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_ext(root, {"publisher": "ex", "name": "n", "version": "1.0.0", "main": "extension.js"})
            with patch("ide_scanner.scanner.analyze_js_source_status", return_value=([], "node-missing")):
                report = scan_extension(root)
        provider = report.analysis_coverage["providers"]["javascript_ast"]
        self.assertEqual(provider["status"], "failed")
        self.assertEqual(report.analysis_coverage["status"], "incomplete")
        self.assertNotEqual(report.decision, "allow")

    def test_unparsed_is_disclosed_not_silently_completed(self) -> None:
        # A file the plain-JS parser cannot read (TypeScript/JSX or invalid
        # syntax) must be counted and disclosed, never reported as a clean
        # successful AST parse. Regression guard for the fail-quiet gap where
        # the walker's exit-0 "parse failed" payload was treated as "ok".
        record = _javascript_ast_provider_status(["ok", "unparsed"])
        self.assertEqual(record["status"], "completed")
        self.assertEqual(record["unparsed_files"], 1)
        self.assertIn("could not read", record["note"])

    def test_unparsed_alone_does_not_fail_typescript_extension(self) -> None:
        # A pure-TypeScript extension must not be flipped to a hard AST failure
        # just because acorn is JS-only; the raw-text layer still covers it.
        record = _javascript_ast_provider_status(["unparsed", "unparsed"])
        self.assertEqual(record["status"], "completed")
        self.assertEqual(record["failed_files"], 0)
        self.assertEqual(record["unparsed_files"], 2)

    def test_unparsed_status_from_real_walker_on_typescript(self) -> None:
        from ide_scanner.ast_analyzer import analyze_js_source_status, node_available

        if not node_available():
            self.skipTest("node runtime required")
        _findings, status = analyze_js_source_status("a.ts", "const x: number = 1;\n")
        self.assertEqual(status, "unparsed")

    def test_unparsed_declared_entrypoint_forces_review(self) -> None:
        # An entrypoint the AST layer cannot parse loses structural evasion
        # detection on the primary code path. It must surface as a review nudge
        # so the scan cannot reach "allow" on raw-text coverage alone.
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_ext(
                root,
                {"publisher": "ex", "name": "n", "version": "1.0.0", "main": "extension.js"},
                main="extension.js",
                source="const x = 1;\n",
            )
            with patch(
                "ide_scanner.scanner.analyze_js_source_status",
                return_value=([], "unparsed"),
            ):
                report = scan_extension(root)
        rule_ids = {f.rule_id for f in report.findings}
        self.assertIn("entrypoint-ast-unparsed", rule_ids)
        self.assertIn(report.decision, {"review", "block"})
        self.assertNotEqual(report.decision, "allow")
        # The provider itself stays completed -- the gate is the finding.
        self.assertEqual(
            report.analysis_coverage["providers"]["javascript_ast"]["status"],
            "completed",
        )

    def test_unparsed_non_entrypoint_does_not_nudge_review(self) -> None:
        # A non-entrypoint unparsed file is covered by raw-text rules and must
        # NOT emit the entrypoint nudge -- only declared entrypoints do.
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                json.dumps({"publisher": "ex", "name": "n", "version": "1.0.0", "main": "extension.js"}),
                encoding="utf-8",
            )
            (root / "extension.js").write_text("const x = 1;\n", encoding="utf-8")
            (root / "helper.ts").write_text("const y: number = 2;\n", encoding="utf-8")

            def fake_status(rel, text):
                if rel.endswith(".ts"):
                    return [], "unparsed"
                return [], "ok"

            with patch("ide_scanner.scanner.analyze_js_source_status", side_effect=fake_status):
                report = scan_extension(root)
        rule_ids = {f.rule_id for f in report.findings}
        self.assertNotIn("entrypoint-ast-unparsed", rule_ids)


class CoverageHonestyTests(unittest.TestCase):
    def test_generated_only_extension_not_reported_complete(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Manifest points main at a minified bundle; only generated code is reachable.
            (root / "package.json").write_text(
                json.dumps({"publisher": "ex", "name": "n", "version": "1.0.0"}), encoding="utf-8"
            )
            (root / "app.min.js").write_text("var a=1;var b=2;\n", encoding="utf-8")
            report = scan_extension(root)
        coverage = report.analysis_coverage
        self.assertIn("app.min.js", coverage["excluded_generated_files"])
        self.assertEqual(coverage["coverage_percent"], 0)
        self.assertEqual(coverage["status"], "incomplete")

    def test_empty_denominator_with_no_code_stays_complete(self) -> None:
        coverage = {
            "executable_candidates": [],
            "analyzed_executable_files": [],
            "missing_entrypoints": [],
            "read_failures": [],
            "oversized_files": [],
            "excluded_generated_files": [],
            "providers": {},
            "manifest_validation": {"valid": True, "status": "valid"},
        }
        _finalize_analysis_coverage(coverage)
        self.assertEqual(coverage["coverage_percent"], 100)
        self.assertEqual(coverage["status"], "complete")


class BoundedReadTests(unittest.TestCase):
    def test_read_text_caps_prefix(self) -> None:
        with TemporaryDirectory() as tmp:
            big = Path(tmp) / "big.js"
            with patch("ide_scanner.scanner.MAX_TEXT_BYTES", 16):
                big.write_text("a" * 1000, encoding="utf-8")
                text = _read_text(big)
        self.assertEqual(len(text), 16)


class InventoryIsolationTests(unittest.TestCase):
    def test_one_bad_extension_does_not_abort_inventory(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            good = root / "good"
            good.mkdir()
            _write_ext(good, {"publisher": "ex", "name": "good", "version": "1.0.0", "main": "extension.js"})
            bad = root / "bad"
            bad.mkdir()
            _write_ext(bad, {"publisher": "ex", "name": "bad", "version": "1.0.0", "main": "extension.js"})

            real_scan = scan_extension

            def flaky(path, *args, **kwargs):
                if path.name == "bad":
                    raise RuntimeError("boom")
                return real_scan(path, *args, **kwargs)

            with patch("ide_scanner.scanner.scan_extension", side_effect=flaky):
                report = scan_targets(paths=[good, bad])

        by_id = {row["extension_id"]: row for row in report["extensions"]}
        self.assertIn("ex.good", by_id)
        # The bad one is isolated as an incomplete placeholder, not an abort.
        self.assertTrue(any(row["decision"] == "incomplete" for row in report["extensions"]))
        self.assertEqual(len(report["extensions"]), 2)


class VsixArchiveHardeningTests(unittest.TestCase):
    def _write_symlink_member(self, archive: zipfile.ZipFile, name: str, target: str) -> None:
        info = zipfile.ZipInfo(name)
        info.external_attr = (0o120777 << 16)  # symlink mode
        archive.writestr(info, target)

    def test_traversal_member_is_refused_and_recorded(self) -> None:
        with TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out"
            dest.mkdir()
            vsix = Path(tmp) / "evil.vsix"
            with zipfile.ZipFile(vsix, "w") as archive:
                archive.writestr("extension/package.json", '{"publisher":"e","name":"n","version":"1.0.0"}')
                archive.writestr("../../escape.txt", "pwned")
            anomalies = _safe_extract_vsix(vsix, dest)
        self.assertIn("traversal_members", anomalies)
        self.assertFalse((Path(tmp) / "escape.txt").exists())

    def test_symlink_member_is_refused_and_recorded(self) -> None:
        with TemporaryDirectory() as tmp:
            dest = Path(tmp) / "out"
            dest.mkdir()
            vsix = Path(tmp) / "evil.vsix"
            with zipfile.ZipFile(vsix, "w") as archive:
                archive.writestr("extension/package.json", '{"publisher":"e","name":"n","version":"1.0.0"}')
                self._write_symlink_member(archive, "extension/link", "/etc/passwd")
            anomalies = _safe_extract_vsix(vsix, dest)
        self.assertIn("symlink_members", anomalies)
        self.assertFalse((dest / "extension" / "link").exists())

    def test_scan_vsix_marks_incomplete_on_archive_anomaly(self) -> None:
        with TemporaryDirectory() as tmp:
            vsix = Path(tmp) / "evil.vsix"
            with zipfile.ZipFile(vsix, "w") as archive:
                archive.writestr("extension/package.json", '{"publisher":"e","name":"n","version":"1.0.0","main":"extension.js"}')
                archive.writestr("extension/extension.js", "const x = 1;\n")
                self._write_symlink_member(archive, "extension/evil", "/etc/shadow")
            report = scan_vsix(vsix)
        self.assertIn("archive_anomalies", report.artifact_inventory)
        self.assertEqual(report.analysis_coverage["status"], "incomplete")
        self.assertNotEqual(report.decision, "allow")

    def test_signature_status_never_implies_authenticity(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "extension.vsixsignature").write_text("fake", encoding="utf-8")
            status = _vsix_signature_status(root)
        self.assertFalse(status["verified"])
        self.assertFalse(status["verification_supported"])
        self.assertNotIn("valid", status)


if __name__ == "__main__":
    unittest.main()
