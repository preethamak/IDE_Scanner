from __future__ import annotations

import json
import struct
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from ide_scanner.providers.static_analysis import (
    _has_valid_embedded_pe,
    _ignore_yara_match,
    _resolved_targets,
    _run_semgrep,
    _run_yara,
    _run_yara_python,
    _semgrep_diagnostic_text,
)


class StaticProviderScopeTests(unittest.TestCase):
    def test_semgrep_uses_native_memory_guard_without_address_space_limit(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "extension.js"
            target.write_text("exports.activate = () => {};", encoding="utf-8")
            observed = {}

            def fake_run(command, **kwargs):
                observed["command"] = command
                observed.update(kwargs)
                return SimpleNamespace(returncode=0, stdout='{"results": [], "errors": []}', stderr="")

            diagnostic = {
                "provider": "semgrep",
                "status": "available",
                "executable": "/scanner/semgrep",
                "ruleset_hash": "rules",
            }
            with (
                patch("ide_scanner.providers.static_analysis.semgrep_diagnostic", return_value=diagnostic),
                patch("ide_scanner.providers.static_analysis.semgrep_config_arguments", return_value=[]),
                patch("ide_scanner.providers.static_analysis.run_bounded_process", side_effect=fake_run),
            ):
                _findings, status = _run_semgrep(root, "example.extension", "1.0.0", [target])

        max_memory_index = observed["command"].index("--max-memory")
        self.assertEqual(observed["command"][max_memory_index + 1], "1536")
        self.assertIsNone(observed["memory_limit_mb"])
        self.assertEqual(status["memory_limit_enforcement"], "semgrep_per_file")

    def test_native_yara_scans_only_selected_targets(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            selected = root / "extension.js"
            excluded = root / "excluded.js"
            selected.write_text("const selected = 1;", encoding="utf-8")
            excluded.write_text("const excluded = 1;", encoding="utf-8")
            observed = {}

            def fake_run(command, **kwargs):
                observed["command"] = command
                observed["targets"] = Path(command[-1]).read_text(encoding="utf-8").splitlines()
                observed.update(kwargs)
                return SimpleNamespace(
                    returncode=0,
                    stdout=f"ide_scanner_unicode_evasion {selected}\n",
                    stderr="",
                )

            diagnostic = {"provider": "yara", "status": "available", "executable": "/scanner/yara"}
            with (
                patch("ide_scanner.providers.static_analysis.yara_diagnostic", return_value=diagnostic),
                patch("ide_scanner.providers.static_analysis.run_bounded_process", side_effect=fake_run),
            ):
                findings, result = _run_yara(
                    root,
                    "example.extension",
                    "1.0.0",
                    [selected],
                )

        self.assertIn("--scan-list", observed["command"])
        self.assertNotIn("-r", observed["command"])
        self.assertEqual(observed["targets"], [str(selected.resolve())])
        self.assertNotIn(str(excluded.resolve()), observed["targets"])
        self.assertEqual(result["files_analyzed"], 1)
        self.assertEqual([item.rule_id for item in findings], ["unicode-evasion"])

    def test_yara_python_runs_in_bounded_worker_process(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "extension.js"
            target.write_text("const value = 1;", encoding="utf-8")
            payload = {
                "schema_version": "1",
                "files_analyzed": 1,
                "matches": [{"rule": "ide_scanner_unicode_evasion", "path": "extension.js"}],
                "errors": [],
                "truncated": False,
            }
            observed = {}

            def fake_run(command, **kwargs):
                observed["command"] = command
                observed.update(kwargs)
                return SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr="")

            status = {"provider": "yara", "status": "available", "executable": "yara-python"}
            with patch("ide_scanner.providers.static_analysis.run_bounded_process", side_effect=fake_run):
                findings, result = _run_yara_python(root, "example.extension", "1.0.0", status, [target])

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["isolation"], "subprocess")
        self.assertEqual(result["files_analyzed"], 1)
        self.assertEqual([item.rule_id for item in findings], ["unicode-evasion"])
        self.assertIn("ide_scanner.providers.yara_worker", observed["command"])
        self.assertGreater(observed["memory_limit_mb"], 0)
        self.assertGreater(observed["file_size_limit_mb"], 0)

    def test_yara_worker_errors_fail_provider_closed(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "extension.js"
            target.write_text("const value = 1;", encoding="utf-8")
            payload = {
                "schema_version": "1",
                "files_analyzed": 0,
                "matches": [],
                "errors": [{"path": "extension.js", "error": "scan timeout"}],
                "truncated": False,
            }
            status = {"provider": "yara", "status": "available", "executable": "yara-python"}
            with patch(
                "ide_scanner.providers.static_analysis.run_bounded_process",
                return_value=SimpleNamespace(returncode=2, stdout=json.dumps(payload), stderr=""),
            ):
                findings, result = _run_yara_python(root, "example.extension", "1.0.0", status, [target])

        self.assertEqual(findings, [])
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error_count"], 1)
        self.assertIn("scan timeout", result["error"])

    def test_semgrep_target_errors_fail_provider_completion(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "extension.js"
            target.write_text("exports.activate = () => {};", encoding="utf-8")
            payload = {
                "results": [],
                "errors": [{"message": f"Syntax error at {target}"}],
            }
            diagnostic = {
                "provider": "semgrep",
                "status": "available",
                "executable": "/scanner/semgrep",
                "ruleset_hash": "rules",
            }
            with (
                patch(
                    "ide_scanner.providers.static_analysis.semgrep_diagnostic",
                    return_value=diagnostic,
                ),
                patch(
                    "ide_scanner.providers.static_analysis.semgrep_config_arguments",
                    return_value=[],
                ),
                patch(
                    "ide_scanner.providers.static_analysis.run_bounded_process",
                    return_value=SimpleNamespace(
                        returncode=0,
                        stdout=json.dumps(payload),
                        stderr="",
                    ),
                ),
            ):
                _findings, status = _run_semgrep(
                    root,
                    "example.extension",
                    "1.0.0",
                    [target],
                )

        self.assertEqual(status["status"], "failed")
        self.assertEqual(status["error_count"], 1)
        self.assertIn("<artifact>/extension.js", status["errors"][0])

    def test_semgrep_parser_incompatibility_is_disclosed_without_failing_other_coverage(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "extension.js"
            target.write_text("exports.activate = () => {};", encoding="utf-8")
            payload = {
                "results": [],
                "errors": [{
                    "type": "Parse error",
                    "message": f"Syntax error at line {target}:1",
                }],
            }
            diagnostic = {
                "provider": "semgrep",
                "status": "available",
                "executable": "/scanner/semgrep",
                "ruleset_hash": "rules",
            }
            with (
                patch("ide_scanner.providers.static_analysis.semgrep_diagnostic", return_value=diagnostic),
                patch("ide_scanner.providers.static_analysis.semgrep_config_arguments", return_value=[]),
                patch(
                    "ide_scanner.providers.static_analysis.run_bounded_process",
                    return_value=SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr=""),
                ),
            ):
                _findings, status = _run_semgrep(
                    root,
                    "example.extension",
                    "1.0.0",
                    [target],
                )

        self.assertEqual(status["status"], "completed")
        self.assertEqual(status["error_count"], 0)
        self.assertEqual(status["unsupported_parse_error_count"], 1)
        self.assertIn("<artifact>/extension.js", status["unsupported_targets"][0])

    def test_semgrep_diagnostics_are_bounded_and_machine_independent(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "random-extraction"
            root.mkdir()
            message = (
                "Timeout when running host.checkout.rules."
                f"credential-dataflow-to-network on {root}/extension.js:\n"
                + "x" * 2_000
            )

            sanitized = _semgrep_diagnostic_text(message, root)

        self.assertEqual(len(sanitized), 500)
        self.assertNotIn(str(root), sanitized)
        self.assertNotIn("host.checkout.rules", sanitized)
        self.assertIn("credential-dataflow-to-network", sanitized)

    def test_targets_cannot_escape_artifact_root(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "extension.js").write_text("const value = 1;", encoding="utf-8")
            selected = _resolved_targets(
                root,
                {"semgrep": ["extension.js", "../outside.js"]},
                "semgrep",
            )
        self.assertEqual([path.name for path in selected or []], ["extension.js"])

    def test_text_yara_rules_do_not_apply_to_binary_media(self) -> None:
        with TemporaryDirectory() as tmp:
            image = Path(tmp) / "image.webp"
            image.write_bytes(b"base64 eval(")
            self.assertTrue(_ignore_yara_match("ide_scanner_encoded_dynamic_execution", "image.webp", image))
            self.assertTrue(_ignore_yara_match("ide_scanner_unicode_evasion", "image.webp", image))

    def test_marker_cooccurrence_is_not_a_valid_embedded_pe(self) -> None:
        with TemporaryDirectory() as tmp:
            binary = Path(tmp) / "linux-host"
            binary.write_bytes(b"\x7fELF" + b"MZ" + b"x" * 62 + b"PE\0\0")
            self.assertFalse(_has_valid_embedded_pe(binary))
            self.assertTrue(_ignore_yara_match("ide_scanner_embedded_pe", "linux-host", binary))

    def test_structurally_valid_embedded_pe_is_retained(self) -> None:
        with TemporaryDirectory() as tmp:
            binary = Path(tmp) / "container.bin"
            payload = bytearray(b"prefix!!" + b"MZ" + b"\0" * 126)
            mz_offset = 8
            struct.pack_into("<I", payload, mz_offset + 60, 64)
            payload[mz_offset + 64:mz_offset + 68] = b"PE\0\0"
            binary.write_bytes(payload)
            self.assertTrue(_has_valid_embedded_pe(binary))
            self.assertFalse(_ignore_yara_match("ide_scanner_embedded_pe", "container.bin", binary))
