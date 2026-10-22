from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ide_scanner.cli import main
from ide_scanner.workspace import build_workspace_lock, discover_workspace_extensions, load_workspace_lock, scan_workspace_extensions, workspace_lock_coverage


class WorkspaceExtensionScanTests(unittest.TestCase):
    def test_discovers_vscode_devcontainer_and_workspace_recommendations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".vscode").mkdir()
            (root / ".devcontainer").mkdir()
            (root / ".vscode" / "extensions.json").write_text('{"recommendations":["ms-python.python","not an extension"]}')
            (root / ".devcontainer" / "devcontainer.json").write_text('{"customizations":{"vscode":{"extensions":["ms-vscode.cmake-tools"]}}}')
            (root / "team.code-workspace").write_text('{"recommendations":["ms-python.python","redhat.java"]}')
            discovery = discover_workspace_extensions(root)
            self.assertEqual(discovery["extensions"], ["ms-python.python", "ms-vscode.cmake-tools", "redhat.java"])
            self.assertEqual(discovery["sources"]["ms-python.python"], [".vscode/extensions.json", "team.code-workspace"])

    def test_lock_pins_each_workspace_release_and_report_keeps_declaration_sources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".vscode").mkdir()
            (root / ".vscode" / "extensions.json").write_text('{"recommendations":["ms-python.python","redhat.java"]}')
            lock = root / "extensions.lock.json"
            lock.write_text(json.dumps({"extensions": {"ms-python.python": {"version": "2026.1.0", "target_platform": "linux-x64"}}}))
            calls = []
            def scanner(**kwargs):
                calls.append(kwargs)
                return {"extensions": [{"extension_id": kwargs["marketplace_scan_ids"][0]}]}
            report = scan_workspace_extensions(root, lock_path=lock, scanner=scanner)
            self.assertEqual(report["schema_version"], "guardrails.workspace-extension-scan.v1")
            self.assertEqual(calls[0]["marketplace_version"], "2026.1.0")
            self.assertEqual(calls[0]["marketplace_target_platform"], "linux-x64")
            self.assertIsNone(calls[1]["marketplace_version"])
            self.assertIsNone(calls[0]["required_providers"])
            self.assertEqual(report["extensions"][0]["declared_in"], [".vscode/extensions.json"])
            self.assertEqual(report["lock_coverage"]["status"], "incomplete")
            self.assertEqual(report["lock_coverage"]["unpinned_extensions"], ["redhat.java"])

    def test_lock_coverage_makes_missing_and_unused_pins_explicit(self) -> None:
        discovery = {"extensions": ["ms-python.python", "redhat.java"]}
        coverage = workspace_lock_coverage(
            discovery,
            {
                "ms-python.python": {"version": "2026.1.0"},
                "unused.publisher": {"version": "1.0.0"},
            },
        )
        self.assertEqual(coverage["status"], "incomplete")
        self.assertEqual(coverage["pinned_extensions"], ["ms-python.python"])
        self.assertEqual(coverage["unpinned_extensions"], ["redhat.java"])
        self.assertEqual(coverage["unused_lock_extensions"], ["unused.publisher"])

    def test_build_lock_uses_only_completed_exact_workspace_evidence(self) -> None:
        report = {
            "schema_version": "guardrails.workspace-extension-scan.v1",
            "extensions": [{
                "extension_id": "ms-python.python",
                "scan": {"extensions": [{
                    "extension_id": "ms-python.python",
                    "version": "2026.1.0",
                    "analysis_status": "complete",
                    "decision": "review",
                    "artifact_identity": {"target_platform": "linux-x64"},
                }]},
            }],
        }
        lock = build_workspace_lock(report)
        self.assertEqual(lock["schema_version"], "guardrails.workspace-extension-lock.v1")
        self.assertEqual(lock["extensions"], {"ms-python.python": {"version": "2026.1.0", "target_platform": "linux-x64"}})

    def test_build_lock_rejects_incomplete_evidence(self) -> None:
        report = {
            "schema_version": "guardrails.workspace-extension-scan.v1",
            "extensions": [{
                "extension_id": "ms-python.python",
                "scan": {"extensions": [{
                    "extension_id": "ms-python.python",
                    "version": "2026.1.0",
                    "analysis_status": "incomplete",
                    "decision": "incomplete",
                }]},
            }],
        }
        with self.assertRaisesRegex(ValueError, "evidence is incomplete"):
            build_workspace_lock(report)

    def test_cli_writes_lock_from_completed_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_path = root / "workspace.json"
            output = root / "extensions.lock.json"
            report_path.write_text(json.dumps({
                "schema_version": "guardrails.workspace-extension-scan.v1",
                "extensions": [{"extension_id": "ms-python.python", "scan": {"extensions": [{"extension_id": "ms-python.python", "version": "2026.1.0", "analysis_status": "complete", "decision": "allow", "artifact_identity": {}}]}}],
            }))
            self.assertEqual(main(["workspace-lock", "--report", str(report_path), "--output", str(output)]), 0)
            self.assertEqual(json.loads(output.read_text())["extensions"]["ms-python.python"]["version"], "2026.1.0")

    def test_require_lock_rejects_unreviewed_workspace_extensions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".vscode").mkdir()
            (root / ".vscode" / "extensions.json").write_text('{"recommendations":["ms-python.python"]}')
            with self.assertRaisesRegex(ValueError, "missing pinned version"):
                scan_workspace_extensions(root, require_lock=True)

    def test_cli_require_lock_fails_before_any_marketplace_scan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".vscode").mkdir()
            (root / ".vscode" / "extensions.json").write_text('{"recommendations":["ms-python.python"]}')
            with self.assertRaises(SystemExit) as failure:
                main(["workspace", "--root", str(root), "--require-lock"])
            self.assertEqual(failure.exception.code, 2)

    def test_deep_workspace_profile_requires_runtime_and_all_required_providers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".vscode").mkdir()
            (root / ".vscode" / "extensions.json").write_text('{"recommendations":["ms-python.python"]}')
            with self.assertRaisesRegex(ValueError, "requires runtime"):
                scan_workspace_extensions(root, profile="deep")
            calls = []
            report = scan_workspace_extensions(root, profile="deep", dynamic_runtime=True, runtime_timeout_seconds=23, scanner=lambda **kwargs: calls.append(kwargs) or {})
            self.assertEqual(report["profile"], "deep")
            self.assertTrue(calls[0]["dynamic_runtime"])
            self.assertEqual(calls[0]["runtime_timeout_seconds"], 23)
            self.assertEqual(calls[0]["required_providers"], frozenset({"semgrep", "yara", "dependency_intelligence"}))

    def test_lock_rejects_invalid_entries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / "extensions.lock.json"
            lock.write_text('{"extensions":{"invalid":{"version":"1.0.0"}}}')
            with self.assertRaisesRegex(ValueError, "invalid extension"):
                load_workspace_lock(lock)
