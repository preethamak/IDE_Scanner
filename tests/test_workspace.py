from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ide_scanner.workspace import discover_workspace_extensions, load_workspace_lock, scan_workspace_extensions


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
            self.assertEqual(report["extensions"][0]["declared_in"], [".vscode/extensions.json"])

    def test_lock_rejects_invalid_entries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / "extensions.lock.json"
            lock.write_text('{"extensions":{"invalid":{"version":"1.0.0"}}}')
            with self.assertRaisesRegex(ValueError, "invalid extension"):
                load_workspace_lock(lock)
