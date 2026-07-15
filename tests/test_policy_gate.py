from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


def policy_gate():
    path = Path(__file__).resolve().parents[1] / "scripts" / "policy_gate.py"
    spec = importlib.util.spec_from_file_location("policy_gate", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PolicyGateTests(unittest.TestCase):
    def test_reads_workspace_and_devcontainer_recommendations(self) -> None:
        gate = policy_gate()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".vscode").mkdir()
            (root / ".devcontainer").mkdir()
            (root / ".vscode" / "extensions.json").write_text('{"recommendations":["ms-python.python"]}')
            (root / ".devcontainer" / "devcontainer.json").write_text('{"customizations":{"vscode":{"extensions":["ms-vscode.cmake-tools"]}}}')
            self.assertEqual(gate.recommended_extensions(root), ["ms-python.python", "ms-vscode.cmake-tools"])

    def test_review_needs_exact_active_approval(self) -> None:
        gate = policy_gate()
        outcome, _ = gate._policy_outcome("publisher.extension", "a" * 64, "1.0.0", "review", {}, {})
        self.assertEqual(outcome, "fail")
        approval = {"publisher.extension": {"sha256": "a" * 64, "version": "1.0.0", "expires_at": "2027-01-01T00:00:00Z"}}
        outcome, _ = gate._policy_outcome("publisher.extension", "a" * 64, "1.0.0", "review", approval, {})
        self.assertEqual(outcome, "pass")

    def test_block_override_is_explicit(self) -> None:
        gate = policy_gate()
        approval = {"publisher.extension": {"sha256": "a" * 64, "version": "1.0.0", "expires_at": "2027-01-01T00:00:00Z"}}
        outcome, _ = gate._policy_outcome("publisher.extension", "a" * 64, "1.0.0", "block", approval, {})
        self.assertEqual(outcome, "fail")
        approval["publisher.extension"]["allow_block_override"] = True
        outcome, _ = gate._policy_outcome("publisher.extension", "a" * 64, "1.0.0", "block", approval, {})
        self.assertEqual(outcome, "pass")
