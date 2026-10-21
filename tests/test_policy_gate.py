from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


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
        approval = {"publisher.extension": {"sha256": "a" * 64, "version": "1.0.0", "expires_at": "2027-01-01T00:00:00Z", "reason": "Security review"}}
        outcome, _ = gate._policy_outcome("publisher.extension", "a" * 64, "1.0.0", "review", approval, {})
        self.assertEqual(outcome, "pass")

    def test_block_override_is_explicit(self) -> None:
        gate = policy_gate()
        approval = {"publisher.extension": {"sha256": "a" * 64, "version": "1.0.0", "expires_at": "2027-01-01T00:00:00Z", "reason": "Security review"}}
        outcome, _ = gate._policy_outcome("publisher.extension", "a" * 64, "1.0.0", "block", approval, {})
        self.assertEqual(outcome, "fail")
        approval["publisher.extension"]["allow_block_override"] = True
        outcome, _ = gate._policy_outcome("publisher.extension", "a" * 64, "1.0.0", "block", approval, {})
        self.assertEqual(outcome, "pass")

    def test_review_approval_needs_expiry_and_reason(self) -> None:
        gate = policy_gate()
        approval = {"publisher.extension": {"sha256": "a" * 64, "version": "1.0.0"}}
        outcome, reason = gate._policy_outcome("publisher.extension", "a" * 64, "1.0.0", "review", approval, {})
        self.assertEqual(outcome, "fail")
        self.assertIn("expiry", reason)
        approval["publisher.extension"]["expires_at"] = "not-a-date"
        outcome, reason = gate._policy_outcome("publisher.extension", "a" * 64, "1.0.0", "review", approval, {})
        self.assertEqual(outcome, "fail")
        self.assertIn("invalid", reason)
        approval["publisher.extension"]["expires_at"] = "2027-01-01T00:00:00"
        outcome, reason = gate._policy_outcome("publisher.extension", "a" * 64, "1.0.0", "review", approval, {})
        self.assertEqual(outcome, "fail")
        self.assertIn("timezone", reason)

    def test_release_lock_must_match_exact_artifact(self) -> None:
        gate = policy_gate()
        entry = {"version": "1.0.0", "sha256": "a" * 64}
        self.assertEqual(gate._lock_outcome(entry, "a" * 64, "1.0.0")[0], "pass")
        outcome, reason = gate._lock_outcome({}, "a" * 64, "1.0.0")
        self.assertEqual(outcome, "fail")
        self.assertIn("No reviewed", reason)
        outcome, reason = gate._lock_outcome(entry, "b" * 64, "1.0.0")
        self.assertEqual(outcome, "fail")
        self.assertIn("SHA-256", reason)

    def test_evaluation_fails_before_policy_when_resolved_artifact_drifts(self) -> None:
        gate = policy_gate()
        report = {
            "extensions": [{"artifact_hash": "b" * 64, "version": "1.0.0", "decision": "allow"}],
            "ruleset_version": "test-ruleset",
        }
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(gate, "recommended_extensions", return_value=["publisher.extension"]),
            patch.object(gate, "download_marketplace_vsix", return_value=Path("/tmp/extension.vsix")),
            patch.object(gate, "scan_targets", return_value=report),
        ):
            result = gate.evaluate(
                Path(directory),
                {},
                {"extensions": {"publisher.extension": {"version": "1.0.0", "sha256": "a" * 64}}},
            )
        row = result["extensions"][0]
        self.assertEqual(row["outcome"], "fail")
        self.assertIn("Release lock", row["reason"])
