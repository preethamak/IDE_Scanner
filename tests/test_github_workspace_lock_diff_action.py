from __future__ import annotations

from pathlib import Path


def test_workspace_lock_diff_action_preserves_outputs_when_drift_fails_the_gate():
    action = (Path(__file__).resolve().parents[1] / ".github" / "actions" / "workspace-lock-diff" / "action.yml").read_text(encoding="utf-8")
    assert "workspace-lock-diff --before" in action
    assert "changed_extension_count" in action
    assert "drift_detected" in action
    assert 'if [ "$status" -ne 0 ] && [ "$status" -ne 1 ]; then exit "$status"; fi' in action
    assert 'exit "$status"' in action
