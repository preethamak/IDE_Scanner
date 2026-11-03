from __future__ import annotations

from pathlib import Path


def test_declaration_diff_action_exposes_drift_outputs_and_preserves_gate_exit_code():
    action = (Path(__file__).resolve().parents[1] / ".github" / "actions" / "mcp-declaration-diff" / "action.yml").read_text(encoding="utf-8")

    assert "mcp-declarations --before" in action
    assert "fail-on-drift" in action
    assert "drift_detected" in action
    assert "changed_tool_count" in action
    assert 'if [ "$status" -ne 0 ] && [ "$status" -ne 1 ]; then exit "$status"; fi' in action
    assert 'exit "$status"' in action
