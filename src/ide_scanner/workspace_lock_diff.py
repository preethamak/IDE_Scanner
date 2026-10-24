"""Deterministic review diff for GuardRails workspace extension locks."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .workspace import load_workspace_lock


def compare_workspace_locks(before: str | Path, after: str | Path) -> dict[str, Any]:
    before_entries = load_workspace_lock(Path(before))
    after_entries = load_workspace_lock(Path(after))
    before_names, after_names = set(before_entries), set(after_entries)
    changed = [
        {"extension_id": key, "before": before_entries[key], "after": after_entries[key]}
        for key in sorted(before_names & after_names) if before_entries[key] != after_entries[key]
    ]
    return {
        "schema_version": "guardrails.workspace-extension-lock-diff.v1",
        "added": sorted(after_names - before_names),
        "removed": sorted(before_names - after_names),
        "changed": changed,
        "unchanged": sorted(key for key in before_names & after_names if before_entries[key] == after_entries[key]),
        "drift_detected": bool(after_names - before_names or before_names - after_names or changed),
    }


__all__ = ["compare_workspace_locks"]
