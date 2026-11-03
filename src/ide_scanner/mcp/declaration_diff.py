"""Deterministic comparison of MCP tool declarations from completed assessments."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def compare_declaration_reports(before: str | Path, after: str | Path) -> dict[str, Any]:
    """Compare declaration fingerprints from two serialized MCP assessments.

    This intentionally compares only server-declared interface evidence. It
    does not reinterpret scan findings, generated descriptions, or decisions.
    """
    before_tools = _read_declarations(before)
    after_tools = _read_declarations(after)
    before_names = set(before_tools)
    after_names = set(after_tools)
    shared = before_names & after_names
    changed = [
        {
            "name": name,
            "before_sha256": before_tools[name],
            "after_sha256": after_tools[name],
        }
        for name in sorted(shared)
        if before_tools[name] != after_tools[name]
    ]
    unchanged = sorted(name for name in shared if before_tools[name] == after_tools[name])
    added = sorted(after_names - before_names)
    removed = sorted(before_names - after_names)
    return {
        "schema_version": "guardrails.mcp-declaration-diff.v1",
        "before_tool_count": len(before_tools),
        "after_tool_count": len(after_tools),
        "added": added,
        "removed": removed,
        "changed": changed,
        "unchanged": unchanged,
        "drift_detected": bool(added or removed or changed),
    }


def _read_declarations(path: str | Path) -> dict[str, str]:
    source = Path(path)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except OSError as error:
        raise ValueError(f"Cannot read MCP assessment {source}: {error}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"MCP assessment {source} is not valid JSON: {error.msg}") from error
    if not isinstance(payload, dict) or not isinstance(payload.get("tools"), list):
        raise ValueError(f"MCP assessment {source} must contain a tools array.")
    declarations: dict[str, str] = {}
    for index, tool in enumerate(payload["tools"]):
        if not isinstance(tool, dict):
            raise ValueError(f"MCP assessment {source} has a non-object tool at index {index}.")
        name = tool.get("name")
        declaration = tool.get("declaration")
        fingerprint = declaration.get("sha256") if isinstance(declaration, dict) else None
        if not isinstance(name, str) or not name:
            raise ValueError(f"MCP assessment {source} has a tool without a name at index {index}.")
        if not isinstance(fingerprint, str) or not _SHA256.fullmatch(fingerprint):
            raise ValueError(
                f"MCP assessment {source} tool {name!r} has no valid declaration SHA-256. "
                "Re-run the assessment with a GuardRails version that records declaration fingerprints.",
            )
        if name in declarations:
            raise ValueError(f"MCP assessment {source} has duplicate tool name {name!r}.")
        declarations[name] = fingerprint
    return declarations


__all__ = ["compare_declaration_reports"]
