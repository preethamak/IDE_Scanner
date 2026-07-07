from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

JS_AST_EXTS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
_WALKER_PATH = Path(__file__).parent / "js_ast" / "walker.js"
_TIMEOUT_SECONDS = 8

_node_available: bool | None = None


def node_available() -> bool:
    global _node_available
    if _node_available is None:
        _node_available = shutil.which("node") is not None
    return _node_available


def analyze_js_source(rel: str, text: str) -> list[dict[str, Any]]:
    """Run the vendored acorn-based walker over one JS/TS source blob and
    return raw finding dicts (rule/line/detail/severity). Returns an empty
    list on any failure -- missing node, parse errors, timeouts, or malformed
    output -- so callers can always fall back silently to regex-only
    findings; this is a best-effort supplemental signal, never a hard gate."""
    if not node_available():
        return []
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=Path(rel).suffix or ".js", delete=False) as handle:
            handle.write(text)
            source_path = handle.name
        try:
            proc = subprocess.run(
                ["node", str(_WALKER_PATH), source_path],
                capture_output=True,
                text=True,
                timeout=_TIMEOUT_SECONDS,
            )
        finally:
            Path(source_path).unlink(missing_ok=True)
    except (OSError, subprocess.SubprocessError):
        return []

    if proc.returncode != 0 and not proc.stdout:
        return []
    try:
        payload = json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return []
    findings = payload.get("findings")
    if not isinstance(findings, list):
        return []
    return [item for item in findings if isinstance(item, dict) and item.get("rule")]
