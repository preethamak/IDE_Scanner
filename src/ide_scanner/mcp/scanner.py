from __future__ import annotations

import asyncio
import json
import threading
from pathlib import Path
from typing import Any, Coroutine
from urllib.parse import urlsplit

from .orchestrator import ServerCatalogRiskConfig, ServerCatalogRiskOrchestrator


def scan_mcp_path(path: str | Path, *, config: ServerCatalogRiskConfig | None = None) -> dict[str, Any]:
    source = Path(path).expanduser().resolve()
    payload = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("MCP assessment input must be a JSON object.")
    payload.setdefault("source", {})
    if isinstance(payload["source"], dict):
        payload["source"].update({"path": str(source), "mode": "full"})
    return scan_mcp_payload(payload, config=config)


def scan_mcp_payload(payload: dict[str, Any], *, config: ServerCatalogRiskConfig | None = None) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("MCP assessment input must be a JSON object.")
    raw = payload.get("server") if isinstance(payload.get("server"), dict) else payload
    normalized = _normalize_input(raw)
    return _run_sync(ServerCatalogRiskOrchestrator(config=config).evaluate(normalized))


def _normalize_input(raw: dict[str, Any]) -> dict[str, Any]:
    _validate_descriptor(raw)
    url = str(raw.get("mcp_url") or raw.get("url") or "").strip()
    transport = str(raw.get("transport") or raw.get("transport_type") or "").lower().strip()
    is_local = bool(raw.get("is_local")) or transport in {"stdio", "local", "command"} or not url
    auth_modes = raw.get("auth_modes") or raw.get("authentication")
    if isinstance(auth_modes, str):
        auth_modes = [auth_modes]
    return {
        **raw,
        "mcp_url": url or None,
        "url": url or None,
        "is_local": is_local,
        "transport": transport or ("stdio" if is_local else "streamable-http"),
        "repo_url": str(raw.get("repo_url") or raw.get("repository") or raw.get("repository_url") or "").strip() or None,
        "package": raw.get("package") or raw.get("install_command") or raw.get("command"),
        "tools": raw.get("tools") if isinstance(raw.get("tools"), list) else [],
        "auth_modes": auth_modes if isinstance(auth_modes, list) else [],
    }


def _validate_descriptor(raw: dict[str, Any]) -> None:
    name = raw.get("name")
    if not isinstance(name, str) or not name.strip() or len(name.strip()) > 200:
        raise ValueError("MCP descriptor requires a non-empty name of at most 200 characters.")
    url = str(raw.get("mcp_url") or raw.get("url") or "").strip()
    transport = str(raw.get("transport") or raw.get("transport_type") or "").lower().strip()
    local_transport = transport in {"stdio", "local", "command"}
    is_local = bool(raw.get("is_local")) or local_transport
    if not url and not is_local:
        raise ValueError("MCP descriptor requires mcp_url/url unless it declares a local stdio, command, or is_local transport.")
    if url:
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("MCP descriptor URL must use http or https and include a hostname.")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("MCP descriptor URL must not include credentials.")
    tools = raw.get("tools")
    if tools is not None and (not isinstance(tools, list) or any(not isinstance(item, dict) for item in tools)):
        raise ValueError("MCP descriptor tools must be an array of objects when provided.")
    auth_modes = raw.get("auth_modes") or raw.get("authentication")
    if auth_modes is not None and not isinstance(auth_modes, (str, list)):
        raise ValueError("MCP descriptor auth_modes must be a string or array when provided.")


def _run_sync(coroutine: Coroutine[Any, Any, dict[str, Any]]) -> dict[str, Any]:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coroutine)
    result: list[dict[str, Any]] = []
    error: list[BaseException] = []

    def runner() -> None:
        try:
            result.append(asyncio.run(coroutine))
        except BaseException as exc:  # pragma: no cover - defensive bridge behavior
            error.append(exc)

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    thread.join()
    if error:
        raise error[0]
    return result[0]


__all__ = ["scan_mcp_path", "scan_mcp_payload"]
