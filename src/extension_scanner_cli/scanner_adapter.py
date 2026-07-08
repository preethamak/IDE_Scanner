from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ide_scanner.discovery import discover_from_path, discover_local_installations
from ide_scanner.registry import search_marketplace_extensions
from ide_scanner.report_bundle import build_report_bundle, write_report_bundle
from ide_scanner.rule_registry import rules_json
from ide_scanner.scanner import scan_targets


def search_extensions(query: str, *, limit: int = 20) -> list[dict[str, Any]]:
    return search_marketplace_extensions(query, page_size=limit)


def installed_extensions() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for target in discover_local_installations():
        path = Path(target["path"])
        manifest = _read_manifest(path / "package.json")
        publisher = str(manifest.get("publisher") or "unknown")
        name = str(manifest.get("name") or path.name)
        rows.append({
            "type": target.get("type", "vscode"),
            "path": str(path),
            "client": _client_from_path(path),
            "extension_id": f"{publisher}.{name}",
            "display_name": str(manifest.get("displayName") or name),
            "name": name,
            "publisher": publisher,
            "version": str(manifest.get("version") or "unknown"),
            "description": str(manifest.get("description") or ""),
        })
    return sorted(rows, key=lambda item: (item["client"], item["display_name"].lower(), item["version"]))


def scan_marketplace(extension_id: str) -> dict[str, Any]:
    return scan_targets(marketplace_scan_ids=[extension_id], online=True, include_posture=False)


def scan_paths(paths: list[str | Path]) -> dict[str, Any]:
    return scan_targets(paths=[Path(item) for item in paths], online=False, include_posture=False)


def discover_paths(path: str | Path) -> list[dict[str, str]]:
    return discover_from_path(path)


def get_rules() -> dict[str, Any]:
    return rules_json()


def write_bundle(report: dict[str, Any], output: str | Path, *, source: str = "cli") -> dict[str, Any]:
    return write_report_bundle(report, output, profile="smart", source=source)


def display_report(report: dict[str, Any], *, source: str = "cli") -> dict[str, Any]:
    bundle = build_report_bundle(report, profile="smart", source=source)
    summary = dict(bundle["summary"]["summary"])
    return {
        "scan_id": bundle["metadata"].get("scan_id", report.get("scan_id", "unknown")),
        "created_at": bundle["metadata"].get("created_at", report.get("created_at", "")),
        "summary": {
            "total_extensions": summary.get("total_extensions", 0),
            "max_risk_score": summary.get("max_risk_score", 0),
            "max_malware_score": summary.get("max_malware_score", 0),
            "posture_status": summary.get("posture_status", ""),
        },
        "extensions": list(bundle["extensions"].values()),
    }


def _read_manifest(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _client_from_path(path: Path) -> str:
    text = str(path).lower()
    if ".cursor" in text:
        return "Cursor"
    if ".windsurf" in text:
        return "Windsurf"
    if ".vscodium" in text:
        return "VSCodium"
    if ".vscode-insiders" in text:
        return "VS Code Insiders"
    return "VS Code"
