"""Discover and review the published extensions recommended by a workspace."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable

from .jsonc import loads_jsonc
from .scanner import DEEP_REQUIRED_PROVIDERS, scan_targets

EXTENSION_ID = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_.-]+$")
IGNORED_DIRECTORIES = frozenset({".git", ".next", "node_modules", "vendor"})
MANIFEST_NAMES = (".vscode/extensions.json", ".devcontainer/devcontainer.json", "devcontainer.json")


def discover_workspace_extensions(root: Path) -> dict[str, Any]:
    root = root.resolve()
    paths = {root / name for name in MANIFEST_NAMES}
    paths.update(root.rglob("*.code-workspace"))
    paths.update(root.rglob(".vscode/extensions.json"))
    paths.update(root.rglob(".devcontainer/devcontainer.json"))
    sources: dict[str, list[str]] = {}
    for path in sorted(paths):
        if not path.is_file() or any(part in IGNORED_DIRECTORIES for part in path.parts):
            continue
        try:
            payload = loads_jsonc(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        relative = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
        for extension_id in _extension_values(payload):
            sources.setdefault(extension_id, []).append(relative)
    return {"workspace": str(root), "extensions": sorted(sources), "sources": {key: sorted(value) for key, value in sorted(sources.items())}}


def load_workspace_lock(path: Path | None) -> dict[str, dict[str, str]]:
    if path is None or not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Workspace lock is not valid JSON: {exc}") from exc
    entries = payload.get("extensions") if isinstance(payload, dict) else None
    if not isinstance(entries, dict):
        raise ValueError("Workspace lock must contain an extensions object")
    locked: dict[str, dict[str, str]] = {}
    for extension_id, value in entries.items():
        if not isinstance(extension_id, str) or not EXTENSION_ID.fullmatch(extension_id) or not isinstance(value, dict):
            raise ValueError("Workspace lock contains an invalid extension entry")
        version = str(value.get("version") or "").strip()
        platform = str(value.get("target_platform") or "").strip().lower()
        if version:
            locked[extension_id] = {"version": version, **({"target_platform": platform} if platform else {})}
    return locked


def workspace_lock_coverage(discovery: dict[str, Any], locked: dict[str, dict[str, str]]) -> dict[str, Any]:
    """Describe whether declared workspace extensions have reviewed pins."""
    declared = set(discovery.get("extensions") or [])
    pinned = sorted(extension_id for extension_id in declared if extension_id in locked)
    unpinned = sorted(declared.difference(pinned))
    unused = sorted(set(locked).difference(declared))
    return {
        "status": "complete" if not unpinned else "incomplete",
        "declared_count": len(declared),
        "pinned_count": len(pinned),
        "pinned_extensions": pinned,
        "unpinned_extensions": unpinned,
        "unused_lock_extensions": unused,
    }


def build_workspace_lock(report: dict[str, Any]) -> dict[str, Any]:
    """Create reviewed version pins from completed workspace scan evidence.

    A lock is an approval input, so it must never be generated from failed or
    incomplete analysis. The lock deliberately pins only coordinates the
    workspace scanner currently enforces: exact version and target platform.
    """
    if report.get("schema_version") != "guardrails.workspace-extension-scan.v1":
        raise ValueError("Workspace lock generation requires a guardrails.workspace-extension-scan.v1 report")
    entries = report.get("extensions")
    if not isinstance(entries, list):
        raise ValueError("Workspace report must contain an extensions list")
    lock_entries: dict[str, dict[str, str]] = {}
    for item in entries:
        if not isinstance(item, dict):
            raise ValueError("Workspace report contains an invalid extension entry")
        extension_id = str(item.get("extension_id") or "").strip()
        if not EXTENSION_ID.fullmatch(extension_id):
            raise ValueError("Workspace report contains an invalid extension identifier")
        scan = item.get("scan")
        scanned_extensions = scan.get("extensions") if isinstance(scan, dict) else None
        if not isinstance(scanned_extensions, list):
            raise ValueError(f"Workspace report has no scanner evidence for {extension_id}")
        matches = [candidate for candidate in scanned_extensions if isinstance(candidate, dict) and candidate.get("extension_id") == extension_id]
        if len(matches) != 1:
            raise ValueError(f"Workspace report must contain exactly one scanner result for {extension_id}")
        evidence = matches[0]
        if evidence.get("analysis_status") != "complete" or evidence.get("decision") == "incomplete":
            raise ValueError(f"Workspace report evidence is incomplete for {extension_id}; refusing to generate a lock")
        version = str(evidence.get("version") or "").strip()
        if not version:
            raise ValueError(f"Workspace report has no exact version for {extension_id}")
        pin = {"version": version}
        artifact_identity = evidence.get("artifact_identity")
        target_platform = str(artifact_identity.get("target_platform") or "").strip().lower() if isinstance(artifact_identity, dict) else ""
        if target_platform:
            pin["target_platform"] = target_platform
        lock_entries[extension_id] = pin
    return {
        "schema_version": "guardrails.workspace-extension-lock.v1",
        "source_report_schema": report["schema_version"],
        "extensions": {extension_id: lock_entries[extension_id] for extension_id in sorted(lock_entries)},
    }


def write_workspace_lock(report: dict[str, Any], path: Path) -> dict[str, Any]:
    lock = build_workspace_lock(report)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return lock


def scan_workspace_extensions(
    root: Path,
    *,
    lock_path: Path | None = None,
    profile: str = "standard",
    require_lock: bool = False,
    dynamic_runtime: bool = False,
    runtime_timeout_seconds: int = 15,
    scanner: Callable[..., dict[str, Any]] = scan_targets,
) -> dict[str, Any]:
    if profile not in {"standard", "deep"}:
        raise ValueError("Workspace profile must be standard or deep")
    if profile == "deep" and not dynamic_runtime:
        raise ValueError("Workspace deep profile requires runtime execution")
    discovery = discover_workspace_extensions(root)
    locked = load_workspace_lock(lock_path)
    lock_coverage = workspace_lock_coverage(discovery, locked)
    if require_lock and lock_coverage["unpinned_extensions"]:
        missing = ", ".join(lock_coverage["unpinned_extensions"])
        raise ValueError(f"Workspace lock is incomplete; missing pinned version for: {missing}")
    records: list[dict[str, Any]] = []
    for extension_id in discovery["extensions"]:
        pin = locked.get(extension_id, {})
        report = scanner(
            marketplace_scan_ids=[extension_id],
            marketplace_version=pin.get("version") or None,
            marketplace_target_platform=pin.get("target_platform") or None,
            online=True,
            include_posture=False,
            required_providers=DEEP_REQUIRED_PROVIDERS if profile == "deep" else None,
            dynamic_runtime=dynamic_runtime,
            runtime_timeout_seconds=runtime_timeout_seconds,
        )
        records.append({"extension_id": extension_id, "declared_in": discovery["sources"][extension_id], "requested_version": pin.get("version") or None, "requested_target_platform": pin.get("target_platform") or None, "scan": report})
    return {
        "schema_version": "guardrails.workspace-extension-scan.v1",
        "workspace": discovery["workspace"],
        "lock_path": str(lock_path) if lock_path else None,
        "lock_coverage": lock_coverage,
        "profile": profile,
        "recommendation_count": len(records),
        "extensions": records,
    }


def _extension_values(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        recommendations = value.get("recommendations")
        if isinstance(recommendations, list):
            found.update(item.strip() for item in recommendations if isinstance(item, str) and EXTENSION_ID.fullmatch(item.strip()))
        customizations = value.get("customizations")
        if isinstance(customizations, dict) and isinstance(customizations.get("vscode"), dict):
            extensions = customizations["vscode"].get("extensions")
            if isinstance(extensions, list):
                found.update(item.strip() for item in extensions if isinstance(item, str) and EXTENSION_ID.fullmatch(item.strip()))
        for child in value.values():
            found.update(_extension_values(child))
    elif isinstance(value, list):
        for child in value:
            found.update(_extension_values(child))
    return found
