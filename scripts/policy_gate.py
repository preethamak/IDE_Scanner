#!/usr/bin/env python3
"""Repository-local extension approval gate.

The gate intentionally scans exact downloaded VSIX artifacts locally and never
executes extension code. It does not replace the hosted intelligence service;
it gives a pull request a reproducible control point when a public report is
not yet available.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ide_scanner.jsonc import loads_jsonc
from ide_scanner.registry import download_marketplace_vsix
from ide_scanner.scanner import scan_targets

MANIFEST_NAMES = (".vscode/extensions.json", ".devcontainer/devcontainer.json", "devcontainer.json")


def recommended_extensions(root: Path) -> list[str]:
    values: set[str] = set()
    paths = [root / name for name in MANIFEST_NAMES]
    paths.extend(root.rglob("*.code-workspace"))
    paths.extend(root.rglob(".vscode/extensions.json"))
    paths.extend(root.rglob(".devcontainer/devcontainer.json"))
    for path in paths:
        if not path.is_file() or any(part in {"node_modules", ".git", ".next"} for part in path.parts):
            continue
        try:
            data = loads_jsonc(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        values.update(_extension_values(data))
    return sorted(values)


def _extension_values(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        direct = value.get("recommendations")
        if isinstance(direct, list):
            found.update(str(item).strip() for item in direct if _valid_id(item))
        custom = value.get("customizations")
        if isinstance(custom, dict):
            vscode = custom.get("vscode")
            if isinstance(vscode, dict) and isinstance(vscode.get("extensions"), list):
                found.update(str(item).strip() for item in vscode["extensions"] if _valid_id(item))
        for child in value.values():
            found.update(_extension_values(child))
    elif isinstance(value, list):
        for child in value:
            found.update(_extension_values(child))
    return found


def _valid_id(value: Any) -> bool:
    return isinstance(value, str) and value.count(".") >= 1 and " " not in value


def evaluate(root: Path, policy: dict[str, Any], lock: dict[str, Any], write_lock: bool = False) -> dict[str, Any]:
    approvals = policy.get("approvals") if isinstance(policy.get("approvals"), dict) else {}
    exceptions = policy.get("exceptions") if isinstance(policy.get("exceptions"), dict) else {}
    locked = lock.get("extensions") if isinstance(lock.get("extensions"), dict) else {}
    rows: list[dict[str, Any]] = []
    generated: dict[str, Any] = {}
    for extension_id in recommended_extensions(root):
        existing = locked.get(extension_id) if isinstance(locked.get(extension_id), dict) else {}
        version = str(existing.get("version") or "") or None
        with tempfile.TemporaryDirectory(prefix="ide-scanner-policy-") as temp:
            vsix = download_marketplace_vsix(extension_id, version=version, destination_dir=temp)
            report = scan_targets(paths=[vsix], include_posture=False, online=True)
        detail = (report.get("extensions") or [{}])[0]
        artifact = str(detail.get("artifact_hash") or detail.get("artifact_identity", {}).get("sha256") or "")
        resolved_version = str(detail.get("version") or version or "")
        decision = str(detail.get("decision") or "incomplete")
        generated[extension_id] = {"version": resolved_version, "sha256": artifact, "decision": decision, "ruleset_version": report.get("ruleset_version", "recorded-in-report")}
        outcome, reason = _policy_outcome(extension_id, artifact, resolved_version, decision, approvals, exceptions)
        rows.append({"extension_id": extension_id, "version": resolved_version, "sha256": artifact, "decision": decision, "outcome": outcome, "reason": reason})
    if write_lock:
        lock["schema_version"] = 1
        lock["generated_at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        lock["extensions"] = generated
    return {"extensions": rows, "summary": _summary(rows), "lock": lock}


def _policy_outcome(extension_id: str, sha256: str, version: str, decision: str, approvals: dict[str, Any], exceptions: dict[str, Any]) -> tuple[str, str]:
    if decision == "allow":
        return "pass", "Required analysis completed without policy-crossing evidence."
    if decision == "incomplete":
        return "fail", "Analysis is incomplete; this artifact cannot be approved."
    entry = exceptions.get(extension_id) if isinstance(exceptions.get(extension_id), dict) else approvals.get(extension_id)
    if not isinstance(entry, dict):
        return "fail", f"{decision.upper()} requires an exact-hash approval or exception."
    if str(entry.get("sha256") or "") != sha256 or str(entry.get("version") or "") != version:
        return "fail", "Approval does not match this exact version and SHA-256."
    expiry = str(entry.get("expires_at") or "")
    if expiry and datetime.fromisoformat(expiry.replace("Z", "+00:00")) <= datetime.now(UTC):
        return "fail", "Approval or exception has expired."
    if decision == "block" and not bool(entry.get("allow_block_override")):
        return "fail", "BLOCK is non-overridable unless allow_block_override is explicit."
    return "pass", f"Exact artifact {decision.upper()} exception is active."


def _summary(rows: list[dict[str, Any]]) -> dict[str, int]:
    return {"total": len(rows), "passed": sum(row["outcome"] == "pass" for row in rows), "failed": sum(row["outcome"] != "pass" for row in rows)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan repository-declared VS Code extensions against exact-artifact policy.")
    parser.add_argument("--root", default=".")
    parser.add_argument("--policy", default=".ide-scanner/policy.json")
    parser.add_argument("--lock", default=".ide-scanner/extensions.lock.json")
    parser.add_argument("--output", default="ide-scanner-policy-result.json")
    parser.add_argument("--write-lock", action="store_true")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    policy_path, lock_path = root / args.policy, root / args.lock
    policy = json.loads(policy_path.read_text()) if policy_path.exists() else {}
    lock = json.loads(lock_path.read_text()) if lock_path.exists() else {}
    result = evaluate(root, policy, lock, args.write_lock)
    Path(args.output).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    if args.write_lock:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path.write_text(json.dumps(result["lock"], indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"]))
    return 1 if result["summary"]["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
