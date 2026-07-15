#!/usr/bin/env python3
"""Detect unapproved extension releases against an exact-artifact lock file."""
from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any

from ide_scanner.registry import download_marketplace_vsix
from ide_scanner.scanner import scan_targets


def check(lock: dict[str, Any]) -> dict[str, Any]:
    known = lock.get("extensions") if isinstance(lock.get("extensions"), dict) else {}
    changes: list[dict[str, Any]] = []
    for extension_id, prior in known.items():
        if not isinstance(prior, dict):
            continue
        with tempfile.TemporaryDirectory(prefix="ide-scanner-monitor-") as directory:
            vsix = download_marketplace_vsix(str(extension_id), destination_dir=directory)
            report = scan_targets(paths=[vsix], include_posture=False, online=True)
        detail = (report.get("extensions") or [{}])[0]
        current = {"version": str(detail.get("version") or ""), "sha256": str(detail.get("artifact_hash") or detail.get("artifact_identity", {}).get("sha256") or ""), "decision": str(detail.get("decision") or "incomplete")}
        if current["version"] != str(prior.get("version") or "") or current["sha256"] != str(prior.get("sha256") or ""):
            changes.append({"extension_id": extension_id, "approved": prior, "current": current, "action": "review_required"})
    return {"changes": changes, "summary": {"watched": len(known), "review_required": len(changes)}}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detect releases newer than a repository's approved extension lock.")
    parser.add_argument("--lock", default=".ide-scanner/extensions.lock.json")
    parser.add_argument("--output", default="ide-scanner-release-monitor.json")
    args = parser.parse_args(argv)
    path = Path(args.lock)
    lock = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"extensions": {}}
    result = check(lock)
    Path(args.output).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
