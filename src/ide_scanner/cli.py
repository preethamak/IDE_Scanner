from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .discovery import discover_from_path, discover_local_installations
from .sandbox_runner import run_sandbox
from .scanner import scan_targets


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ide-scanner", description="Scan VS Code-compatible extensions for security risk.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Run a security scan.")
    scan.add_argument("--fixtures", action="store_true", help="Scan bundled sample extensions.")
    scan.add_argument("--all", action="store_true", help="Scan local VS Code-compatible extension installs.")
    scan.add_argument("--path", action="append", default=[], help="Extension folder, extensions directory, or VSIX file to scan.")
    scan.add_argument("--extension-id", action="append", default=[], help="Extension identifier to check against online registries.")
    scan.add_argument("--online", action="store_true", help="Enable registry and dependency vulnerability checks.")
    scan.add_argument("--known-bad-hashes", help="JSON or line-based SHA-256 feed for known malicious artifacts.")
    scan.add_argument("--threat-feed", help="JSON feed of known malicious or suspicious extension ids.")
    scan.add_argument("--sandbox-observations", help="JSON observations from an external sandbox run. The scanner imports this evidence but does not execute extensions.")
    scan.add_argument("--previous-report", help="Previous ide-scanner JSON report to compare versions, dependencies, scores, and artifacts.")
    scan.add_argument("--out", help="Write JSON report to this file.")

    inventory = subparsers.add_parser("inventory", help="List discovered extension paths without scanning.")
    inventory.add_argument("--all", action="store_true", help="List local VS Code-compatible extension installs.")
    inventory.add_argument("--path", action="append", default=[], help="Extension folder, extensions directory, or VSIX file to inspect.")

    sandbox = subparsers.add_parser("sandbox", help="Create or run a disposable sandbox observation plan.")
    sandbox.add_argument("--path", required=True, help="Extension folder or VSIX file to sandbox.")
    sandbox.add_argument("--out", required=True, help="Write sandbox observations JSON to this file.")
    sandbox.add_argument("--allow-execute", action="store_true", help="Actually execute package lifecycle commands in a temporary HOME/workspace.")
    sandbox.add_argument("--timeout", type=int, default=15, help="Execution timeout per command in seconds.")

    benchmark = subparsers.add_parser("benchmark", help="Run scanner against bundled ground-truth fixtures.")
    benchmark.add_argument("--out", help="Write benchmark JSON result to this file.")

    args = parser.parse_args(argv)
    if args.command == "scan":
        report = scan_targets(
            paths=[Path(item) for item in args.path],
            extension_ids=args.extension_id,
            include_fixtures=args.fixtures,
            all_local=args.all,
            online=args.online,
            known_bad_hashes_file=args.known_bad_hashes,
            threat_feed_file=args.threat_feed,
            sandbox_observations_file=args.sandbox_observations,
            previous_report_file=args.previous_report,
        )
        _emit(report, args.out)
        return 0
    if args.command == "inventory":
        targets: list[dict[str, str]] = []
        for item in args.path:
            targets.extend(discover_from_path(item))
        if args.all:
            targets.extend(discover_local_installations())
        _emit({"extensions": targets}, None)
        return 0
    if args.command == "sandbox":
        observations = run_sandbox(Path(args.path), allow_execute=args.allow_execute, timeout_seconds=args.timeout)
        _emit(observations, args.out)
        return 0
    if args.command == "benchmark":
        result = _run_benchmark()
        _emit(result, args.out)
        return 0
    return 2


def _emit(data: dict[str, Any], out: str | None) -> None:
    payload = json.dumps(data, indent=2, sort_keys=True)
    if out:
        Path(out).write_text(payload + "\n", encoding="utf-8")
        return
    print(payload)


def _run_benchmark() -> dict[str, Any]:
    truth_path = Path(__file__).resolve().parents[2] / "benchmarks" / "ground-truth.json"
    truth = json.loads(truth_path.read_text(encoding="utf-8"))
    threat_feed = truth_path.parent / "threat-feed.json"
    report = scan_targets(
        paths=[truth_path.parent / item["path"] for item in truth["extensions"]],
        threat_feed_file=threat_feed if threat_feed.exists() else None,
    )
    by_id = {extension["extension_id"]: extension for extension in report["extensions"]}
    rows: list[dict[str, Any]] = []
    correct = 0
    false_positive = 0
    false_negative = 0
    for expected in truth["extensions"]:
        extension_id = expected["extension_id"]
        actual = by_id.get(extension_id)
        actual_verdict = actual["verdict"] if actual else "missing"
        ok = actual_verdict == expected["expected_verdict"]
        correct += int(ok)
        if expected["expected_verdict"] in {"clean", "review"} and actual_verdict in {"suspicious", "malicious"}:
            false_positive += 1
        if expected["expected_verdict"] in {"suspicious", "malicious"} and actual_verdict in {"clean", "review", "missing"}:
            false_negative += 1
        rows.append({
            "extension_id": extension_id,
            "expected_verdict": expected["expected_verdict"],
            "actual_verdict": actual_verdict,
            "ok": ok,
            "reason": expected.get("reason", ""),
            "risk_score": actual.get("risk_score") if actual else None,
            "malware_score": actual.get("malware_score") if actual else None,
            "top_findings": [finding["rule_id"] for finding in (actual.get("findings", []) if actual else [])[:5]],
        })
    malicious_expected = [row for row in rows if row["expected_verdict"] in {"suspicious", "malicious"}]
    malicious_detected = [row for row in malicious_expected if row["actual_verdict"] in {"suspicious", "malicious"}]
    return {
        "schema_version": "0.1.0",
        "total": len(rows),
        "correct": correct,
        "accuracy": round(correct / len(rows), 4) if rows else 0,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "malicious_recall": round(len(malicious_detected) / len(malicious_expected), 4) if malicious_expected else 0,
        "rows": rows,
        "scanner_summary": report["summary"],
    }
