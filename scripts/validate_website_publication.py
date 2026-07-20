from __future__ import annotations

import argparse
import json
import urllib.request
from pathlib import Path
from typing import Any


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate frozen website-corpus expectations against published canonical scans.")
    parser.add_argument("--results", type=Path, default=Path("benchmarks/website-corpus/v1/results.json"))
    parser.add_argument("--publication-url", default="https://ide-scanner.vercel.app/api/benchmark")
    args = parser.parse_args()
    expected = json.loads(args.results.read_text(encoding="utf-8")).get("rows") or []
    with urllib.request.urlopen(args.publication_url, timeout=60) as response:
        actual = json.loads(response.read().decode()).get("rows") or []
    summary = validate_rows(expected, actual)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 1 if summary["awaiting"] or summary["mismatches"] else 0


def validate_rows(expected: list[dict[str, Any]], actual: list[dict[str, Any]]) -> dict[str, Any]:
    by_key = {artifact_key(row.get("extension_id"), row.get("version")): row for row in actual}
    mismatches: list[dict[str, str]] = []
    awaiting: list[str] = []
    for row in expected:
        key = artifact_key(row.get("extension_id"), row.get("version"))
        published = by_key.get(key)
        scan = (published or {}).get("scan") or {}
        if not scan:
            awaiting.append(key)
            continue
        checks = {
            "sha256": (str(row.get("sha256") or "").lower(), str(published.get("sha256") or "").lower()),
            "decision": (str(row.get("frozen_expected_decision") or row.get("artifact_aware_expected_decision") or ""), str(scan.get("decision") or "")),
            "coverage": ("100", str(scan.get("coverage_percent") or 0)),
            "score_schema": ("2", str(scan.get("score_schema_version") or "")),
        }
        for field, (wanted, observed) in checks.items():
            if wanted != observed:
                mismatches.append({"artifact": key, "field": field, "expected": wanted, "actual": observed})
    return {"total": len(expected), "published": len(expected) - len(awaiting), "awaiting": awaiting, "mismatches": mismatches}


def artifact_key(extension_id: object, version: object) -> str:
    return f"{str(extension_id).lower()}@{version}"


if __name__ == "__main__":
    raise SystemExit(main())
