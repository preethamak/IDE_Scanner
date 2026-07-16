#!/usr/bin/env python3
"""Normalize frozen, first-pass, and post-fix website benchmark results."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import Counter
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--corrections", type=Path, required=True)
    parser.add_argument("--first-pass", type=Path, required=True)
    parser.add_argument("--post-fix", type=Path, required=True)
    parser.add_argument("--final", type=Path, required=True)
    parser.add_argument("--malicious-regression", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    manifest = _read(args.manifest)
    corrections = {
        str(row["extension_id"]).lower(): row
        for row in _read(args.corrections).get("corrections", [])
    }
    expected = {
        str(row["extension_id"]).lower(): row
        for row in manifest.get("artifacts", [])
    }
    scans = {
        "first_pass": _read(args.first_pass),
        "post_fix": _read(args.post_fix),
        "final": _read(args.final),
    }
    by_scan = {
        name: {str(row["extension_id"]).lower(): row for row in scan.get("extensions", [])}
        for name, scan in scans.items()
    }
    if any(set(rows) != set(expected) for rows in by_scan.values()):
        raise ValueError("Every scan must contain exactly the frozen artifact identities.")

    rows = []
    for key, artifact in sorted(expected.items()):
        correction = corrections.get(key)
        corrected_expected = str((correction or {}).get("corrected_expected_decision") or artifact["expected_decision"])
        row = {
            "extension_id": artifact["extension_id"],
            "version": artifact["version"],
            "sha256": artifact["sha256"],
            "split": artifact["split"],
            "classification": artifact["classification"],
            "frozen_expected_decision": artifact["expected_decision"],
            "artifact_aware_expected_decision": corrected_expected,
            "label_correction": correction,
        }
        for scan_name, scan_rows in by_scan.items():
            observed = scan_rows[key]
            row[scan_name] = {
                "verdict": observed["verdict"],
                "decision": observed["decision"],
                "severity": observed["severity"],
                "malware_score": observed["malware_score"],
                "risk_score": observed["risk_score"],
                "coverage_status": observed["analysis_coverage"]["status"],
                "coverage_percent": observed["analysis_coverage"]["coverage_percent"],
            }
        rows.append(row)

    malicious = _read(args.malicious_regression)
    malicious_rows = [
        {
            "extension_id": row["extension_id"],
            "version": row["version"],
            "verdict": row["verdict"],
            "decision": row["decision"],
            "malware_score": row["malware_score"],
            "risk_score": row["risk_score"],
            "coverage_status": row["analysis_coverage"]["status"],
        }
        for row in malicious.get("extensions", [])
    ]
    payload = {
        "schema_version": "1.0",
        "cohort_id": manifest.get("cohort_id"),
        "artifact_count": len(rows),
        "artifact_bytes": sum(int(row.get("size_bytes") or 0) for row in manifest.get("artifacts", [])),
        "raw_report_sha256": {
            "first_pass": _sha256(args.first_pass),
            "post_fix": _sha256(args.post_fix),
            "final": _sha256(args.final),
            "malicious_regression": _sha256(args.malicious_regression),
        },
        "first_pass_metrics": _metrics(rows, "first_pass", expected_field="frozen_expected_decision"),
        "final_regression_metrics": _metrics(rows, "final", expected_field="artifact_aware_expected_decision"),
        "final_decision_counts": dict(sorted(Counter(row["final"]["decision"] for row in rows).items())),
        "rows": rows,
        "malicious_development_regression": {
            "metric_eligible": False,
            "reason": "The malicious sample informed scanner policy and is development data, not a frozen holdout.",
            "rows": malicious_rows,
        },
        "publication_status": {
            "methodology_and_results": "publishable-with-limitations",
            "ecosystem_accuracy_claim": "not-supported",
            "malicious_recall_claim": "not-supported-no-fresh-malicious-holdout",
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


def _metrics(rows: list[dict], scan_name: str, *, expected_field: str) -> dict:
    complete = [row for row in rows if row[scan_name]["coverage_status"] == "complete"]
    exact = [row for row in complete if row[scan_name]["decision"] == row[expected_field]]
    fresh = [row for row in rows if row["split"] == "fresh-artifact-holdout"]
    fresh_complete = [row for row in fresh if row[scan_name]["coverage_status"] == "complete"]
    fresh_exact = [row for row in fresh_complete if row[scan_name]["decision"] == row[expected_field]]
    false_blocks = [row for row in complete if row[scan_name]["decision"] == "block"]
    return {
        "admitted": len(rows),
        "complete": len(complete),
        "coverage_rate": _rate(len(complete), len(rows)),
        "exact_routing_among_complete": _rate(len(exact), len(complete)),
        "legitimate_false_block_rate_among_complete": _rate(len(false_blocks), len(complete)),
        "fresh_admitted": len(fresh),
        "fresh_complete": len(fresh_complete),
        "fresh_exact_routing_among_complete": _rate(len(fresh_exact), len(fresh_complete)),
    }


def _rate(numerator: int, denominator: int) -> dict:
    if denominator == 0:
        return {"numerator": numerator, "denominator": denominator, "rate": None, "wilson_95": None}
    proportion = numerator / denominator
    z = 1.959963984540054
    center = (proportion + z * z / (2 * denominator)) / (1 + z * z / denominator)
    margin = z * math.sqrt(proportion * (1 - proportion) / denominator + z * z / (4 * denominator * denominator)) / (1 + z * z / denominator)
    return {
        "numerator": numerator,
        "denominator": denominator,
        "rate": round(proportion, 6),
        "wilson_95": [round(max(0, center - margin), 6), round(min(1, center + margin), 6)],
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


if __name__ == "__main__":
    raise SystemExit(main())
