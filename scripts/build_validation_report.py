"""Compare cohort sweep results against researcher expectations.

Reads every per-artifact result JSON produced by run_cohort_validation.py,
checks it against its expectations row (strict decision, allowed
alternatives, outcome, risk band, severity ceiling, required rules), prints
a delta table, evaluates the release gates, and optionally emits the
validation report consumed by ide-scanner-web's
scripts/activate-scan-publication.mjs.

Gates:
  - block precision >= --min-block-precision (default 0.9)
  - zero strict-decision mismatches
  - zero incomplete analyses

Usage:
  python scripts/build_validation_report.py \
      --expectations benchmarks/marketplace-cohort/v2/expectations.json \
      --results-dir benchmarks/marketplace-cohort/v2/results \
      [--emit-report validation-report.json] [--min-block-precision 0.9]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _load_expectations(path: Path) -> dict[str, dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = data.get("extensions") or {}
    if not isinstance(rows, dict):
        raise SystemExit("expectations 'extensions' must map id@version -> row")
    return rows


def _check_row(key: str, row: dict, ext: dict) -> list[str]:
    problems: list[str] = []
    decision = str(ext.get("decision") or "")
    expected_decision = str(row.get("expected_decision") or "")
    strict = bool(row.get("strict_decision", True))
    alternatives = [str(item) for item in (row.get("allowed_alt_decisions") or [])]

    if strict and decision != expected_decision:
        problems.append(f"{key}: decision {decision!r} != strict expectation {expected_decision!r}")
    elif not strict and decision != expected_decision and decision not in alternatives:
        problems.append(
            f"{key}: decision {decision!r} matches neither primary {expected_decision!r} "
            f"nor alternatives {alternatives}"
        )

    expected_outcome = row.get("expected_outcome")
    if expected_outcome:
        actual_outcome = str(ext.get("public_outcome") or "")
        # Outcome drift within the same decision is tolerated unless the row
        # pins a strict outcome.
        if strict and actual_outcome != str(expected_outcome) and decision == expected_decision:
            problems.append(
                f"{key}: public_outcome {actual_outcome!r} != strict expectation {expected_outcome!r}"
            )

    band = row.get("risk_band")
    if band and isinstance(band, list) and len(band) == 2:
        risk = int(ext.get("risk_score") or 0)
        if not (int(band[0]) <= risk <= int(band[1])):
            problems.append(f"{key}: risk {risk} outside band {band}")

    severity_max = row.get("severity_max")
    if severity_max:
        rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        severity = str(ext.get("severity") or "INFO")
        if rank.get(severity, 0) > rank.get(str(severity_max), 0):
            problems.append(f"{key}: severity {severity} exceeds cap {severity_max}")

    for rule_id in row.get("require_rule_ids") or []:
        found = {str(f.get("rule_id")) for f in ext.get("findings", [])}
        if str(rule_id) not in found:
            problems.append(f"{key}: required rule {rule_id} missing")

    if str(ext.get("analysis_status") or "") != "complete":
        problems.append(f"{key}: analysis_status {ext.get('analysis_status')!r} != complete")
    return problems


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expectations", type=Path, required=True)
    parser.add_argument("--results-dir", type=Path, required=True)
    parser.add_argument("--emit-report", type=Path, default=None)
    parser.add_argument("--min-block-precision", type=float, default=0.9)
    args = parser.parse_args()

    expectations = _load_expectations(args.expectations)

    matched = 0
    missing: list[str] = []
    problems: list[str] = []
    blocks_total = 0
    blocks_wrong = 0
    rows: list[tuple[str, str, str, int, str]] = []

    for key, row in sorted(expectations.items()):
        ext_id = str(row["extension_id"])
        result_path = args.results_dir / f"{ext_id.replace('/', '_')}@{row['version']}.json"
        if not result_path.exists():
            missing.append(key)
            continue
        ext = json.loads(result_path.read_text(encoding="utf-8"))
        decision = str(ext.get("decision") or "")
        rows.append((key, decision, str(ext.get("public_outcome") or ""), int(ext.get("risk_score") or 0), str(ext.get("decision_basis") or "")))
        if decision == "block":
            blocks_total += 1
        row_problems = _check_row(key, row, ext)
        if row_problems:
            if decision == "block" and str(row.get("expected_decision")) != "block":
                blocks_wrong += 1
            problems.extend(row_problems)
        else:
            matched += 1

    print(f"{'extension':52} {'decision':10} {'outcome':28} {'risk':>4}  basis")
    for key, decision, outcome, risk, basis in rows:
        marker = "OK " if f"{key}:" not in " ".join(problems) else "!! "
        print(f"{marker}{key:50} {decision:10} {outcome:28} {risk:>4}  {basis[:60]}")

    total = len(expectations)
    block_precision = (blocks_total - blocks_wrong) / blocks_total if blocks_total else 1.0
    summary = {
        "total": total,
        "results_found": total - len(missing),
        "missing_results": sorted(missing),
        "matched_expectations": matched,
        "problem_count": len(problems),
        "blocks_total": blocks_total,
        "blocks_against_expectation": blocks_wrong,
        "block_precision": round(block_precision, 4),
        "problems": problems,
    }

    gates_failed: list[str] = []
    if missing:
        gates_failed.append(f"{len(missing)} artifacts have no result JSON")
    if any(": decision" in p or "analysis_status" in p for p in problems):
        pass  # individual problems already listed; strict gate below
    if block_precision < args.min_block_precision:
        gates_failed.append(f"block precision {block_precision:.3f} < {args.min_block_precision}")
    strict_failures = [
        p for p in problems
        if "strict expectation" in p or "analysis_status" in p or "no prior" in p
    ]
    if strict_failures:
        gates_failed.append(f"{len(strict_failures)} strict mismatches")

    summary["gates_failed"] = gates_failed
    print()
    print(json.dumps({k: v for k, v in summary.items() if k != "problems"}, indent=2))
    if problems:
        print("\nProblems:")
        for problem in problems:
            print(f"  - {problem}")

    meta_path = args.results_dir / "_meta.json"
    if args.emit_report:
        if not meta_path.exists():
            sys.exit("_meta.json missing from results dir; cannot emit report")
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        build_sha = str(meta.get("scanner_build") or "")
        entries = []
        for key, row in sorted(expectations.items()):
            ext_id = str(row["extension_id"])
            result_path = args.results_dir / f"{ext_id.replace('/', '_')}@{row['version']}.json"
            if not result_path.exists():
                continue
            ext = json.loads(result_path.read_text(encoding="utf-8"))
            coverage = ext.get("analysis_coverage") or {}
            entries.append({
                "extension_id": ext_id,
                "version": str(ext.get("version") or row["version"]),
                "artifact_hash": str(ext.get("artifact_hash") or ""),
                "decision": str(ext.get("decision") or ""),
                "severity": str(ext.get("severity") or ""),
                "analysis_coverage": {
                    "providers": coverage.get("providers") or {},
                    "required_providers_complete": coverage.get("required_providers_complete"),
                },
            })
        report = {
            "extensions": entries,
            "scanner_build": build_sha,
            "policy_version": str(meta.get("policy_version") or ""),
            "ruleset_version": str(meta.get("ruleset_version") or ""),
        }
        args.emit_report.write_text(json.dumps(report, indent=2))
        print(f"\nvalidation report written to {args.emit_report}"
              + (" (scanner_build is not 40-hex; production republish must regenerate from published rows)"
                 if len(build_sha) != 40 else ""))

    if gates_failed:
        print("\nGATES FAILED:")
        for gate in gates_failed:
            print(f"  - {gate}")
        sys.exit(1)
    print("\nAll gates passed.")


if __name__ == "__main__":
    main()
