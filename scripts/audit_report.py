#!/usr/bin/env python3
"""Produce rule-level precision triage from a canonical scanner report.

This is intentionally a report auditor, not a second classifier. It makes
review-volume drivers visible and can optionally compare observed routing with
an external label file. Labels are never inferred from the scanner itself.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from ide_scanner.classification_policy import finding_actionability


def audit_report(report: dict[str, Any], labels: dict[str, str] | None = None) -> dict[str, Any]:
    extensions = report.get("extensions")
    if not isinstance(extensions, list):
        raise ValueError("Report must contain an extensions array.")

    verdict_counts: Counter[str] = Counter()
    eligible_verdict_counts: Counter[str] = Counter()
    decision_counts: Counter[str] = Counter()
    analysis_counts: Counter[str] = Counter()
    routing_counts: Counter[str] = Counter()
    finding_actionability_counts: Counter[str] = Counter()
    extensions_with_actionable_findings = 0
    rule_counts: Counter[str] = Counter()
    rule_extensions: dict[str, set[str]] = defaultdict(set)
    rule_extension_outcomes: dict[str, dict[str, str]] = defaultdict(dict)
    rule_evidence: dict[str, Counter[str]] = defaultdict(Counter)
    rule_actionability: dict[str, Counter[str]] = defaultdict(Counter)
    extension_rows: list[dict[str, Any]] = []

    for raw_extension in extensions:
        if not isinstance(raw_extension, dict):
            continue
        extension_id = str(raw_extension.get("extension_id") or "unknown")
        verdict = str(raw_extension.get("verdict") or "unknown")
        decision = str(raw_extension.get("decision") or "unknown")
        coverage = raw_extension.get("analysis_coverage")
        coverage = coverage if isinstance(coverage, dict) else {}
        explicit_analysis_status = raw_extension.get("analysis_status") or coverage.get("status")
        analysis_status = str(explicit_analysis_status or ("incomplete" if decision == "incomplete" else "complete"))
        routing_outcome = verdict if analysis_status == "complete" and decision != "incomplete" else "incomplete"
        verdict_counts[verdict] += 1
        if routing_outcome != "incomplete":
            eligible_verdict_counts[verdict] += 1
        decision_counts[decision] += 1
        analysis_counts[analysis_status] += 1
        routing_counts[routing_outcome] += 1
        findings = raw_extension.get("findings")
        findings = findings if isinstance(findings, list) else []
        finding_rule_ids: Counter[str] = Counter()
        extension_actionability: Counter[str] = Counter()
        for raw_finding in findings:
            if not isinstance(raw_finding, dict):
                continue
            rule_id = str(raw_finding.get("rule_id") or "unknown")
            evidence = raw_finding.get("evidence")
            evidence = evidence if isinstance(evidence, dict) else {}
            evidence_class = str(evidence.get("evidence_class") or "unknown")
            actionability = _finding_actionability(raw_finding, rule_id, evidence)
            rule_counts[rule_id] += 1
            rule_extensions[rule_id].add(extension_id)
            # An extension may legitimately emit the same rule many times. A
            # calibration report must measure how many distinct extensions were
            # routed by that rule, not how many duplicate findings it produced.
            rule_extension_outcomes[rule_id][extension_id] = routing_outcome
            rule_evidence[rule_id][evidence_class] += 1
            rule_actionability[rule_id][actionability] += 1
            finding_actionability_counts[actionability] += 1
            extension_actionability[actionability] += 1
            finding_rule_ids[rule_id] += 1
        if extension_actionability.get("review", 0) or extension_actionability.get("block", 0):
            extensions_with_actionable_findings += 1
        extension_rows.append({
            "extension_id": extension_id,
            "version": str(raw_extension.get("version") or "unknown"),
            "verdict": verdict,
            "decision": decision,
            "analysis_status": analysis_status,
            "routing_outcome": routing_outcome,
            "finding_count": sum(finding_rule_ids.values()),
            "actionability_counts": dict(extension_actionability),
            "top_rules": [rule_id for rule_id, _ in finding_rule_ids.most_common(8)],
            "label": _lookup_label(labels, extension_id, str(raw_extension.get("version") or "unknown")) if labels else None,
        })

    rules = []
    for rule_id, finding_count in rule_counts.most_common():
        outcomes = rule_extension_outcomes[rule_id].values()
        verdicts = Counter(outcomes)
        clean_extensions = verdicts.get("clean", 0)
        review_extensions = sum(verdicts.get(value, 0) for value in ("review", "suspicious", "malicious"))
        rules.append({
            "rule_id": rule_id,
            "finding_count": finding_count,
            "extension_count": len(rule_extensions[rule_id]),
            "clean_extension_count": clean_extensions,
            "review_or_higher_extension_count": review_extensions,
            "mixed_outcome": clean_extensions > 0 and review_extensions > 0,
            "routing_outcome_counts": dict(verdicts),
            "evidence_class_counts": dict(rule_evidence[rule_id]),
            "actionability_counts": dict(rule_actionability[rule_id]),
        })

    result: dict[str, Any] = {
        "schema_version": "guardrails.report-audit.v1",
        "source_scan_id": str(report.get("scan_id") or "unknown"),
        "scanner_build": str(report.get("scanner_build") or "unknown"),
        "ruleset_version": str(report.get("ruleset_version") or "unknown"),
        "summary": {
            "total_extensions": len(extension_rows),
            "verdict_counts": dict(verdict_counts),
            "eligible_verdict_counts": dict(eligible_verdict_counts),
            "decision_counts": dict(decision_counts),
            "analysis_status_counts": dict(analysis_counts),
            "routing_outcome_counts": dict(routing_counts),
            "incomplete_extension_count": routing_counts.get("incomplete", 0),
            "mixed_outcome_rule_count": sum(1 for rule in rules if rule["mixed_outcome"]),
            "finding_actionability_counts": dict(finding_actionability_counts),
            "actionable_finding_count": finding_actionability_counts.get("review", 0) + finding_actionability_counts.get("block", 0),
            "low_finding_count": finding_actionability_counts.get("low", 0),
            "contextual_finding_count": finding_actionability_counts.get("contextual", 0),
            "extensions_with_actionable_findings": extensions_with_actionable_findings,
        },
        "rule_observations": rules,
        "extensions": sorted(extension_rows, key=lambda row: (row["verdict"], row["extension_id"].lower())),
    }
    if labels is not None:
        result["label_metrics"] = _label_metrics(extension_rows, labels)
    return result


def _finding_actionability(raw_finding: dict[str, Any], rule_id: str, evidence: dict[str, Any]) -> str:
    """Resolve actionability exactly as the scanner does for serialized findings."""
    serialized = str(raw_finding.get("actionability") or evidence.get("actionability") or "").strip().lower()
    if serialized in {"contextual", "low", "review", "block"}:
        return serialized
    return str(finding_actionability(SimpleNamespace(rule_id=rule_id, evidence=evidence)))


def _label_metrics(rows: list[dict[str, Any]], labels: dict[str, str]) -> dict[str, Any]:
    eligible = [
        row for row in rows
        if _lookup_label(labels, row["extension_id"], row["version"]) is not None
    ]
    mismatches = []
    false_positive_reviews = 0
    false_negative_malware = 0
    for row in eligible:
        expected = _lookup_label(labels, row["extension_id"], row["version"])
        if expected is None:
            continue
        observed = row["routing_outcome"]
        observed_malware = observed in {"suspicious", "malicious"}
        expected_malware = expected in {"suspicious", "malicious"}
        if expected == "allow" and observed != "clean":
            false_positive_reviews += 1
        if expected_malware and not observed_malware:
            false_negative_malware += 1
        if (expected == "allow" and observed != "clean") or (expected != "allow" and observed == "clean"):
            mismatches.append({
                "extension_id": row["extension_id"],
                "expected": expected,
                "observed": observed,
            })
    return {
        "labeled_extensions": len(eligible),
        "routing_accuracy": sum(
            1 for row in eligible
            if (_lookup_label(labels, row["extension_id"], row["version"]) == "allow" and row["verdict"] == "clean")
            or (_lookup_label(labels, row["extension_id"], row["version"]) != "allow" and row["verdict"] != "clean")
        ) / len(eligible) if eligible else None,
        "false_positive_review_count": false_positive_reviews,
        "false_negative_malware_count": false_negative_malware,
        "mismatches": mismatches,
    }


def _artifact_key(extension_id: object, version: object) -> str:
    return f"{str(extension_id).strip().lower()}@{str(version).strip()}"


def _lookup_label(labels: dict[str, str] | None, extension_id: str, version: str) -> str | None:
    if not labels:
        return None
    return labels.get(_artifact_key(extension_id, version)) or labels.get(extension_id.lower())


def _load_labels(path: Path) -> dict[str, str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict) and isinstance(payload.get("samples"), list):
        rows = payload["samples"]
    elif isinstance(payload, dict) and isinstance(payload.get("rows"), list):
        rows = payload["rows"]
    elif isinstance(payload, list):
        rows = payload
    else:
        raise ValueError("Labels must be a list, or an object containing samples or rows.")
    labels: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict) or not row.get("extension_id"):
            continue
        label = row.get("artifact_aware_expected_decision") or row.get("expected_decision") or row.get("expected_verdict")
        if label:
            extension_id = str(row["extension_id"])
            version = row.get("version")
            labels[_artifact_key(extension_id, version)] = str(label) if version is not None else str(label)
            if version is None:
                labels[extension_id.lower()] = str(label)
    return labels


def _load_corrections(path: Path) -> dict[str, str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = payload.get("corrections") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        raise ValueError("Corrections must be an object containing a corrections array.")
    corrections: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict) or not row.get("extension_id"):
            continue
        label = row.get("corrected_expected_decision")
        if not label:
            continue
        extension_id = str(row["extension_id"])
        version = row.get("version")
        corrections[_artifact_key(extension_id, version)] = str(label) if version is not None else str(label)
        if version is None:
            corrections[extension_id.lower()] = str(label)
    return corrections


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True, help="Canonical scanner JSON report.")
    parser.add_argument("--labels", type=Path, help="Optional frozen labels JSON for routing metrics.")
    parser.add_argument("--corrections", type=Path, help="Optional exact-artifact label corrections to apply after labels.")
    parser.add_argument("--out", "--output", dest="output", type=Path, required=True)
    args = parser.parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8"))
    if not isinstance(report, dict):
        raise ValueError("Report must be a JSON object.")
    labels = _load_labels(args.labels) if args.labels else None
    if args.corrections:
        labels = {**(labels or {}), **_load_corrections(args.corrections)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(audit_report(report, labels), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
