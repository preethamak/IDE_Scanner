"""SARIF 2.1.0 export for GuardRails scanner reports."""

from __future__ import annotations

from typing import Any

from .evidence import location_from_finding
from .rule_registry import rule_registry


def report_to_sarif(report: dict[str, Any]) -> dict[str, Any]:
    """Convert one scanner report to a truthful SARIF 2.1.0 log.

    A finding gets a physical location only when the scanner recorded one. The
    exact release identity remains in result properties even for manifest,
    registry, or runtime findings that have no source file location.
    """
    metadata = {
        key: report.get(key)
        for key in ("scan_id", "created_at", "scanner_build", "policy_version", "ruleset_version", "schema_version")
        if report.get(key) is not None
    }
    catalog = {rule.rule_id: rule for rule in rule_registry()}
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for extension in report.get("extensions", []):
        if not isinstance(extension, dict):
            continue
        identity = {
            "extension_id": str(extension.get("extension_id") or "unknown"),
            "version": str(extension.get("version") or "unknown"),
            "artifact_sha256": str(extension.get("artifact_hash") or extension.get("artifact_sha256") or "unknown"),
            "decision": str(extension.get("decision") or "incomplete"),
            "analysis_status": str(extension.get("analysis_status") or "incomplete"),
        }
        for finding in extension.get("findings", []):
            if not isinstance(finding, dict):
                continue
            rule_id = str(finding.get("rule_id") or "guardrails-observation")
            rules.setdefault(rule_id, _rule_descriptor(rule_id, catalog))
            results.append(_result(rule_id, finding, identity))
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "GuardRails Scanner", "informationUri": "https://abscissa.dev", "rules": list(rules.values())}},
            "automationDetails": {"id": str(report.get("scan_id") or "guardrails-scan")},
            "properties": metadata,
            "results": results,
        }],
    }


def _rule_descriptor(rule_id: str, catalog: dict[str, Any]) -> dict[str, Any]:
    rule = catalog.get(rule_id)
    if rule is None:
        return {"id": rule_id, "shortDescription": {"text": rule_id.replace("-", " ").title()}}
    return {
        "id": rule_id,
        "name": rule.title,
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": rule.description},
        "help": {"text": rule.recommendation},
        "properties": {
            "category": rule.category,
            "evidence_class": rule.evidence_class,
            "decision_effect": rule.decision_effect,
            "scanner_engine": rule.engine,
        },
    }


def _result(rule_id: str, finding: dict[str, Any], identity: dict[str, str]) -> dict[str, Any]:
    severity = str(finding.get("effective_severity") or finding.get("severity") or "INFO").upper()
    result: dict[str, Any] = {
        "ruleId": rule_id,
        "level": _sarif_level(severity),
        "message": {"text": str(finding.get("evidence_summary") or finding.get("summary") or rule_id)},
        "properties": {
            **identity,
            "severity": severity,
            "evidence_class": str(finding.get("evidence_class") or "unknown"),
            "actionability": str(finding.get("actionability") or "unknown"),
        },
    }
    location = location_from_finding(finding)
    if location["file"]:
        region = {"startLine": location["line"]} if location["line"] is not None else {}
        result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": str(location["file"])}, **({"region": region} if region else {})}}]
    return result


def _sarif_level(severity: str) -> str:
    if severity in {"CRITICAL", "HIGH"}:
        return "error"
    if severity == "MEDIUM":
        return "warning"
    return "note"
