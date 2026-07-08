from __future__ import annotations

from pathlib import Path
from typing import Any


def export_markdown(report: dict[str, Any], output: str | Path) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(to_markdown(report), encoding="utf-8")
    return path


def to_markdown(report: dict[str, Any]) -> str:
    summary = dict(report.get("summary") or {})
    lines = [
        "# Extension Scanner Report",
        "",
        "## Summary",
        f"- Scan ID: `{report.get('scan_id', 'unknown')}`",
        f"- Total extensions: {summary.get('total_extensions', len(report.get('extensions') or []))}",
        f"- Max risk score: {summary.get('max_risk_score', 0)}",
        f"- Max malware score: {summary.get('max_malware_score', 0)}",
        "",
    ]
    for extension in report.get("extensions") or []:
        lines.extend(_extension_markdown(extension))
    return "\n".join(lines).rstrip() + "\n"


def _extension_markdown(extension: dict[str, Any]) -> list[str]:
    lines = [
        f"## {extension.get('extension_id', 'unknown')}",
        "",
        f"- Version: {extension.get('version', 'unknown')}",
        f"- Publisher: {extension.get('publisher', 'unknown')}",
        f"- Verdict: {extension.get('verdict_label') or extension.get('verdict')}",
        f"- Grade: {extension.get('grade', '')}",
        f"- Severity: {extension.get('severity', '')}",
        f"- Risk score: {extension.get('risk_score', 0)}",
        f"- Malware score: {extension.get('malware_score', 0)}",
        f"- Context score: {extension.get('context_score', 0)}",
        "",
        "### Findings",
        "",
        "| Severity | Rule | Class | Summary |",
        "| --- | --- | --- | --- |",
    ]
    findings = list(extension.get("findings") or [])
    if not findings:
        lines.append("| - | - | - | No findings reported |")
    for finding in findings:
        evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
        lines.append(
            "| {severity} | `{rule}` | {klass} | {summary} |".format(
                severity=_clean(finding.get("severity", "")),
                rule=_clean(finding.get("rule_id", "")),
                klass=_clean(finding.get("evidence_class") or evidence.get("evidence_class") or ""),
                summary=_clean(finding.get("evidence_summary", "")),
            )
        )
    lines.append("")
    return lines


def _clean(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")
