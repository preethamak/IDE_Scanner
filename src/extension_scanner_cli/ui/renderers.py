from __future__ import annotations

from typing import Any

from .panels import panel, section
from .tables import key_values, score_bar, table
from .theme import color, severity_style, verdict_style


def render_scan_report(report: dict[str, Any]) -> str:
    extensions = list(report.get("extensions") or [])
    summary = dict(report.get("summary") or {})
    lines = [
        panel(
            "Extension Scanner",
            key_values([
                ("Scan ID", report.get("scan_id", "unknown")),
                ("Extensions", summary.get("total_extensions", len(extensions))),
                ("Max risk", summary.get("max_risk_score", 0)),
                ("Max malware", summary.get("max_malware_score", 0)),
            ]),
            subtitle="scan complete",
        )
    ]
    if len(extensions) > 1:
        lines.append(render_extension_summary_table(extensions))
    for extension in extensions:
        lines.append(render_extension_detail(extension))
    return "\n".join(lines)


def render_extension_summary_table(extensions: list[dict[str, Any]]) -> str:
    rows = []
    for index, ext in enumerate(_rank_extensions(extensions), start=1):
        state = str(ext.get("verdict_label") or ext.get("verdict") or "")
        rows.append([
            index,
            ext.get("extension_id", ""),
            color(state, verdict_style(str(ext.get("verdict") or ""), str(ext.get("verdict_state") or ""))),
            ext.get("severity", ""),
            ext.get("risk_score", 0),
            ext.get("malware_score", 0),
            ext.get("finding_count", len(ext.get("findings") or [])),
        ])
    return section("Extensions") + "\n" + table(
        ["#", "Extension", "Verdict", "Severity", "Risk", "Malware", "Findings"],
        rows,
        max_widths=[4, 36, 18, 10, 7, 8, 9],
    )


def render_extension_detail(extension: dict[str, Any]) -> str:
    label = str(extension.get("verdict_label") or extension.get("verdict") or "unknown")
    verdict = color(label.upper(), verdict_style(str(extension.get("verdict") or ""), str(extension.get("verdict_state") or "")))
    severity = color(str(extension.get("severity") or "UNKNOWN"), severity_style(str(extension.get("severity") or "")))
    header = key_values([
        ("Extension", extension.get("extension_id", "unknown")),
        ("Version", extension.get("version", "unknown")),
        ("Publisher", extension.get("publisher", "unknown")),
        ("Verdict", verdict),
        ("Grade", extension.get("grade", "")),
        ("Severity", severity),
    ])
    scores = key_values([
        ("Risk", score_bar(int(extension.get("risk_score") or 0))),
        ("Malware", score_bar(int(extension.get("malware_score") or 0))),
        ("Context", score_bar(int(extension.get("context_score") or 0))),
    ])
    findings = list(extension.get("findings") or [])
    finding_rows = []
    for finding in findings[:12]:
        severity_text = color(str(finding.get("severity") or ""), severity_style(str(finding.get("severity") or "")))
        finding_rows.append([
            severity_text,
            finding.get("rule_id", ""),
            finding.get("evidence_class") or _class_from_evidence(finding),
            finding.get("actionability") or _action_from_severity(str(finding.get("severity") or "")),
            finding.get("evidence_summary", ""),
        ])
    body = header + "\n\nScores\n" + scores
    if extension.get("verdict_reason"):
        body += "\n\nReason\n" + str(extension.get("verdict_reason"))
    lines = [section(str(extension.get("name") or extension.get("extension_id") or "Extension")), body]
    if finding_rows:
        lines.append("\nFindings\n" + table(
            ["Sev", "Rule", "Class", "Action", "Summary"],
            finding_rows,
            max_widths=[9, 32, 14, 13, 56],
        ))
    else:
        lines.append(color("\nNo findings reported.", "green"))
    return "\n".join(lines)


def render_rules(rules: list[dict[str, Any]], *, limit: int = 40) -> str:
    rows = []
    for rule in rules[:limit]:
        rows.append([
            rule.get("rule_id", ""),
            rule.get("category", ""),
            color(rule.get("default_severity", ""), severity_style(str(rule.get("default_severity") or ""))),
            rule.get("evidence_class", ""),
            rule.get("title", ""),
        ])
    return table(["Rule", "Category", "Severity", "Class", "Title"], rows, max_widths=[34, 22, 10, 14, 42])


def _rank_extensions(extensions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        extensions,
        key=lambda item: (int(item.get("malware_score") or 0), int(item.get("risk_score") or 0), int(item.get("context_score") or 0)),
        reverse=True,
    )


def _class_from_evidence(finding: dict[str, Any]) -> str:
    evidence = finding.get("evidence")
    if isinstance(evidence, dict):
        return str(evidence.get("evidence_class") or "")
    return ""


def _action_from_severity(severity: str) -> str:
    if severity.upper() in {"CRITICAL", "HIGH"}:
        return "investigate"
    if severity.upper() == "MEDIUM":
        return "review"
    return "contextual"
