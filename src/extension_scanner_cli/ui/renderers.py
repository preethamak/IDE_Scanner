from __future__ import annotations

import textwrap
from typing import Any

from .panels import banner, panel, section
from .tables import count_bar, key_values, score_bar, table, terminal_width, truncate, visible_len
from .theme import color, severity_label, severity_style, verdict_style


def render_scan_report(report: dict[str, Any]) -> str:
    extensions = list(report.get("extensions") or [])
    summary = dict(report.get("summary") or {})
    lines = [
        banner("Security Report"),
        panel(
            "Scan Metadata",
            key_values([
                ("Scan ID", report.get("scan_id", "unknown")),
                ("Extensions", summary.get("total_extensions", len(extensions))),
                ("Max risk", summary.get("max_risk_score", 0)),
                ("Max malware", summary.get("max_malware_score", 0)),
                ("Created", report.get("created_at", "n/a") or "n/a"),
            ]),
            subtitle="complete",
        )
    ]
    lines.append(render_security_score(summary, extensions))
    lines.append(render_severity_breakdown(extensions))
    if len(extensions) > 1:
        lines.append(render_extension_summary_table(extensions))
    for extension in extensions:
        lines.append(render_extension_detail(extension))
    lines.append(render_rules_run(extensions))
    lines.append(color("─ Extension Scanner v0.1.0 | local scan report ─", "violet"))
    return "\n".join(lines)


def render_security_score(summary: dict[str, Any], extensions: list[dict[str, Any]]) -> str:
    max_risk = int(summary.get("max_risk_score") or 0)
    max_malware = int(summary.get("max_malware_score") or 0)
    max_context = max((int(item.get("context_score") or 0) for item in extensions), default=0)
    score = max(max_risk, max_malware)
    grade = _overall_grade(extensions, score)
    verdict = _overall_verdict(extensions)
    style = verdict_style(verdict)
    body = "\n".join([
        f"   {color(grade, style)}  {score} / 100",
        f"   {color(_score_phrase(score, verdict), style)}",
        "",
        f"   Risk     {score_bar(max_risk, width=30)}",
        f"   Malware  {score_bar(max_malware, width=30)}",
        f"   Context  {score_bar(max_context, width=30)}",
    ])
    return panel("Security Score", body)


def render_severity_breakdown(extensions: list[dict[str, Any]]) -> str:
    counts = {severity: 0 for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}
    for extension in extensions:
        for finding in extension.get("findings") or []:
            severity = str(finding.get("severity") or "INFO").upper()
            counts[severity] = counts.get(severity, 0) + 1
    maximum = max(counts.values(), default=1)
    rows = []
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        label = _severity_text(severity)
        rows.append(f"  {label}{' ' * max(16 - visible_len(label), 1)}{counts.get(severity, 0):>3}   {count_bar(counts.get(severity, 0), maximum)}")
    return panel("Severity Breakdown", "\n".join(rows))


def render_extension_summary_table(extensions: list[dict[str, Any]]) -> str:
    rows = []
    for index, ext in enumerate(_rank_extensions(extensions), start=1):
        state = str(ext.get("verdict_label") or ext.get("verdict") or "")
        rows.append([
            index,
            ext.get("extension_id", ""),
            color(state, verdict_style(str(ext.get("verdict") or ""), str(ext.get("verdict_state") or ""))),
            _severity_text(str(ext.get("severity") or "")),
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
    severity = _severity_text(str(extension.get("severity") or "UNKNOWN"))
    header = key_values([
        ("Extension", extension.get("extension_id", "unknown")),
        ("Version", extension.get("version", "unknown")),
        ("Publisher", extension.get("publisher", "unknown")),
        ("Verdict", verdict),
        ("Grade", extension.get("grade", "")),
        ("Severity", severity),
    ])
    scores = key_values([
        ("Risk", score_bar(int(extension.get("risk_score") or 0), width=30)),
        ("Malware", score_bar(int(extension.get("malware_score") or 0), width=30)),
        ("Context", score_bar(int(extension.get("context_score") or 0), width=30)),
    ])
    findings = list(extension.get("findings") or [])
    finding_rows = []
    for finding in findings[:12]:
        severity_text = _severity_text(str(finding.get("severity") or ""))
        finding_rows.append([
            severity_text,
            finding.get("rule_id", ""),
            finding.get("evidence_class") or _class_from_evidence(finding),
            finding.get("actionability") or _action_from_severity(str(finding.get("severity") or "")),
            finding.get("evidence_summary", ""),
        ])
    body = header + "\n\nScores\n" + scores
    if extension.get("verdict_reason"):
        body += "\n\nReason\n" + _wrap_text(str(extension.get("verdict_reason") or ""))
    lines = [section(str(extension.get("name") or extension.get("extension_id") or "Extension")), body]
    if finding_rows:
        lines.append("\nFindings\n" + table(
            ["Sev", "Rule", "Class", "Action", "Summary"],
            finding_rows,
            max_widths=[9, 32, 14, 13, 56],
        ))
        lines.append(render_detailed_findings(findings))
    else:
        lines.append(color("\nNo findings reported.", "green"))
    return "\n".join(lines)


def render_detailed_findings(findings: list[dict[str, Any]]) -> str:
    lines = [section("Detailed Findings")]
    for index, finding in enumerate(findings[:8], start=1):
        severity = str(finding.get("severity") or "INFO").upper()
        title = str(finding.get("rule_id") or "finding")
        body = key_values([
            ("Description", finding.get("evidence_summary", "")),
            ("Location", ", ".join(finding.get("file_refs") or []) or "n/a"),
            ("Detector", finding.get("rule_id", "")),
            ("Category", finding.get("category", "")),
            ("Evidence", finding.get("evidence_class") or _class_from_evidence(finding) or "n/a"),
            ("Fix", finding.get("recommendation") or "Review the finding and confirm expected extension behavior."),
        ], key_width=14)
        lines.append(panel(f"#{index} {severity_label(severity)} {title}", body, subtitle=f"{severity} | confidence {finding.get('confidence', 'n/a')}"))
    return "\n".join(lines)


def render_rules_run(extensions: list[dict[str, Any]]) -> str:
    rule_ids = []
    seen: set[str] = set()
    for extension in extensions:
        for finding in extension.get("findings") or []:
            rule_id = str(finding.get("rule_id") or "")
            if rule_id and rule_id not in seen:
                seen.add(rule_id)
                rule_ids.append(rule_id)
    if not rule_ids:
        return ""
    lines = [section("Rules Triggered")]
    for index, rule_id in enumerate(rule_ids[:18]):
        branch = "└──" if index == len(rule_ids[:18]) - 1 else "├──"
        lines.append(truncate(f"{branch} {rule_id}", terminal_width()))
    return "\n".join(lines)


def render_rules(rules: list[dict[str, Any]], *, limit: int = 40) -> str:
    rows = []
    for rule in rules[:limit]:
        rows.append([
            rule.get("rule_id", ""),
            rule.get("category", ""),
            _severity_text(str(rule.get("default_severity") or "")),
            rule.get("evidence_class", ""),
            rule.get("title", ""),
        ])
    return table(["Rule", "Category", "Severity", "Class", "Title"], rows, max_widths=[34, 22, 10, 14, 42])


def _severity_text(severity: str) -> str:
    return color(severity_label(severity), severity_style(severity))


def _wrap_text(value: str) -> str:
    width = max(24, terminal_width())
    lines: list[str] = []
    for line in value.splitlines() or [""]:
        lines.extend(textwrap.wrap(line, width=width, break_long_words=True, break_on_hyphens=False) or [""])
    return "\n".join(lines)


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


def _overall_grade(extensions: list[dict[str, Any]], score: int) -> str:
    grades = [str(item.get("grade") or "") for item in extensions if item.get("grade")]
    if grades:
        order = {"F": 0, "D": 1, "C": 2, "B": 3, "A": 4}
        return min(grades, key=lambda grade: order.get(grade[:1], 99))
    if score >= 90:
        return "F"
    if score >= 70:
        return "D"
    if score >= 45:
        return "C"
    if score >= 20:
        return "B"
    return "A"


def _overall_verdict(extensions: list[dict[str, Any]]) -> str:
    ranks = {"malicious": 4, "suspicious": 3, "review": 2, "clean": 1}
    verdicts = [str(item.get("verdict") or "clean") for item in extensions]
    return max(verdicts, key=lambda verdict: ranks.get(verdict, 0), default="clean")


def _score_phrase(score: int, verdict: str) -> str:
    if verdict == "malicious":
        return "Confirmed malicious - remove immediately"
    if verdict == "suspicious":
        return "Suspicious - investigate before use"
    if verdict == "review":
        return "Needs review - non-confirmed risk evidence"
    if score == 0:
        return "Safe with notes - no actionable risk"
    return "Low risk - contextual findings present"
