from __future__ import annotations

import html
from pathlib import Path
from typing import Any


def export_html(report: dict[str, Any], output: str | Path) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(to_html(report), encoding="utf-8")
    return path


def to_html(report: dict[str, Any]) -> str:
    summary = dict(report.get("summary") or {})
    cards = "".join(_card(label, summary.get(key, 0)) for label, key in [
        ("Extensions", "total_extensions"),
        ("Max Risk", "max_risk_score"),
        ("Max Malware", "max_malware_score"),
        ("Posture", "posture_status"),
    ])
    extensions = "\n".join(_extension_html(extension) for extension in report.get("extensions") or [])
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Extension Scanner Report</title>
  <style>
    body {{ margin: 0; background: #080a0f; color: #eef2ff; font-family: Inter, Segoe UI, sans-serif; }}
    main {{ max-width: 1120px; margin: 0 auto; padding: 32px; }}
    h1, h2 {{ margin: 0 0 12px; }}
    .hero, .ext {{ border: 1px solid #263044; border-radius: 12px; background: #10141d; padding: 20px; margin-bottom: 16px; }}
    .cards {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-top: 18px; }}
    .card {{ border: 1px solid #263044; border-radius: 9px; padding: 12px; background: #151b27; }}
    .card span {{ display: block; color: #8b94aa; font-size: 12px; }}
    .card strong {{ font-size: 22px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
    th, td {{ border-bottom: 1px solid #263044; padding: 9px; text-align: left; font-size: 13px; }}
    th {{ color: #9fb3ff; }}
    .score {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; margin: 12px 0; }}
    .bar {{ height: 8px; background: #242d3e; border-radius: 99px; overflow: hidden; }}
    .bar i {{ display: block; height: 100%; background: #7dd3fc; }}
    .verdict {{ color: #4ade80; font-weight: 700; }}
  </style>
</head>
<body>
<main>
  <section class="hero">
    <h1>Extension Scanner Report</h1>
    <p>Scan ID: {html.escape(str(report.get("scan_id", "unknown")))}</p>
    <div class="cards">{cards}</div>
  </section>
  {extensions}
</main>
</body>
</html>
"""


def _card(label: str, value: object) -> str:
    return f'<div class="card"><span>{html.escape(label)}</span><strong>{html.escape(str(value))}</strong></div>'


def _extension_html(extension: dict[str, Any]) -> str:
    findings = "\n".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            html.escape(str(finding.get("severity", ""))),
            html.escape(str(finding.get("rule_id", ""))),
            html.escape(str(finding.get("category", ""))),
            html.escape(str(finding.get("evidence_summary", ""))),
        )
        for finding in extension.get("findings") or []
    )
    if not findings:
        findings = '<tr><td colspan="4">No findings reported.</td></tr>'
    return f"""<section class="ext">
  <h2>{html.escape(str(extension.get("extension_id", "unknown")))}</h2>
  <p class="verdict">{html.escape(str(extension.get("verdict_label") or extension.get("verdict") or "unknown"))}</p>
  <div class="score">
    {_score("Risk", extension.get("risk_score", 0))}
    {_score("Malware", extension.get("malware_score", 0))}
    {_score("Context", extension.get("context_score", 0))}
  </div>
  <table>
    <thead><tr><th>Severity</th><th>Rule</th><th>Category</th><th>Summary</th></tr></thead>
    <tbody>{findings}</tbody>
  </table>
</section>"""


def _score(label: str, value: object) -> str:
    number = max(0, min(100, int(value or 0)))
    return f'<div class="card"><span>{html.escape(label)}</span><strong>{number}/100</strong><div class="bar"><i style="width:{number}%"></i></div></div>'
