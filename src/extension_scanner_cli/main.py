from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from .exporters.html import export_html
from .exporters.json_export import export_json
from .exporters.markdown import export_markdown
from .report_reader import read_report, validate_report
from .scanner_adapter import (
    discover_paths,
    display_report,
    get_rules,
    installed_extensions,
    scan_marketplace,
    scan_paths,
    search_extensions,
    write_bundle,
)
from .ui.panels import panel, section
from .ui.prompts import confirm, prompt_choice, prompt_text
from .ui.renderers import render_rules, render_scan_report
from .ui.tables import key_values, table
from .ui.theme import color, severity_style, supports_color


APP_NAME = "Extension Scanner"
EXPORT_FORMATS = {"zip", "md", "html", "json", "none"}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        return interactive_home()

    command = argv[0]
    rest = argv[1:]
    if command in {"-h", "--help", "help"}:
        return cmd_help(rest)
    if command == "search":
        return cmd_search(rest)
    if command == "local":
        return cmd_local(rest)
    if command == "file":
        return cmd_file(rest)
    if command == "report":
        return cmd_report(rest)
    if command == "rules":
        return cmd_rules(rest)
    if command == "metrics":
        return cmd_metrics(rest)
    if command == "doctor":
        return cmd_doctor(rest)
    if command == "test":
        return cmd_test(rest)
    print(color(f"Unknown command: {command}", "red"))
    return cmd_help([])


def interactive_home() -> int:
    print(panel(APP_NAME, "Search, select, scan, and export IDE extension security reports.", subtitle="terminal UI"))
    choices = [
        "Search marketplace extension",
        "Scan installed extension",
        "Scan VSIX / ZIP / folder",
        "View or export report",
        "Rules",
        "Metrics",
        "Doctor",
        "Help",
    ]
    print(table(["#", "Action"], [[index, label] for index, label in enumerate(choices, start=1)], max_widths=[4, 42]))
    selected = prompt_choice("Select action", choices)
    if selected == 0:
        return cmd_search([])
    if selected == 1:
        return cmd_local([])
    if selected == 2:
        return cmd_file([])
    if selected == 3:
        return cmd_report([])
    if selected == 4:
        return cmd_rules([])
    if selected == 5:
        return cmd_metrics([])
    if selected == 6:
        return cmd_doctor([])
    return cmd_help([])


def cmd_help(args: list[str]) -> int:
    topic = args[0] if args else "main"
    topics = {
        "main": [
            ("scan", "Open interactive terminal UI"),
            ("scan search [query]", "Search marketplace, select an extension, scan it"),
            ("scan local", "List installed extensions, select one, scan it"),
            ("scan file [path]", "Scan VSIX, ZIP, or extension folder"),
            ("scan report", "View, validate, or export report files"),
            ("scan rules", "List or inspect scanner rules"),
            ("scan metrics", "Explain scores, evidence classes, and verdicts"),
            ("scan doctor", "Check local scanner CLI environment"),
            ("scan test", "Run scanner verification tests"),
        ],
        "search": [
            ("scan search prettier", "Search marketplace for matching extensions"),
            ("scan search", "Prompt for query, then show selectable results"),
        ],
        "local": [
            ("scan local", "Show installed extensions from VS Code, Cursor, Windsurf, VSCodium"),
            ("scan local --filter vyper", "Filter installed extensions before selection"),
        ],
        "file": [
            ("scan file extension.vsix", "Scan a VSIX package"),
            ("scan file ./extension-folder", "Scan an unpacked extension folder"),
        ],
        "report": [
            ("scan report validate report.zip", "Check report.zip structure"),
            ("scan report view report.zip", "Display report summary"),
            ("scan report export report.zip --format md --output report.md", "Export Markdown"),
        ],
        "rules": [
            ("scan rules", "List rules"),
            ("scan rules search credential", "Search rules"),
            ("scan rules show credential-exfiltration-chain", "Show one rule"),
        ],
        "metrics": [
            ("scan metrics", "Explain all metrics"),
            ("scan metrics scores", "Explain risk, malware, context, grade"),
            ("scan metrics evidence", "Explain evidence classes"),
        ],
    }
    rows = topics.get(topic, topics["main"])
    print(panel(APP_NAME, "Direct scanner CLI. No web app, no HTTP bridge, no score recomputation.", subtitle="help"))
    print(table(["Command", "Use"], rows, max_widths=[48, 74]))
    return 0


def cmd_search(args: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="scan search", add_help=False)
    parser.add_argument("query", nargs="*")
    parser.add_argument("--limit", type=int, default=15)
    ns = parser.parse_args(args)
    query = " ".join(ns.query).strip() or prompt_text("Search marketplace")
    if not query:
        print(color("Search query is required.", "red"))
        return 2

    print(color(f"Searching marketplace for: {query}", "cyan"))
    try:
        results = search_extensions(query, limit=ns.limit)
    except Exception as exc:  # noqa: BLE001
        print(color(f"Marketplace search failed: {exc}", "red"))
        return 1
    if not results:
        print(color("No marketplace results found.", "yellow"))
        return 1

    print(_marketplace_table(results))
    selected = prompt_choice("Select extension to scan", [str(item.get("extension_id", "")) for item in results])
    extension_id = str(results[selected].get("extension_id") or "")
    print(color(f"Scanning {extension_id}...", "cyan"))
    report = scan_marketplace(extension_id)
    print(render_scan_report(display_report(report, source="marketplace")))
    return maybe_export(report, default_base=_safe_name(extension_id), source="marketplace")


def cmd_local(args: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="scan local", add_help=False)
    parser.add_argument("--filter", default="")
    ns = parser.parse_args(args)
    rows = installed_extensions()
    if ns.filter:
        needle = ns.filter.lower()
        rows = [item for item in rows if needle in item["extension_id"].lower() or needle in item["display_name"].lower()]
    if not rows:
        print(color("No installed extensions found.", "yellow"))
        return 1
    print(_installed_table(rows))
    selected = prompt_choice("Select extension to scan", [item["extension_id"] for item in rows])
    target = rows[selected]
    print(color(f"Scanning {target['extension_id']}...", "cyan"))
    report = scan_paths([target["path"]])
    print(render_scan_report(display_report(report, source="local")))
    return maybe_export(report, default_base=_safe_name(target["extension_id"]), source="local")


def cmd_file(args: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="scan file", add_help=False)
    parser.add_argument("path", nargs="?")
    ns = parser.parse_args(args)
    path = ns.path or prompt_text("VSIX, ZIP, or extension folder")
    if not path:
        print(color("Path is required.", "red"))
        return 2
    targets = discover_paths(path)
    if not targets:
        print(color(f"No extension target found at {path}", "red"))
        return 1
    print(table(["Type", "Path"], [[item.get("type"), item.get("path")] for item in targets], max_widths=[10, 86]))
    report = scan_paths([item["path"] for item in targets])
    print(render_scan_report(display_report(report, source="file")))
    return maybe_export(report, default_base=_safe_name(Path(path).stem or "report"), source="file")


def cmd_report(args: list[str]) -> int:
    if not args:
        print(panel("Report", "Commands: view, validate, export", subtitle="help"))
        print(table(["Command", "Use"], [
            ("scan report view report.zip", "Display report summary"),
            ("scan report validate report.zip", "Validate report structure"),
            ("scan report export report.zip --format md --output report.md", "Export report"),
        ], max_widths=[58, 72]))
        return 0
    action = args[0]
    if action == "validate":
        path = _arg_or_prompt(args[1:], "Report path")
        ok, errors = validate_report(path)
        status = color("OK", "green") if ok else color("FAILED", "red")
        print(table(["Report", "Status"], [[path, status]], max_widths=[72, 12]))
        for error in errors:
            print(color(f"- {error}", "red"))
        return 0 if ok else 1
    if action == "view":
        path = _arg_or_prompt(args[1:], "Report path")
        print(_render_read_report(read_report(path)))
        return 0
    if action == "export":
        return _report_export(args[1:])
    print(color(f"Unknown report action: {action}", "red"))
    return 2


def cmd_rules(args: list[str]) -> int:
    rules = list(get_rules().get("rules") or [])
    if args and args[0] == "search":
        query = " ".join(args[1:]).lower() or prompt_text("Rule search").lower()
        rules = [rule for rule in rules if query in json.dumps(rule).lower()]
    elif args and args[0] == "show":
        rule_id = args[1] if len(args) > 1 else prompt_text("Rule ID")
        match = next((rule for rule in rules if rule.get("rule_id") == rule_id), None)
        if not match:
            print(color(f"Rule not found: {rule_id}", "red"))
            return 1
        print(panel(str(match.get("rule_id")), key_values([
            ("Title", match.get("title", "")),
            ("Category", match.get("category", "")),
            ("Severity", color(match.get("default_severity", ""), severity_style(str(match.get("default_severity") or "")))),
            ("Class", match.get("evidence_class", "")),
            ("Description", match.get("description", "")),
            ("Recommendation", match.get("recommendation", "")),
            ("False positives", match.get("false_positive_notes", "")),
        ]), subtitle="rule"))
        return 0
    print(panel("Rules", f"Ruleset version: {get_rules().get('ruleset_version', 'unknown')}", subtitle=f"{len(rules)} rules"))
    print(render_rules(rules))
    return 0


def cmd_metrics(args: list[str]) -> int:
    topic = args[0] if args else "all"
    blocks = {
        "scores": [
            ("Risk score", "Actionable extension risk if the extension is compromised or abused."),
            ("Malware score", "Confidence that evidence indicates malicious behavior or confirmed intelligence."),
            ("Context score", "Metadata, reputation, posture, and hygiene notes that should not alone create malware alarm."),
            ("Grade", "Scanner-provided display grade derived from scanner scores."),
        ],
        "evidence": [
            ("confirmed", "Known-bad hash, malware removal, trusted threat feed, or equivalent confirmed intel."),
            ("correlated", "Multiple behavior signals combined into an abuse chain."),
            ("capability", "Powerful permission, API, artifact, or IDE contribution requiring review."),
            ("reputation", "Marketplace/repository metadata and trust context."),
            ("weak", "Standalone static signal or contextual note."),
        ],
        "verdicts": [
            ("Safe with notes", "No actionable risk, but contextual findings may exist."),
            ("Review", "Non-confirmed risk evidence that needs human context."),
            ("Suspicious", "Correlated or high-risk behavior chain."),
            ("Confirmed malicious", "Confirmed intelligence indicates malicious package or artifact."),
        ],
    }
    rows = []
    if topic == "all":
        for values in blocks.values():
            rows.extend(values)
    else:
        rows = blocks.get(topic, blocks["scores"])
    print(panel("Metrics", "Scanner-owned scoring model. CLI formats these values only.", subtitle=topic))
    print(table(["Metric", "Meaning"], rows, max_widths=[24, 96]))
    return 0


def cmd_doctor(args: list[str]) -> int:
    checks = [
        ("Python", "OK", sys.version.split()[0]),
        ("Scanner import", "OK" if importlib.util.find_spec("ide_scanner") else "FAIL", "ide_scanner"),
        ("Node AST analyzer", "OK" if shutil.which("node") else "WARN", shutil.which("node") or "node not found"),
        ("Vendored acorn", "OK" if _acorn_path().exists() else "FAIL", str(_acorn_path())),
        ("Color terminal", "OK" if supports_color() else "WARN", "enabled" if supports_color() else "disabled/non-tty"),
        ("Output directory", "OK" if Path.cwd().exists() else "FAIL", str(Path.cwd())),
    ]
    print(panel("Doctor", "Local CLI environment checks.", subtitle=APP_NAME))
    print(table(["Check", "Status", "Detail"], [[a, _status(b), c] for a, b, c in checks], max_widths=[24, 10, 80]))
    return 0 if all(status != "FAIL" for _, status, _ in checks) else 1


def cmd_test(args: list[str]) -> int:
    print(color("Running scanner tests...", "cyan"))
    result = subprocess.run(
        [sys.executable, "-m", "unittest", "tests.test_scanner"],
        cwd=Path(__file__).resolve().parents[2],
        text=True,
        capture_output=True,
        env={**dict(os.environ), "PYTHONPATH": "src"},
    )
    status = "PASS" if result.returncode == 0 else "FAIL"
    print(table(["Suite", "Status"], [["tests.test_scanner", _status(status)]], max_widths=[32, 10]))
    output = result.stdout + result.stderr
    tail = "\n".join(output.splitlines()[-12:])
    print(tail)
    return result.returncode


def maybe_export(report: dict[str, Any], *, default_base: str, source: str) -> int:
    if not sys.stdin.isatty():
        return 0
    if not confirm("Export report", default=False):
        return 0
    choices = ["zip", "md", "html", "json", "none"]
    index = prompt_choice("Format", choices)
    fmt = choices[index]
    if fmt == "none":
        return 0
    default = f"{default_base}-report.{fmt if fmt != 'zip' else 'zip'}"
    output = prompt_text("Output path", default=default)
    export_report(report, fmt, output, source=source)
    print(color(f"Wrote {output}", "green"))
    return 0


def export_report(report: dict[str, Any], fmt: str, output: str, *, source: str = "cli") -> None:
    if fmt == "zip":
        write_bundle(report, output, source=source)
    elif fmt == "md":
        export_markdown(display_report(report, source=source), output)
    elif fmt == "html":
        export_html(display_report(report, source=source), output)
    elif fmt == "json":
        export_json(report, output)
    else:
        raise ValueError(f"unknown export format: {fmt}")


def _report_export(args: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="scan report export", add_help=False)
    parser.add_argument("report", nargs="?")
    parser.add_argument("--format", choices=sorted(EXPORT_FORMATS - {"none"}), required=False)
    parser.add_argument("--output", "--out", dest="output")
    ns = parser.parse_args(args)
    report_path = ns.report or prompt_text("Report path")
    fmt = ns.format or prompt_text("Format", default="md")
    output = ns.output or prompt_text("Output path", default=f"{Path(report_path).stem}.{fmt}")
    report = _bundle_to_report(read_report(report_path))
    export_report(report, fmt, output)
    print(color(f"Wrote {output}", "green"))
    return 0


def _marketplace_table(results: list[dict[str, Any]]) -> str:
    rows = []
    for index, item in enumerate(results, start=1):
        rows.append([
            index,
            item.get("display_name") or item.get("extension_id"),
            item.get("publisher", ""),
            _compact_int(item.get("install_count", 0)),
            f"{float(item.get('rating_average') or 0):.1f}" if item.get("rating_average") else "-",
            "yes" if item.get("publisher_verified") else "no",
            item.get("extension_id", ""),
        ])
    return table(["#", "Extension", "Publisher", "Installs", "Rating", "Verified", "ID"], rows, max_widths=[4, 30, 18, 10, 8, 9, 34])


def _installed_table(rows: list[dict[str, Any]]) -> str:
    return table(
        ["#", "Extension", "Version", "Client", "Publisher", "ID"],
        [[index, item["display_name"], item["version"], item["client"], item["publisher"], item["extension_id"]] for index, item in enumerate(rows, start=1)],
        max_widths=[4, 30, 12, 16, 18, 34],
    )


def _render_read_report(data: dict[str, Any]) -> str:
    if "extensions" in data:
        return render_scan_report(data)
    return render_scan_report(_bundle_to_report(data))


def _bundle_to_report(data: dict[str, Any]) -> dict[str, Any]:
    if "extensions" in data:
        return data
    details = list((data.get("details") or {}).values())
    metadata = dict(data.get("metadata") or {})
    summary = dict((data.get("summary") or {}).get("summary") or {})
    return {
        "scan_id": metadata.get("scan_id", "report"),
        "created_at": metadata.get("created_at", ""),
        "summary": {
            "total_extensions": summary.get("total_extensions", len(details)),
            "max_risk_score": summary.get("max_risk_score", 0),
            "max_malware_score": summary.get("max_malware_score", 0),
            "posture_status": summary.get("posture_status", ""),
        },
        "extensions": details,
    }


def _arg_or_prompt(args: list[str], label: str) -> str:
    return args[0] if args else prompt_text(label)


def _safe_name(value: str) -> str:
    out = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "-" for ch in value)
    return out.strip("-") or "extension"


def _compact_int(value: object) -> str:
    number = int(value or 0)
    if number >= 1_000_000:
        return f"{number / 1_000_000:.1f}M"
    if number >= 1_000:
        return f"{number / 1_000:.1f}K"
    return str(number)


def _status(value: str) -> str:
    if value == "OK" or value == "PASS":
        return color(value, "green")
    if value == "WARN":
        return color(value, "yellow")
    return color(value, "red")


def _acorn_path() -> Path:
    import ide_scanner

    return Path(ide_scanner.__file__).parent / "js_ast" / "acorn_vendor.js"


if __name__ == "__main__":
    raise SystemExit(main())
