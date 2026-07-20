from __future__ import annotations

import argparse
import json
import subprocess
import urllib.request
from pathlib import Path
from typing import Any


DEFAULT_RESULTS = Path("benchmarks/website-corpus/v1/results.json")
DEFAULT_PUBLICATION_URL = "https://ide-scanner.vercel.app/api/benchmark"


def main() -> int:
    parser = argparse.ArgumentParser(description="Dispatch exact, canonical cloud scans for the frozen website corpus.")
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--publication-url", default=DEFAULT_PUBLICATION_URL)
    parser.add_argument("--include-published", action="store_true", help="Rescan rows that already have a valid canonical publication.")
    parser.add_argument("--require-current-build", action="store_true", help="Treat publications from earlier scanner builds as pending.")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    corpus = json.loads(args.results.read_text(encoding="utf-8"))
    rows = list(corpus.get("rows") or [])
    current_build = git_output("rev-parse", "HEAD")
    published = {} if args.include_published else published_artifacts(args.publication_url, current_build if args.require_current_build else None)
    pending = rows_to_dispatch(rows, published)
    for row in pending:
        command = [
            "gh", "workflow", "run", "deep-scan.yml", "--ref", "main",
            "-f", f"extension_id={row['extension_id']}",
            "-f", f"version={row['version']}",
            "-f", "scan_purpose=public_intelligence",
        ]
        if args.dry_run:
            print(f"Would dispatch {row['extension_id']}@{row['version']}")
        else:
            subprocess.run(command, check=True)
            print(f"Dispatched {row['extension_id']}@{row['version']}")
    print(json.dumps({"corpus": len(rows), "already_published": len(rows) - len(pending), "dispatched": 0 if args.dry_run else len(pending), "scanner_build": current_build}, sort_keys=True))
    return 0


def published_artifacts(url: str, required_build: str | None = None) -> dict[str, str]:
    with urllib.request.urlopen(url, timeout=60) as response:
        body = json.loads(response.read().decode())
    published: dict[str, str] = {}
    for row in body.get("rows") or []:
        scan = row.get("scan") or {}
        if (required_build and scan.get("scanner_build") != required_build) or scan.get("score_schema_version") != "2" or scan.get("coverage_percent") != 100:
            continue
        published[artifact_key(row.get("extension_id"), row.get("version"))] = str(row.get("sha256") or "").lower()
    return published


def rows_to_dispatch(rows: list[dict[str, Any]], published: dict[str, str]) -> list[dict[str, Any]]:
    return [
        row for row in rows
        if published.get(artifact_key(row.get("extension_id"), row.get("version"))) != str(row.get("sha256") or "").lower()
    ]


def artifact_key(extension_id: object, version: object) -> str:
    return f"{str(extension_id).lower()}@{version}"


def git_output(*arguments: str) -> str:
    return subprocess.run(["git", *arguments], check=True, capture_output=True, text=True).stdout.strip()


if __name__ == "__main__":
    raise SystemExit(main())
