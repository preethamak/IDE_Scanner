from __future__ import annotations

import argparse
import json
import subprocess
import urllib.request
from urllib.parse import urlparse
from pathlib import Path
from typing import Any


DEFAULT_RESULTS = Path("benchmarks/website-corpus/v1/results.json")
DEFAULT_PUBLICATION_URL = "https://ide-scanner.vercel.app/api/benchmark"


def main() -> int:
    parser = argparse.ArgumentParser(description="Dispatch exact, canonical cloud scans for the frozen website corpus.")
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--publication-url", default=DEFAULT_PUBLICATION_URL)
    parser.add_argument("--include-published", action="store_true", help="Rescan rows that already have a valid canonical publication.")
    parser.add_argument(
        "--require-current-build",
        action="store_true",
        help="Deprecated compatibility flag; current-build matching is now the default.",
    )
    parser.add_argument(
        "--allow-stale-build",
        action="store_true",
        help="Allow an older scanner build to satisfy an existing publication. Use only for historical reports.",
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if args.require_current_build and args.allow_stale_build:
        parser.error("--require-current-build and --allow-stale-build are mutually exclusive")

    corpus = json.loads(args.results.read_text(encoding="utf-8"))
    rows = list(corpus.get("rows") or [])
    current_build = git_output("rev-parse", "HEAD")
    required_build = None if args.allow_stale_build else current_build
    published = {} if args.include_published else published_artifacts(args.publication_url, required_build)
    pending = rows_to_dispatch(rows, published)
    if pending and not args.dry_run:
        verify_remote_build(current_build)
    for row in pending:
        command = workflow_command(row, scanner_build=current_build)
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


def workflow_command(row: dict[str, Any], *, scanner_build: str) -> list[str]:
    if len(scanner_build) != 40 or any(character not in "0123456789abcdef" for character in scanner_build.lower()):
        raise ValueError("scanner_build must be a full 40-character Git commit SHA")
    command = [
        "gh", "workflow", "run", "deep-scan.yml", "--ref", "main",
        "-f", f"extension_id={row['extension_id']}",
        "-f", f"version={row['version']}",
        "-f", "scan_purpose=public_intelligence",
        "-f", f"scanner_build={scanner_build}",
    ]
    target_platform = str(row.get("target_platform") or "").strip()
    if target_platform:
        command.extend(["-f", f"target_platform={target_platform}"])
    return command


def verify_remote_build(scanner_build: str) -> None:
    """Fail closed when the exact release is still local-only.

    The workflow checks out ``scanner_build`` by immutable SHA. Dispatching a
    scan before that object is reachable from GitHub would either fail after
    queueing work or, worse, tempt an operator to remove the pin and scan a
    different revision. Keep the publication command side-effect free until
    the exact commit is available in the canonical repository.
    """
    repository = github_repository_full_name(
        git_output("config", "--get", "remote.origin.url")
    )
    result = subprocess.run(
        ["gh", "api", f"repos/{repository}/commits/{scanner_build}", "--silent"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "GitHub could not resolve the commit").strip().splitlines()[-1]
        raise RuntimeError(
            f"scanner build {scanner_build} is not available in GitHub repository {repository}: {detail}"
        )


def github_repository_full_name(origin_url: str) -> str:
    """Extract and validate the owner/repository pair used by ``gh api``."""
    value = str(origin_url or "").strip()
    if value.startswith("git@github.com:"):
        path = value.split(":", 1)[1]
    else:
        parsed = urlparse(value)
        if parsed.hostname != "github.com":
            raise RuntimeError("publication requires a GitHub origin remote")
        path = parsed.path.lstrip("/")
    path = path.removesuffix("/").removesuffix(".git")
    parts = path.split("/")
    if len(parts) != 2 or not all(parts):
        raise RuntimeError(f"publication origin is not an owner/repository pair: {origin_url}")
    return "/".join(parts)


def git_output(*arguments: str) -> str:
    return subprocess.run(["git", *arguments], check=True, capture_output=True, text=True).stdout.strip()


if __name__ == "__main__":
    raise SystemExit(main())
