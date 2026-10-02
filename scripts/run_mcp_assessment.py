"""Run the existing full MCP assessment pipeline for a CI job."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from ide_scanner.mcp import scan_mcp_payload
from ide_scanner.mcp.orchestrator import ServerCatalogRiskConfig


def _config() -> ServerCatalogRiskConfig:
    tokens = [item.strip() for item in os.environ.get("MCP_GITHUB_TOKENS", "").split(",") if item.strip()]
    return ServerCatalogRiskConfig(
        gh_token=os.environ.get("MCP_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN"),
        gh_tokens=tokens or None,
        vertex_project_id=os.environ.get("VERTEX_PROJECT_ID"),
        google_api_key=os.environ.get("GOOGLE_API_KEY"),
        google_search_cx=os.environ.get("GOOGLE_SEARCH_CX"),
        env=os.environ.get("SCANNER_ENV", "production"),
        datadog_malicious_home=os.environ.get("DATADOG_MALICIOUS_HOME"),
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    payload = json.loads(args.input.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("MCP assessment input must be a JSON object")
    report = scan_mcp_payload(payload, config=_config())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, separators=(",", ":"), default=str), encoding="utf-8")


if __name__ == "__main__":
    main()
