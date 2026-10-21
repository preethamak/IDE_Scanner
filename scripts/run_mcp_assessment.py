"""Run the existing full MCP assessment pipeline for a CI job."""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
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
    parser.add_argument("--encrypted-input", action="store_true")
    parser.add_argument("--encrypted-output", action="store_true")
    args = parser.parse_args()

    input_bytes = args.input.read_bytes()
    if args.encrypted_input:
        input_bytes = _decrypt_packet(input_bytes)
    payload = json.loads(input_bytes.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("MCP assessment input must be a JSON object")
    report = scan_mcp_payload(payload, config=_config())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    output = json.dumps(report, separators=(",", ":"), default=str).encode("utf-8")
    if args.encrypted_output:
        output = _encrypt_packet(output)
    args.output.write_bytes(output)


def _encryption_key() -> bytes:
    encoded = os.environ.get("MCP_SCAN_ENCRYPTION_KEY", "")
    try:
        key = base64.b64decode(encoded, validate=True)
    except Exception as error:
        raise RuntimeError("MCP_SCAN_ENCRYPTION_KEY is not valid base64") from error
    if len(key) != 32:
        raise RuntimeError("MCP_SCAN_ENCRYPTION_KEY must decode to 32 bytes")
    return key


def _decrypt_packet(encoded: bytes) -> bytes:
    try:
        packet = base64.b64decode(encoded, validate=True)
    except Exception as error:
        raise RuntimeError("Encrypted MCP input is not valid base64") from error
    if len(packet) < 13:
        raise RuntimeError("Encrypted MCP input is truncated")
    return AESGCM(_encryption_key()).decrypt(packet[:12], packet[12:], None)


def _encrypt_packet(plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    packet = nonce + AESGCM(_encryption_key()).encrypt(nonce, plaintext, None)
    return base64.b64encode(packet)


if __name__ == "__main__":
    main()
