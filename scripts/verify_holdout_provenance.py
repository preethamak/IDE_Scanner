#!/usr/bin/env python3
"""Verify that the labelled accuracy holdout is tied to exact evidence.

This is deliberately an offline verifier. It cannot decide whether a source
report is truthful, but it prevents a holdout from silently changing the
extension identity, version, or bytes after the report was reviewed. Malicious
labels must also resolve to the versioned exact-hash advisory snapshot used by
the scanner.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
SOURCE_SCHEMA = "guardrails.holdout-source.v1"


def verify_holdout_provenance(source_path: Path | str, advisories_path: Path | str) -> dict[str, Any]:
    source_file = Path(source_path).resolve()
    advisory_file = Path(advisories_path).resolve()
    source = _read_object(source_file, "holdout source")
    advisories = _read_object(advisory_file, "advisory snapshot")
    if source.get("schema_version") != SOURCE_SCHEMA:
        raise ValueError(f"holdout source must use schema_version {SOURCE_SCHEMA}")
    entries = advisories.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ValueError("advisory snapshot must contain a non-empty entries array")
    by_advisory_id: dict[str, dict[str, Any]] = {}
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"advisory snapshot entry {index} is not an object")
        advisory_id = str(entry.get("advisory_id") or "").strip()
        if not advisory_id or advisory_id in by_advisory_id:
            raise ValueError(f"advisory snapshot entry {index} has a missing or duplicate advisory_id")
        if not SHA256_RE.fullmatch(str(entry.get("artifact_sha256") or "")):
            raise ValueError(f"advisory snapshot entry {index} requires an exact artifact SHA-256")
        by_advisory_id[advisory_id] = entry

    artifacts = source.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ValueError("holdout source requires a non-empty artifacts array")
    matched_advisories = 0
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            raise ValueError(f"holdout source artifact {index} is not an object")
        extension_id = str(artifact.get("extension_id") or "").strip()
        version = str(artifact.get("version") or "").strip()
        label = str(artifact.get("label") or "").strip()
        artifact_sha256 = str(artifact.get("sha256") or "").strip().lower()
        evidence = artifact.get("label_evidence")
        if not extension_id or not version or label not in {"known_safe", "known_malicious"}:
            raise ValueError(f"holdout source artifact {index} has an invalid identity or label")
        if not SHA256_RE.fullmatch(artifact_sha256):
            raise ValueError(f"holdout source artifact {index} requires an exact SHA-256")
        if not isinstance(evidence, dict):
            raise ValueError(f"holdout source artifact {index} requires structured label evidence")
        if evidence.get("evidence_scope") != "exact-artifact":
            raise ValueError(f"holdout source artifact {index} must declare exact-artifact evidence")
        if str(evidence.get("extension_id") or "").strip().lower() != extension_id.lower():
            raise ValueError(f"holdout source artifact {index} evidence extension_id does not match the artifact")
        if str(evidence.get("version") or "").strip() != version:
            raise ValueError(f"holdout source artifact {index} evidence version does not match the artifact")
        if str(evidence.get("artifact_sha256") or "").strip().lower() != artifact_sha256:
            raise ValueError(f"holdout source artifact {index} evidence SHA-256 does not match the artifact")
        _https_url(evidence.get("source_url"), f"holdout source artifact {index} evidence source_url")
        if evidence.get("source_secondary_url") is not None:
            _https_url(evidence.get("source_secondary_url"), f"holdout source artifact {index} evidence source_secondary_url")
        if label != "known_malicious":
            continue
        advisory_id = str(evidence.get("advisory_id") or "").strip()
        if not advisory_id:
            raise ValueError(f"known-malicious holdout artifact {index} requires an exact advisory_id")
        advisory = by_advisory_id.get(advisory_id)
        if advisory is None:
            raise ValueError(f"holdout source artifact {index} references an unknown advisory_id {advisory_id!r}")
        if (
            str(advisory.get("extension_id") or "").strip().lower() != extension_id.lower()
            or str(advisory.get("version") or "").strip() != version
            or str(advisory.get("artifact_sha256") or "").strip().lower() != artifact_sha256
            or str(advisory.get("threat_classification") or "").strip().lower() != "malicious"
            or str(advisory.get("policy_action") or "").strip().lower() != "block"
        ):
            raise ValueError(f"holdout source artifact {index} advisory does not match the exact malicious artifact")
        evidence_urls = {str(evidence.get("source_url") or "").strip(), str(evidence.get("source_secondary_url") or "").strip()}
        advisory_urls = {str(advisory.get("source") or "").strip(), str(advisory.get("source_secondary") or "").strip()}
        if not evidence_urls.intersection(advisory_urls):
            raise ValueError(f"holdout source artifact {index} advisory source does not match label evidence")
        matched_advisories += 1

    snapshot = source.get("advisory_snapshot")
    if snapshot is not None:
        if not isinstance(snapshot, dict):
            raise ValueError("holdout advisory_snapshot must be an object")
        relative_path = str(snapshot.get("path") or "").strip()
        if not relative_path:
            raise ValueError("holdout advisory_snapshot requires path")
        declared_path = (source_file.parent / relative_path).resolve()
        if declared_path != advisory_file:
            raise ValueError("holdout advisory_snapshot path does not match the verifier input")
        declared_sha256 = str(snapshot.get("sha256") or "").strip().lower()
        actual_sha256 = _sha256(advisory_file.read_bytes())
        if declared_sha256 != actual_sha256:
            raise ValueError("holdout advisory_snapshot SHA-256 does not match the retained advisory snapshot")
        declared_version = str(snapshot.get("snapshot_version") or "").strip()
        if declared_version != str(advisories.get("snapshot_version") or "").strip():
            raise ValueError("holdout advisory_snapshot version does not match the retained advisory snapshot")

    return {
        "status": "verified",
        "source": str(source_file),
        "source_sha256": _sha256(source_file.read_bytes()),
        "advisory_snapshot": str(advisory_file),
        "advisory_snapshot_sha256": _sha256(advisory_file.read_bytes()),
        "advisory_snapshot_version": str(advisories.get("snapshot_version") or ""),
        "artifact_count": len(artifacts),
        "malicious_artifacts_with_exact_advisories": matched_advisories,
    }


def _read_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} could not be read: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _https_url(value: Any, label: str) -> str:
    url = str(value or "").strip()
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.port not in (None, 443):
        raise ValueError(f"{label} must use public HTTPS on port 443 without credentials")
    return url


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify exact evidence provenance for the publication holdout.")
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--advisories", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = verify_holdout_provenance(args.source, args.advisories)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
