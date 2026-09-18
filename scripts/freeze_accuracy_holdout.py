#!/usr/bin/env python3
"""Acquire and freeze exact, externally labelled VSIX bytes for the accuracy gate.

This command deliberately does not scan or execute the acquired artifacts. It
only creates a private, hash-addressed input directory plus the two manifests
consumed by ``scan_corpus.py`` and ``build_publication_accuracy_gate.py``.
Keep the output outside Git: a malicious VSIX is untrusted input.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from ide_scanner.artifact_input import ArtifactInputError, acquire_https_vsix  # noqa: E402
from scripts.build_publication_accuracy_gate import LABELS, SHA256_RE, _validate_label_evidence  # noqa: E402

SOURCE_SCHEMA = "guardrails.holdout-source.v1"
CORPUS_SCHEMA = "1.0"
MANIFEST_SCHEMA = "guardrails.corpus-manifest.v1"


def freeze_holdout(
    source_path: Path | str,
    output_dir: Path | str,
    corpus_path: Path | str,
    manifest_path: Path | str,
) -> dict[str, Any]:
    source = _read_source(Path(source_path))
    destination = Path(output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    artifacts: list[dict[str, Any]] = []
    manifest_artifacts: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for index, item in enumerate(source["artifacts"]):
        if not isinstance(item, dict):
            raise ValueError(f"source artifact {index} is not an object")
        extension_id = _required_string(item, "extension_id", index)
        version = _required_string(item, "version", index)
        label = item.get("label")
        if label not in LABELS:
            raise ValueError(f"source artifact {index} label must be known_safe or known_malicious")
        key = (extension_id.lower(), version)
        if key in seen:
            raise ValueError(f"source artifact {index} duplicates {extension_id}@{version}")
        seen.add(key)
        source_url = _https_url(item.get("artifact_url"), f"source artifact {index} artifact_url")
        sha256 = str(item.get("sha256") or "").strip().lower()
        if not SHA256_RE.fullmatch(sha256):
            raise ValueError(f"source artifact {index} requires a 64-character SHA-256")
        _validate_label_evidence(item.get("label_evidence"), index)

        filename = f"{_safe_name(extension_id)}-{_safe_name(version)}-{sha256[:16]}.vsix"
        target = destination / filename
        local_path = item.get("local_path")
        _acquire_or_verify(source_url, sha256, target, destination, local_path=local_path, source_root=Path(source_path).resolve().parent)
        artifacts.append({
            "extension_id": extension_id,
            "version": version,
            "gate_required": True,
            "label": label,
            "label_evidence": item["label_evidence"],
            "artifact": {
                "source_type": "pinned_https",
                "source_url": source_url,
                "path": filename,
                "original_bytes_available": True,
                "sha256": sha256,
            },
        })
        manifest_artifacts.append({
            "path": filename,
            "extension_id": extension_id,
            "version": version,
            "sha256": sha256,
        })

    corpus = {
        "schema_version": CORPUS_SCHEMA,
        "corpus_id": source["corpus_id"],
        "corpus_version": source["corpus_version"],
        "holdout": {
            "status": "fresh-labeled",
            "frozen_before_scan": True,
            "frozen_at": source["holdout"]["frozen_at"],
            "original_bytes_available": True,
            "label_source": source["holdout"]["label_source"],
        },
        "artifacts": artifacts,
    }
    manifest = {"schema_version": MANIFEST_SCHEMA, "artifacts": manifest_artifacts}
    _write_json(Path(corpus_path), corpus)
    _write_json(Path(manifest_path), manifest)
    return {
        "corpus": str(Path(corpus_path)),
        "manifest": str(Path(manifest_path)),
        "artifacts": len(artifacts),
        "directory": str(destination),
    }


def _read_source(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"holdout source could not be read: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema_version") != SOURCE_SCHEMA:
        raise ValueError(f"holdout source must use schema_version {SOURCE_SCHEMA}")
    corpus_id = str(value.get("corpus_id") or "").strip()
    corpus_version = str(value.get("corpus_version") or "").strip()
    if not corpus_id or not corpus_version:
        raise ValueError("holdout source requires corpus_id and corpus_version")
    holdout = value.get("holdout")
    if not isinstance(holdout, dict) or holdout.get("status") != "fresh-labeled":
        raise ValueError("holdout source must declare status fresh-labeled")
    label_source = str(holdout.get("label_source") or "").strip()
    frozen_at = str(holdout.get("frozen_at") or "").strip()
    if not label_source or not frozen_at:
        raise ValueError("holdout source requires holdout.label_source and holdout.frozen_at")
    try:
        datetime.fromisoformat(frozen_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("holdout.frozen_at must be ISO-8601") from exc
    artifacts = value.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ValueError("holdout source requires a non-empty artifacts array")
    return {
        "corpus_id": corpus_id,
        "corpus_version": corpus_version,
        "holdout": {"label_source": label_source, "frozen_at": frozen_at},
        "artifacts": artifacts,
    }


def _acquire_or_verify(
    url: str,
    expected_sha256: str,
    target: Path,
    destination: Path,
    *,
    local_path: Any = None,
    source_root: Path | None = None,
) -> None:
    if target.exists():
        if target.is_file() and _sha256(target) == expected_sha256:
            return
        raise ValueError(f"refusing to overwrite an existing non-matching holdout artifact: {target}")
    if local_path is not None and str(local_path).strip():
        candidate = Path(str(local_path)).expanduser()
        if not candidate.is_absolute() and source_root is not None:
            candidate = source_root / candidate
        # A private local cache is optional. Clean CI checkouts do not carry
        # the retained bytes, so a missing cache must fall through to the
        # pinned HTTPS acquisition path below. Existing-but-unsafe or
        # hash-mismatched bytes remain hard failures.
        if candidate.is_symlink() or (candidate.exists() and not candidate.is_file()):
            raise ValueError(f"local holdout artifact is not a regular file: {candidate}")
        if candidate.is_file():
            candidate = candidate.resolve()
            if _sha256(candidate) != expected_sha256:
                raise ValueError(f"local holdout artifact SHA-256 does not match the required digest: {candidate}")
            shutil.copyfile(candidate, target)
            return
    try:
        temporary = acquire_https_vsix(url, expected_sha256, destination)
    except ArtifactInputError as exc:
        raise ValueError(f"could not acquire {url}: {exc}") from exc
    temporary.replace(target)


def _https_url(value: Any, label: str) -> str:
    url = str(value or "").strip()
    parsed = urlparse(url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"{label} must use a valid HTTPS port") from exc
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or port not in (None, 443):
        raise ValueError(f"{label} must be public HTTPS on port 443 without credentials")
    return url


def _required_string(item: dict[str, Any], field: str, index: int) -> str:
    value = str(item.get(field) or "").strip()
    if not value:
        raise ValueError(f"source artifact {index} requires {field}")
    return value


def _safe_name(value: str) -> str:
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip(".-")
    return name[:120] or "artifact"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Acquire and freeze exact labelled VSIX bytes for the publication accuracy gate.")
    parser.add_argument("--source", required=True, type=Path, help=f"JSON source spec using schema {SOURCE_SCHEMA}.")
    parser.add_argument("--output-dir", required=True, type=Path, help="Private directory for retained VSIX bytes.")
    parser.add_argument("--corpus", required=True, type=Path, help="Output fresh holdout corpus JSON.")
    parser.add_argument("--manifest", required=True, type=Path, help="Output scan_corpus manifest JSON.")
    args = parser.parse_args(argv)
    try:
        result = freeze_holdout(args.source, args.output_dir, args.corpus, args.manifest)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
