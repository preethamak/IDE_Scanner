#!/usr/bin/env python3
"""Acquire a frozen legitimate VSIX cohort without installing or executing it."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from ide_scanner.registry import download_marketplace_vsix


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("frozen_manifest", type=Path)
    parser.add_argument("output_directory", type=Path)
    args = parser.parse_args()

    frozen = _read_object(args.frozen_manifest)
    samples = frozen.get("samples")
    if not isinstance(samples, list) or not samples:
        raise ValueError("Frozen manifest has no samples.")

    output = args.output_directory.resolve()
    artifacts = output / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    inventory_path = output / "inventory.json"
    prior = _read_object(inventory_path) if inventory_path.exists() else {}
    rows_by_key = {
        (str(row.get("extension_id")), str(row.get("version"))): row
        for row in prior.get("artifacts", [])
        if isinstance(row, dict)
    }

    for sample in samples:
        if not isinstance(sample, dict):
            raise ValueError("Frozen sample is not an object.")
        extension_id = str(sample.get("extension_id") or "")
        version = str(sample.get("version") or "")
        if not extension_id or not version:
            raise ValueError("Frozen sample is missing extension_id or version.")
        filename = f"{extension_id}-{version}.vsix"
        destination = artifacts / filename
        existing = rows_by_key.get((extension_id, version))
        if destination.exists() and existing and _sha256(destination) == existing.get("sha256"):
            print(f"verified-existing {extension_id}@{version}", flush=True)
            continue

        registry: dict[str, str] = {}
        with tempfile.TemporaryDirectory(dir=output) as temporary:
            downloaded = download_marketplace_vsix(
                extension_id,
                version=version,
                destination_dir=temporary,
                max_bytes=500 * 1024 * 1024,
                timeout=180,
                registry_out=registry,
            )
            identity = _vsix_identity(downloaded)
            if identity[0].lower() != extension_id.lower() or identity[1] != version:
                raise ValueError(
                    f"Artifact identity mismatch for {extension_id}@{version}: "
                    f"embedded {identity[0]}@{identity[1]}"
                )
            digest = _sha256(downloaded)
            os.replace(downloaded, destination)

        registry_name = registry.get("registry") or "unknown"
        source_url = _source_url(extension_id, version, registry_name)
        rows_by_key[(extension_id, version)] = {
            **sample,
            "artifact_filename": filename,
            "sha256": digest,
            "size_bytes": destination.stat().st_size,
            "registry": registry_name,
            "source_url": source_url,
            "acquired_at": datetime.now(UTC).isoformat(),
            "embedded_extension_id": identity[0],
            "embedded_version": identity[1],
        }
        _write_inventory(inventory_path, frozen, rows_by_key)
        print(f"acquired {extension_id}@{version} sha256={digest}", flush=True)

    _write_inventory(inventory_path, frozen, rows_by_key)
    return 0


def _vsix_identity(path: Path) -> tuple[str, str]:
    with zipfile.ZipFile(path) as archive:
        with archive.open("extension/package.json") as handle:
            package = json.load(handle)
    publisher = str(package.get("publisher") or "")
    name = str(package.get("name") or "")
    version = str(package.get("version") or "")
    if not publisher or not name or not version:
        raise ValueError(f"VSIX manifest identity is incomplete: {path.name}")
    return f"{publisher}.{name}", version


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _source_url(extension_id: str, version: str, registry: str) -> str:
    publisher, name = extension_id.split(".", 1)
    if registry == "openvsx":
        return f"https://open-vsx.org/api/{publisher}/{name}/{version}/file/{publisher}.{name}-{version}.vsix"
    return (
        f"https://marketplace.visualstudio.com/_apis/public/gallery/publishers/{publisher}/"
        f"vsextensions/{name}/{version}/vspackage"
    )


def _read_object(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def _write_inventory(path: Path, frozen: dict, rows_by_key: dict[tuple[str, str], dict]) -> None:
    rows = sorted(rows_by_key.values(), key=lambda row: str(row.get("extension_id", "")).lower())
    payload = {
        "schema_version": "1.0",
        "cohort_id": frozen.get("cohort_id"),
        "frozen_on": frozen.get("frozen_on"),
        "scanner_commit": frozen.get("scanner_commit"),
        "artifact_count": len(rows),
        "artifacts": rows,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
