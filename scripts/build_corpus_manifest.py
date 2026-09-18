#!/usr/bin/env python3
"""Build an exact VSIX manifest without executing or installing artifacts."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from scripts.scan_corpus import _canonical_artifact_sha256, _degzip_if_needed

EXTENSION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.[A-Za-z0-9][A-Za-z0-9._-]*$")
MAX_PACKAGE_JSON_BYTES = 1024 * 1024


def build_manifest(paths: list[Path | str], output: Path | str, *, max_artifacts: int = 5000) -> dict[str, Any]:
    artifacts = _discover(paths)
    if not artifacts:
        raise ValueError("no VSIX artifacts were discovered")
    if len(artifacts) > max_artifacts:
        raise ValueError(f"artifact count exceeds the {max_artifacts}-artifact bound")
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for path in artifacts:
        extension_id, version = _identity(path)
        key = (extension_id.lower(), version)
        if key in seen:
            raise ValueError(f"duplicate extension identity: {extension_id}@{version}")
        seen.add(key)
        rows.append({
            "path": str(path),
            "extension_id": extension_id,
            "version": version,
            "sha256": _canonical_artifact_sha256(path),
        })
    payload = {"schema_version": "guardrails.corpus-manifest.v1", "artifacts": rows}
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"output": str(destination), "artifacts": len(rows)}


def _discover(paths: list[Path | str]) -> list[Path]:
    found: dict[str, Path] = {}
    for raw in paths:
        path = Path(raw).expanduser().resolve()
        if path.is_file() and path.suffix.lower() == ".vsix":
            found[str(path)] = path
        elif path.is_dir():
            for candidate in path.rglob("*.vsix"):
                if candidate.is_file():
                    resolved = candidate.resolve()
                    found[str(resolved)] = resolved
    return [found[key] for key in sorted(found)]


def _identity(path: Path) -> tuple[str, str]:
    with tempfile.TemporaryDirectory(prefix="guardrails-manifest-") as directory:
        canonical = Path(directory) / path.name
        canonical.write_bytes(path.read_bytes())
        _degzip_if_needed(canonical)
        try:
            with zipfile.ZipFile(canonical) as archive:
                names = [name for name in archive.namelist() if name in {"extension/package.json", "package.json"}]
                if not names:
                    raise ValueError(f"VSIX has no package.json: {path}")
                package_name = "extension/package.json" if "extension/package.json" in names else names[0]
                with archive.open(package_name) as handle:
                    raw = handle.read(MAX_PACKAGE_JSON_BYTES + 1)
        except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
            raise ValueError(f"could not read VSIX metadata {path}: {exc}") from exc
    if len(raw) > MAX_PACKAGE_JSON_BYTES:
        raise ValueError(f"VSIX package.json exceeds the {MAX_PACKAGE_JSON_BYTES}-byte limit: {path}")
    try:
        package = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"VSIX package.json is invalid: {path}") from exc
    if not isinstance(package, dict):
        raise ValueError(f"VSIX package.json must be an object: {path}")
    publisher = str(package.get("publisher") or "").strip()
    name = str(package.get("name") or "").strip()
    version = str(package.get("version") or "").strip()
    extension_id = f"{publisher}.{name}"
    if not EXTENSION_ID_RE.fullmatch(extension_id) or not version:
        raise ValueError(f"VSIX package.json has incomplete identity: {path}")
    return extension_id, version


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a hash-pinned corpus manifest from VSIX artifacts.")
    parser.add_argument("--path", action="append", required=True, help="VSIX file or directory to scan recursively.")
    parser.add_argument("--out", "--output", required=True, type=Path)
    parser.add_argument("--max-artifacts", type=int, default=5000)
    args = parser.parse_args(argv)
    if not 1 <= args.max_artifacts <= 5000:
        parser.error("max-artifacts must be between 1 and 5000")
    try:
        result = build_manifest(args.path, args.out, max_artifacts=args.max_artifacts)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
