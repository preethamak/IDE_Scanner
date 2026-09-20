#!/usr/bin/env python3
"""Download and verify pinned extension runtime sidecars.

The scanner never downloads during a scan. Run this command in a trusted
build or worker-image step, then point scans at the resulting cache with
GUARDRAILS_RUNTIME_CACHE.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import shutil
import sys
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ide_scanner.runtime_dependencies import locked_downloads


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _download(entry: dict[str, str], cache: Path) -> dict[str, str]:
    destination = cache / entry["cache_subpath"]
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="guardrails-runtime-") as temp_dir:
        compressed = Path(temp_dir) / entry["asset_name"]
        urllib.request.urlretrieve(entry["download_url"], compressed)
        asset_hash = _sha256(compressed)
        if asset_hash != entry["asset_sha256"]:
            raise SystemExit(
                f"{entry['dependency']} asset hash mismatch: {asset_hash} != {entry['asset_sha256']}"
            )
        temporary = Path(temp_dir) / "runtime-sidecar"
        with gzip.open(compressed, "rb") as source, temporary.open("wb") as target:
            shutil.copyfileobj(source, target)
        binary_hash = _sha256(temporary)
        if binary_hash != entry["binary_sha256"]:
            raise SystemExit(
                f"{entry['dependency']} binary hash mismatch: {binary_hash} != {entry['binary_sha256']}"
            )
        temporary.chmod(0o755)
        temporary.replace(destination)
    return {
        "dependency": entry["dependency"],
        "version": entry["version"],
        "path": str(destination),
        "sha256": entry["binary_sha256"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, required=True, help="Trusted runtime cache directory")
    parser.add_argument("--dependency", default="all", choices=["all", "rust-analyzer"])
    args = parser.parse_args()
    entries = [entry for entry in locked_downloads() if args.dependency == "all" or entry["dependency"] == args.dependency]
    results = [_download(entry, args.cache.expanduser()) for entry in entries]
    print(json.dumps({"cache": str(args.cache.expanduser()), "dependencies": results}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
