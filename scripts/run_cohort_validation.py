"""Run the served-registry cohort through the full production scan path.

For every artifact listed in the expectations manifest this performs the same
flow the CI worker uses — ``scan_targets`` with marketplace download (SHA-256
integrity binding), online registry enrichment, and the deep provider profile
— then saves the canonical report JSON for comparison against expectations.

Resumable: an artifact whose report already exists on disk is skipped unless
--force is passed. Designed to run in the background over long wall clocks;
progress is written after every artifact.

Usage:
  python scripts/run_cohort_validation.py \
      --expectations benchmarks/marketplace-cohort/v2/expectations.json \
      --out-dir benchmarks/marketplace-cohort/v2/results \
      [--limit N] [--ids id1,id2,...] [--force]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

# Large publisher artifacts (claude-code, pylance, ...) exceed the 50 MiB
# default download cap; match the production worker's ceiling.
os.environ.setdefault("IDE_SCANNER_MAX_VSIX_BYTES", "524288000")
os.environ.setdefault("IDE_SCANNER_BUILD_SHA", "local-cohort-validation")


def _load_expectations(path: Path) -> dict[str, dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = data.get("extensions") if isinstance(data, dict) else data
    if not isinstance(rows, dict):
        raise SystemExit("expectations must map 'id@version' -> row")
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expectations", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=0, help="process at most N pending artifacts")
    parser.add_argument("--ids", type=str, default="", help="comma-separated subset of extension ids")
    parser.add_argument("--force", action="store_true", help="rescan artifacts that already have reports")
    args = parser.parse_args()

    expectations = _load_expectations(args.expectations)
    args.out_dir.mkdir(parents=True, exist_ok=True)

    wanted_ids = {item.strip().lower() for item in args.ids.split(",") if item.strip()}
    pending: list[tuple[str, str, dict, Path]] = []
    for key, row in expectations.items():
        ext_id = str(row.get("extension_id") or key.split("@")[0])
        if wanted_ids and ext_id.lower() not in wanted_ids:
            continue
        report_path = args.out_dir / f"{ext_id.replace('/', '_')}@{row.get('version')}.json"
        if not args.force and report_path.exists():
            continue
        pending.append((key, ext_id, row, report_path))
    pending.sort()
    if args.limit:
        pending = pending[: args.limit]

    print(f"{len(pending)} artifact(s) to scan", flush=True)

    # Imported after env setup so IDE_SCANNER_BUILD_SHA binds this run.
    from ide_scanner.scanner import DEEP_REQUIRED_PROVIDERS, scan_targets

    meta_path = args.out_dir / "_meta.json"
    failures: list[str] = []
    started = time.time()
    for index, (key, ext_id, row, report_path) in enumerate(pending, start=1):
        version = str(row.get("version"))
        label = f"[{index}/{len(pending)}] {ext_id}@{version}"
        began = time.time()
        try:
            bundle = scan_targets(
                marketplace_scan_ids=[ext_id],
                marketplace_version=version,
                online=True,
                required_providers=set(DEEP_REQUIRED_PROVIDERS),
            )
            extensions = [item for item in bundle.get("extensions", []) if isinstance(item, dict)]
            if len(extensions) != 1:
                raise RuntimeError(f"expected exactly one extension in bundle, got {len(extensions)}")
            payload = extensions[0]
            report_path.write_text(json.dumps(payload, ensure_ascii=False))
            if not meta_path.exists():
                meta_path.write_text(json.dumps({
                    "policy_version": bundle.get("policy_version"),
                    "ruleset_version": bundle.get("ruleset_version"),
                    "scanner_build": bundle.get("scanner_build"),
                    "score_schema_version": bundle.get("score_schema_version"),
                }, indent=2))
            status = payload.get("analysis_status")
            decision = payload.get("decision")
            basis = payload.get("decision_basis")
            print(
                f"{label} -> {status}/{decision}/{basis} "
                f"risk={payload.get('risk_score')} malware={payload.get('malware_score')} "
                f"({time.time() - began:.0f}s)",
                flush=True,
            )
            if status != "complete":
                failures.append(f"{key}: analysis_status={status}")
        except Exception as exc:  # noqa: BLE001 - sweep isolation by design
            failures.append(f"{key}: {type(exc).__name__}: {exc}")
            print(f"{label} -> ERROR {exc}", flush=True)

    summary = {
        "requested": len(pending),
        "failures": failures,
        "wall_seconds": round(time.time() - started, 1),
    }
    (args.out_dir / "_run-summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
