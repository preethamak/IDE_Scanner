from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from scripts.verify_holdout_provenance import verify_holdout_provenance


ROOT = Path(__file__).parents[1]
SOURCE = ROOT / "benchmarks" / "holdouts" / "real-evidence-2026-source.json"
ADVISORIES = ROOT / "src" / "ide_scanner" / "intelligence" / "extension-advisories.json"


def test_real_holdout_provenance_matches_exact_advisories() -> None:
    result = verify_holdout_provenance(SOURCE, ADVISORIES)

    assert result["status"] == "verified"
    assert result["artifact_count"] == 10
    assert result["malicious_artifacts_with_exact_advisories"] == 5
    assert result["advisory_snapshot_version"] == "2026-09-22.1"


def test_provenance_rejects_changed_evidence_hash() -> None:
    source = json.loads(SOURCE.read_text(encoding="utf-8"))
    source["artifacts"][0]["label_evidence"]["artifact_sha256"] = "0" * 64
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "source.json"
        path.write_text(json.dumps(source), encoding="utf-8")
        with pytest.raises(ValueError, match="evidence SHA-256"):
            verify_holdout_provenance(path, ADVISORIES)


def test_provenance_rejects_advisory_identity_drift() -> None:
    source = json.loads(SOURCE.read_text(encoding="utf-8"))
    source["artifacts"][5]["label_evidence"]["advisory_id"] = "KNOSTIC-BCAI-2026-4.0.37"
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "source.json"
        path.write_text(json.dumps(source), encoding="utf-8")
        with pytest.raises(ValueError, match="advisory does not match"):
            verify_holdout_provenance(path, ADVISORIES)
