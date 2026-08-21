from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from ide_scanner.benchmarks.production import (
    evaluate_production_corpus,
    load_production_corpus,
    validate_production_corpus,
)


CORPUS_PATH = Path("benchmarks/production-corpus.json")


def test_packaged_production_corpus_is_valid_and_version_pinned() -> None:
    corpus = load_production_corpus(CORPUS_PATH)

    assert corpus["corpus_id"] == "ide-scanner-production-gate"
    assert len(corpus["artifacts"]) >= 10
    assert all(item["version"] != "latest" for item in corpus["artifacts"])
    assert any(item["category"] == "coding-agent" for item in corpus["artifacts"])
    assert any(item["label"] == "known_malicious" for item in corpus["artifacts"])


def test_production_gate_passes_required_artifacts_and_tracks_optional_backlog(tmp_path: Path) -> None:
    corpus = load_production_corpus(CORPUS_PATH)
    extensions = [_actual_for(item) for item in corpus["artifacts"] if item["gate_required"]]
    report = tmp_path / "report.json"
    report.write_text(json.dumps({
        "scanner_build": "test-build",
        "policy_version": "test-policy",
        "extensions": extensions,
    }), encoding="utf-8")

    result = evaluate_production_corpus(CORPUS_PATH, report)

    assert result["gate"]["passed"] is True
    assert result["summary"]["required_pass_rate"] == 1.0
    assert result["summary"]["not_scanned"] > 0
    assert result["summary"]["safe_block_rate"] == 0
    assert result["summary"]["malicious_allow_rate"] == 0


def test_production_gate_fails_safe_block_and_missing_malicious_artifact(tmp_path: Path) -> None:
    corpus = load_production_corpus(CORPUS_PATH)
    required = [item for item in corpus["artifacts"] if item["gate_required"]]
    extensions = [_actual_for(item) for item in required if item["label"] != "known_malicious"]
    safe = next(item for item in extensions if item["extension_id"] == "trusted.trusted-formatter")
    safe.update({"verdict": "suspicious", "decision": "block", "risk_score": 90})
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"extensions": extensions}), encoding="utf-8")

    result = evaluate_production_corpus(CORPUS_PATH, report)

    assert result["gate"]["passed"] is False
    assert result["gate"]["checks"]["safe_block_rate"] is False
    assert result["summary"]["required_failed"] >= 2
    missing = next(item for item in result["artifacts"] if item["extension_id"] == "unknown.shadow-helper")
    assert missing["gate_passed"] is False
    assert "not present" in missing["violations"][0]


def test_production_gate_rejects_artifact_hash_mismatch(tmp_path: Path) -> None:
    corpus = load_production_corpus(CORPUS_PATH)
    expected = next(item for item in corpus["artifacts"] if item["gate_required"])
    actual = _actual_for(expected)
    actual["artifact_hash"] = "0" * 64
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"extensions": [actual]}), encoding="utf-8")

    result = evaluate_production_corpus(CORPUS_PATH, report)

    row = next(item for item in result["artifacts"] if item["extension_id"] == expected["extension_id"])
    assert any("artifact SHA-256 does not match" in item for item in row["violations"])


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda data: data.update(schema_version="2"), "schema_version"),
        (lambda data: data["artifacts"][0].update(version="latest"), "exact version"),
        (lambda data: data["artifacts"][0]["artifact"].update(sha256="bad"), "SHA-256"),
        (lambda data: data["artifacts"][0].update(label="probably_safe"), "unsupported label"),
        (lambda data: data["thresholds"].update(required_pass_rate=1.1), "between 0 and 1"),
    ],
)
def test_invalid_production_corpus_fails_closed(mutation, message: str) -> None:
    corpus = copy.deepcopy(load_production_corpus(CORPUS_PATH))
    mutation(corpus)

    with pytest.raises(ValueError, match=message):
        validate_production_corpus(corpus)


def _actual_for(expected: dict) -> dict:
    constraints = expected["expected"]
    return {
        "extension_id": expected["extension_id"],
        "version": expected["version"],
        "verdict": constraints["allowed_verdicts"][0],
        "decision": constraints["allowed_decisions"][0],
        "analysis_status": constraints["allowed_analysis_statuses"][0],
        "risk_score": constraints.get("min_risk_score", 0),
        "malware_score": constraints.get("min_malware_score", 0),
        "artifact_hash": expected["artifact"].get("sha256", ""),
        "findings": [{"rule_id": rule_id} for rule_id in constraints.get("required_rule_ids", [])],
    }
