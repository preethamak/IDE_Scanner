#!/usr/bin/env python3
"""Combine regression and fresh-holdout evidence for public release activation.

The deterministic production corpus protects known scanner invariants. It is
not an ecosystem accuracy claim. Public registry activation additionally
requires a separately frozen exact-artifact holdout with documented labels and
both known-safe and known-malicious samples.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
BUILD_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
LABELS = {"known_safe", "known_malicious"}


def build_publication_accuracy_gate(
    regression_gate_path: Path | str,
    holdout_gate_path: Path | str,
    holdout_corpus_path: Path | str,
) -> dict[str, Any]:
    regression_bytes, regression = _read_json(regression_gate_path)
    holdout_bytes, holdout_gate = _read_json(holdout_gate_path)
    corpus_bytes, holdout_corpus = _read_json(holdout_corpus_path)

    _validate_gate(regression, "regression")
    _validate_gate(holdout_gate, "holdout")
    _validate_holdout_corpus(holdout_corpus)

    regression_identity = _identity(regression)
    holdout_identity = _identity(holdout_gate)
    if regression_identity != holdout_identity:
        raise ValueError("Regression and holdout gates do not share one scanner, policy, and ruleset identity.")
    scanner_build = regression_identity["scanner_build"]
    if not BUILD_RE.fullmatch(scanner_build):
        raise ValueError("Publication accuracy gates require a full 40-character scanner build, not unknown.")

    corpus_id = str(holdout_corpus["corpus_id"])
    corpus_version = str(holdout_corpus.get("corpus_version") or "unknown")
    if str(holdout_gate.get("corpus_id") or "") != corpus_id:
        raise ValueError("Holdout gate corpus_id does not match the frozen holdout corpus.")
    if str(holdout_gate.get("corpus_version") or "") != corpus_version:
        raise ValueError("Holdout gate corpus_version does not match the frozen holdout corpus.")

    summary = _object(holdout_gate.get("summary"))
    artifacts = holdout_corpus["artifacts"]
    if len(artifacts) != _number(summary.get("required_artifacts")):
        raise ValueError("Every frozen holdout artifact must be required by the holdout gate.")
    if _number(summary.get("not_scanned")) != 0 or _number(summary.get("incomplete_required")) != 0:
        raise ValueError("The publication holdout must scan every exact artifact completely.")
    if _number(summary.get("required_passed")) != len(artifacts):
        raise ValueError("The publication holdout contains a labelled routing mismatch.")
    if _number(summary.get("safe_evaluated")) < 1 or _number(summary.get("malicious_evaluated")) < 1:
        raise ValueError("The publication holdout must contain known-safe and known-malicious artifacts.")

    return {
        "schema_version": "1.0",
        "corpus_id": str(regression.get("corpus_id") or ""),
        "corpus_version": str(regression.get("corpus_version") or "unknown"),
        "report_identity": regression_identity,
        "gate": dict(_object(regression.get("gate"))),
        "summary": dict(_object(regression.get("summary"))),
        "rule_matrix": dict(_object(regression.get("rule_matrix"))),
        "holdout": {
            "status": "fresh-labeled",
            "complete": True,
            "corpus_id": corpus_id,
            "corpus_version": corpus_version,
            "scanner_build": scanner_build,
            "policy_version": regression_identity["policy_version"],
            "ruleset_version": regression_identity["ruleset_version"],
            "artifact_count": len(artifacts),
            "safe_evaluated": _number(summary.get("safe_evaluated")),
            "malicious_evaluated": _number(summary.get("malicious_evaluated")),
            "required_pass_rate": _number(summary.get("required_pass_rate")),
            "safe_block_rate": _number(summary.get("safe_block_rate")),
            "malicious_allow_rate": _number(summary.get("malicious_allow_rate")),
            "gate": dict(_object(holdout_gate.get("gate"))),
        },
        "provenance": {
            "regression_gate_sha256": _sha256(regression_bytes),
            "holdout_gate_sha256": _sha256(holdout_bytes),
            "holdout_corpus_sha256": _sha256(corpus_bytes),
        },
    }


def _validate_gate(gate: dict[str, Any], name: str) -> None:
    if str(gate.get("schema_version") or "") != "1.0":
        raise ValueError(f"{name} gate schema_version must be 1.0")
    if _object(gate.get("gate")).get("passed") is not True:
        raise ValueError(f"{name} gate did not pass")
    checks = _object(gate.get("gate")).get("checks")
    if not isinstance(checks, dict) or not checks or any(value is not True for value in checks.values()):
        raise ValueError(f"{name} gate contains a failed or missing check")
    identity = _identity(gate)
    if not BUILD_RE.fullmatch(identity["scanner_build"]):
        raise ValueError(f"{name} gate requires a full 40-character scanner build")
    summary = _object(gate.get("summary"))
    if _number(summary.get("required_pass_rate")) < 1:
        raise ValueError(f"{name} gate required pass rate is below 100 percent")
    if _number(summary.get("safe_block_rate")) > 0 or _number(summary.get("malicious_allow_rate")) > 0:
        raise ValueError(f"{name} gate contains a safe block or malicious allow")


def _validate_holdout_corpus(corpus: dict[str, Any]) -> None:
    if corpus.get("schema_version") != "1.0":
        raise ValueError("Holdout corpus schema_version must be 1.0")
    if not str(corpus.get("corpus_id") or "").strip():
        raise ValueError("Holdout corpus requires a corpus_id")
    metadata = _object(corpus.get("holdout"))
    if metadata.get("status") != "fresh-labeled" or metadata.get("frozen_before_scan") is not True:
        raise ValueError("Holdout corpus must be frozen and labelled before scanning")
    if metadata.get("original_bytes_available") is not True or not str(metadata.get("label_source") or "").strip():
        raise ValueError("Holdout corpus must retain original bytes and document its label source")
    artifacts = corpus.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ValueError("Holdout corpus requires a non-empty artifacts array")
    seen: set[tuple[str, str]] = set()
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            raise ValueError(f"Holdout artifact {index} is not an object")
        key = (str(artifact.get("extension_id") or "").lower(), str(artifact.get("version") or ""))
        if not key[0] or not key[1] or key in seen:
            raise ValueError(f"Holdout artifact {index} has an invalid or duplicate identity")
        seen.add(key)
        if artifact.get("gate_required") is not True or artifact.get("label") not in LABELS:
            raise ValueError(f"Holdout artifact {index} must be a required known_safe or known_malicious label")
        if not str(artifact.get("label_evidence") or "").strip():
            raise ValueError(f"Holdout artifact {index} requires artifact-specific label evidence")
        identity = _object(artifact.get("artifact"))
        source_type = str(identity.get("source_type") or "")
        if source_type == "fixture_directory" or not source_type:
            raise ValueError(f"Holdout artifact {index} cannot use a synthetic fixture source")
        if identity.get("original_bytes_available") is not True or not SHA256_RE.fullmatch(str(identity.get("sha256") or "")):
            raise ValueError(f"Holdout artifact {index} requires retained exact bytes and a SHA-256")


def _identity(value: dict[str, Any]) -> dict[str, str]:
    identity = _object(value.get("report_identity"))
    return {
        "scanner_build": str(identity.get("scanner_build") or ""),
        "policy_version": str(identity.get("policy_version") or ""),
        "ruleset_version": str(identity.get("ruleset_version") or ""),
    }


def _read_json(path: Path | str) -> tuple[bytes, dict[str, Any]]:
    raw = Path(path).read_bytes()
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object: {path}")
    return raw, value


def _object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _number(value: Any) -> int | float:
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else -1


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the publication accuracy gate from regression and fresh holdout evidence.")
    parser.add_argument("--regression-gate", required=True, type=Path)
    parser.add_argument("--holdout-gate", required=True, type=Path)
    parser.add_argument("--holdout-corpus", required=True, type=Path)
    parser.add_argument("--out", "--output", required=True, type=Path)
    args = parser.parse_args()
    result = build_publication_accuracy_gate(args.regression_gate, args.holdout_gate, args.holdout_corpus)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.out), "status": "fresh-labeled", "holdout": result["holdout"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
