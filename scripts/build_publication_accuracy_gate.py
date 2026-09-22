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
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
BUILD_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
LABELS = {"known_safe", "known_malicious"}
VERDICTS = {"clean", "review", "suspicious", "malicious"}
DECISIONS = {"allow", "review", "block"}
REQUIRED_GATE_CHECKS = {
    "required_pass_rate",
    "safe_block_rate",
    "safe_review_rate",
    "malicious_allow_rate",
    "incomplete_required",
}
LABEL_EVIDENCE_SOURCE_TYPES = {
    "independent_adjudication",
    "independent_review",
    "independent_threat_report",
    "independent_hash_report_and_official_release",
    "maintainer_advisory_and_independent_hash_report",
    "trusted_threat_feed_and_independent_hash_report",
    "malware_removal_and_independent_hash_report",
}
SAFE_LABEL_EVIDENCE_SOURCE_TYPES = {
    "independent_adjudication",
    "independent_review",
    "independent_hash_report_and_official_release",
}
MALICIOUS_LABEL_EVIDENCE_SOURCE_TYPES = {
    "independent_adjudication",
    "independent_threat_report",
    "maintainer_advisory_and_independent_hash_report",
    "trusted_threat_feed_and_independent_hash_report",
    "malware_removal_and_independent_hash_report",
}
# A two-artifact holdout can only catch a catastrophic regression.  Public
# classification needs a small, independently labelled sample on both sides
# before it is allowed to represent ecosystem accuracy.
MIN_FRESH_HOLDOUT_SAFE = 5
MIN_FRESH_HOLDOUT_MALICIOUS = 5
# The public contract distinguishes non-executable packages from packages that
# require capability-gated execution. A holdout that exercises only one side
# cannot validate that distinction before a large registry rollout.
MIN_DYNAMIC_REQUIRED = 1
MIN_DYNAMIC_NOT_APPLICABLE = 1
MAX_SAFE_REVIEW_RATE = 0.2


def build_publication_accuracy_gate(
    regression_gate_path: Path | str,
    holdout_gate_path: Path | str,
    holdout_corpus_path: Path | str,
    behavior_gate_path: Path | str | None = None,
) -> dict[str, Any]:
    regression_bytes, regression = _read_json(regression_gate_path)
    holdout_bytes, holdout_gate = _read_json(holdout_gate_path)
    corpus_bytes, holdout_corpus = _read_json(holdout_corpus_path)
    behavior_bytes: bytes | None = None
    behavior_gate: dict[str, Any] | None = None
    if behavior_gate_path is not None:
        behavior_bytes, behavior_gate = _read_json(behavior_gate_path)

    _validate_gate(regression, "regression")
    _validate_gate(holdout_gate, "holdout")
    _validate_holdout_corpus(holdout_corpus)
    runtime_evidence = _object(holdout_gate.get("runtime_evidence"))
    if (
        runtime_evidence.get("required") is not True
        or runtime_evidence.get("runtime_enabled") is not True
        or str(runtime_evidence.get("profile") or "") != "deep"
        or runtime_evidence.get("external_syscall_trace") is not True
    ):
        raise ValueError("Publication holdout must prove a required deep runtime scan with external syscall tracing")

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
    if (
        _number(summary.get("safe_evaluated")) < MIN_FRESH_HOLDOUT_SAFE
        or _number(summary.get("malicious_evaluated")) < MIN_FRESH_HOLDOUT_MALICIOUS
    ):
        raise ValueError(
            "The publication holdout must contain at least "
            f"{MIN_FRESH_HOLDOUT_SAFE} known-safe and "
            f"{MIN_FRESH_HOLDOUT_MALICIOUS} known-malicious artifacts."
        )
    if _number(summary.get("dynamic_required")) < MIN_DYNAMIC_REQUIRED or _number(summary.get("dynamic_not_applicable")) < MIN_DYNAMIC_NOT_APPLICABLE:
        raise ValueError("Publication holdout must include both executable-capability and explicit runtime-not-applicable artifacts.")
    label_counts = {
        "known_safe": sum(1 for artifact in artifacts if artifact.get("label") == "known_safe"),
        "known_malicious": sum(1 for artifact in artifacts if artifact.get("label") == "known_malicious"),
    }
    corpus_provenance = _validate_holdout_provenance_metadata(holdout_corpus, label_counts)
    if (
        _number(summary.get("safe_evaluated")) != label_counts["known_safe"]
        or _number(summary.get("malicious_evaluated")) != label_counts["known_malicious"]
    ):
        raise ValueError("The publication holdout summary label counts do not match the frozen corpus.")
    holdout_summary = _validate_holdout_results(holdout_gate, artifacts)
    for key, expected_value in holdout_summary.items():
        if summary.get(key) != expected_value:
            raise ValueError(f"The publication holdout summary field {key!r} does not match its result rows")
    holdout_rule_matrix = _holdout_rule_matrix(holdout_gate, artifacts)
    _validate_rule_matrix(holdout_rule_matrix, label_counts)

    behavior_result: dict[str, Any] | None = None
    if behavior_gate is not None:
        _validate_gate(behavior_gate, "behavior-only")
        if behavior_gate.get("classification_mode") != "behavior-only":
            raise ValueError("Behavior-only gate must declare classification_mode behavior-only")
        behavior_identity = _identity(behavior_gate)
        if behavior_identity != regression_identity:
            raise ValueError("Behavior-only and primary gates do not share one scanner, policy, and ruleset identity.")
        if str(behavior_gate.get("corpus_id") or "") != corpus_id or str(behavior_gate.get("corpus_version") or "") != corpus_version:
            raise ValueError("Behavior-only gate does not match the frozen holdout corpus.")
        behavior_runtime = _object(behavior_gate.get("runtime_evidence"))
        if (
            behavior_runtime.get("required") is not True
            or behavior_runtime.get("runtime_enabled") is not True
            or str(behavior_runtime.get("profile") or "") != "deep"
            or behavior_runtime.get("external_syscall_trace") is not True
        ):
            raise ValueError("Behavior-only holdout must prove a required deep runtime scan with external syscall tracing")
        behavior_snapshot = _object(behavior_gate.get("advisory_snapshot"))
        if (
            behavior_snapshot.get("status") != "completed"
            or behavior_snapshot.get("entry_count") != 0
            or not SHA256_RE.fullmatch(str(behavior_snapshot.get("sha256") or ""))
        ):
            raise ValueError("Behavior-only holdout must prove a completed empty advisory snapshot")
        behavior_summary = _validate_holdout_results(
            behavior_gate,
            artifacts,
            require_malicious_block=False,
        )
        behavior_gate_summary = _object(behavior_gate.get("summary"))
        for key, expected_value in behavior_summary.items():
            if behavior_gate_summary.get(key) != expected_value:
                raise ValueError(f"The behavior-only holdout summary field {key!r} does not match its result rows")
        behavior_rule_matrix = _holdout_rule_matrix(behavior_gate, artifacts)
        _validate_rule_matrix(behavior_rule_matrix, label_counts)
        behavior_result = {
            "status": "behavior-only",
            "complete": True,
            "scanner_build": behavior_identity["scanner_build"],
            "policy_version": behavior_identity["policy_version"],
            "ruleset_version": behavior_identity["ruleset_version"],
            "required_pass_rate": behavior_summary["required_pass_rate"],
            "safe_evaluated": behavior_summary["safe_evaluated"],
            "safe_block_rate": behavior_summary["safe_block_rate"],
            "safe_review_rate": behavior_summary["safe_review_rate"],
            "malicious_evaluated": behavior_summary["malicious_evaluated"],
            "malicious_allow_rate": behavior_summary["malicious_allow_rate"],
            "malicious_detection_rate": behavior_summary["malicious_detection_rate"],
            "malicious_block_rate": behavior_summary["malicious_block_rate"],
            "dynamic_required": _number(behavior_gate_summary.get("dynamic_required")),
            "dynamic_not_applicable": _number(behavior_gate_summary.get("dynamic_not_applicable")),
            "rule_matrix": behavior_rule_matrix,
            "runtime_evidence": dict(behavior_runtime),
            "advisory_snapshot": dict(behavior_snapshot),
        }

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
            "label_counts": label_counts,
            "required_pass_rate": _number(summary.get("required_pass_rate")),
            "safe_block_rate": _number(summary.get("safe_block_rate")),
            "safe_reviewed": _number(summary.get("safe_reviewed")),
            "safe_review_rate": _number(summary.get("safe_review_rate")),
            "max_safe_review_rate": MAX_SAFE_REVIEW_RATE,
            "malicious_allow_rate": _number(summary.get("malicious_allow_rate")),
            "malicious_blocked": _number(summary.get("malicious_blocked")),
            "malicious_block_rate": _number(summary.get("malicious_block_rate")),
            "malicious_reviewed": _number(summary.get("malicious_reviewed")),
            "malicious_review_rate": _number(summary.get("malicious_review_rate")),
            "malicious_detected": _number(summary.get("malicious_detected")),
            "malicious_detection_rate": _number(summary.get("malicious_detection_rate")),
            "dynamic_required": _number(summary.get("dynamic_required")),
            "dynamic_not_applicable": _number(summary.get("dynamic_not_applicable")),
            "rule_matrix": holdout_rule_matrix,
            "runtime_evidence": dict(runtime_evidence),
            "gate": dict(_object(holdout_gate.get("gate"))),
            "provenance": corpus_provenance,
            **({"behavior_only": behavior_result} if behavior_result is not None else {}),
        },
        "provenance": {
            "regression_gate_sha256": _sha256(regression_bytes),
            "holdout_gate_sha256": _sha256(holdout_bytes),
            "holdout_corpus_sha256": _sha256(corpus_bytes),
            **({"behavior_gate_sha256": _sha256(behavior_bytes)} if behavior_bytes is not None else {}),
        },
    }


def _validate_gate(gate: dict[str, Any], name: str) -> None:
    if str(gate.get("schema_version") or "") != "1.0":
        raise ValueError(f"{name} gate schema_version must be 1.0")
    if _object(gate.get("gate")).get("passed") is not True:
        raise ValueError(f"{name} gate did not pass")
    checks = _object(gate.get("gate")).get("checks")
    if (
        not isinstance(checks, dict)
        or not REQUIRED_GATE_CHECKS.issubset(checks)
        or any(value is not True for value in checks.values())
    ):
        raise ValueError(f"{name} gate contains a failed or missing check")
    identity = _identity(gate)
    if not BUILD_RE.fullmatch(identity["scanner_build"]):
        raise ValueError(f"{name} gate requires a full 40-character scanner build")
    summary = _object(gate.get("summary"))
    for key in ("required_pass_rate", "safe_block_rate", "safe_review_rate", "malicious_allow_rate"):
        value = summary.get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1:
            raise ValueError(f"{name} gate summary {key} must be a number between 0 and 1")
    for key in ("required_artifacts", "required_passed", "required_failed", "incomplete_required"):
        value = summary.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"{name} gate summary {key} must be a non-negative integer")
    if summary["required_artifacts"] < 1 or summary["required_passed"] != summary["required_artifacts"] or summary["required_failed"] != 0:
        raise ValueError(f"{name} gate required artifacts are incomplete")
    if summary["incomplete_required"] != 0:
        raise ValueError(f"{name} gate contains incomplete required artifacts")
    if summary["required_pass_rate"] < 1:
        raise ValueError(f"{name} gate required pass rate is below 100 percent")
    if summary["safe_block_rate"] > 0 or summary["malicious_allow_rate"] > 0:
        raise ValueError(f"{name} gate contains a safe block or malicious allow")
    if summary["safe_review_rate"] > MAX_SAFE_REVIEW_RATE:
        raise ValueError(f"{name} gate safe review rate exceeds the {MAX_SAFE_REVIEW_RATE:.0%} noise ceiling")


def _validate_holdout_corpus(corpus: dict[str, Any]) -> None:
    if corpus.get("schema_version") != "1.0":
        raise ValueError("Holdout corpus schema_version must be 1.0")
    if not str(corpus.get("corpus_id") or "").strip():
        raise ValueError("Holdout corpus requires a corpus_id")
    metadata = _object(corpus.get("holdout"))
    if metadata.get("status") != "fresh-labeled" or metadata.get("frozen_before_scan") is not True:
        raise ValueError("Holdout corpus must be frozen and labelled before scanning")
    frozen_at = _parse_timestamp(metadata.get("frozen_at"), "Holdout corpus frozen_at")
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
        identity = _object(artifact.get("artifact"))
        _validate_label_evidence(
            artifact.get("label_evidence"),
            index,
            str(artifact.get("label") or ""),
            extension_id=key[0],
            version=key[1],
            artifact_sha256=str(identity.get("sha256") or ""),
        )
        evidence_at = _parse_timestamp(
            _object(artifact.get("label_evidence")).get("retrieved_at"),
            f"Holdout artifact {index} label evidence retrieved_at",
        )
        if evidence_at > frozen_at:
            raise ValueError(f"Holdout artifact {index} label evidence was retrieved after the holdout was frozen")
        source_type = str(identity.get("source_type") or "")
        if source_type == "fixture_directory" or not source_type:
            raise ValueError(f"Holdout artifact {index} cannot use a synthetic fixture source")
        if identity.get("original_bytes_available") is not True or not SHA256_RE.fullmatch(str(identity.get("sha256") or "")):
            raise ValueError(f"Holdout artifact {index} requires retained exact bytes and a SHA-256")


def _validate_holdout_provenance_metadata(
    corpus: dict[str, Any],
    label_counts: dict[str, int],
) -> dict[str, Any]:
    metadata = _object(corpus.get("holdout"))
    provenance = _object(metadata.get("provenance"))
    for field in ("source_sha256", "advisory_snapshot_sha256"):
        if not SHA256_RE.fullmatch(str(provenance.get(field) or "")):
            raise ValueError(f"Holdout corpus provenance requires a valid {field}")
    if not str(provenance.get("advisory_snapshot_version") or "").strip():
        raise ValueError("Holdout corpus provenance requires advisory_snapshot_version")
    matched = provenance.get("malicious_artifacts_with_exact_advisories")
    if isinstance(matched, bool) or not isinstance(matched, int) or matched != label_counts["known_malicious"]:
        raise ValueError("Holdout corpus provenance must tie every malicious label to an exact advisory")
    return {
        "source_sha256": str(provenance["source_sha256"]).lower(),
        "advisory_snapshot_sha256": str(provenance["advisory_snapshot_sha256"]).lower(),
        "advisory_snapshot_version": str(provenance["advisory_snapshot_version"]),
        "malicious_artifacts_with_exact_advisories": matched,
    }


def _validate_label_evidence(
    value: Any,
    index: int,
    label: str | None = None,
    *,
    extension_id: str | None = None,
    version: str | None = None,
    artifact_sha256: str | None = None,
) -> None:
    """Require auditable evidence instead of an operator-written label claim."""
    if not isinstance(value, dict):
        raise ValueError(f"Holdout artifact {index} requires structured label evidence")
    source_type = str(value.get("source_type") or "").strip()
    source_url = str(value.get("source_url") or "").strip()
    retrieved_at = str(value.get("retrieved_at") or "").strip()
    evidence_sha256 = str(value.get("artifact_sha256") or "").strip().lower()
    evidence_scope = str(value.get("evidence_scope") or "").strip()
    asserted_extension_id = str(value.get("extension_id") or "").strip()
    asserted_version = str(value.get("version") or "").strip()
    if not source_type or not source_url or not retrieved_at:
        raise ValueError(f"Holdout artifact {index} label evidence requires source_type, source_url, and retrieved_at")
    if evidence_scope != "exact-artifact":
        raise ValueError(f"Holdout artifact {index} label evidence must use evidence_scope exact-artifact")
    if not SHA256_RE.fullmatch(evidence_sha256):
        raise ValueError(f"Holdout artifact {index} label evidence requires the exact artifact SHA-256")
    if extension_id is not None and asserted_extension_id.lower() != str(extension_id).strip().lower():
        raise ValueError(f"Holdout artifact {index} label evidence extension_id does not match the frozen artifact")
    if version is not None and asserted_version != str(version).strip():
        raise ValueError(f"Holdout artifact {index} label evidence version does not match the frozen artifact")
    if artifact_sha256 is not None and evidence_sha256 != str(artifact_sha256).strip().lower():
        raise ValueError(f"Holdout artifact {index} label evidence SHA-256 does not match the frozen artifact")
    if label == "known_malicious" and not str(value.get("advisory_id") or "").strip():
        raise ValueError(f"Holdout artifact {index} known_malicious evidence requires advisory_id")
    if source_type not in LABEL_EVIDENCE_SOURCE_TYPES:
        raise ValueError(
            f"Holdout artifact {index} label evidence requires an approved independent source_type"
        )
    if label == "known_safe" and source_type not in SAFE_LABEL_EVIDENCE_SOURCE_TYPES:
        raise ValueError(f"Holdout artifact {index} known_safe label requires independent safety evidence")
    if label == "known_malicious" and source_type not in MALICIOUS_LABEL_EVIDENCE_SOURCE_TYPES:
        raise ValueError(f"Holdout artifact {index} known_malicious label requires threat evidence")
    parsed = urlparse(source_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError(f"Holdout artifact {index} label evidence requires a public HTTPS source URL")
    if parsed.port not in (None, 443):
        raise ValueError(f"Holdout artifact {index} label evidence URL must use the standard HTTPS port")
    try:
        datetime.fromisoformat(retrieved_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Holdout artifact {index} label evidence retrieved_at must be ISO-8601") from exc


def _parse_timestamp(value: Any, label: str) -> datetime:
    text = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include an explicit timezone")
    return parsed


def _validate_holdout_results(
    gate: dict[str, Any],
    corpus_artifacts: list[dict[str, Any]],
    *,
    require_malicious_block: bool = True,
) -> dict[str, int | float]:
    results = gate.get("artifacts")
    if not isinstance(results, list) or len(results) != len(corpus_artifacts):
        raise ValueError("The holdout gate must retain one result row for every frozen artifact.")
    expected = {
        (str(item.get("extension_id") or "").lower(), str(item.get("version") or "")): item
        for item in corpus_artifacts
    }
    seen: set[tuple[str, str]] = set()
    safe_evaluated = 0
    safe_blocks = 0
    safe_reviewed = 0
    malicious_evaluated = 0
    malicious_allows = 0
    malicious_blocked = 0
    malicious_reviewed = 0
    malicious_detected = 0
    dynamic_required = 0
    dynamic_not_applicable = 0
    required_passed = 0
    for index, result in enumerate(results):
        if not isinstance(result, dict):
            raise ValueError(f"Holdout gate result {index} is not an object")
        key = (str(result.get("extension_id") or "").lower(), str(result.get("version") or ""))
        if key not in expected or key in seen:
            raise ValueError(f"Holdout gate result {index} has an unexpected or duplicate artifact identity")
        seen.add(key)
        artifact = expected[key]
        if (
            result.get("label") != artifact.get("label")
            or result.get("gate_required") is not True
            or result.get("scanned") is not True
            or result.get("passed") is not True
            or result.get("gate_passed") is not True
        ):
            raise ValueError(f"Holdout gate result {index} does not preserve the frozen label")
        actual = _object(result.get("actual"))
        if actual.get("analysis_status") != "complete":
            raise ValueError(f"Holdout artifact {key[0]}@{key[1]} was not completely analyzed")
        verdict = str(actual.get("verdict") or "")
        decision = str(actual.get("decision") or "")
        if verdict not in VERDICTS or decision not in {"allow", "review", "block"}:
            raise ValueError(f"Holdout artifact {key[0]}@{key[1]} is missing a valid verdict and decision")
        runtime_errors = _runtime_contract_errors(_object(actual.get("runtime_contract")))
        if runtime_errors:
            raise ValueError(
                f"Holdout artifact {key[0]}@{key[1]} has incomplete runtime coverage: "
                + "; ".join(runtime_errors)
            )
        runtime_contract = _object(actual.get("runtime_contract"))
        if runtime_contract.get("required") is True:
            dynamic_required += 1
        elif runtime_contract.get("required") is False:
            dynamic_not_applicable += 1
        if artifact.get("label") == "known_safe":
            safe_evaluated += 1
            if _review_or_higher(actual):
                safe_reviewed += 1
            if decision == "block" or verdict == "malicious":
                safe_blocks += 1
                raise ValueError(f"Known-safe holdout artifact {key[0]}@{key[1]} was blocked or classified malicious")
        else:
            malicious_evaluated += 1
            if decision == "allow" or verdict == "clean":
                malicious_allows += 1
            if decision == "block":
                malicious_blocked += 1
            if decision == "review":
                malicious_reviewed += 1
            if _review_or_higher(actual):
                malicious_detected += 1
            if verdict not in {"suspicious", "malicious"}:
                raise ValueError(f"Known-malicious holdout artifact {key[0]}@{key[1]} lacks a risk verdict")
            if require_malicious_block and decision != "block":
                raise ValueError(f"Known-malicious holdout artifact {key[0]}@{key[1]} was not blocked with a risk verdict")
        expected_sha256 = str(_object(artifact.get("artifact")).get("sha256") or "").lower()
        if str(actual.get("artifact_sha256") or "").lower() != expected_sha256:
            raise ValueError(f"Holdout artifact {key[0]}@{key[1]} does not retain the scanned artifact hash")
        required_passed += 1

    total = len(corpus_artifacts)
    return {
        "total_artifacts": total,
        "scanned_artifacts": total,
        "not_scanned": 0,
        "required_artifacts": total,
        "required_passed": required_passed,
        "required_failed": total - required_passed,
        "required_pass_rate": round(required_passed / total, 4) if total else 0.0,
        "safe_evaluated": safe_evaluated,
        "safe_blocks": safe_blocks,
        "safe_block_rate": round(safe_blocks / safe_evaluated, 4) if safe_evaluated else 0.0,
        "safe_reviewed": safe_reviewed,
        "safe_review_rate": round(safe_reviewed / safe_evaluated, 4) if safe_evaluated else 0.0,
        "malicious_evaluated": malicious_evaluated,
        "malicious_allows": malicious_allows,
        "malicious_allow_rate": round(malicious_allows / malicious_evaluated, 4) if malicious_evaluated else 0.0,
        "malicious_blocked": malicious_blocked,
        "malicious_block_rate": round(malicious_blocked / malicious_evaluated, 4) if malicious_evaluated else 0.0,
        "malicious_reviewed": malicious_reviewed,
        "malicious_review_rate": round(malicious_reviewed / malicious_evaluated, 4) if malicious_evaluated else 0.0,
        "malicious_detected": malicious_detected,
        "malicious_detection_rate": round(malicious_detected / malicious_evaluated, 4) if malicious_evaluated else 0.0,
        "dynamic_required": dynamic_required,
        "dynamic_not_applicable": dynamic_not_applicable,
        "incomplete_required": 0,
    }


def _holdout_rule_matrix(gate: dict[str, Any], corpus_artifacts: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    """Recompute per-rule labelled fire counts from retained holdout rows."""
    labels = {
        (str(item.get("extension_id") or "").lower(), str(item.get("version") or "")): str(item.get("label") or "")
        for item in corpus_artifacts
    }
    matrix: dict[str, dict[str, int]] = {}
    for result in gate.get("artifacts") or []:
        if not isinstance(result, dict):
            continue
        key = (str(result.get("extension_id") or "").lower(), str(result.get("version") or ""))
        label = labels.get(key)
        actual = result.get("actual") if isinstance(result.get("actual"), dict) else {}
        if not label or actual.get("analysis_status") != "complete":
            continue
        for rule_id in actual.get("rule_ids") or []:
            if not isinstance(rule_id, str) or not rule_id:
                continue
            cell = matrix.setdefault(rule_id, {"fired_on_known_safe": 0, "fired_on_known_malicious": 0})
            cell[f"fired_on_{label}"] += 1
    return dict(sorted(matrix.items()))


def _validate_rule_matrix(matrix: dict[str, dict[str, int]], label_counts: dict[str, int]) -> None:
    """Require auditable per-rule evidence for the public accuracy claim."""
    if not matrix:
        raise ValueError("The publication holdout must retain at least one labelled rule firing")
    for rule_id, counts in matrix.items():
        if not isinstance(rule_id, str) or not rule_id.strip() or not isinstance(counts, dict):
            raise ValueError("The publication holdout rule matrix contains an invalid rule row")
        for label in LABELS:
            value = counts.get(f"fired_on_{label}")
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"The publication holdout rule matrix has an invalid {label} count")
            if value > label_counts[label]:
                raise ValueError(f"The publication holdout rule matrix overcounts {label} artifacts")
        if set(counts) != {"fired_on_known_safe", "fired_on_known_malicious"}:
            raise ValueError("The publication holdout rule matrix contains unexpected fields")


def _review_or_higher(actual: dict[str, Any]) -> bool:
    return (
        str(actual.get("decision") or "") in {"review", "block"}
        or str(actual.get("verdict") or "") in {"review", "suspicious", "malicious"}
    )


def _runtime_contract_errors(contract: dict[str, Any]) -> list[str]:
    if contract.get("coverage_status") != "complete" or contract.get("required_providers_complete") is not True:
        return ["required analysis coverage is not complete"]
    if not isinstance(contract.get("required"), bool):
        return ["required is not boolean"]
    if contract["required"]:
        expected = {
            "provider_status": "completed",
            "execution": "controlled-bubblewrap",
            "runtime_policy": "capability-gated-v1",
            "executed": True,
            "external_syscall_trace": True,
        }
    else:
        expected = {
            "provider_status": "not-applicable",
            "execution": "policy-gated",
            "runtime_policy": "capability-gated-v1",
            "executed": False,
            "external_syscall_trace": False,
        }
    return [
        f"{field}={contract.get(field)!r} expected {value!r}"
        for field, value in expected.items()
        if contract.get(field) != value
    ]


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
    parser.add_argument("--behavior-gate", required=True, type=Path)
    parser.add_argument("--holdout-corpus", required=True, type=Path)
    parser.add_argument("--out", "--output", required=True, type=Path)
    args = parser.parse_args()
    result = build_publication_accuracy_gate(
        args.regression_gate,
        args.holdout_gate,
        args.holdout_corpus,
        args.behavior_gate,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.out), "status": "fresh-labeled", "holdout": result["holdout"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
