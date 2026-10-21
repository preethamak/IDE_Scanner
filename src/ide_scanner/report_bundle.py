from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import re
import zipfile
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .build_identity import scanner_build
from .classification_policy import effective_finding_severity, finding_actionability, finding_evidence_class
from .evidence import location_from_finding
from .jsonc import loads_jsonc
from .models import ExtensionDetail, ExtensionReport, ExtensionSummary, Recommendation, ReportMetadata
from .rule_registry import rules_json

SCHEMA_VERSION = "2.3"


def build_report_bundle(
    report: dict[str, Any],
    *,
    profile: str = "smart",
    source: str = "unknown",
    include_raw_evidence: bool = False,
) -> dict[str, Any]:
    extensions = [_extension_from_dict(item) for item in report.get("extensions") or [] if isinstance(item, dict)]
    metadata = _metadata(report, extensions, profile=profile, source=source)
    summaries = [_to_summary(extension) for extension in extensions]
    details = [
        _to_detail(
            extension,
            include_raw_evidence=include_raw_evidence,
            policy_version=metadata.policy_version,
        )
        for extension in extensions
    ]
    return {
        "metadata": metadata.to_dict(),
        "summary": _summary(report, extensions, summaries),
        "leaderboard": {"extensions": [summary.to_dict() for summary in _rank_summaries(summaries)]},
        "posture": {
            "posture_summary": report.get("posture_summary") or {},
            "posture": report.get("posture") or [],
        },
        "rules": rules_json(),
        "extensions": {
            summary.detail_ref: detail.to_dict()
            for summary, detail in zip(summaries, details, strict=True)
        },
    }


def write_report_bundle(
    report: dict[str, Any],
    output: Path | str,
    *,
    profile: str = "smart",
    source: str = "unknown",
    include_raw_evidence: bool = False,
    signing_key: Path | str | None = None,
    signing_key_id: str | None = None,
) -> dict[str, Any]:
    bundle = build_report_bundle(
        report,
        profile=profile,
        source=source,
        include_raw_evidence=include_raw_evidence,
    )
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    members = _bundle_members(bundle)
    integrity_payload = _json_bytes(_integrity_manifest(members))
    provenance = _signed_provenance(integrity_payload, signing_key, signing_key_id) if signing_key else None
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in members.items():
            archive.writestr(name, payload)
        archive.writestr("integrity.json", integrity_payload)
        if provenance:
            archive.writestr("provenance.json", _json_bytes(provenance))
    receipt = {
        "output": str(output_path),
        "metadata": bundle["metadata"],
        "summary": bundle["summary"]["summary"],
    }
    if provenance:
        receipt["provenance"] = {
            "signed": True,
            "signing_key_id": provenance["signing_key_id"],
            "public_key_fingerprint": provenance["public_key_fingerprint"],
        }
    return receipt


def verify_report_bundle(
    path: Path | str,
    *,
    public_key: Path | str | None = None,
    expected_key_id: str | None = None,
    require_signature: bool = False,
) -> dict[str, Any]:
    """Verify a bundle's internal member hashes.

    This checks accidental or transit tampering inside a report ZIP. It does
    not authenticate the publisher of the archive; use a signed provenance
    layer when that trust boundary is required.
    """
    bundle_path = Path(path)
    try:
        with zipfile.ZipFile(bundle_path) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise ValueError("Report bundle contains duplicate member names.")
            if "integrity.json" not in names:
                raise ValueError("Report bundle has no integrity manifest.")
            try:
                manifest = json.loads(archive.read("integrity.json"))
            except (KeyError, json.JSONDecodeError) as exc:
                raise ValueError("Report bundle integrity manifest is invalid.") from exc
            if not isinstance(manifest, dict) or manifest.get("schema_version") != "guardrails.report-integrity.v1":
                raise ValueError("Report bundle integrity schema is unsupported.")
            files = manifest.get("files")
            if not isinstance(files, dict) or not files:
                raise ValueError("Report bundle integrity manifest has no files.")
            expected = set(files)
            actual = set(names) - {"integrity.json", "provenance.json"}
            if actual != expected:
                raise ValueError("Report bundle members do not match its integrity manifest.")
            for name, claim in files.items():
                if not isinstance(name, str) or not isinstance(claim, dict):
                    raise ValueError("Report bundle integrity entry is invalid.")
                payload = archive.read(name)
                digest = hashlib.sha256(payload).hexdigest()
                if claim.get("sha256") != digest or claim.get("size_bytes") != len(payload):
                    raise ValueError(f"Report bundle integrity check failed for {name}.")
            provenance = _read_provenance(archive, names)
            authentication = _verify_provenance(
                provenance,
                integrity_payload=archive.read("integrity.json"),
                public_key=public_key,
                expected_key_id=expected_key_id,
                require_signature=require_signature,
            )
    except (OSError, zipfile.BadZipFile) as exc:
        raise ValueError(f"Report bundle could not be read: {exc}") from exc
    result = {
        "valid": True,
        "bundle": str(bundle_path),
        "integrity_schema": "guardrails.report-integrity.v1",
        **authentication,
    }
    return result


def iter_report_events(report: dict[str, Any], *, profile: str = "smart", source: str = "unknown", output: str = ""):
    bundle = build_report_bundle(report, profile=profile, source=source)
    metadata = bundle["metadata"]
    yield {
        "type": "scan_started",
        "scan_id": metadata["scan_id"],
        "profile": metadata["profile"],
        "source": metadata["source"],
        "total_extensions": metadata["total_extensions"],
    }
    for row in bundle["leaderboard"]["extensions"]:
        yield {
            "type": "extension_summary_ready",
            "scan_id": metadata["scan_id"],
            "extension_id": row["extension_id"],
            "risk_score": row["risk_score"],
            "malware_score": row["malware_score"],
            "context_score": row["context_score"],
            "verdict": row["verdict"],
            "verdict_state": row["verdict_state"],
            "verdict_label": row["verdict_label"],
            "decision": row["decision"],
            "decision_reason": row["decision_reason"],
            "coverage_percent": row["coverage_percent"],
            "severity": row["severity"],
            "grade": row["grade"],
            "detail_ref": row["detail_ref"],
        }
        yield {
            "type": "extension_detail_ready",
            "scan_id": metadata["scan_id"],
            "extension_id": row["extension_id"],
            "detail_ref": row["detail_ref"],
        }
    yield {
        "type": "scan_completed",
        "scan_id": metadata["scan_id"],
        "output": output,
        "completed_extensions": metadata["completed_extensions"],
        "incomplete_extensions": metadata["incomplete_extensions"],
    }


def _metadata(report: dict[str, Any], extensions: list[ExtensionReport], *, profile: str, source: str) -> ReportMetadata:
    created_at = str(report.get("created_at") or dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z"))
    scan_id = str(report.get("scan_id") or f"scan_{dt.datetime.now(dt.UTC).strftime('%Y%m%d%H%M%S')}")
    incomplete = sum(1 for extension in extensions if _scan_incomplete(extension))
    return ReportMetadata(
        schema_version=SCHEMA_VERSION,
        scan_id=scan_id,
        created_at=created_at,
        scanner_version=_scanner_version(),
        ruleset_version=str(report.get("ruleset_version") or "legacy"),
        profile=profile,
        source=source,
        total_extensions=len(extensions),
        completed_extensions=len(extensions) - incomplete,
        incomplete_extensions=incomplete,
        scanner_build=str(report.get("scanner_build") or _scanner_build()),
        policy_version=str(report.get("policy_version") or "legacy"),
        intelligence_snapshot=dict(report.get("intelligence")) if isinstance(report.get("intelligence"), dict) else {},
    )


def _summary(
    report: dict[str, Any],
    extensions: list[ExtensionReport],
    summaries: list[ExtensionSummary],
) -> dict[str, Any]:
    verdict_counts = {verdict: 0 for verdict in ("clean", "review", "suspicious", "malicious")}
    severity_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    finding_counts: dict[str, int] = {}
    finding_actionability_counts: dict[str, int] = {}
    evidence_class_counts: dict[str, int] = {}
    decision_counts = {decision: 0 for decision in ("block", "review", "incomplete", "allow")}
    analysis_status_counts: dict[str, int] = {}
    for extension in extensions:
        decision_counts[extension.decision] = decision_counts.get(extension.decision, 0) + 1
        analysis_status = str(extension.analysis_status or "incomplete")
        analysis_status_counts[analysis_status] = analysis_status_counts.get(analysis_status, 0) + 1
        if analysis_status == "complete" and extension.decision != "incomplete":
            verdict_counts[extension.verdict] = verdict_counts.get(extension.verdict, 0) + 1
        severity_counts[extension.severity] = severity_counts.get(extension.severity, 0) + 1
        for finding in extension.findings:
            finding_counts[finding.rule_id] = finding_counts.get(finding.rule_id, 0) + 1
            category_counts[finding.category] = category_counts.get(finding.category, 0) + 1
            actionability = finding_actionability(finding)
            finding_actionability_counts[actionability] = finding_actionability_counts.get(actionability, 0) + 1
            evidence_class = str((finding.evidence or {}).get("evidence_class") or "weak")
            evidence_class_counts[evidence_class] = evidence_class_counts.get(evidence_class, 0) + 1
    posture_summary = report.get("posture_summary") if isinstance(report.get("posture_summary"), dict) else {}
    return {
        "summary": {
            "total_extensions": len(extensions),
            "clean": verdict_counts.get("clean", 0),
            "review": verdict_counts.get("review", 0),
            "suspicious": verdict_counts.get("suspicious", 0),
            "malicious": verdict_counts.get("malicious", 0),
            "max_risk_score": max((extension.risk_score for extension in extensions), default=0),
            "max_malware_score": max((extension.malware_score for extension in extensions), default=0),
            "max_context_score": max((_context_score(extension) for extension in extensions), default=0),
            "posture_status": posture_summary.get("status", "skipped"),
            "decision_counts": decision_counts,
            "analysis_status_counts": analysis_status_counts,
            "incomplete": decision_counts.get("incomplete", 0),
        },
        "top_risk_extensions": [summary.to_dict() for summary in _rank_summaries(summaries)[:10]],
        "finding_counts": _sorted_counts(finding_counts),
        "finding_actionability_counts": _sorted_counts(finding_actionability_counts),
        "severity_counts": _sorted_counts(severity_counts),
        "category_counts": _sorted_counts(category_counts),
        "evidence_class_counts": _sorted_counts(evidence_class_counts),
        "version_deltas": list(report.get("version_deltas") or []),
    }


def _to_summary(extension: ExtensionReport) -> ExtensionSummary:
    ranked_findings = _rank_findings(extension.findings)
    actionability_counts = {
        "block": sum(1 for finding in extension.findings if finding_actionability(finding) == "block"),
        "review": sum(1 for finding in extension.findings if finding_actionability(finding) in {"review", "investigate"}),
        "low": sum(1 for finding in extension.findings if finding_actionability(finding) == "low"),
        "contextual": sum(1 for finding in extension.findings if finding_actionability(finding) == "contextual"),
    }
    headline_findings = [
        finding for finding in ranked_findings
        if finding_actionability(finding) in {"block", "review", "low"}
    ]
    return ExtensionSummary(
        extension_id=extension.extension_id,
        name=extension.name,
        publisher=extension.publisher,
        version=extension.version,
        source=extension.source,
        verdict=extension.verdict,
        severity=extension.severity,
        risk_score=extension.risk_score,
        malware_score=extension.malware_score,
        context_score=_context_score(extension),
        grade=grade_extension(extension.verdict, extension.risk_score, extension.malware_score, extension.findings),
        verdict_state=_verdict_state(extension),
        verdict_label=_verdict_label(extension),
        # Context-only capability and posture signals remain in the exact
        # detail report, but headline evidence must not present them as
        # security alerts when no action is required.
        top_findings=[finding.rule_id for finding in headline_findings[:5]],
        finding_count=len(extension.findings),
        actionable_finding_count=actionability_counts["block"] + actionability_counts["review"],
        low_finding_count=actionability_counts["low"],
        contextual_finding_count=actionability_counts["contextual"],
        dependency_count=len(extension.dependencies),
        activation_summary=_activation_summary(extension),
        detail_ref=f"extensions/{_safe_detail_name(extension.extension_id, extension.version)}.json",
        icon_ref="",
        from_cache=bool(getattr(extension, "from_cache", False)),
        scan_incomplete=_scan_incomplete(extension),
        skipped_reason=_skipped_reason(extension),
        decision=extension.decision,
        decision_reason=extension.decision_reason,
        public_outcome=extension.public_outcome,
        decision_basis=extension.decision_basis,
        evidence_confidence=extension.evidence_confidence,
        provenance=dict(extension.provenance),
        capability_assessment=dict(extension.capability_assessment),
        score_schema_version=extension.score_schema_version,
        artifact_sha256=str(extension.artifact_identity.get("sha256") or extension.artifact_hash),
        coverage_percent=int(extension.analysis_coverage.get("coverage_percent") or 0),
        analysis_status=extension.analysis_status,
        baseline_changed=bool(extension.baseline_diff.get("baseline_changed")),
        trust_tier=extension.trust_tier,
        trust_tier_label=extension.trust_tier_label,
        trust_tier_reason=extension.trust_tier_reason,
    )


def _to_detail(
    extension: ExtensionReport,
    *,
    include_raw_evidence: bool,
    policy_version: str,
) -> ExtensionDetail:
    evidence_store: dict[str, Any] = {}
    findings: list[dict[str, Any]] = []
    for finding in _rank_findings(extension.findings):
        finding_data = finding.to_dict()
        evidence_id = _evidence_id(finding_data)
        evidence_store[evidence_id] = _evidence_record(finding_data, include_raw_evidence=include_raw_evidence)
        finding_data["evidence_refs"] = [evidence_id]
        finding_data["evidence_class"] = _finding_evidence_class(finding)
        if policy_version == "legacy":
            finding_data["actionability"] = _legacy_finding_actionability(finding)
            finding_data["effective_severity"] = str(getattr(finding, "severity", "INFO"))
        else:
            finding_data["actionability"] = _finding_actionability(finding)
            finding_data["effective_severity"] = effective_finding_severity(finding)
        if not include_raw_evidence:
            finding_data.pop("evidence", None)
        finding_data["file_refs"] = list(finding_data.get("file_refs") or [])[:5]
        findings.append(finding_data)

    return ExtensionDetail(
        extension_id=extension.extension_id,
        name=extension.name,
        publisher=extension.publisher,
        version=extension.version,
        description=extension.description,
        repository=extension.repository,
        source=extension.source,
        verdict=extension.verdict,
        severity=extension.severity,
        risk_score=extension.risk_score,
        malware_score=extension.malware_score,
        context_score=_context_score(extension),
        grade=grade_extension(extension.verdict, extension.risk_score, extension.malware_score, extension.findings),
        verdict_state=_verdict_state(extension),
        verdict_label=_verdict_label(extension),
        score_details=extension.score_details,
        score_explanation=_score_explanation(extension),
        verdict_reason=extension.verdict_reason,
        recommendations=_recommendations(extension),
        findings=findings,
        evidence=evidence_store,
        manifest=_manifest(extension),
        dependencies=dict(list(extension.dependencies.items())[:200]),
        dependency_inventory=list(extension.artifact_inventory.get("dependency_inventory") or [])[:1000],
        artifact_inventory=dict(extension.artifact_inventory),
        security_dimensions=_security_dimensions(extension),
        capabilities={str(item.get("id") or index): item for index, item in enumerate(extension.capabilities) if isinstance(item, dict)},
        from_cache=bool(getattr(extension, "from_cache", False)),
        scan_incomplete=_scan_incomplete(extension),
        skipped_reason=_skipped_reason(extension),
        decision=extension.decision,
        decision_reason=extension.decision_reason,
        public_outcome=extension.public_outcome,
        decision_basis=extension.decision_basis,
        evidence_confidence=extension.evidence_confidence,
        provenance=dict(extension.provenance),
        capability_assessment=dict(extension.capability_assessment),
        score_schema_version=extension.score_schema_version,
        artifact_identity=dict(extension.artifact_identity),
        analysis_coverage=dict(extension.analysis_coverage),
        analysis_status=extension.analysis_status,
        baseline_diff=dict(extension.baseline_diff),
        trust_tier=extension.trust_tier,
        trust_tier_label=extension.trust_tier_label,
        trust_tier_reason=extension.trust_tier_reason,
    )


def grade_extension(verdict: str, risk_score: int, malware_score: int, findings: list[Any] | None = None) -> str:
    # Grades are a user-facing summary.  Use the same actionability policy as
    # verdict classification so a contextual HIGH detector signal cannot make
    # an otherwise reviewable extension look more dangerous in the dashboard.
    has_high_or_medium = any(
        effective_finding_severity(finding) in {"HIGH", "MEDIUM", "CRITICAL"}
        for finding in findings or []
    )
    if verdict == "malicious" or malware_score >= 90:
        return "F"
    if verdict == "suspicious" or risk_score >= 75 or malware_score >= 70:
        return "D"
    if verdict == "review" and has_high_or_medium:
        return "C"
    if verdict == "review":
        return "B"
    if risk_score > 0 or malware_score > 0:
        return "A-"
    return "A"


_DIMENSION_CATEGORIES = {
    "behavior_safety": {"process", "network", "filesystem", "code", "cross-extension-exposure", "agent", "webview"},
    "supply_chain_integrity": {"supply-chain", "registry", "lifecycle", "provenance"},
    "dependency_health": {"dependency", "vulnerability"},
    "artifact_integrity": {"artifact", "obfuscation", "binary", "evasion"},
    "publisher_project_health": {"reputation", "repository-posture", "license"},
}


def _security_dimensions(extension: ExtensionReport) -> dict[str, Any]:
    severity_weight = {"CRITICAL": 30, "HIGH": 18, "MEDIUM": 9, "LOW": 3, "INFO": 0}
    dimensions: dict[str, Any] = {}
    for dimension, categories in _DIMENSION_CATEGORIES.items():
        deductions: list[dict[str, Any]] = []
        score = 100
        for finding in extension.findings:
            if finding.category not in categories:
                continue
            # Dimension scores are user-facing risk summaries. Apply the same
            # evidence policy as verdicts and headlines so a raw HIGH/MEDIUM
            # detector label that is explicitly contextual cannot deduct
            # points from a legitimate extension's security posture.
            effective_severity = effective_finding_severity(finding)
            weight = severity_weight.get(effective_severity, 0)
            evidence_class = str((finding.evidence or {}).get("evidence_class") or "weak")
            if evidence_class in {"weak", "reputation"}:
                weight = max(1 if weight else 0, weight // 2)
            if weight:
                score -= weight
                deductions.append({"rule_id": finding.rule_id, "points": weight, "severity": effective_severity})
        final_score = max(0, score)
        dimensions[dimension] = {
            "score": final_score,
            "status": _dimension_status(final_score),
            "deductions": deductions[:20],
            "basis": "Deterministic evidence deductions; higher is better and is not a probability.",
        }

    coverage = extension.analysis_coverage or {}
    coverage_score = int(coverage.get("coverage_percent") or 0)
    providers = coverage.get("providers") if isinstance(coverage.get("providers"), dict) else {}
    unavailable = [
        name for name, provider in providers.items()
        if isinstance(provider, dict) and str(provider.get("status") or "") not in {"complete", "completed", "available"}
    ]
    dimensions["analysis_confidence"] = {
        "score": coverage_score,
        "status": "unknown" if coverage.get("status") != "complete" else _dimension_status(coverage_score),
        "deductions": [{"provider": name, "reason": "not complete"} for name in unavailable],
        "basis": "Executable coverage and recorded analyzer completion; higher is better.",
    }
    return dimensions


def _dimension_status(score: int) -> str:
    if score >= 90:
        return "strong"
    if score >= 70:
        return "attention"
    return "weak"


def _verdict_label(extension: ExtensionReport) -> str:
    return {
        "safe": "Safe",
        "safe_with_notes": "Safe with notes",
        "needs_review": "Needs review",
        "suspicious": "Suspicious",
        "confirmed_malicious": "Confirmed malicious",
    }[_verdict_state(extension)]


def _verdict_state(extension: ExtensionReport) -> str:
    if extension.verdict == "malicious":
        return "confirmed_malicious"
    if extension.verdict == "suspicious":
        return "suspicious"
    if extension.verdict == "review":
        return "needs_review"
    if _context_score(extension) > 0:
        return "safe_with_notes"
    return "safe"


def _context_score(extension: ExtensionReport) -> int:
    contextual = [finding for finding in extension.findings if _finding_actionability(finding) in {"contextual", "low"}]
    if not contextual:
        return 0
    components = extension.score_details.get("components") if isinstance(extension.score_details, dict) else {}
    reputation = int((components or {}).get("reputation") or 0)
    posture = int((components or {}).get("posture") or 0)
    weak = int((components or {}).get("weak_context") or 0)
    return min(100, max(reputation, posture, weak) + min(40, len(contextual) * 6))


def _finding_actionability(finding: Any) -> str:
    return finding_actionability(finding)


def _legacy_finding_actionability(finding: Any) -> str:
    evidence_class = _finding_evidence_class(finding)
    rule_id = str(getattr(finding, "rule_id", ""))
    severity = str(getattr(finding, "severity", ""))
    if evidence_class == "confirmed":
        return "block"
    if evidence_class in {"correlated", "observed"} and severity in {"HIGH", "CRITICAL"}:
        return "investigate"
    if evidence_class in {"dependency", "provenance", "capability", "posture", "exposure"}:
        if rule_id in {"startup-activation", "repo-url-missing", "security-policy-missing", "license-missing", "repo-maintained"}:
            return "contextual"
        return "review"
    return "contextual"


def _finding_evidence_class(finding: Any) -> str:
    return finding_evidence_class(finding)


def _score_explanation(extension: ExtensionReport) -> list[str]:
    explanations = [extension.verdict_reason]
    for finding in _rank_findings(extension.findings)[:6]:
        explanations.append(finding.evidence_summary)
    return list(dict.fromkeys(item for item in explanations if item))[:8]


def _recommendations(extension: ExtensionReport) -> list[Recommendation]:
    if extension.verdict == "malicious":
        return [Recommendation(
            priority="critical",
            title="Remove or block this extension",
            description=extension.verdict_reason,
            action="Uninstall the extension and investigate affected workspaces.",
        )]
    if extension.verdict == "suspicious":
        return [Recommendation(
            priority="high",
            title="Review extension before continued use",
            description=extension.verdict_reason,
            action="Review source or uninstall if behavior is unexpected.",
        )]
    if extension.verdict == "review":
        return [Recommendation(
            priority="medium",
            title="Review extension risk context",
            description=extension.verdict_reason,
            action="Confirm publisher intent, dependency posture, and requested IDE capabilities.",
        )]
    if extension.findings:
        return [Recommendation(
            priority="low",
            title="Keep monitoring contextual findings",
            description="The scanner found contextual signals that did not change the verdict.",
            action="Re-scan after extension updates or ruleset changes.",
        )]
    return []


def _activation_summary(extension: ExtensionReport) -> str:
    activation = []
    for capability in extension.capabilities:
        if isinstance(capability, dict) and capability.get("id") == "activation":
            activation = [str(item) for item in capability.get("evidence") or []]
            break
    if "*" in activation:
        return "broad activation"
    if "onStartupFinished" in activation:
        return "startup activation"
    if activation:
        return f"{len(activation)} activation event(s)"
    return "no activation events reported"


def _manifest(extension: ExtensionReport) -> dict[str, Any]:
    path = Path(extension.install_path)
    if path.suffix.lower() == ".vsix" or not path.exists() or not path.is_dir():
        return {}
    try:
        parsed = loads_jsonc((path / "package.json").read_text(encoding="utf-8"))
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _evidence_id(finding: dict[str, Any]) -> str:
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    normalized = json.dumps({
        "rule_id": finding.get("rule_id"),
        "file_refs": finding.get("file_refs") or [],
        "summary": finding.get("evidence_summary") or "",
        "evidence": evidence,
    }, sort_keys=True, default=str)
    return "ev_" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def _evidence_record(finding: dict[str, Any], *, include_raw_evidence: bool) -> dict[str, Any]:
    location = location_from_finding(finding)
    record = {
        "file": location["file"],
        "line": location["line"],
        "summary": finding.get("evidence_summary") or "",
        "evidence_class": (finding.get("evidence") or {}).get("evidence_class") if isinstance(finding.get("evidence"), dict) else "weak",
    }
    if include_raw_evidence and isinstance(finding.get("evidence"), dict):
        record["raw"] = finding["evidence"]
    return record


def _rank_findings(findings: list[Any]) -> list[Any]:
    actionability_rank = {"block": 4, "review": 3, "low": 2, "contextual": 1}
    severity_rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    return sorted(findings, key=lambda item: (
        actionability_rank.get(finding_actionability(item), 0),
        severity_rank.get(effective_finding_severity(item), 0),
        finding_evidence_class(item) in {"confirmed", "vulnerability", "correlated"},
        int(getattr(item, "score", 0) or 0),
        float(getattr(item, "confidence", 0) or 0),
        str(getattr(item, "rule_id", "")),
    ), reverse=True)


def _rank_summaries(summaries: list[ExtensionSummary]) -> list[ExtensionSummary]:
    verdict_rank = {"malicious": 4, "suspicious": 3, "review": 2, "clean": 1}
    severity_rank = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    return sorted(summaries, key=lambda item: (
        verdict_rank.get(item.verdict, 0),
        severity_rank.get(item.severity, 0),
        item.malware_score,
        item.risk_score,
        item.extension_id,
    ), reverse=True)


def _extension_from_dict(data: dict[str, Any]) -> ExtensionReport:
    from .models import Finding

    findings = [
        Finding(
            finding_id=str(item.get("finding_id") or ""),
            extension_id=str(item.get("extension_id") or data.get("extension_id") or ""),
            version=str(item.get("version") or data.get("version") or ""),
            rule_id=str(item.get("rule_id") or "unknown"),
            category=str(item.get("category") or "unknown"),
            severity=str(item.get("severity") or "INFO"),  # type: ignore[arg-type]
            confidence=float(item.get("confidence") or 0),
            score=int(item.get("score") or 0),
            evidence_type=str(item.get("evidence_type") or "static"),
            evidence_summary=str(item.get("evidence_summary") or ""),
            file_refs=[str(ref) for ref in item.get("file_refs") or []],
            recommendation=str(item.get("recommendation") or ""),
            evidence=item.get("evidence") if isinstance(item.get("evidence"), dict) else None,
        )
        for item in data.get("findings") or []
        if isinstance(item, dict)
    ]
    return ExtensionReport(
        instance_id=str(data.get("instance_id") or ""),
        extension_id=str(data.get("extension_id") or ""),
        name=str(data.get("name") or ""),
        publisher=str(data.get("publisher") or ""),
        version=str(data.get("version") or ""),
        description=str(data.get("description") or ""),
        repository=str(data.get("repository") or ""),
        install_path=str(data.get("install_path") or ""),
        source=str(data.get("source") or ""),
        artifact_hash=str(data.get("artifact_hash") or ""),
        severity=str(data.get("severity") or "INFO"),  # type: ignore[arg-type]
        verdict=str(data.get("verdict") or "clean"),  # type: ignore[arg-type]
        malware_authority=str(data.get("malware_authority") or "none"),
        verdict_reason=str(data.get("verdict_reason") or ""),
        malware_score=int(data.get("malware_score") or 0),
        risk_score=int(data.get("risk_score") or 0),
        score_details=data.get("score_details") if isinstance(data.get("score_details"), dict) else {},
        capabilities=data.get("capabilities") if isinstance(data.get("capabilities"), list) else [],
        artifact_inventory=data.get("artifact_inventory") if isinstance(data.get("artifact_inventory"), dict) else {},
        findings=findings,
        scanned_files=int(data.get("scanned_files") or 0),
        dependencies=data.get("dependencies") if isinstance(data.get("dependencies"), dict) else {},
        decision=str(data.get("decision") or "incomplete"),  # type: ignore[arg-type]
        decision_reason=str(data.get("decision_reason") or "Analysis has not completed."),
        public_outcome=str(data.get("public_outcome") or "incomplete"),  # type: ignore[arg-type]
        decision_basis=str(data.get("decision_basis") or "incomplete"),
        evidence_confidence=str(data.get("evidence_confidence") or "none"),
        provenance=data.get("provenance") if isinstance(data.get("provenance"), dict) else {},
        capability_assessment=data.get("capability_assessment") if isinstance(data.get("capability_assessment"), dict) else {},
        score_schema_version=str(data.get("score_schema_version") or "1"),
        artifact_identity=data.get("artifact_identity") if isinstance(data.get("artifact_identity"), dict) else {},
        analysis_coverage=data.get("analysis_coverage") if isinstance(data.get("analysis_coverage"), dict) else {},
        analysis_status=_analysis_status_from_dict(data),  # type: ignore[arg-type]
        baseline_diff=data.get("baseline_diff") if isinstance(data.get("baseline_diff"), dict) else {},
        trust_tier=str(data.get("trust_tier") or ""),
        trust_tier_label=str(data.get("trust_tier_label") or ""),
        trust_tier_reason=str(data.get("trust_tier_reason") or ""),
    )


def _analysis_status_from_dict(data: dict[str, Any]) -> str:
    explicit = str(data.get("analysis_status") or "")
    if explicit in {"complete", "incomplete", "failed"}:
        return explicit
    coverage = data.get("analysis_coverage") if isinstance(data.get("analysis_coverage"), dict) else {}
    providers = coverage.get("providers") if isinstance(coverage.get("providers"), dict) else {}
    acquisition = providers.get("artifact_acquisition") if isinstance(providers, dict) else None
    manifest = coverage.get("manifest_validation") if isinstance(coverage.get("manifest_validation"), dict) else {}
    if (
        data.get("source") == "marketplace-error"
        or (isinstance(acquisition, dict) and acquisition.get("status") == "failed")
        or manifest.get("status") == "scan-aborted"
    ):
        return "failed"
    inventory = data.get("artifact_inventory") if isinstance(data.get("artifact_inventory"), dict) else {}
    if inventory.get("scan_incomplete") or coverage.get("status") == "incomplete" or data.get("decision") == "incomplete":
        return "incomplete"
    if coverage.get("status") == "complete" or data.get("decision") in {"allow", "review", "block"}:
        return "complete"
    return "incomplete"


def _scan_incomplete(extension: ExtensionReport) -> bool:
    return bool(
        extension.analysis_status != "complete"
        or getattr(extension, "scan_incomplete", False)
        or extension.artifact_inventory.get("scan_incomplete")
    )


def _skipped_reason(extension: ExtensionReport) -> str:
    return str(getattr(extension, "skipped_reason", "") or extension.artifact_inventory.get("skipped_reason") or "")


def _safe_detail_name(extension_id: str, version_value: str) -> str:
    raw = f"{extension_id}@{version_value}"
    return re.sub(r"[^A-Za-z0-9._@-]+", "_", raw).strip("._") or "extension"


def _sorted_counts(counts: dict[str, int]) -> dict[str, int]:
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def _scanner_version() -> str:
    try:
        return version("guardlens")
    except PackageNotFoundError:
        return "unknown"


def _scanner_build() -> str:
    """Return the immutable CI or source-checkout revision when available."""
    return scanner_build()


def _write_json(archive: zipfile.ZipFile, name: str, data: Any) -> None:
    archive.writestr(name, json.dumps(data, indent=2, sort_keys=True) + "\n")


def _bundle_members(bundle: dict[str, Any]) -> dict[str, bytes]:
    members = {
        "metadata.json": _json_bytes(bundle["metadata"]),
        "summary.json": _json_bytes(bundle["summary"]),
        "leaderboard.json": _json_bytes(bundle["leaderboard"]),
        "posture.json": _json_bytes(bundle["posture"]),
        "rules.json": _json_bytes(bundle["rules"]),
    }
    members.update({ref: _json_bytes(detail) for ref, detail in sorted(bundle["extensions"].items())})
    return members


def _integrity_manifest(members: dict[str, bytes]) -> dict[str, Any]:
    return {
        "schema_version": "guardrails.report-integrity.v1",
        "algorithm": "sha256",
        "files": {
            name: {"sha256": hashlib.sha256(payload).hexdigest(), "size_bytes": len(payload)}
            for name, payload in sorted(members.items())
        },
        "authentication": "none",
        "note": "Hashes detect altered bundle members but do not authenticate the publisher.",
    }


def _signed_provenance(
    integrity_payload: bytes,
    signing_key: Path | str,
    signing_key_id: str | None,
) -> dict[str, Any]:
    private_key = _load_ed25519_private_key(signing_key)
    public_key = private_key.public_key()
    fingerprint = _public_key_fingerprint(public_key)
    provenance = {
        "schema_version": "guardrails.report-provenance.v1",
        "algorithm": "ed25519",
        "signed_member": "integrity.json",
        "signed_member_sha256": hashlib.sha256(integrity_payload).hexdigest(),
        "signing_key_id": signing_key_id or fingerprint,
        "public_key_fingerprint": fingerprint,
    }
    signature = private_key.sign(_provenance_payload(provenance))
    return {**provenance, "signature_base64": base64.b64encode(signature).decode("ascii")}


def generate_report_signing_keypair(
    private_key_path: Path | str,
    public_key_path: Path | str,
    *,
    signing_key_id: str | None = None,
) -> dict[str, str]:
    """Create a non-overwritable Ed25519 keypair for report provenance.

    The private key is deliberately unencrypted because the scanner's signing
    interface accepts CI-injected PEM material without an interactive prompt.
    It must be moved to an access-controlled secret store before use in CI.
    """
    private_path = Path(private_key_path)
    public_path = Path(public_key_path)
    if private_path.resolve() == public_path.resolve():
        raise ValueError("Private and public signing key paths must be different.")
    if private_path.exists() or public_path.exists():
        raise ValueError("Refusing to overwrite an existing signing key file.")
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    private_payload = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_payload = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _write_new_key_file(private_path, private_payload, mode=0o600)
    try:
        _write_new_key_file(public_path, public_payload, mode=0o644)
    except Exception:
        private_path.unlink(missing_ok=True)
        raise
    fingerprint = _public_key_fingerprint(private_key.public_key())
    return {
        "algorithm": "ed25519",
        "private_key": str(private_path),
        "public_key": str(public_path),
        "public_key_fingerprint": fingerprint,
        "signing_key_id": signing_key_id or fingerprint,
    }


def _read_provenance(archive: zipfile.ZipFile, names: list[str]) -> dict[str, Any] | None:
    if "provenance.json" not in names:
        return None
    try:
        provenance = json.loads(archive.read("provenance.json"))
    except (KeyError, json.JSONDecodeError) as exc:
        raise ValueError("Report bundle provenance record is invalid.") from exc
    if not isinstance(provenance, dict):
        raise ValueError("Report bundle provenance record is invalid.")
    return provenance


def _verify_provenance(
    provenance: dict[str, Any] | None,
    *,
    integrity_payload: bytes,
    public_key: Path | str | None,
    expected_key_id: str | None,
    require_signature: bool,
) -> dict[str, Any]:
    if provenance is None:
        if require_signature or public_key or expected_key_id:
            raise ValueError("Report bundle has no signed provenance record.")
        return {
            "authenticated": False,
            "provenance": {"status": "not_signed"},
            "note": "Internal member hashes match. This bundle has no publisher signature.",
        }
    _validate_provenance(provenance, integrity_payload, expected_key_id)
    if public_key is None:
        if require_signature:
            raise ValueError("A public key is required to authenticate signed provenance.")
        return {
            "authenticated": False,
            "provenance": {
                "status": "present_unverified",
                "signing_key_id": provenance["signing_key_id"],
                "public_key_fingerprint": provenance["public_key_fingerprint"],
            },
            "note": "Signed provenance is present but was not authenticated against a trusted public key.",
        }
    trusted_key = _load_ed25519_public_key(public_key)
    fingerprint = _public_key_fingerprint(trusted_key)
    if fingerprint != provenance["public_key_fingerprint"]:
        raise ValueError("Report bundle provenance key does not match the trusted public key.")
    try:
        signature = base64.b64decode(provenance["signature_base64"], validate=True)
        trusted_key.verify(signature, _provenance_payload(provenance))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ValueError("Report bundle provenance signature is invalid.") from exc
    return {
        "authenticated": True,
        "provenance": {
            "status": "verified",
            "signing_key_id": provenance["signing_key_id"],
            "public_key_fingerprint": fingerprint,
        },
        "note": "Bundle members and signed provenance were verified against the trusted public key.",
    }


def _validate_provenance(
    provenance: dict[str, Any], integrity_payload: bytes, expected_key_id: str | None
) -> None:
    required = {
        "schema_version",
        "algorithm",
        "signed_member",
        "signed_member_sha256",
        "signing_key_id",
        "public_key_fingerprint",
        "signature_base64",
    }
    if set(provenance) != required:
        raise ValueError("Report bundle provenance record has unsupported fields.")
    if provenance["schema_version"] != "guardrails.report-provenance.v1" or provenance["algorithm"] != "ed25519":
        raise ValueError("Report bundle provenance schema or algorithm is unsupported.")
    if provenance["signed_member"] != "integrity.json":
        raise ValueError("Report bundle provenance does not sign the integrity manifest.")
    if provenance["signed_member_sha256"] != hashlib.sha256(integrity_payload).hexdigest():
        raise ValueError("Report bundle provenance does not match the integrity manifest.")
    if not all(isinstance(provenance[key], str) and provenance[key] for key in required):
        raise ValueError("Report bundle provenance record is invalid.")
    if expected_key_id and provenance["signing_key_id"] != expected_key_id:
        raise ValueError("Report bundle provenance key id does not match the expected key id.")


def _provenance_payload(provenance: dict[str, Any]) -> bytes:
    return _json_bytes({key: value for key, value in provenance.items() if key != "signature_base64"})


def _load_ed25519_private_key(path: Path | str) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    except (OSError, TypeError, ValueError) as exc:
        raise ValueError("Signing key must be an unencrypted PEM Ed25519 private key.") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Signing key must be an Ed25519 private key.")
    return key


def _load_ed25519_public_key(path: Path | str) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(Path(path).read_bytes())
    except (OSError, TypeError, ValueError) as exc:
        raise ValueError("Trusted public key must be a PEM Ed25519 public key.") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Trusted public key must be an Ed25519 public key.")
    return key


def _public_key_fingerprint(public_key: Ed25519PublicKey) -> str:
    encoded = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _write_new_key_file(path: Path, payload: bytes, *, mode: int) -> None:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    except FileExistsError as exc:
        raise ValueError("Refusing to overwrite an existing signing key file.") from exc
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(path, mode)


def _json_bytes(data: Any) -> bytes:
    return (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8")
