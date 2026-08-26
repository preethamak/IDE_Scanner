from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from .capability_contracts import (
    class_contract,
    classify_extension,
    expected_capabilities,
    extension_profile,
    intent_profile_entry,
    resolve_intent,
)
from .models import ExtensionReport


# These profiles explain intended power; they are not allowlists. A profile can
# only produce an expected-capability outcome when registry identity, repository
# ownership, artifact identity, and analysis coverage all agree and no
# unexplained decision-relevant evidence remains.
#
# The authoritative profile table now lives in contracts/intent-v2.json
# (extension_profiles); this legacy mapping remains only so existing imports
# keep resolving. New entries must go into the JSON contract.
LEGACY_EXPECTED_CAPABILITY_PROFILES: dict[str, dict[str, Any]] = {
    "dbaeumer.vscode-eslint": {
        "id": "vscode-eslint-v1",
        "publisher": "dbaeumer",
        "repository_owners": ["microsoft/vscode-eslint"],
        "capabilities": ["activation", "dynamic_code", "filesystem", "ide_contributions", "lifecycle_scripts", "process_execution"],
    },
    "eamodio.gitlens": {
        "id": "gitlens-v1",
        "publisher": "eamodio",
        "repository_owners": ["gitkraken/vscode-gitlens", "eamodio/vscode-gitlens"],
        "capabilities": ["activation", "credential_commands", "credential_configuration", "ide_contributions", "lifecycle_scripts", "process_execution"],
    },
    "ms-python.python": {
        "id": "vscode-python-v1",
        "publisher": "ms-python",
        "repository_owners": ["microsoft/vscode-python"],
        "capabilities": ["activation", "ide_contributions", "lifecycle_scripts", "native_code", "packed_artifacts", "process_execution"],
    },
    "rust-lang.rust-analyzer": {
        "id": "rust-analyzer-v1",
        "publisher": "rust-lang",
        "repository_owners": ["rust-lang/rust-analyzer"],
        "capabilities": ["activation", "ide_contributions", "native_code", "packed_artifacts", "process_execution"],
    },
    "semgrep.semgrep": {
        "id": "semgrep-vscode-v1",
        "publisher": "semgrep",
        "repository_owners": ["semgrep/semgrep-vscode"],
        "capabilities": ["activation", "ide_contributions", "lifecycle_scripts", "native_code", "packed_artifacts", "process_execution"],
    },
    "snyk-security.snyk-vulnerability-scanner": {
        "id": "snyk-vscode-v1",
        "publisher": "snyk-security",
        "repository_owners": ["snyk/vscode-extension"],
        "capabilities": ["activation", "credential_commands", "credential_configuration", "ide_contributions", "lifecycle_scripts", "native_code", "packed_artifacts", "process_execution"],
    },
    "sonarsource.sonarlint-vscode": {
        "id": "sonarqube-vscode-v1",
        "publisher": "sonarsource",
        "repository_owners": ["sonarsource/sonarlint-vscode"],
        "capabilities": ["activation", "ide_contributions", "lifecycle_scripts", "native_code", "packed_artifacts", "process_execution"],
    },
}

_PROVENANCE_CONFLICT_RULES = {
    "known-bad-artifact",
    "marketplace-extension-not-found",
    "marketplace-name-impersonation",
    "marketplace-removed-malware",
    "marketplace-removed-package",
    "source-vsix-diff-unexplained",
    "trusted-threat-feed-hit",
}
_EXPLAINABLE_CLASSES = {"capability", "reputation", "weak"}


def provenance_facts(extension: ExtensionReport) -> dict[str, Any]:
    """Resolve spoof-resistant provenance inputs shared by the decision-time
    intent gate and this display assessment.

    Identity anchors, in order of strength:
    1. Artifact binding — the scanned VSIX came from the registry download
       path AND its SHA-256 matched the marketplace-served digest for that
       exact id@version (recorded by _apply_marketplace_integrity). Manifest
       strings are attacker-controlled; only a hash-bound registry artifact
       proves the bytes belong to the assessed identity.
    2. Publisher identity — marketplace domain-verified flag plus exact
       case-insensitive equality with the curated profile's publisher.
    3. Repository ownership — parsed github.com owner/repo segment equality
       against the profile's pinned owners. Substring matching previously
       accepted ``https://attacker/x?mirror=github.com/microsoft`` spoofs.
    """
    profile = intent_profile_entry(extension.extension_id)
    rule_ids = {finding.rule_id for finding in extension.findings}
    verified = "marketplace-verified-publisher" in rule_ids
    conflicted = bool(rule_ids & _PROVENANCE_CONFLICT_RULES)
    coverage_complete = str(extension.analysis_coverage.get("status") or "") == "complete"

    identity = extension.artifact_identity if isinstance(extension.artifact_identity, dict) else {}
    original_registry_artifact = bool(identity.get("original_registry_artifact"))
    signature = extension.artifact_inventory.get("vsix_signature")
    signature = signature if isinstance(signature, dict) else {}
    package_integrity = signature.get("package_integrity")
    package_integrity = package_integrity if isinstance(package_integrity, dict) else {}
    acquisition = identity.get("acquisition")
    acquisition = acquisition if isinstance(acquisition, dict) else {}
    # Two binding tiers: exact digest equality against the listing's published
    # hash (strongest), or bytes served by the marketplace CDN itself over TLS
    # for listings that publish no per-version digest. Open VSX fallback
    # downloads never qualify.
    artifact_sha_bound = bool(package_integrity.get("matched")) or bool(acquisition.get("registry_served"))
    artifact_consistent = (
        identity.get("extension_id") == extension.extension_id
        and identity.get("version") == extension.version
        and len(str(identity.get("sha256") or "")) == 64
    )
    artifact_bound = original_registry_artifact and artifact_sha_bound and artifact_consistent

    publisher_matches = bool(profile) and extension.publisher.lower() == str(profile.get("publisher", "")).lower()
    repository_matches = bool(profile) and _repository_owner_match(
        extension.repository, profile.get("repository_owners", [])
    )

    established = bool(
        profile and verified and publisher_matches and repository_matches
        and artifact_bound and coverage_complete and not conflicted
    )
    if conflicted:
        tier = "conflicted"
    elif established:
        tier = "established"
    elif verified:
        tier = "verified"
    else:
        tier = "unknown"
    return {
        "profile": profile,
        "profile_id": str(profile.get("id") or "") if profile else "",
        "verified": verified,
        "publisher_matches": publisher_matches,
        "repository_matches": repository_matches,
        "artifact_consistent": artifact_consistent,
        "artifact_bound": artifact_bound,
        "coverage_complete": coverage_complete,
        "conflicted": conflicted,
        "established": established,
        "tier": tier,
    }


def _repository_owner_match(repository: str, owners: list[str] | None) -> bool:
    """Exact owner/repo segment comparison on a github.com URL."""
    if not owners:
        return False
    raw = str(repository or "").strip()
    if not raw:
        return False
    try:
        parsed = urlparse(raw)
    except ValueError:
        return False
    host = (parsed.netloc or "").lower()
    if host not in {"github.com", "www.github.com"}:
        return False
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        return False
    repo_segment = parts[1]
    if repo_segment.lower().endswith(".git"):
        repo_segment = repo_segment[: -len(".git")]
    candidate = f"{parts[0]}/{repo_segment}".lower()
    return candidate in {str(owner).strip().lower() for owner in owners}


def apply_public_assessment(extension: ExtensionReport) -> None:
    facts = provenance_facts(extension)
    profile = facts["profile"]
    established = facts["established"]
    classification = classify_extension(extension)
    rule_ids = {finding.rule_id for finding in extension.findings}
    evidence_classes = {_evidence_class(finding) for finding in extension.findings}

    intent = resolve_intent(
        extension_id=extension.extension_id,
        name=extension.name,
        description=extension.description,
        capabilities=extension.capabilities,
        findings=extension.findings,
    )
    capability_ids = sorted(
        str(item.get("id")) for item in extension.capabilities
        if isinstance(item, dict) and item.get("id")
    )
    legacy_profile = extension_profile(extension.extension_id) or LEGACY_EXPECTED_CAPABILITY_PROFILES.get(extension.extension_id.lower())
    contract_class = str(legacy_profile.get("class") or classification["primary"]) if legacy_profile else str(classification["primary"])
    # Display expectations keep the historical v1 semantics; the decision-time
    # gate resolves expectations through intent-v2 instead.
    expected = expected_capabilities(legacy_profile, contract_class) if legacy_profile else set()
    forbidden = set(class_contract(contract_class).get("forbidden", []))
    matched = sorted(set(capability_ids) & expected)
    unexpected_capabilities = sorted(set(capability_ids) - expected) if legacy_profile else capability_ids
    unexplained_findings = sorted(
        finding.rule_id for finding in extension.findings
        if _evidence_class(finding) not in _EXPLAINABLE_CLASSES
    )

    extension.provenance = {
        "tier": facts["tier"],
        "publisher_verified": facts["verified"],
        "publisher_matches_profile": facts["publisher_matches"],
        "repository_matches_profile": facts["repository_matches"],
        "artifact_identity_consistent": facts["artifact_consistent"],
        "artifact_registry_bound": facts["artifact_bound"],
        "profile_id": facts["profile_id"] or (str(legacy_profile["id"]) if legacy_profile else ""),
        "intent_source": intent.source,
        "intent_class_id": intent.class_id,
    }
    extension.capability_assessment = {
        "profile_id": facts["profile_id"] or (str(legacy_profile["id"]) if legacy_profile else ""),
        "observed": capability_ids,
        "matched": matched,
        "unexpected": unexpected_capabilities,
        "unexplained_findings": unexplained_findings,
        "classification": classification,
        "contract_class": contract_class,
        "forbidden_observed": sorted(set(capability_ids) & forbidden),
        "intent": intent.as_dict(),
    }

    if extension.decision == "incomplete":
        extension.public_outcome = "incomplete"
        extension.decision_basis = "incomplete_analysis"
        extension.evidence_confidence = "none"
    elif extension.verdict == "malicious":
        extension.public_outcome = "confirmed_threat"
        extension.decision_basis = "authoritative_threat_evidence"
        extension.evidence_confidence = "confirmed"
    elif extension.decision_basis == "intent_explained_preventive_chain":
        # Set by the decision-time intent gate: preventive-chain evidence that a
        # curated profile explains. Deliberately distinct from
        # expected_capability, which continues to imply zero unexpected
        # capabilities and zero unexplained findings.
        extension.public_outcome = "explained_preventive_chain"
        extension.evidence_confidence = "high"
    elif extension.decision == "block":
        extension.public_outcome = "preventive_block"
        extension.decision_basis = "high_specificity_abuse_path"
        extension.evidence_confidence = "high"
    elif (
        extension.decision == "review"
        and established
        and not unexpected_capabilities
        and not unexplained_findings
        and evidence_classes <= _EXPLAINABLE_CLASSES
    ):
        extension.decision_reason = (
            "Review is capability-based: the observed powerful behavior matches "
            "the extension's established publisher and expected-capability profile."
        )
        extension.public_outcome = "expected_capability"
        extension.decision_basis = "established_expected_capability"
        extension.evidence_confidence = "contextual"
    elif extension.decision == "review":
        extension.public_outcome = "investigate"
        extension.decision_basis = "unexplained_or_unestablished_behavior"
        extension.evidence_confidence = str(extension.score_details.get("confidence") or "medium")
    else:
        extension.public_outcome = "clear"
        extension.decision_basis = "no_actionable_evidence"
        extension.evidence_confidence = "none"


def _evidence_class(finding: Any) -> str:
    evidence = getattr(finding, "evidence", None)
    if isinstance(evidence, dict) and isinstance(evidence.get("evidence_class"), str):
        return str(evidence["evidence_class"])
    return "weak"
