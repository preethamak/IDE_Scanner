"""Decision-time preventive-block veto.

A curated profile can explain preventive-chain evidence only when every
fail-closed condition holds. Any single failure returns ``None`` and the
preventive block stands. The gate is intentionally hard to satisfy:

- only explicit curated profiles qualify (inferred classes never veto);
- the artifact must be registry-served AND hash-bound to its listing;
- deep providers must have actually completed (not merely "no limitations");
- download-target attribution is recorded forensically but never gates the
  veto: serious toolchain managers build their release URLs dynamically, so
  static host stamping cannot distinguish them — behavioral corroboration
  (install-constrained sinks) carries that weight instead;
- an artifact that changed against its baseline withholds the veto (a missing
  baseline is fine — registry hash binding already pins first-seen identity);
- unmapped blocking rules can never be explained (closed-world map).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .capability_contracts import resolve_intent
from .classification_policy import finding_actionability
from .models import ExtensionReport


# Blocking rules whose behavior a profile may explain. Closed world on purpose:
# adding a new blocking rule requires a conscious decision to map it here or to
# declare it unmappable below.
RULE_BEHAVIOR_MAP: dict[str, frozenset[str]] = {
    "remote-vsix-install-chain": frozenset({"network", "filesystem", "ide_contributions"}),
    "download-and-execute": frozenset({"network", "process_execution"}),
    "install-download-execute": frozenset({"lifecycle_scripts", "network", "process_execution"}),
}

# Blocking rules that no profile may ever explain: credential access,
# destructive behavior, persistence, obfuscation chains, droppers, and every
# sandbox observation are malicious-specificity territory regardless of who
# published the artifact. The closed-world guard test asserts that every
# blocking rule lives here or in RULE_BEHAVIOR_MAP.
UNMAPPABLE_BLOCKING_RULES: frozenset[str] = frozenset({
    "supply-chain-dropper-chain",
    "credential-exfiltration-chain",
    "credential-harvesting-exfiltration",
    "credential-identifier-flow-to-network",
    "obfuscated-credential-harvesting-exfiltration",
    "agent-data-exfil-chain",
    "destructive-transfer-chain",
    "install-secret-access",
    "install-shell-obfuscation",
    "persistence-chain",
    "obfuscation-execution-network",
    "observed-secret-exfil",
    "observed-download-execute",
    "observed-persistence",
    "observed-destructive-behavior",
})

# Rules that disqualify the veto by mere presence: they indicate either runtime
# observation or a specificity abuser co-resident with the explained chain.
_VETO_DENY_RULES = frozenset({
    "obfuscation-execution-network",
    "credential-harvesting-exfiltration",
    "obfuscated-credential-harvesting-exfiltration",
    "credential-identifier-flow-to-network",
    # All sandbox observations are deny-grade.
    "observed-secret-exfil",
    "observed-download-execute",
    "observed-persistence",
    "observed-destructive-behavior",
    "observed-process-exec",
    "observed-filesystem-write",
    "observed-secret-read",
    "observed-unexpected-network",
})

# Credential surfaces that gate download-and-execute escalation. Unlike the
# deny family above, contextual members (e.g. credential-config-key in Dev
# Containers) do NOT disqualify: only decision-relevant findings count.
_CREDENTIAL_SIGNAL_RULES = frozenset({
    "credential-command-control",
    "credential-config-key",
    "credential-config-update",
    "credential-global-state-key",
    "credential-global-state-storage",
    "credential-inputbox-prompt",
})

_DEEP_PROVIDERS = ("semgrep", "yara", "dependency_intelligence")


@dataclass(frozen=True)
class PreventiveBlockVeto:
    profile_source: str  # always "explicit_profile"
    profile_id: str
    class_id: str
    explained_rules: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "class_id": self.class_id,
            "explained_rules": list(self.explained_rules),
        }


def evaluate_preventive_block_veto(
    extension: ExtensionReport,
    blocking_rule_ids: Iterable[str],
) -> PreventiveBlockVeto | None:
    blocking = frozenset(blocking_rule_ids)
    if not blocking:
        return None

    findings = extension.findings

    # 1. Mechanical evidence bar. Confirmed intel or block-actionable
    #    vulnerability advisories outrank any intent explanation.
    if extension.verdict == "malicious" or int(extension.malware_score or 0) > 0:
        return None
    for finding in findings:
        evidence_class = str((getattr(finding, "evidence", None) or {}).get("evidence_class") or "weak")
        if evidence_class == "confirmed":
            return None
        if evidence_class == "vulnerability" and finding_actionability(finding) == "block":
            return None

    # 2. Spoof-proof provenance: registry-served, hash-bound artifact for a
    #    domain-verified publisher matching a curated profile.
    from .public_outcomes import provenance_facts

    facts = provenance_facts(extension)
    if not facts["established"]:
        return None

    # 3. Deep providers actually completed. Coverage status alone treats
    #    unavailable analyzers as absent limitations on default profiles.
    coverage = extension.analysis_coverage if isinstance(extension.analysis_coverage, dict) else {}
    providers = coverage.get("providers") if isinstance(coverage.get("providers"), dict) else {}
    if coverage.get("required_providers_complete") is not True:
        return None
    for name in _DEEP_PROVIDERS:
        provider = providers.get(name)
        provider = provider if isinstance(provider, dict) else {}
        if provider.get("status") != "completed":
            return None

    # 4. Only explicit curated profiles may explain chain evidence.
    intent = resolve_intent(
        extension_id=extension.extension_id,
        name=extension.name,
        description=extension.description,
        capabilities=extension.capabilities,
        findings=findings,
    )
    if intent.source != "explicit_profile":
        return None

    # 5. Closed-world behavior mapping plus capability-subset check.
    explained: list[str] = []
    for rule_id in sorted(blocking):
        behaviors = RULE_BEHAVIOR_MAP.get(rule_id)
        if behaviors is None or not behaviors <= intent.expected:
            return None
        explained.append(rule_id)

    rule_ids = {finding.rule_id for finding in findings}

    # 6a. Deny-family co-factors: presence alone disqualifies.
    if rule_ids & _VETO_DENY_RULES:
        return None
    # 6b. Secret references count only when decision-relevant. Weak/contextual
    #     mentions (e.g. tooling that legitimately loads .env files) coexist
    #     with established profiles; correlated/observed ones do not.
    for finding in findings:
        if finding.rule_id.startswith("secret-reference:") and _decision_relevant(finding):
            return None
    # 6c. Credential signals count only when decision-relevant. Contextual
    #     exposure surfaces (config keys etc.) legitimately coexist with
    #     container/toolchain managers.
    for finding in findings:
        if finding.rule_id in _CREDENTIAL_SIGNAL_RULES and finding_actionability(finding) in {"review", "block"}:
            return None

    mapped_rules = blocking & set(RULE_BEHAVIOR_MAP)
    download_findings = [f for f in findings if f.rule_id in mapped_rules]
    if not download_findings:
        return None

    # 6e. Baseline continuity: when a previous report exists, an artifact or
    #     analysis change voids behavioral continuity. A missing baseline is
    #     NOT itself disqualifying — brand-new versions of established
    #     publishers have no prior report, and their identity is already
    #     pinned by the registry hash binding + verified-publisher gates
    #     required above.
    baseline_diff = extension.baseline_diff if isinstance(extension.baseline_diff, dict) else {}
    if baseline_diff.get("artifact_changed"):
        return None

    # 7. Behavioral corroboration for install-chain behavior: the sink must be
    #     constrained to IDE extension/tool installation, or the flow must show
    #     integrity verification. Arbitrary execution targets never qualify.
    if not _install_chain_corroborated(download_findings):
        return None

    return PreventiveBlockVeto(
        profile_source="explicit_profile",
        profile_id=intent.profile_id,
        class_id=intent.class_id,
        explained_rules=tuple(explained),
    )


def _decision_relevant(finding: Any) -> bool:
    """True when a finding's evidence weight or actionability makes it a
    decision-relevant co-factor rather than contextual surface."""
    evidence_class = str((getattr(finding, "evidence", None) or {}).get("evidence_class") or "weak")
    if evidence_class in {"confirmed", "correlated", "observed", "vulnerability"}:
        return True
    return finding_actionability(finding) in {"review", "block"}


def ai_assistant_review(extension: ExtensionReport) -> bool:
    """Standing-review policy for curated AI coding assistants.

    An established publisher and intent-consistent behavior earn an allow for
    ordinary tooling, but assistants with model access and code-transmission
    surfaces keep human oversight even when everything matches their profile —
    the blast radius of a compromised assistant is the user's entire codebase.
    Only explicit curated profiles qualify; unknown publishers already land on
    review through the unexplained-behavior path."""
    from .capability_contracts import resolve_intent

    intent = resolve_intent(
        extension_id=extension.extension_id,
        name=getattr(extension, "name", ""),
        description=getattr(extension, "description", ""),
        capabilities=list(getattr(extension, "capabilities", []) or []),
        findings=list(getattr(extension, "findings", []) or []),
    )
    return intent.source == "explicit_profile" and intent.class_id == "ai_assistant"


def _install_chain_corroborated(findings: list[Any]) -> bool:
    """True when at least one mapped finding shows an install-constrained sink
    or explicit integrity verification. Emitters record ``sink`` and
    ``integrity_verification`` at evidence top level (optionally mirrored in a
    structured ``correlation`` payload); check all locations."""
    for finding in findings:
        evidence = getattr(finding, "evidence", None)
        evidence = evidence if isinstance(evidence, dict) else {}
        blobs: list[str] = []
        sink = str(evidence.get("sink") or "")
        if sink:
            blobs.append(sink)
        correlation = evidence.get("correlation")
        if isinstance(correlation, dict):
            blobs.extend(str(correlation.get(key) or "") for key in ("sink", "transform", "source"))
        elif isinstance(correlation, str):
            blobs.append(correlation)
        for blob in blobs:
            lowered = blob.lower()
            if "installextension" in lowered or "extensions.install" in lowered or "install-tool" in lowered:
                return True
        if str(evidence.get("integrity_verification") or "").lower() in {"true", "verified"}:
            return True
    return False
