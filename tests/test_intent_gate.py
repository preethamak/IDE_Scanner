from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ide_scanner.capability_contracts import resolve_intent  # noqa: E402
from ide_scanner.intent_gate import (  # noqa: E402
    RULE_BEHAVIOR_MAP,
    UNMAPPABLE_BLOCKING_RULES,
    evaluate_preventive_block_veto,
)
from ide_scanner.models import ExtensionReport, Finding  # noqa: E402
from ide_scanner.scanner import BLOCKING_CORRELATED_RULES, BLOCKING_OBSERVED_RULES  # noqa: E402


def _finding(rule_id: str, *, severity: str = "HIGH", confidence: float = 0.9,
             evidence: dict | None = None) -> Finding:
    return Finding(
        finding_id=f"f-{rule_id}",
        extension_id="ms-python.python",
        version="1.0.0",
        rule_id=rule_id,
        category="execution",
        severity=severity,  # type: ignore[arg-type]
        confidence=confidence,
        score=78,
        evidence_type="static",
        evidence_summary=rule_id,
        file_refs=["dist/extension.js"],
        evidence=evidence,
    )


def _extension(**overrides) -> ExtensionReport:
    base = dict(
        instance_id="i1",
        extension_id="ms-python.python",
        name="Python",
        publisher="ms-python",
        version="2026.1.0",
        description="Python language support with tooling",
        repository="https://github.com/microsoft/vscode-python",
        install_path="marketplace:ms-python.python",
        source="vs-marketplace",
        artifact_hash="a" * 64,
        severity="HIGH",
        verdict="suspicious",
        malware_authority="none",
        verdict_reason="Correlated static evidence matches a realistic abuse path.",
        malware_score=0,
        risk_score=99,
        score_details={},
        capabilities=[
            {"id": "activation"}, {"id": "ide_contributions"}, {"id": "lifecycle_scripts"},
            {"id": "process_execution"}, {"id": "network"}, {"id": "filesystem"},
            {"id": "dynamic_code"}, {"id": "native_code"}, {"id": "packed_artifacts"},
        ],
        artifact_inventory={
            "vsix_signature": {
                "package_integrity": {
                    "matched": True,
                    "expected": "a" * 64,
                    "actual": "a" * 64,
                    "source": "vs-marketplace-version-property",
                },
            },
        },
        findings=[],
        scanned_files=10,
        analysis_coverage={
            "status": "complete",
            "required_providers_complete": True,
            "providers": {
                "semgrep": {"status": "completed"},
                "yara": {"status": "completed"},
                "dependency_intelligence": {"status": "completed"},
            },
        },
        artifact_identity={
            "extension_id": "ms-python.python",
            "version": "2026.1.0",
            "sha256": "a" * 64,
            "original_registry_artifact": True,
        },
        baseline_diff={"analysis_changed": False},
    )
    base.update(overrides)
    return ExtensionReport(**base)


_CHAIN_EVIDENCE = {
    "evidence_class": "correlated",
    "source": "remote-download",
    "sink": "workbench.extensions.installExtension",
    "download_host": "marketplace.visualstudio.com",
}

_VERIFIED = _finding("marketplace-verified-publisher", severity="INFO", confidence=0.95)


def _ready_extension(findings: list[Finding], **overrides) -> ExtensionReport:
    ext = _extension(findings=findings + [_VERIFIED], **overrides)
    return ext


def test_veto_fires_for_profiled_toolchain_manager():
    ext = _ready_extension([_finding("remote-vsix-install-chain", evidence=dict(_CHAIN_EVIDENCE))])
    veto = evaluate_preventive_block_veto(ext, {"remote-vsix-install-chain"})
    assert veto is not None
    assert veto.profile_id == "vscode-python-v2"
    assert veto.class_id == "language_toolchain_manager"
    assert veto.explained_rules == ("remote-vsix-install-chain",)


def test_veto_fires_despite_contextual_credential_surface():
    # remote-containers carries contextual credential-config-key; only
    # decision-relevant credential findings disqualify.
    findings = [
        _finding("remote-vsix-install-chain", evidence=dict(_CHAIN_EVIDENCE)),
        _finding("credential-config-key", severity="LOW", confidence=0.5,
                 evidence={"evidence_class": "exposure"}),
    ]
    ext = ExtensionReport(**{**_extension(findings=findings + [_VERIFIED]).__dict__})
    ext.extension_id = "ms-vscode-remote.remote-containers"
    ext.publisher = "ms-vscode-remote"
    ext.repository = "https://github.com/microsoft/vscode-remote-release"
    ext.artifact_identity["extension_id"] = ext.extension_id
    veto = evaluate_preventive_block_veto(ext, {"remote-vsix-install-chain"})
    assert veto is not None


def test_withheld_when_publisher_unverified():
    ext = _extension(findings=[_finding("remote-vsix-install-chain", evidence=dict(_CHAIN_EVIDENCE))])
    assert evaluate_preventive_block_veto(ext, {"remote-vsix-install-chain"}) is None


def test_withheld_when_repository_owner_mismatched():
    ext = _ready_extension([_finding("remote-vsix-install-chain", evidence=dict(_CHAIN_EVIDENCE))])
    ext.repository = "https://github.com/attacker/microsoft/vscode-python-mirror"
    assert evaluate_preventive_block_veto(ext, {"remote-vsix-install-chain"}) is None


def test_withheld_when_artifact_not_registry_bound():
    ext = _ready_extension([_finding("remote-vsix-install-chain", evidence=dict(_CHAIN_EVIDENCE))])
    ext.artifact_inventory["vsix_signature"]["package_integrity"]["matched"] = False
    assert evaluate_preventive_block_veto(ext, {"remote-vsix-install-chain"}) is None


def test_withheld_when_not_original_registry_artifact():
    ext = _ready_extension([_finding("remote-vsix-install-chain", evidence=dict(_CHAIN_EVIDENCE))])
    ext.artifact_identity["original_registry_artifact"] = False
    assert evaluate_preventive_block_veto(ext, {"remote-vsix-install-chain"}) is None


def test_withheld_when_deep_providers_incomplete():
    for provider in ("semgrep", "yara", "dependency_intelligence"):
        ext = _ready_extension([_finding("remote-vsix-install-chain", evidence=dict(_CHAIN_EVIDENCE))])
        ext.analysis_coverage["providers"][provider]["status"] = "unavailable"
        assert evaluate_preventive_block_veto(ext, {"remote-vsix-install-chain"}) is None
    ext = _ready_extension([_finding("remote-vsix-install-chain", evidence=dict(_CHAIN_EVIDENCE))])
    ext.analysis_coverage["required_providers_complete"] = False
    assert evaluate_preventive_block_veto(ext, {"remote-vsix-install-chain"}) is None


def test_inferred_class_intent_never_vetoes():
    ext = ExtensionReport(**_ready_extension(
        [_finding("remote-vsix-install-chain", evidence=dict(_CHAIN_EVIDENCE))]
    ).__dict__)
    ext.extension_id = "acme.sdk-manager"  # no curated profile
    ext.publisher = "acme"
    assert evaluate_preventive_block_veto(ext, {"remote-vsix-install-chain"}) is None


def test_withheld_on_unmapped_blocking_rule():
    ext = _ready_extension([_finding("persistence-chain", evidence=dict(_CHAIN_EVIDENCE))])
    assert evaluate_preventive_block_veto(ext, {"persistence-chain"}) is None


def test_withheld_on_deny_family_presence():
    for deny in ("obfuscation-execution-network", "observed-download-execute", "credential-harvesting-exfiltration"):
        ext = _ready_extension([
            _finding("remote-vsix-install-chain", evidence=dict(_CHAIN_EVIDENCE)),
            _finding(deny),
        ])
        assert evaluate_preventive_block_veto(ext, {"remote-vsix-install-chain"}) is None


def test_weak_secret_reference_does_not_withhold_but_correlated_does():
    """Weak/contextual secret mentions (tooling legitimately loading .env
    files) coexist with established profiles; decision-relevant ones do not."""
    weak = _ready_extension([
        _finding("remote-vsix-install-chain", evidence=dict(_CHAIN_EVIDENCE)),
        _finding("secret-reference:env-file", severity="LOW", confidence=0.56,
                 evidence={"evidence_class": "weak"}),
    ])
    veto = evaluate_preventive_block_veto(weak, {"remote-vsix-install-chain"})
    assert veto is not None and "remote-vsix-install-chain" in veto.explained_rules

    correlated = _ready_extension([
        _finding("remote-vsix-install-chain", evidence=dict(_CHAIN_EVIDENCE)),
        _finding("secret-reference:hardcoded-key", severity="HIGH", confidence=0.9,
                 evidence={"evidence_class": "correlated"}),
    ])
    assert evaluate_preventive_block_veto(correlated, {"remote-vsix-install-chain"}) is None


def test_withheld_on_decision_relevant_credential_signal():
    ext = _ready_extension([
        _finding("remote-vsix-install-chain", evidence=dict(_CHAIN_EVIDENCE)),
        _finding("credential-command-control", evidence={"evidence_class": "exposure"}),
    ])
    assert evaluate_preventive_block_veto(ext, {"remote-vsix-install-chain"}) is None


def test_dynamic_or_missing_download_hosts_do_not_withhold():
    """Serious toolchain managers (pylance, dart-code) build their release URLs
    dynamically, so static host stamping cannot attribute them. Download-host
    evidence is forensic context only; identity stays pinned by the
    established tier and behavior by install-sink corroboration."""
    unstamped = {k: v for k, v in _CHAIN_EVIDENCE.items() if k != "download_host"}
    ext = _ready_extension([_finding("remote-vsix-install-chain", evidence=dict(unstamped))])
    veto = evaluate_preventive_block_veto(ext, {"remote-vsix-install-chain"})
    assert veto is not None and "remote-vsix-install-chain" in veto.explained_rules

    evil_host = _ready_extension([_finding("remote-vsix-install-chain", evidence={
        **_CHAIN_EVIDENCE, "download_host": "cdn.evil.example",
    })])
    assert evaluate_preventive_block_veto(evil_host, {"remote-vsix-install-chain"}) is not None


def test_first_seen_artifact_without_baseline_still_qualifies():
    """Registry hash binding + verified-publisher gates already pin identity,
    so brand-new versions of established publishers must not be blocked just
    for having no prior report."""
    ext = _ready_extension([_finding("remote-vsix-install-chain", evidence=dict(_CHAIN_EVIDENCE))])
    ext.baseline_diff = {}
    veto = evaluate_preventive_block_veto(ext, {"remote-vsix-install-chain"})
    assert veto is not None
    assert "remote-vsix-install-chain" in veto.explained_rules


def test_withheld_when_baseline_changed():
    ext = _ready_extension([_finding("remote-vsix-install-chain", evidence=dict(_CHAIN_EVIDENCE))])
    ext.baseline_diff = {"artifact_changed": True}
    assert evaluate_preventive_block_veto(ext, {"remote-vsix-install-chain"}) is None


def test_confirmed_and_malware_score_outrank_veto():
    confirmed = _extension(findings=[
        _finding("remote-vsix-install-chain", evidence=dict(_CHAIN_EVIDENCE)),
        _finding("known-bad-artifact", severity="CRITICAL", confidence=0.98),
        _VERIFIED,
    ])
    confirmed.verdict = "malicious"
    assert evaluate_preventive_block_veto(confirmed, {"remote-vsix-install-chain"}) is None

    scored = _ready_extension([_finding("remote-vsix-install-chain", evidence=dict(_CHAIN_EVIDENCE))])
    scored.malware_score = 84
    assert evaluate_preventive_block_veto(scored, {"remote-vsix-install-chain"}) is None


def test_closed_world_map_accounts_for_every_blocking_rule():
    blocking_ids = BLOCKING_CORRELATED_RULES | BLOCKING_OBSERVED_RULES
    accounted = set(RULE_BEHAVIOR_MAP) | set(UNMAPPABLE_BLOCKING_RULES)
    assert blocking_ids <= accounted, f"new blocking rules must be mapped or declared unmappable: {sorted(blocking_ids - accounted)}"


def test_mapped_behaviors_subset_of_profile_expectations():
    from ide_scanner.capability_contracts import intent_profile_entry

    for target in (
        "ms-python.python", "ms-python.vscode-pylance", "ms-python.vscode-python-envs",
        "ms-toolsai.jupyter", "ms-vscode-remote.remote-containers", "eamodio.gitlens",
        "redhat.vscode-yaml", "dart-code.dart-code",
    ):
        profile = intent_profile_entry(target)
        assert profile, f"{target} missing an intent-v2 profile row"
        expected = set(profile["capabilities"])
        mapped = {rid: behaviors for rid, behaviors in RULE_BEHAVIOR_MAP.items()
                  if set(behaviors) <= expected}
        assert mapped, f"{target} explains no mapped rules; veto could never fire"


def test_resolve_intent_strong_manifest_signals():
    intent = resolve_intent(
        extension_id="unknown.vendor.thing",
        name="Thing",
        description="does things",
        capabilities=[],
        findings=[_finding("powerful-ide-contribution", severity="LOW", confidence=0.6,
                           evidence={"contribution": "debuggers"})],
    )
    assert intent.source == "inferred_class"
    assert intent.class_id == "debugger"

    agentic = resolve_intent(
        extension_id="unknown.vendor.thing2",
        name="Thing2",
        description="does things",
        capabilities=[],
        findings=[_finding("mcp-server-command", severity="MEDIUM", confidence=0.7)],
    )
    assert agentic.class_id == "ai_assistant"
