from __future__ import annotations

from .models import RuleMetadata
from .rules import CODE_RULES

RULESET_VERSION = "2026.07.07"


_RULE_OVERRIDES: dict[str, dict[str, object]] = {
    "credential-exfiltration-chain": {
        "title": "Credential exfiltration chain",
        "category": "credential-access",
        "evidence_class": "correlated",
        "default_severity": "HIGH",
        "description": "Detects code paths combining credential references, local file reads, and outbound transfer.",
        "recommendation": "Review source and remove the extension if behavior is unexpected.",
        "false_positive_notes": "May trigger on legitimate cloud tooling or credential helpers.",
        "benchmark_tags": ["credential", "filesystem", "network"],
    },
    "agent-data-exfil-chain": {
        "title": "Agent data exfiltration chain",
        "category": "agentic",
        "evidence_class": "correlated",
        "default_severity": "HIGH",
        "description": "Detects agent-facing code combined with sensitive references and outbound network behavior.",
        "recommendation": "Review agent tool boundaries and approval prompts before trusting the extension.",
        "benchmark_tags": ["agentic", "credential", "network"],
    },
    "download-and-execute": {
        "title": "Download and execute",
        "category": "execution",
        "evidence_class": "correlated",
        "default_severity": "HIGH",
        "description": "Detects source files that can download content and execute local processes.",
        "recommendation": "Verify download source, integrity checks, and execution purpose.",
        "benchmark_tags": ["download", "execution", "network"],
    },
    "lifecycle-script": {
        "title": "Lifecycle script",
        "category": "supply-chain",
        "evidence_class": "capability",
        "default_severity": "MEDIUM",
        "description": "Package defines install or uninstall lifecycle scripts.",
        "recommendation": "Inspect lifecycle scripts because they execute outside normal extension UI flows.",
        "false_positive_notes": "Many legitimate packages use install scripts to prepare native components.",
        "benchmark_tags": ["supply-chain", "install"],
    },
    "agentic-tooling": {
        "title": "Agent-facing IDE capability",
        "category": "agentic",
        "evidence_class": "capability",
        "default_severity": "MEDIUM",
        "description": "Extension contributes language model tools, chat participants, or MCP server surfaces.",
        "recommendation": "Review tool permissions and approval behavior before trusting agent-facing extensions.",
        "benchmark_tags": ["agentic", "mcp"],
    },
    "native-or-packed-artifact": {
        "title": "Native or packed artifact",
        "category": "artifact",
        "evidence_class": "capability",
        "default_severity": "MEDIUM",
        "description": "Extension package contains native binaries or packed archives.",
        "recommendation": "Confirm binary provenance and inspect packed artifacts before deployment.",
        "benchmark_tags": ["native", "artifact"],
    },
    "known-bad-artifact": {
        "title": "Known-bad artifact",
        "category": "confirmed-intelligence",
        "evidence_class": "confirmed",
        "default_severity": "CRITICAL",
        "description": "Package or file hash matched configured malicious intelligence.",
        "recommendation": "Block or remove this extension.",
        "benchmark_tags": ["confirmed", "hash"],
    },
    "marketplace-removed-package": {
        "title": "Marketplace removed package",
        "category": "provenance",
        "evidence_class": "provenance",
        "default_severity": "HIGH",
        "description": "Extension appears in a marketplace removed package list.",
        "recommendation": "Review removal reason and avoid the extension unless trust is independently established.",
        "benchmark_tags": ["marketplace", "provenance"],
    },
    "malicious-npm-dependency": {
        "title": "Malicious npm dependency",
        "category": "dependency",
        "evidence_class": "confirmed",
        "default_severity": "CRITICAL",
        "description": "Dependency vulnerability intelligence identifies a malicious package.",
        "recommendation": "Remove the extension or replace the affected dependency before use.",
        "benchmark_tags": ["dependency", "malware"],
    },
    "vulnerable-npm-dependency": {
        "title": "Vulnerable npm dependency",
        "category": "dependency",
        "evidence_class": "dependency",
        "default_severity": "HIGH",
        "description": "Dependency vulnerability intelligence reported vulnerable runtime dependencies.",
        "recommendation": "Upgrade or replace the vulnerable dependency.",
        "benchmark_tags": ["dependency", "vulnerability"],
    },
}


def rule_registry() -> list[RuleMetadata]:
    rules: dict[str, RuleMetadata] = {}
    for rule in CODE_RULES:
        rules[rule.id] = RuleMetadata(
            rule_id=rule.id,
            title=_title(rule.id),
            category=rule.category,
            evidence_class="weak",
            default_severity=rule.severity,  # type: ignore[arg-type]
            description=rule.summary,
            recommendation="Treat this as review evidence unless it combines with credential, network, download, or destructive behavior.",
            benchmark_tags=[rule.category],
        )

    for rule_id, override in _RULE_OVERRIDES.items():
        rules[rule_id] = RuleMetadata(
            rule_id=rule_id,
            title=str(override["title"]),
            category=str(override["category"]),
            evidence_class=str(override["evidence_class"]),
            default_severity=str(override["default_severity"]),  # type: ignore[arg-type]
            description=str(override["description"]),
            recommendation=str(override["recommendation"]),
            false_positive_notes=str(override.get("false_positive_notes") or ""),
            benchmark_tags=list(override.get("benchmark_tags") or []),
        )
    return sorted(rules.values(), key=lambda item: item.rule_id)


def rules_json() -> dict[str, object]:
    return {
        "ruleset_version": RULESET_VERSION,
        "rules": [rule.to_dict() for rule in rule_registry()],
    }


def _title(rule_id: str) -> str:
    return rule_id.replace("-", " ").replace(":", ": ").title()
