from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from importlib.resources import files
from typing import Any


@lru_cache(maxsize=1)
def load_contracts() -> dict[str, Any]:
    payload = json.loads(files("ide_scanner").joinpath("contracts/capability-v1.json").read_text(encoding="utf-8"))
    if payload.get("schema_version") != "1" or not isinstance(payload.get("classes"), dict):
        raise ValueError("Invalid capability contract policy")
    return payload


@lru_cache(maxsize=1)
def load_intent_contracts() -> dict[str, Any]:
    payload = json.loads(files("ide_scanner").joinpath("contracts/intent-v2.json").read_text(encoding="utf-8"))
    if payload.get("schema_version") != "2" or not isinstance(payload.get("classes"), dict):
        raise ValueError("Invalid intent contract policy")
    if not isinstance(payload.get("extension_profiles"), dict):
        raise ValueError("Invalid intent contract policy: extension_profiles must be an object")
    return payload


@dataclass(frozen=True)
class IntentProfile:
    """Resolved intent for one extension. ``source`` records how it was derived:
    explicit curated profiles are the only source allowed to influence the
    preventive-block veto; inferred classes are context/explanation only."""

    source: str  # "explicit_profile" | "inferred_class" | "unknown"
    profile_id: str  # extension_profiles id, "" when inferred
    class_id: str
    expected: frozenset[str] = field(default_factory=frozenset)
    forbidden: frozenset[str] = field(default_factory=frozenset)
    confidence: float = 0.0
    ambiguous: bool = False
    signals: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "profile_id": self.profile_id,
            "class_id": self.class_id,
            "expected": sorted(self.expected),
            "forbidden": sorted(self.forbidden),
            "confidence": self.confidence,
            "ambiguous": self.ambiguous,
            "signals": list(self.signals),
        }


def intent_profile_entry(extension_id: str) -> dict[str, Any] | None:
    profile = load_intent_contracts()["extension_profiles"].get(extension_id.lower())
    return dict(profile) if isinstance(profile, dict) else None


def _intent_class_contract(class_id: str) -> dict[str, Any]:
    contract = load_intent_contracts()["classes"].get(class_id, {})
    return contract if isinstance(contract, dict) else {}


def resolve_intent(
    *,
    extension_id: str,
    name: str,
    description: str,
    capabilities: list[dict[str, Any]],
    findings: list[Any] | None = None,
) -> IntentProfile:
    """Resolve intended behavior for an extension.

    Precedence (first hit wins):
    1. Explicit curated profile keyed by extension id.
    2. Strong manifest signals visible in already-emitted findings.
    3. Keyword/capability-signal scoring over class templates (ambiguity-aware).
    4. Unknown.
    """
    profile = intent_profile_entry(extension_id)
    observed = {
        str(item.get("id"))
        for item in (capabilities or [])
        if isinstance(item, dict) and item.get("id")
    }
    if profile is not None:
        expected = {str(item) for item in profile.get("capabilities", [])}
        class_id = str(profile.get("class_id") or "")
        if not expected and class_id:
            expected = {str(item) for item in _intent_class_contract(class_id).get("expected", [])}
        forbidden = {str(item) for item in _intent_class_contract(class_id).get("forbidden", [])}
        return IntentProfile(
            source="explicit_profile",
            profile_id=str(profile.get("id") or ""),
            class_id=class_id,
            expected=frozenset(expected),
            forbidden=frozenset(forbidden),
            confidence=1.0,
        )

    strong = _strong_manifest_class(findings or [])
    if strong is not None:
        class_id, signals = strong
        contract = _intent_class_contract(class_id)
        return IntentProfile(
            source="inferred_class",
            profile_id="",
            class_id=class_id,
            expected=frozenset(str(item) for item in contract.get("expected", [])),
            forbidden=frozenset(str(item) for item in contract.get("forbidden", [])),
            confidence=0.8,
            signals=tuple(signals),
        )

    text = " ".join((str(name), str(description))).lower()
    scored: list[tuple[int, str, list[str]]] = []
    for class_id, contract in load_intent_contracts()["classes"].items():
        signals: list[str] = []
        for keyword in contract.get("keywords", []):
            if str(keyword).lower() in text:
                signals.append(f"text:{keyword}")
        for capability in contract.get("signals", []):
            if capability in observed:
                signals.append(f"capability:{capability}")
        scored.append((len(signals), str(class_id), signals))
    scored.sort(key=lambda entry: (-entry[0], entry[1]))
    if not scored or scored[0][0] == 0:
        return IntentProfile(source="unknown", profile_id="", class_id="unknown")

    top_score, top_class, top_signals = scored[0]
    tied = [entry for entry in scored if top_score - entry[0] <= 1]
    ambiguous = len(tied) > 1
    if ambiguous:
        merged: set[str] = set()
        for _, class_id, _ in tied:
            merged.update(str(item) for item in _intent_class_contract(class_id).get("expected", []))
        expected = merged
    else:
        expected = {str(item) for item in _intent_class_contract(top_class).get("expected", [])}
    return IntentProfile(
        source="inferred_class",
        profile_id="",
        class_id=top_class,
        expected=frozenset(expected),
        confidence=min(0.95, 0.35 + top_score * 0.15),
        ambiguous=ambiguous,
        signals=tuple(top_signals),
    )


def _strong_manifest_class(findings: list[Any]) -> tuple[str, list[str]] | None:
    """Classes derivable from high-specificity manifest evidence only."""
    contribution_keys: set[str] = set()
    rule_ids: set[str] = set()
    for finding in findings:
        rule_ids.add(str(getattr(finding, "rule_id", "")))
        evidence = getattr(finding, "evidence", None)
        if isinstance(evidence, dict) and evidence.get("contribution"):
            contribution_keys.add(str(evidence["contribution"]))
    if "powerful-ide-contribution" in rule_ids and "debuggers" in contribution_keys:
        return "debugger", ["contribution:debuggers"]
    if rule_ids & {"agentic-tooling", "mcp-server-command"}:
        return "ai_assistant", [f"rule:{rule}" for rule in sorted(rule_ids & {"agentic-tooling", "mcp-server-command"})]
    if "lifecycle-script" in rule_ids and rule_ids & {"process-execution", "network-access"}:
        return "language_toolchain_manager", ["rule:lifecycle-script+exec-or-network"]
    return None


def classify_extension(extension: Any) -> dict[str, Any]:
    """Infer functional class as context; classification never grants trust."""
    payload = load_contracts()
    text = " ".join((str(extension.name), str(extension.description))).lower()
    capabilities = {
        str(item.get("id")) for item in extension.capabilities
        if isinstance(item, dict) and item.get("id")
    }
    ranked: list[tuple[int, str, list[str]]] = []
    for class_id, contract in payload["classes"].items():
        signals: list[str] = []
        for keyword in contract.get("keywords", []):
            if str(keyword).lower() in text:
                signals.append(f"text:{keyword}")
        for capability in contract.get("signals", []):
            if capability in capabilities:
                signals.append(f"capability:{capability}")
        ranked.append((len(signals), str(class_id), signals))
    score, class_id, signals = max(ranked, default=(0, "unknown", []))
    if score == 0:
        class_id, signals = "unknown", []
    return {
        "primary": class_id,
        "confidence": round(min(0.95, 0.35 + score * 0.15), 2) if score else 0.0,
        "signals": signals,
        "contract_version": str(payload["policy_version"]),
    }


def extension_profile(extension_id: str) -> dict[str, Any] | None:
    profile = load_contracts().get("extension_profiles", {}).get(extension_id.lower())
    return dict(profile) if isinstance(profile, dict) else None


def class_contract(class_id: str) -> dict[str, Any]:
    contract = load_contracts()["classes"].get(class_id, {})
    return dict(contract) if isinstance(contract, dict) else {}


def expected_capabilities(profile: dict[str, Any] | None, class_id: str) -> set[str]:
    if profile and isinstance(profile.get("capabilities"), list):
        return {str(item) for item in profile["capabilities"]}
    return {str(item) for item in class_contract(class_id).get("expected", [])}
