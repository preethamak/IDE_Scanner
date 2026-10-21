"""CycloneDX export for exact extension scan reports."""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Any
from urllib.parse import quote


def build_cyclonedx_bom(report: dict[str, Any], *, profile: str = "smart", source: str = "unknown") -> dict[str, Any]:
    """Build a CycloneDX 1.5 SBOM from resolved scanner output, not manifests."""
    extensions = [item for item in report.get("extensions") or [] if isinstance(item, dict)]
    scan_id = _text(report.get("scan_id"), 200) or "unidentified-scan"
    components: dict[str, dict[str, Any]] = {}
    relationships: list[dict[str, Any]] = []
    vulnerabilities: list[dict[str, Any]] = []

    for extension in extensions:
        extension_id = _text(extension.get("extension_id"), 240) or "unknown.extension"
        version = _text(extension.get("version"), 160) or "unknown"
        extension_ref = _extension_ref(extension_id, version)
        components[extension_ref] = _extension_component(extension, extension_id, version, extension_ref)
        vulnerabilities.extend(_vulnerabilities(extension, extension_id, version, extension_ref))
        dependency_refs: list[str] = []
        for dependency in _dependencies(extension):
            name = _text(dependency.get("name"), 300)
            dependency_version = _text(dependency.get("version"), 160)
            if not name or not dependency_version:
                continue
            dependency_ref = _npm_ref(name, dependency_version)
            components.setdefault(dependency_ref, _dependency_component(dependency, dependency_ref))
            dependency_refs.append(dependency_ref)
        relationships.append({"ref": extension_ref, "dependsOn": sorted(set(dependency_refs))})

    namespace = uuid.UUID("c62e2a1c-66dc-4e14-a1eb-76c4d46fcc33")
    identity = "|".join([scan_id, *sorted(components)])
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid5(namespace, identity)}",
        "version": 1,
        "metadata": {
            "timestamp": _timestamp(report.get("created_at")),
            "tools": [{"vendor": "GuardRails", "name": "ide-scanner", "version": _text(report.get("scanner_version"), 100) or "unknown"}],
            "component": {"type": "application", "name": "GuardRails extension scan", "version": scan_id},
            "properties": [
                _property("guardrails:scan-id", scan_id),
                _property("guardrails:profile", profile),
                _property("guardrails:source", source),
                _property("guardrails:scanner-build", _text(report.get("scanner_build"), 160) or "unknown"),
                _property("guardrails:ruleset-version", _text(report.get("ruleset_version"), 160) or "unknown"),
            ],
        },
        "components": [components[component_ref] for component_ref in sorted(components)],
        "dependencies": sorted(relationships, key=lambda item: str(item["ref"])),
        "vulnerabilities": sorted(vulnerabilities, key=lambda item: str(item["id"])),
    }


def _extension_component(extension: dict[str, Any], extension_id: str, version: str, bom_ref: str) -> dict[str, Any]:
    publisher, _, name = extension_id.partition(".")
    sha256 = _sha256(_artifact_hash(extension))
    return {
        "type": "application", "bom-ref": bom_ref, "name": name or extension_id, "group": publisher or None,
        "version": version, "purl": bom_ref, "hashes": [{"alg": "SHA-256", "content": sha256}] if sha256 else [],
        "properties": [
            _property("guardrails:extension-id", extension_id),
            _property("guardrails:decision", _text(extension.get("decision"), 80) or "incomplete"),
            _property("guardrails:analysis-status", _text(extension.get("analysis_status"), 80) or "incomplete"),
            _property("guardrails:coverage-percent", str(_coverage_percent(extension))),
        ],
    }


def _dependency_component(dependency: dict[str, Any], bom_ref: str) -> dict[str, Any]:
    return {
        "type": "library", "bom-ref": bom_ref, "name": _text(dependency.get("name"), 300),
        "version": _text(dependency.get("version"), 160), "purl": bom_ref,
        "properties": [_property("guardrails:relationship", _text(dependency.get("relationship"), 80) or "unknown")],
    }


def _dependencies(extension: dict[str, Any]) -> list[dict[str, Any]]:
    inventory = extension.get("artifact_inventory")
    candidates = inventory.get("dependency_inventory") if isinstance(inventory, dict) else None
    if isinstance(candidates, list):
        return [item for item in candidates if isinstance(item, dict)]
    dependencies = extension.get("dependencies")
    return [{"name": name, "version": version, "relationship": "unknown"} for name, version in dependencies.items()] if isinstance(dependencies, dict) else []


def _vulnerabilities(extension: dict[str, Any], extension_id: str, version: str, component_ref: str) -> list[dict[str, Any]]:
    findings = extension.get("findings")
    if not isinstance(findings, list):
        return []
    records: list[dict[str, Any]] = []
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict) or _text(finding.get("actionability"), 32) not in {"review", "block"}:
            continue
        rule_id = _text(finding.get("rule_id"), 160) or "unknown-rule"
        finding_id = _text(finding.get("finding_id"), 160) or f"{rule_id}-{index + 1}"
        severity = _cyclonedx_severity(_text(finding.get("effective_severity"), 16) or _text(finding.get("severity"), 16))
        evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
        records.append({
            "id": f"guardrails:{quote(extension_id, safe='')}@{quote(version, safe='')}:{quote(finding_id, safe='')}",
            "source": {"name": "GuardRails", "url": "https://abscissa.dev"},
            "ratings": [{"method": "other", "severity": severity}],
            "description": _text(finding.get("evidence_summary"), 2_000) or f"GuardRails {rule_id} finding.",
            "affects": [{"ref": component_ref}],
            "properties": [
                _property("guardrails:rule-id", rule_id),
                _property("guardrails:finding-id", finding_id),
                _property("guardrails:actionability", _text(finding.get("actionability"), 32)),
                _property("guardrails:evidence-class", _text(finding.get("evidence_class"), 80) or _text(evidence.get("evidence_class"), 80) or "unknown"),
            ],
        })
    return records


def _extension_ref(extension_id: str, version: str) -> str:
    publisher, _, name = extension_id.partition(".")
    return f"pkg:generic/{quote(publisher, safe='')}/{quote(name or extension_id, safe='')}@{quote(version, safe='')}?type=vsix"


def _npm_ref(name: str, version: str) -> str:
    return f"pkg:npm/{quote(name, safe='/')}@{quote(version, safe='')}"


def _artifact_hash(extension: dict[str, Any]) -> Any:
    identity = extension.get("artifact_identity")
    return identity.get("sha256") if isinstance(identity, dict) else extension.get("artifact_hash")


def _coverage_percent(extension: dict[str, Any]) -> int:
    coverage = extension.get("analysis_coverage")
    value = coverage.get("coverage_percent", coverage.get("executable_file_coverage_percent", 0)) if isinstance(coverage, dict) else 0
    return int(value) if isinstance(value, (int, float)) else 0


def _timestamp(value: Any) -> str:
    return value.strip() if isinstance(value, str) and value.strip() else dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z")


def _sha256(value: Any) -> str | None:
    candidate = _text(value, 64).lower()
    return candidate if len(candidate) == 64 and all(character in "0123456789abcdef" for character in candidate) else None


def _cyclonedx_severity(value: str) -> str:
    normalized = value.lower()
    return normalized if normalized in {"critical", "high", "medium", "low", "info"} else "unknown"


def _text(value: Any, limit: int) -> str:
    return value.strip()[:limit] if isinstance(value, str) else ""


def _property(name: str, value: str) -> dict[str, str]:
    return {"name": name, "value": value}
