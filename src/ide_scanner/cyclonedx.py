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
    extension_refs = _extension_refs(extensions)

    for extension in extensions:
        extension_id = _text(extension.get("extension_id"), 240) or "unknown.extension"
        version = _text(extension.get("version"), 160) or "unknown"
        extension_ref = _extension_ref(extension_id, version)
        components[extension_ref] = _extension_component(extension, extension_id, version, extension_ref)
        dependency_refs: list[str] = []
        for dependency in _dependencies(extension):
            name = _text(dependency.get("name"), 300)
            dependency_version = _text(dependency.get("version"), 160)
            if not name or not dependency_version:
                continue
            dependency_ref = _npm_ref(name, dependency_version)
            components.setdefault(dependency_ref, _dependency_component(dependency, dependency_ref))
            dependency_refs.append(dependency_ref)
        dependency_refs.extend(_scanned_extension_relationship_refs(extension, extension_ref, extension_refs))
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
            *_relationship_scan_properties(extension),
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


def _extension_refs(extensions: list[dict[str, Any]]) -> dict[str, list[str]]:
    refs: dict[str, list[str]] = {}
    for extension in extensions:
        extension_id = _text(extension.get("extension_id"), 240)
        version = _text(extension.get("version"), 160)
        if extension_id and version:
            refs.setdefault(extension_id.lower(), []).append(_extension_ref(extension_id, version))
    return refs


def _scanned_extension_relationship_refs(
    extension: dict[str, Any],
    extension_ref: str,
    extension_refs: dict[str, list[str]],
) -> list[str]:
    inventory = extension.get("artifact_inventory")
    declared = inventory.get("declared_extension_relationships") if isinstance(inventory, dict) else None
    if not isinstance(declared, list):
        return []
    related_refs: list[str] = []
    for relationship in declared:
        if not isinstance(relationship, dict):
            continue
        related_id = _text(relationship.get("extension_id"), 240).lower()
        candidates = extension_refs.get(related_id, [])
        # A declaration has no version. Link it only when this scan output
        # contains exactly one concrete related artifact; otherwise retaining
        # the manifest evidence without a guessed SBOM component is safer.
        if len(candidates) == 1 and candidates[0] != extension_ref:
            related_refs.append(candidates[0])
    return related_refs


def _relationship_scan_properties(extension: dict[str, Any]) -> list[dict[str, str]]:
    identity = extension.get("artifact_identity")
    relationship_scan = identity.get("relationship_scan") if isinstance(identity, dict) else None
    if not isinstance(relationship_scan, dict):
        return []
    properties = [
        _property("guardrails:relationship-selection", _text(relationship_scan.get("selection"), 80) or "unknown"),
        _property("guardrails:relationship-version-pinned", str(bool(relationship_scan.get("version_pinned"))).lower()),
    ]
    parent = _text(relationship_scan.get("parent_extension_id"), 240)
    relationship = _text(relationship_scan.get("relationship"), 80)
    if parent:
        properties.append(_property("guardrails:relationship-parent", parent))
    if relationship:
        properties.append(_property("guardrails:relationship-type", relationship))
    return properties


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


def _text(value: Any, limit: int) -> str:
    return value.strip()[:limit] if isinstance(value, str) else ""


def _property(name: str, value: str) -> dict[str, str]:
    return {"name": name, "value": value}
