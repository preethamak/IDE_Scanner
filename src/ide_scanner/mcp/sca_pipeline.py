from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx


@dataclass
class PipelineVulnerability:
    id: str
    transitive: bool = False
    reachable: bool = False
    exploitable: bool = False
    used_in_num_locations: int = 0
    severity: str = "UNKNOWN"
    scanner_source: str = "osv"
    raw_details: dict[str, Any] = field(default_factory=dict)


@dataclass
class PipelinePackage:
    ecosystem: str
    name: str
    versions: list[str] = field(default_factory=list)
    purl: str = ""
    contains_cve: bool = False
    contains_malware: bool = False
    cve_details: list[PipelineVulnerability] = field(default_factory=list)
    malware_details: list[PipelineVulnerability] = field(default_factory=list)


@dataclass
class PipelineResult:
    success: bool
    error_message: str | None = None
    purl_vulns: list[PipelinePackage] = field(default_factory=list)
    dependencies: list[dict[str, Any]] = field(default_factory=list)


class SCAPipeline:
    """Repository dependency extraction plus OSV enrichment."""

    @classmethod
    async def scan(cls, repo_path: str | Path) -> PipelineResult:
        root = Path(repo_path)
        try:
            dependencies = cls._discover_dependencies(root)
            packages: list[PipelinePackage] = []
            async with httpx.AsyncClient(timeout=15) as client:
                for dependency in dependencies:
                    package = PipelinePackage(
                        ecosystem=dependency["ecosystem"],
                        name=dependency["name"],
                        versions=[dependency["version"]] if dependency.get("version") else [],
                        purl=cls._purl(dependency),
                    )
                    package.cve_details = await cls._query_osv(client, dependency)
                    package.contains_cve = bool(package.cve_details)
                    packages.append(package)
            return PipelineResult(success=True, purl_vulns=packages, dependencies=dependencies)
        except Exception as exc:
            return PipelineResult(success=False, error_message=str(exc), dependencies=[])

    @staticmethod
    def _purl(dependency: dict[str, Any]) -> str:
        ecosystem = dependency["ecosystem"]
        prefix = "pkg:npm/" if ecosystem == "npm" else "pkg:pypi/"
        return f"{prefix}{dependency['name']}" + (f"@{dependency['version']}" if dependency.get("version") else "")

    @classmethod
    def _discover_dependencies(cls, root: Path) -> list[dict[str, Any]]:
        found: dict[tuple[str, str], dict[str, Any]] = {}
        package_json = root / "package.json"
        if package_json.is_file():
            data = json.loads(package_json.read_text(encoding="utf-8"))
            for section in ("dependencies", "devDependencies", "optionalDependencies"):
                for name, version in (data.get(section) or {}).items():
                    found.setdefault(("npm", name), {"ecosystem": "npm", "name": name, "version": str(version), "transitive": section != "dependencies"})
        for file_name in ("requirements.txt", "requirements-dev.txt"):
            path = root / file_name
            if not path.is_file():
                continue
            for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = raw.strip()
                if not line or line.startswith("#") or line.startswith(("-", "git+")):
                    continue
                match = re.match(r"([A-Za-z0-9_.-]+)\s*(?:==|>=|~=|<=|>)?\s*([^;\s]+)?", line)
                if match:
                    name, version = match.groups()
                    found.setdefault(("PyPI", name.lower()), {"ecosystem": "PyPI", "name": name.lower(), "version": version or "", "transitive": False})
        pyproject = root / "pyproject.toml"
        if pyproject.is_file():
            in_dependencies = False
            for raw in pyproject.read_text(encoding="utf-8", errors="replace").splitlines():
                line = raw.strip()
                if line.startswith("["):
                    in_dependencies = line in {"[project]", "[project.optional-dependencies]"}
                if not in_dependencies or not line.startswith(('"', "'")):
                    continue
                match = re.search(r"[\"']([A-Za-z0-9_.-]+)(?:\s*(?:==|>=|~=|<=|>)\s*([^\"']+))?[\"']", line)
                if match:
                    name, version = match.groups()
                    found.setdefault(("PyPI", name.lower()), {"ecosystem": "PyPI", "name": name.lower(), "version": version or "", "transitive": False})
        return list(found.values())

    @staticmethod
    async def _query_osv(client: httpx.AsyncClient, dependency: dict[str, Any]) -> list[PipelineVulnerability]:
        payload: dict[str, Any] = {"package": {"name": dependency["name"], "ecosystem": dependency["ecosystem"]}}
        if dependency.get("version"):
            payload["version"] = dependency["version"]
        response = await client.post("https://api.osv.dev/v1/query", json=payload)
        response.raise_for_status()
        vulnerabilities: list[PipelineVulnerability] = []
        for item in response.json().get("vulns", []) or []:
            database = item.get("database_specific") or {}
            severity = str(database.get("severity") or "UNKNOWN").upper()
            if severity == "CRITICAL":
                severity = "CRITICAL"
            vulnerabilities.append(PipelineVulnerability(
                id=str(item.get("id") or "unknown"),
                transitive=bool(dependency.get("transitive")),
                severity=severity,
                raw_details=item,
            ))
        return vulnerabilities

    @staticmethod
    def load_datadog_manifests(home: str) -> list[dict[str, Any]]:
        root = Path(home)
        manifests: list[dict[str, Any]] = []
        if not root.is_dir():
            return manifests
        for path in root.rglob("*.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    manifests.extend(item for item in data if isinstance(item, dict))
                elif isinstance(data, dict):
                    manifests.append(data)
            except (OSError, ValueError):
                continue
        return manifests

    @staticmethod
    def merge_datadog_malicious(packages: list[PipelinePackage], dependencies: list[dict[str, Any]], manifests: list[dict[str, Any]]) -> list[PipelinePackage]:
        malicious = {(str(item.get("ecosystem") or ""), str(item.get("name") or "")) for item in manifests}
        for package in packages:
            if (package.ecosystem, package.name) in malicious:
                package.contains_malware = True
                package.malware_details.append(PipelineVulnerability(id=f"malicious:{package.ecosystem}:{package.name}", severity="HIGH", scanner_source="malicious-manifest"))
        return packages

