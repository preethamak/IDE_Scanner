from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from .discovery import discover_from_path, discover_local_installations
from .jsonc import loads_jsonc
from .models import ExtensionReport, Finding
from .posture import scan_posture, summarize_posture
from .registry import enrich_registry
from .rules import (
    CODE_RULES,
    DESTRUCTIVE_RE,
    DOWNLOAD_RE,
    ENCODE_ARCHIVE_RE,
    FILE_READ_RE,
    FILE_WRITE_RE,
    NETWORK_SINK_RE,
    SECRET_PATTERNS,
    rank_severity,
    score_finding,
)

TEXT_EXTS = {
    ".cjs",
    ".cts",
    ".js",
    ".json",
    ".jsonc",
    ".jsx",
    ".mjs",
    ".mts",
    ".ps1",
    ".py",
    ".sh",
    ".ts",
    ".tsx",
    ".yaml",
    ".yml",
    ".html",
    ".htm",
}
EXEC_TEXT_EXTS = {".cjs", ".cts", ".js", ".jsx", ".mjs", ".mts", ".ps1", ".py", ".sh", ".ts", ".tsx"}
BINARY_RISK_EXTS = {".dll", ".dylib", ".exe", ".node", ".so"}
PACKED_RISK_EXTS = {".7z", ".asar", ".gz", ".jar", ".rar", ".tar", ".tgz", ".war", ".zip"}
SKIP_DIRS = {".git", ".hg", ".svn", "dist", "media", "node_modules", "resources", "syntaxes", "themes"}
MAX_TEXT_BYTES = 220_000
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
CONFIRMED_RULES = {"known-bad-artifact", "marketplace-removed-malware", "malicious-npm-dependency", "trusted-threat-feed-hit"}
OBSERVED_RULES = {
    "observed-secret-exfil",
    "observed-download-execute",
    "observed-persistence",
    "observed-destructive-behavior",
    "observed-process-exec",
    "observed-filesystem-write",
}
CORRELATED_RULES = {
    "agent-data-exfil-chain",
    "credential-exfiltration-chain",
    "destructive-transfer-chain",
    "download-and-execute",
    "install-download-execute",
    "install-secret-access",
    "install-shell-obfuscation",
    "obfuscation-execution-network",
    "persistence-chain",
    "supply-chain-dropper-chain",
}
CAPABILITY_RULES = {
    "agent-filesystem-tool",
    "agent-network-tool",
    "agent-prompt-injection-sink",
    "agent-shell-tool",
    "agentic-tooling",
    "broad-activation",
    "dynamic-shell-execution",
    "lifecycle-script",
    "mcp-server-command",
    "native-or-packed-artifact",
    "powerful-ide-contribution",
    "sensitive-activation",
    "startup-activation",
    "untrusted-input-execution",
    "webview-csp-missing",
    "webview-csp-unsafe-directive",
}
DEPENDENCY_RULES = {"mutable-dependency-source", "unpinned-dependency", "vulnerable-npm-dependency"}
PROVENANCE_RULES = {"marketplace-removed-package", "packed-artifact", "source-vsix-diff-unexplained", "binary-without-origin"}
POSTURE_RULES = {"dangerous-github-workflow", "repo-binary-artifacts", "workflow-token-permissions-broad"}
REPUTATION_RULES = {
    "marketplace-extension-not-found",
    "marketplace-low-install-count",
    "marketplace-low-rating",
    "marketplace-name-impersonation",
    "marketplace-stale-extension",
    "marketplace-unverified-publisher",
    "marketplace-verified-publisher",
    "install-rating-mismatch",
    "repo-archived",
    "repo-maintained",
    "repo-stale",
    "repo-url-missing",
    "security-policy-missing",
    "license-missing",
}
MALWARE_REMOVAL_TYPES = {"malware"}
SUSPICIOUS_REMOVAL_TYPES = {"suspicious"}


def scan_targets(
    paths: list[Path | str] | None = None,
    extension_ids: list[str] | None = None,
    include_fixtures: bool = False,
    all_local: bool = False,
    online: bool = False,
    known_bad_hashes_file: Path | str | None = None,
    threat_feed_file: Path | str | None = None,
    sandbox_observations_file: Path | str | None = None,
    previous_report_file: Path | str | None = None,
) -> dict[str, Any]:
    targets: list[dict[str, str]] = []
    root = Path.cwd()

    if include_fixtures:
        targets.extend(discover_from_path(root / "fixtures"))
    for path in paths or []:
        targets.extend(discover_from_path(path))
    if all_local:
        targets.extend(discover_local_installations())

    unique: dict[str, dict[str, str]] = {}
    for target in targets:
        unique[target["path"]] = target

    known_bad_hashes = _load_known_bad_hashes(known_bad_hashes_file)
    extensions = [
        _scan_discovered_target(target, known_bad_hashes)
        for target in unique.values()
    ]
    extensions.extend(_registry_only_extension(extension_id) for extension_id in extension_ids or [])
    _apply_threat_feed(extensions, _load_threat_feed(threat_feed_file))
    _apply_sandbox_observations(extensions, _load_sandbox_observations(sandbox_observations_file))
    registry = enrich_registry(extensions, online=online)
    _apply_registry_findings(extensions, registry["findings"])
    return _build_report(extensions, registry, _load_previous_report(previous_report_file))


def scan_extension(path: Path, source: str = "vscode", known_bad_hashes: dict[str, dict[str, Any]] | None = None) -> ExtensionReport:
    manifest = _read_manifest(path / "package.json")
    name = str(manifest.get("name") or path.name)
    publisher = str(manifest.get("publisher") or "unknown")
    version = str(manifest.get("version") or "0.0.0")
    extension_id = f"{publisher}.{name}"
    findings: list[Finding] = []
    capabilities: dict[str, dict[str, Any]] = {}
    scanned_files = 0

    _add_manifest_findings(extension_id, version, manifest, findings, capabilities)
    _add_dependency_source_findings(extension_id, version, manifest, findings)

    files = _walk_extension_files(path)
    artifact_inventory = _artifact_inventory(path, files)
    _add_artifact_inventory_findings(extension_id, version, artifact_inventory, known_bad_hashes or {}, findings, capabilities, path)
    _add_repository_posture_findings(extension_id, version, manifest, path, findings, artifact_inventory)

    for file in files:
        rel = file.relative_to(path).as_posix()
        suffix = file.suffix.lower()
        if suffix in BINARY_RISK_EXTS:
            continue
        if suffix not in TEXT_EXTS or _is_ignored_static_asset(rel):
            continue

        text = _read_text(file)
        if text is None:
            continue
        scanned_files += 1
        if suffix in EXEC_TEXT_EXTS:
            _add_code_findings(extension_id, version, rel, text, findings, capabilities)
        if suffix in EXEC_TEXT_EXTS or suffix in {".html", ".htm"}:
            _add_webview_csp_findings(extension_id, version, rel, text, findings)

    verdict, verdict_reason, malware_authority, severity, malware_score, risk_score, score_details = _classify_findings(findings)

    return ExtensionReport(
        instance_id=_stable_id(str(path)),
        extension_id=extension_id,
        name=name,
        publisher=publisher,
        version=version,
        description=str(manifest.get("description") or ""),
        repository=_repository_url(manifest.get("repository")),
        install_path=str(path),
        source=source,
        artifact_hash=_manifest_hash(path),
        severity=severity,
        verdict=verdict,
        malware_authority=malware_authority,
        verdict_reason=verdict_reason,
        malware_score=malware_score,
        risk_score=risk_score,
        score_details=score_details,
        capabilities=list(capabilities.values()),
        artifact_inventory=artifact_inventory,
        findings=findings,
        scanned_files=scanned_files,
        dependencies=_dependencies(manifest, path),
    )


def scan_vsix(path: Path, known_bad_hashes: dict[str, dict[str, Any]] | None = None) -> ExtensionReport:
    vsix_path = path.expanduser().resolve()
    vsix_hash, vsix_size = _hash_file(vsix_path)
    with tempfile.TemporaryDirectory(prefix="ide-scanner-vsix-") as tmp:
        tmp_root = Path(tmp)
        _safe_extract_vsix(vsix_path, tmp_root)
        extension_root = _find_extracted_extension_root(tmp_root)
        report = scan_extension(extension_root, source="vsix", known_bad_hashes=known_bad_hashes)
        report.install_path = str(vsix_path)
        report.source = "vsix"
        report.artifact_hash = vsix_hash[:24]
        report.artifact_inventory["vsix_hash"] = vsix_hash
        report.artifact_inventory["vsix_size_bytes"] = vsix_size
        report.artifact_inventory["source_artifact"] = vsix_path.name
        report.artifact_inventory["vsix_signature"] = _vsix_signature_status(tmp_root)
        _apply_vsix_known_bad_match(report, known_bad_hashes or {})
        return report


def _scan_discovered_target(target: dict[str, str], known_bad_hashes: dict[str, dict[str, Any]]) -> ExtensionReport:
    path = Path(target["path"])
    if target.get("type") == "vsix":
        return scan_vsix(path, known_bad_hashes=known_bad_hashes)
    return scan_extension(path, source=target.get("type", "vscode"), known_bad_hashes=known_bad_hashes)


def _registry_only_extension(extension_id: str) -> ExtensionReport:
    publisher, _, name = extension_id.partition(".")
    if not name:
        publisher = "unknown"
        name = extension_id
    return ExtensionReport(
        instance_id=_stable_id(f"registry:{extension_id}"),
        extension_id=extension_id,
        name=name,
        publisher=publisher,
        version="unknown",
        description="",
        repository="",
        install_path="",
        source="registry-id",
        artifact_hash="",
        severity="INFO",
        verdict="clean",
        malware_authority="none",
        verdict_reason="No local extension package was provided; only registry checks can run.",
        malware_score=0,
        risk_score=0,
        score_details=_empty_score_details(),
        capabilities=[],
        artifact_inventory=_empty_artifact_inventory(),
        findings=[],
        scanned_files=0,
        dependencies={},
    )


def _add_manifest_findings(
    extension_id: str,
    version: str,
    manifest: dict[str, Any],
    findings: list[Finding],
    capabilities: dict[str, dict[str, Any]],
) -> None:
    activation = [str(item) for item in manifest.get("activationEvents") or []]
    sensitive_prefixes = ("onUri", "onAuthenticationRequest", "onTerminal", "onTaskType", "onDebug", "onWebviewPanel", "onCustomEditor")
    for event in activation:
        if event == "*":
            findings.append(_finding(
                extension_id,
                version,
                "broad-activation",
                "activation",
                "LOW",
                0.52,
                "Extension activates for every workspace.",
                ["package.json"],
                "Prefer event-scoped activation unless the extension genuinely needs global startup behavior.",
            ))
        elif event == "onStartupFinished":
            findings.append(_finding(
                extension_id,
                version,
                "startup-activation",
                "activation",
                "LOW",
                0.45,
                "Extension runs automatically after IDE startup.",
                ["package.json"],
                "Review whether startup activation is necessary for this extension.",
            ))
        elif event.startswith(sensitive_prefixes):
            findings.append(_finding(
                extension_id,
                version,
                "sensitive-activation",
                "activation",
                "LOW",
                0.5,
                f"Extension activates on sensitive IDE event: {event}.",
                ["package.json"],
                "Check whether this activation path matches the extension's purpose.",
                {"activation_event": event},
            ))
    if activation:
        capabilities["activation"] = {"id": "activation", "evidence": activation}

    scripts = manifest.get("scripts") if isinstance(manifest.get("scripts"), dict) else {}
    for script_name in ("preinstall", "install", "postinstall", "vscode:uninstall"):
        if script_name in scripts:
            findings.append(_finding(
                extension_id,
                version,
                "lifecycle-script",
                "supply-chain",
                "MEDIUM",
                0.7,
                f"Package defines a lifecycle script: {script_name}.",
                ["package.json"],
                "Inspect lifecycle scripts because they execute outside normal extension UI flows.",
                {"script": script_name, "command": scripts[script_name]},
            ))
            capabilities.setdefault("lifecycle_scripts", {"id": "lifecycle_scripts", "evidence": []})["evidence"].append(script_name)
            _add_lifecycle_script_chain_findings(extension_id, version, script_name, str(scripts[script_name]), findings)

    contributes = manifest.get("contributes") if isinstance(manifest.get("contributes"), dict) else {}
    for key in ("debuggers", "taskDefinitions", "terminal"):
        if key in contributes:
            findings.append(_finding(
                extension_id,
                version,
                "powerful-ide-contribution",
                "ide-capability",
                "LOW",
                0.5,
                f"Extension contributes IDE capability: {key}.",
                ["package.json"],
                "Validate that this capability is core to the extension's stated function.",
                {"contribution": key},
            ))
            capabilities.setdefault("ide_contributions", {"id": "ide_contributions", "evidence": []})["evidence"].append(key)
    for key in ("languageModelTools", "chatParticipants", "mcpServers"):
        if key in contributes:
            findings.append(_finding(
                extension_id,
                version,
                "agentic-tooling",
                "agentic",
                "MEDIUM",
                0.66,
                f"Extension contributes agent-facing capability: {key}.",
                ["package.json"],
                "Review tool permissions and approval behavior before trusting agent-facing extensions.",
                {"contribution": key},
            ))
            capabilities.setdefault("agentic", {"id": "agentic", "evidence": []})["evidence"].append(key)
            _add_agent_capability_findings(extension_id, version, key, contributes.get(key), findings, capabilities)


def _add_dependency_source_findings(
    extension_id: str,
    version: str,
    manifest: dict[str, Any],
    findings: list[Finding],
) -> None:
    for name, spec in _manifest_runtime_dependencies(manifest).items():
        normalized = spec.strip().lower()
        if normalized in {"*", "latest", "x"} or normalized.endswith(".x"):
            findings.append(_finding(
                extension_id,
                version,
                "unpinned-dependency",
                "dependency",
                "LOW",
                0.62,
                f"Runtime dependency {name} uses an unpinned version specifier: {spec}.",
                ["package.json"],
                "Pin runtime dependencies or resolve them through a lockfile before trusting the artifact.",
                {"package": name, "specifier": spec},
            ))
        elif _is_mutable_dependency_spec(normalized):
            findings.append(_finding(
                extension_id,
                version,
                "mutable-dependency-source",
                "dependency",
                "MEDIUM",
                0.68,
                f"Runtime dependency {name} is loaded from a mutable or non-registry source: {spec}.",
                ["package.json"],
                "Verify the source is expected, immutable, and pinned to a commit or checksum.",
                {"package": name, "specifier": spec},
            ))


def _add_lifecycle_script_chain_findings(
    extension_id: str,
    version: str,
    script_name: str,
    command: str,
    findings: list[Finding],
) -> None:
    text = command.lower()
    evidence = {"script": script_name, "command": command}
    has_download = bool(re.search(r"\b(curl|wget|invoke-webrequest|irm|fetch|https?://)\b", text))
    has_execute = bool(re.search(r"\b(node|npm|npx|bash|sh|zsh|powershell|pwsh|python|chmod|exec)\b", text))
    if has_download and has_execute:
        findings.append(_finding(
            extension_id,
            version,
            "install-download-execute",
            "install-time",
            "HIGH",
            0.82,
            f"Lifecycle script {script_name} can download content and execute commands.",
            ["package.json"],
            "Require pinned URLs, checksums, signatures, and a clear install-time purpose.",
            evidence,
        ))
    if re.search(r"(\.npmrc|\.ssh|\.env|aws_access_key_id|aws_secret_access_key|npm_token|github_token|google_application_credentials)", text):
        findings.append(_finding(
            extension_id,
            version,
            "install-secret-access",
            "install-time",
            "HIGH",
            0.84,
            f"Lifecycle script {script_name} references credential material.",
            ["package.json"],
            "Do not allow install-time scripts to access local credentials without explicit justification.",
            evidence,
        ))
    if re.search(r"(base64\s+-d|frombase64string|eval|iex|invoke-expression|curl[^|]+\|\s*(bash|sh)|wget[^|]+\|\s*(bash|sh))", text):
        findings.append(_finding(
            extension_id,
            version,
            "install-shell-obfuscation",
            "install-time",
            "HIGH",
            0.82,
            f"Lifecycle script {script_name} contains obfuscated or piped shell execution.",
            ["package.json"],
            "Block or manually review obfuscated install-time shell behavior.",
            evidence,
        ))
    if has_download and re.search(r"(telemetry|analytics|posthog|segment|mixpanel|amplitude|track|metrics)", text):
        findings.append(_finding(
            extension_id,
            version,
            "install-network-telemetry",
            "install-time",
            "MEDIUM",
            0.62,
            f"Lifecycle script {script_name} appears to send install-time telemetry.",
            ["package.json"],
            "Confirm telemetry is declared, minimal, and opt-out capable.",
            evidence,
        ))


def _add_agent_capability_findings(
    extension_id: str,
    version: str,
    key: str,
    value: Any,
    findings: list[Finding],
    capabilities: dict[str, dict[str, Any]],
) -> None:
    text = json.dumps(value, sort_keys=True).lower() if value is not None else ""
    if not text:
        return
    checks = [
        ("agent-shell-tool", r"\b(shell|terminal|command|exec|spawn|process|subprocess|bash|powershell|cmd)\b", "Agent-facing tool surface can run shell or process commands.", "agent_shell"),
        ("agent-filesystem-tool", r"\b(file|filesystem|workspace|readfile|writefile|path|directory|folder|glob)\b", "Agent-facing tool surface can read or write files.", "agent_filesystem"),
        ("agent-network-tool", r"\b(http|https|url|fetch|request|websocket|network|api)\b", "Agent-facing tool surface can reach network resources.", "agent_network"),
    ]
    for rule_id, pattern, summary, capability_id in checks:
        if re.search(pattern, text):
            findings.append(_finding(
                extension_id,
                version,
                rule_id,
                "agentic",
                "MEDIUM",
                0.68,
                summary,
                ["package.json"],
                "Review agent tool schemas, approval requirements, and data boundaries.",
                {"contribution": key},
            ))
            capabilities.setdefault(capability_id, {"id": capability_id, "evidence": []})["evidence"].append(key)
    if key == "mcpServers":
        findings.append(_finding(
            extension_id,
            version,
            "mcp-server-command",
            "agentic",
            "MEDIUM",
            0.66,
            "Extension registers an MCP server command or server definition.",
            ["package.json"],
            "Verify the MCP server command, package source, pinning, and tool permissions.",
            {"contribution": key},
        ))
    if re.search(r"\b(prompt|instruction|webview|markdown|html|remotecontent|usercontent)\b", text) and re.search(r"\b(tool|command|execute|shell|terminal)\b", text):
        findings.append(_finding(
            extension_id,
            version,
            "agent-prompt-injection-sink",
            "agentic",
            "MEDIUM",
            0.58,
            "Agent-facing contribution may route untrusted content into tool execution context.",
            ["package.json"],
            "Review prompt/tool boundaries and sanitize untrusted content before tool invocation.",
            {"contribution": key},
        ))


def _add_repository_posture_findings(
    extension_id: str,
    version: str,
    manifest: dict[str, Any],
    path: Path,
    findings: list[Finding],
    artifact_inventory: dict[str, Any] | None = None,
) -> None:
    if not _repository_url(manifest.get("repository")):
        findings.append(_finding(
            extension_id,
            version,
            "repo-url-missing",
            "reputation",
            "LOW",
            0.5,
            "Extension manifest does not declare a source repository.",
            ["package.json"],
            "A source repository improves provenance review but absence is not malware evidence.",
        ))
    if not any((path / item).exists() for item in ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md")):
        findings.append(_finding(
            extension_id,
            version,
            "security-policy-missing",
            "repository-posture",
            "LOW",
            0.42,
            "No local security policy file was found in the packaged artifact.",
            [],
            "Treat as posture context only; small extensions may not ship security policy files.",
        ))
    if not any((path / item).exists() for item in ("LICENSE", "LICENSE.md", "LICENSE.txt", "license", "license.md")):
        findings.append(_finding(
            extension_id,
            version,
            "license-missing",
            "repository-posture",
            "LOW",
            0.4,
            "No local LICENSE file was found in the packaged artifact.",
            [],
            "Treat as posture context only; absence of a license file is not malware evidence.",
        ))
    for artifact in (artifact_inventory or {}).get("risky_artifacts", []):
        if artifact.get("kind") != "native":
            continue
        rel = str(artifact["path"])
        findings.append(_finding(
            extension_id,
            version,
            "repo-binary-artifacts",
            "repository-posture",
            "LOW",
            0.5,
            f"Packaged artifact ships a committed native binary: {rel}.",
            [rel],
            "Confirm committed binaries are expected and, where possible, built reproducibly rather than checked in directly.",
        ))
    for workflow in (path / ".github" / "workflows").glob("*.yml"):
        text = _read_text(workflow) or ""
        _add_workflow_findings(extension_id, version, workflow.relative_to(path).as_posix(), text, findings)
    for workflow in (path / ".github" / "workflows").glob("*.yaml"):
        text = _read_text(workflow) or ""
        _add_workflow_findings(extension_id, version, workflow.relative_to(path).as_posix(), text, findings)


def _add_workflow_findings(extension_id: str, version: str, rel: str, text: str, findings: list[Finding]) -> None:
    lowered = text.lower()
    if "pull_request_target" in lowered or "permissions: write-all" in lowered or re.search(r"contents:\s*write", lowered):
        findings.append(_finding(
            extension_id,
            version,
            "dangerous-github-workflow",
            "repository-posture",
            "MEDIUM",
            0.66,
            f"GitHub Actions workflow has dangerous supply-chain posture: {rel}.",
            [rel],
            "Review workflow permissions and untrusted pull request execution paths.",
        ))
    has_permissions_block = bool(re.search(r"^permissions:\s*$|^permissions:\s*\S", lowered, re.MULTILINE))
    grants_broad_write = bool(re.search(r"id-token:\s*write", lowered)) and bool(re.search(r"contents:\s*write", lowered))
    uses_github_token = "github_token" in lowered or "secrets.github_token" in lowered
    if grants_broad_write or (uses_github_token and not has_permissions_block):
        findings.append(_finding(
            extension_id,
            version,
            "workflow-token-permissions-broad",
            "repository-posture",
            "LOW",
            0.5,
            f"GitHub Actions workflow {rel} grants broad token permissions or relies on the implicit default token scope.",
            [rel],
            "Declare an explicit least-privilege `permissions:` block scoped to only the jobs that need it.",
        ))


def _add_artifact_inventory_findings(
    extension_id: str,
    version: str,
    artifact_inventory: dict[str, Any],
    known_bad_hashes: dict[str, dict[str, Any]],
    findings: list[Finding],
    capabilities: dict[str, dict[str, Any]],
    path: Path | None = None,
) -> None:
    all_paths = {str(entry.get("path")) for entry in artifact_inventory.get("_all_file_hashes", [])}
    for artifact in artifact_inventory["risky_artifacts"]:
        rel = str(artifact["path"])
        kind = str(artifact["kind"])
        rule_id = "native-or-packed-artifact" if kind == "native" else "packed-artifact"
        category = "artifact" if kind == "native" else "provenance"
        recommendation = (
            "Confirm the binary is expected, signed, and published by the same trusted vendor."
            if kind == "native"
            else "Inspect archive contents and verify the packed artifact is expected and reproducible."
        )
        findings.append(_finding(
            extension_id,
            version,
            rule_id,
            category,
            "MEDIUM",
            0.62 if kind == "native" else 0.58,
            f"Extension contains a {kind} artifact: {rel}.",
            [rel],
            recommendation,
            {
                "sha256": artifact["sha256"],
                "size_bytes": artifact["size_bytes"],
                "kind": kind,
            },
        ))
        capability_id = "native_code" if kind == "native" else "packed_artifacts"
        capabilities.setdefault(capability_id, {"id": capability_id, "evidence": []})["evidence"].append(rel)

        if kind == "native" and not _has_origin_evidence(path, rel, all_paths):
            findings.append(_finding(
                extension_id,
                version,
                "binary-without-origin",
                "provenance",
                "MEDIUM",
                0.55,
                f"Native binary {rel} has no companion checksum or signature file and no documented provenance.",
                [rel],
                "Publish a checksum/signature alongside the binary or document its build origin in SECURITY.md/README.",
                {"sha256": artifact["sha256"]},
            ))

    matches = _known_bad_matches(artifact_inventory, known_bad_hashes)
    if matches:
        artifact_inventory["known_bad_matches"] = matches
    for match in matches:
        rel = str(match.get("path") or "package")
        source = str(match.get("source") or "known-bad hash feed")
        findings.append(_finding(
            extension_id,
            version,
            "known-bad-artifact",
            "confirmed-intelligence",
            "CRITICAL",
            0.99,
            f"Artifact hash matches a known-bad entry from {source}.",
            [] if rel == "package" else [rel],
            "Block or remove this extension. A local artifact hash matched confirmed malicious intelligence.",
            match,
        ))


def _has_origin_evidence(path: Path | None, rel: str, all_paths: set[str]) -> bool:
    companions = {f"{rel}.sha256", f"{rel}.sig", f"{rel}.asc", f"{rel}.p7s"}
    if companions & all_paths:
        return True
    if path is None:
        return False
    stem = rel.rsplit("/", 1)[-1]
    for doc_name in ("SECURITY.md", "README.md", "docs/SECURITY.md"):
        text = _read_text(path / doc_name)
        if text and stem in text:
            return True
    return False


def _add_code_findings(
    extension_id: str,
    version: str,
    rel: str,
    text: str,
    findings: list[Finding],
    capabilities: dict[str, dict[str, Any]],
) -> None:
    secret_refs = [(secret_id, label) for secret_id, label, regex in SECRET_PATTERNS if regex.search(text)]
    has_file_read = bool(FILE_READ_RE.search(text))
    has_file_write = bool(FILE_WRITE_RE.search(text))
    has_network = bool(NETWORK_SINK_RE.search(text))
    has_encode = bool(ENCODE_ARCHIVE_RE.search(text))
    has_destructive = bool(DESTRUCTIVE_RE.search(text))
    has_download = bool(DOWNLOAD_RE.search(text))
    has_obfuscation = bool(re.search(r"(atob\(|buffer\.from\([^)]*,\s*['\"]base64['\"]|fromcharcode|\\x[0-9a-f]{2})", text, re.I))
    has_dynamic_exec = bool(re.search(r"\b(eval\(|new Function\(|vm\.runIn|import\s*\(|exec\(|spawn\()", text))
    has_exec_file = bool(re.search(r"\b(execFile|execFileSync)\b", text))
    has_shell_exec = bool(re.search(r"\b(exec|execSync)\s*\(|shell\s*:\s*true", text))
    has_configured_cli = has_exec_file and bool(re.search(r"getConfiguration\(|config\.get\(|executablePath|cliPath", text))
    has_editor_input = bool(re.search(r"activeTextEditor|document\.getText|selection|workspace\.workspaceFolders|uri\.fsPath|fileName", text))
    has_persistence = bool(re.search(r"(\.bashrc|\.zshrc|\.profile|crontab|launchagents|runonce|scheduledtask|systemd|update_rc|startup\s*folder)", text, re.I))
    has_agent_surface = bool(re.search(r"(languageModel|chatParticipant|mcp|toolInvocation|invokeTool)", text, re.I))
    secret_regex = _combined_secret_regex(secret_refs)

    for rule in CODE_RULES:
        if not rule.regex.search(text):
            continue
        findings.append(_finding(
            extension_id,
            version,
            rule.id,
            rule.category,
            rule.severity,
            rule.confidence,
            rule.summary,
            [rel],
            "Treat this as review evidence unless it combines with credential, network, download, or destructive behavior.",
        ))
        capabilities.setdefault(rule.capability, {"id": rule.capability, "evidence": []})["evidence"].append(rel)

    if _is_generated_code_blob(rel, text):
        return

    if has_configured_cli and not has_shell_exec and not has_download:
        findings.append(_finding(
            extension_id,
            version,
            "safe-configured-cli-execution",
            "execution",
            "INFO",
            0.72,
            "Code executes a configured local CLI through execFile-style process execution.",
            [rel],
            "Treat as contextual when the binary path is user-configured and arguments are explicit.",
        ))
    if has_shell_exec:
        findings.append(_finding(
            extension_id,
            version,
            "dynamic-shell-execution",
            "execution",
            "MEDIUM",
            0.72,
            "Code uses shell-style process execution.",
            [rel],
            "Review command construction and avoid shell execution for untrusted input.",
        ))
    if (has_shell_exec or has_dynamic_exec) and has_editor_input:
        findings.append(_finding(
            extension_id,
            version,
            "untrusted-input-execution",
            "execution",
            "MEDIUM",
            0.62,
            "Code appears to combine IDE/workspace input with process execution.",
            [rel],
            "Ensure file paths, document content, and workspace values are passed as arguments without shell interpolation.",
        ))

    for secret_id, label in secret_refs:
        findings.append(_finding(
            extension_id,
            version,
            f"secret-reference:{secret_id}",
            "credential-access",
            "LOW",
            0.56,
            f"Code references {label}.",
            [rel],
            "Confirm that the extension only reads secrets with explicit user intent and does not transmit them.",
        ))

    if secret_refs and has_file_read and _features_nearby(text, [secret_regex, FILE_READ_RE]):
        labels = ", ".join(label for _, label in secret_refs)
        findings.append(_finding(
            extension_id,
            version,
            "credential-file-read",
            "credential-access",
            "MEDIUM",
            0.82,
            f"Code can read local files and references sensitive material: {labels}.",
            [rel],
            "Require a product reason and user-visible flow for reading credential files.",
        ))
    if secret_refs and has_file_read and has_network and _features_nearby(text, [secret_regex, FILE_READ_RE, NETWORK_SINK_RE]):
        findings.append(_finding(
            extension_id,
            version,
            "credential-exfiltration-chain",
            "credential-access",
            "HIGH",
            0.9,
            "Code combines credential references, local file reads, and outbound network writes.",
            [rel],
            "Remove or block this extension until the data flow is manually verified.",
        ))
    if has_destructive and has_encode and has_network and _features_nearby(text, [DESTRUCTIVE_RE, ENCODE_ARCHIVE_RE, NETWORK_SINK_RE]):
        findings.append(_finding(
            extension_id,
            version,
            "destructive-transfer-chain",
            "destructive-activity",
            "HIGH",
            0.84,
            "Code combines destructive file activity with archive/encoding and network behavior.",
            [rel],
            "Treat as suspicious unless this is a clearly documented backup, cleanup, or migration tool.",
        ))
    if has_obfuscation and has_dynamic_exec and has_network and _features_nearby(text, [
        re.compile(r"(atob\(|buffer\.from\([^)]*,\s*['\"]base64['\"]|fromcharcode|\\x[0-9a-f]{2})", re.I),
        re.compile(r"\b(eval\(|new Function\(|vm\.runIn|import\s*\(|exec\(|spawn\()"),
        NETWORK_SINK_RE,
    ]):
        findings.append(_finding(
            extension_id,
            version,
            "obfuscation-execution-network",
            "execution",
            "HIGH",
            0.82,
            "Code combines obfuscation, dynamic execution, and network behavior.",
            [rel],
            "Treat as suspicious unless the generated or dynamic code path is clearly documented and reproducible.",
        ))
    if has_persistence and has_file_write and (has_network or has_dynamic_exec) and _features_nearby(text, [
        re.compile(r"(\.bashrc|\.zshrc|\.profile|crontab|launchagents|runonce|scheduledtask|systemd|update_rc|startup\s*folder)", re.I),
        FILE_WRITE_RE,
        NETWORK_SINK_RE if has_network else re.compile(r"\b(eval\(|new Function\(|vm\.runIn|import\s*\(|exec\(|spawn\()"),
    ]):
        findings.append(_finding(
            extension_id,
            version,
            "persistence-chain",
            "persistence",
            "HIGH",
            0.84,
            "Code appears to modify persistence locations and execute or communicate externally.",
            [rel],
            "Block or manually review persistence behavior in IDE extensions.",
        ))
    if has_agent_surface and secret_refs and has_network and _features_nearby(text, [
        re.compile(r"(languageModel|chatParticipant|mcp|toolInvocation|invokeTool)", re.I),
        secret_regex,
        NETWORK_SINK_RE,
    ]):
        findings.append(_finding(
            extension_id,
            version,
            "agent-data-exfil-chain",
            "agentic",
            "HIGH",
            0.84,
            "Agent-facing code combines sensitive references with outbound network behavior.",
            [rel],
            "Review agent tool data boundaries and approval prompts before trusting this extension.",
        ))
    if has_download and any(item.rule_id == "process-execution" and rel in item.file_refs for item in findings) and _features_nearby(text, [
        DOWNLOAD_RE,
        re.compile(r"\b(child_process|spawnSync|execSync|execFileSync|spawn\(|exec\(|ProcessBuilder|Runtime\.getRuntime\(\)\.exec)"),
    ]):
        findings.append(_finding(
            extension_id,
            version,
            "download-and-execute",
            "execution",
            "HIGH",
            0.82,
            "Code can download content and execute local processes from the same file.",
            [rel],
            "Verify the download source, integrity checks, and execution purpose.",
        ))


def _combined_secret_regex(secret_refs: list[tuple[str, str]]) -> re.Pattern[str]:
    if not secret_refs:
        return re.compile(r"a\Ab")
    patterns = [
        regex.pattern
        for secret_id, _, regex in SECRET_PATTERNS
        if any(secret_id == found_id for found_id, _ in secret_refs)
    ]
    return re.compile("|".join(f"(?:{pattern})" for pattern in patterns), re.I)


def _features_nearby(text: str, patterns: list[re.Pattern[str]], window_lines: int = 45) -> bool:
    if not patterns:
        return False
    line_hits: list[list[int]] = []
    lines = text.splitlines() or [text]
    for pattern in patterns:
        hits = [index for index, line in enumerate(lines) if pattern.search(line)]
        if not hits:
            return False
        line_hits.append(hits)
    for anchor in line_hits[0]:
        if all(any(abs(hit - anchor) <= window_lines for hit in hits) for hits in line_hits[1:]):
            return True
    return False


WEBVIEW_SURFACE_RE = re.compile(r"createWebviewPanel\(|registerWebviewViewProvider\(|\.webview\.html\s*=", re.I)
CSP_META_RE = re.compile(r"<meta[^>]+http-equiv\s*=\s*[\"']Content-Security-Policy[\"'][^>]*>", re.I)
CSP_UNSAFE_DIRECTIVE_RE = re.compile(r"unsafe-inline|unsafe-eval|script-src[^;\"']*\*", re.I)


def _add_webview_csp_findings(extension_id: str, version: str, rel: str, text: str, findings: list[Finding]) -> None:
    if not WEBVIEW_SURFACE_RE.search(text):
        return
    csp_match = CSP_META_RE.search(text)
    if not csp_match:
        findings.append(_finding(
            extension_id,
            version,
            "webview-csp-missing",
            "webview",
            "MEDIUM",
            0.6,
            f"Extension creates a webview in {rel} without a detected Content-Security-Policy meta tag.",
            [rel],
            "Add a strict Content-Security-Policy meta tag to every webview HTML document, scoping script-src/style-src to the webview's own origin and the webview.cspSource.",
        ))
        return
    if CSP_UNSAFE_DIRECTIVE_RE.search(csp_match.group(0)):
        findings.append(_finding(
            extension_id,
            version,
            "webview-csp-unsafe-directive",
            "webview",
            "MEDIUM",
            0.58,
            f"Extension webview in {rel} declares a Content-Security-Policy with an unsafe directive (unsafe-inline, unsafe-eval, or a wildcard script-src).",
            [rel],
            "Avoid unsafe-inline, unsafe-eval, and wildcard script-src in webview CSP; use nonces or content hashes instead.",
        ))


def _apply_registry_findings(extensions: list[ExtensionReport], raw_findings: list[dict[str, Any]]) -> None:
    by_id = {extension.extension_id: extension for extension in extensions}
    for raw in raw_findings:
        extension = by_id.get(str(raw.get("extension_id")))
        if extension is None:
            continue
        finding = _finding(
            extension.extension_id,
            extension.version,
            str(raw["rule_id"]),
            str(raw["category"]),
            str(raw["severity"]),
            float(raw["confidence"]),
            str(raw["evidence_summary"]),
            [],
            "Use registry evidence as high-confidence supply-chain signal and remove the extension if malicious.",
            _evidence_with_class(str(raw["rule_id"]), raw.get("evidence")),
        )
        extension.findings.append(finding)
        extension.severity = rank_severity(extension.severity, finding.severity)
        extension.risk_score = max(extension.risk_score, finding.score)
        if _is_confirmed_malware_finding(finding):
            extension.verdict = "malicious"
            extension.verdict_reason = "Confirmed registry or malicious-package evidence matched this extension."
            extension.malware_score = max(extension.malware_score, 95)
            extension.risk_score = max(extension.risk_score, 95)
        elif _is_suspicious_removed_finding(finding) and extension.verdict in {"clean", "review"}:
            extension.verdict = "suspicious"
            extension.verdict_reason = "Marketplace removal evidence says this extension was removed as suspicious."
        elif finding.severity == "HIGH" and extension.verdict == "clean":
            extension.verdict = "suspicious"
            extension.verdict_reason = "Dependency registry evidence produced a high-confidence vulnerability signal."
        elif extension.verdict == "clean" and _evidence_class(str(raw["rule_id"]), raw.get("evidence")) != "reputation":
            extension.verdict = "review"
            extension.verdict_reason = "Registry evidence found dependency risk that needs review."
        (
            extension.verdict,
            extension.verdict_reason,
            extension.malware_authority,
            extension.severity,
            extension.malware_score,
            extension.risk_score,
            extension.score_details,
        ) = _classify_findings(extension.findings)


def _apply_sandbox_observations(extensions: list[ExtensionReport], observations: dict[str, list[dict[str, Any]]]) -> None:
    if not observations:
        return
    by_id = {extension.extension_id: extension for extension in extensions}
    for extension_id, items in observations.items():
        extension = by_id.get(extension_id)
        if extension is None:
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            finding = _sandbox_observation_finding(extension, item)
            if finding is None:
                continue
            extension.findings.append(finding)
        (
            extension.verdict,
            extension.verdict_reason,
            extension.malware_authority,
            extension.severity,
            extension.malware_score,
            extension.risk_score,
            extension.score_details,
        ) = _classify_findings(extension.findings)


def _apply_threat_feed(extensions: list[ExtensionReport], feed: dict[str, dict[str, Any]]) -> None:
    if not feed:
        return
    by_id = {extension.extension_id.lower(): extension for extension in extensions}
    for extension_id, metadata in feed.items():
        extension = by_id.get(extension_id.lower())
        if extension is None:
            continue
        classification = str(metadata.get("classification") or metadata.get("verdict") or "").lower()
        malicious = classification in {"malware", "malicious"}
        severity = "CRITICAL" if malicious else "HIGH"
        rule_id = "trusted-threat-feed-hit" if malicious else "marketplace-removed-package"
        evidence = dict(metadata)
        evidence.setdefault("extension_id", extension.extension_id)
        evidence.setdefault("type", classification or "suspicious")
        finding = _finding(
            extension.extension_id,
            extension.version,
            rule_id,
            "confirmed-intelligence" if malicious else "provenance",
            severity,
            0.97 if malicious else 0.82,
            f"Extension matched configured threat feed as {classification or 'suspicious'}.",
            [],
            "Block malware feed hits. Review non-malware feed hits according to source confidence.",
            evidence,
        )
        extension.findings.append(finding)
        (
            extension.verdict,
            extension.verdict_reason,
            extension.malware_authority,
            extension.severity,
            extension.malware_score,
            extension.risk_score,
            extension.score_details,
        ) = _classify_findings(extension.findings)


def _load_threat_feed(path: Path | str | None = None) -> dict[str, dict[str, Any]]:
    raw_path = str(path or os.environ.get("IDE_SCANNER_THREAT_FEED_FILE") or "")
    if not raw_path:
        return {}
    try:
        parsed = json.loads(Path(raw_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    entries = parsed.get("extensions") if isinstance(parsed, dict) else parsed
    out: dict[str, dict[str, Any]] = {}
    if isinstance(entries, list):
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            extension_id = str(entry.get("extension_id") or entry.get("id") or "").strip()
            if extension_id:
                out[extension_id] = dict(entry)
    elif isinstance(entries, dict):
        for extension_id, metadata in entries.items():
            if isinstance(extension_id, str):
                out[extension_id] = dict(metadata) if isinstance(metadata, dict) else {"classification": str(metadata)}
    return out


def _sandbox_observation_finding(extension: ExtensionReport, item: dict[str, Any]) -> Finding | None:
    kind = str(item.get("kind") or item.get("type") or item.get("rule_id") or "").strip()
    mapping = {
        "secret_read": ("observed-secret-read", "MEDIUM", 0.78, "Sandbox observed reads of canary or sensitive credential paths."),
        "secret_exfil": ("observed-secret-exfil", "HIGH", 0.9, "Sandbox observed canary or sensitive data leaving the process."),
        "download_execute": ("observed-download-execute", "HIGH", 0.86, "Sandbox observed downloaded content being executed or loaded."),
        "persistence": ("observed-persistence", "HIGH", 0.84, "Sandbox observed persistence or autorun behavior."),
        "destructive": ("observed-destructive-behavior", "HIGH", 0.88, "Sandbox observed destructive file behavior."),
        "unexpected_network": ("observed-unexpected-network", "MEDIUM", 0.68, "Sandbox observed network traffic to an unexpected destination."),
        "process_exec": ("observed-process-exec", "MEDIUM", 0.66, "Sandbox observed process execution."),
        "filesystem_write": ("observed-filesystem-write", "LOW", 0.58, "Sandbox observed filesystem writes."),
    }
    if kind not in mapping:
        return None
    rule_id, severity, confidence, summary = mapping[kind]
    evidence = dict(item)
    evidence["evidence_class"] = "observed"
    file_refs = [str(ref) for ref in item.get("file_refs", [])] if isinstance(item.get("file_refs"), list) else []
    return _finding(
        extension.extension_id,
        extension.version,
        rule_id,
        "dynamic-sandbox",
        severity,
        confidence,
        summary,
        file_refs,
        "Review the sandbox trace. Dynamic observations are strong evidence but not authoritative malware without confirmed intelligence.",
        evidence,
    )


def _load_sandbox_observations(path: Path | str | None = None) -> dict[str, list[dict[str, Any]]]:
    raw_path = str(path or os.environ.get("IDE_SCANNER_SANDBOX_OBSERVATIONS_FILE") or "")
    if not raw_path:
        return {}
    try:
        parsed = json.loads(Path(raw_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if isinstance(parsed, dict) and isinstance(parsed.get("extensions"), dict):
        parsed = parsed["extensions"]
    if not isinstance(parsed, dict):
        return {}
    out: dict[str, list[dict[str, Any]]] = {}
    for extension_id, items in parsed.items():
        if isinstance(extension_id, str) and isinstance(items, list):
            out[extension_id] = [item for item in items if isinstance(item, dict)]
    return out


def _build_report(
    extensions: list[ExtensionReport],
    registry: dict[str, Any],
    previous_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    by_verdict: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    max_score = 0
    max_malware_score = 0
    max_risk_score = 0
    for extension in extensions:
        by_verdict[extension.verdict] = by_verdict.get(extension.verdict, 0) + 1
        by_severity[extension.severity] = by_severity.get(extension.severity, 0) + 1
        max_malware_score = max(max_malware_score, extension.malware_score)
        max_risk_score = max(max_risk_score, extension.risk_score)
        max_score = max(max_score, extension.risk_score)

    now = dt.datetime.now(dt.UTC)
    version_deltas = _version_deltas(extensions, previous_report)
    posture_metrics = scan_posture()
    posture_summary = summarize_posture(posture_metrics)
    summary = {
        "total_extensions": len(extensions),
        "by_verdict": by_verdict,
        "by_severity": by_severity,
        "max_score": max_score,
        "max_malware_score": max_malware_score,
        "max_risk_score": max_risk_score,
        "posture_score": posture_summary["score"],
        "posture_status": posture_summary["status"],
    }
    return {
        "schema_version": "0.1.0",
        "scan_id": f"scan_{now.strftime('%Y%m%d%H%M%S')}",
        "created_at": now.isoformat().replace("+00:00", "Z"),
        "privacy_mode": "local-metadata-and-static-features",
        "registry_checks": registry,
        "summary": summary,
        "human_summary": _human_summary(summary, extensions, registry, version_deltas, posture_summary),
        "version_deltas": version_deltas,
        "posture_summary": posture_summary,
        "posture": [metric.to_dict() for metric in posture_metrics],
        "extensions": [extension.to_dict() for extension in extensions],
    }


def _human_summary(
    summary: dict[str, Any],
    extensions: list[ExtensionReport],
    registry: dict[str, Any],
    version_deltas: list[dict[str, Any]],
    posture_summary: dict[str, Any] | None = None,
) -> list[str]:
    by_verdict = summary.get("by_verdict", {})
    notes = [
        f"Scanned {summary.get('total_extensions', 0)} extension(s): "
        f"{by_verdict.get('malicious', 0)} malicious, "
        f"{by_verdict.get('suspicious', 0)} suspicious, "
        f"{by_verdict.get('review', 0)} review, "
        f"{by_verdict.get('clean', 0)} clean."
    ]
    if registry.get("enabled"):
        notes.append(
            f"Online registry checks returned {len(registry.get('findings', []))} finding(s) "
            f"and {len(registry.get('errors', []))} error(s)."
        )
    if posture_summary:
        counts = posture_summary.get("counts", {})
        notes.append(
            f"IDE/client posture: {posture_summary.get('status', 'unknown')} "
            f"with score {posture_summary.get('score', 0)}/100 "
            f"({counts.get('failure', 0)} failures, {counts.get('warning', 0)} warnings)."
        )
    top = sorted(extensions, key=lambda item: (item.malware_score, item.risk_score), reverse=True)[:3]
    if top:
        notes.append("Highest-priority items: " + "; ".join(
            f"{item.extension_id}={item.verdict}/M{item.malware_score}/R{item.risk_score}"
            for item in top
        ))
    if version_deltas:
        notes.append(f"Compared with previous report: {len(version_deltas)} extension(s) changed version, score, dependency, or artifact inventory.")
    return notes


def _load_previous_report(path: Path | str | None) -> dict[str, Any] | None:
    if not path:
        return None
    try:
        parsed = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _version_deltas(extensions: list[ExtensionReport], previous_report: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not previous_report:
        return []
    previous_extensions = previous_report.get("extensions")
    if not isinstance(previous_extensions, list):
        return []
    by_id = {
        str(item.get("extension_id")): item
        for item in previous_extensions
        if isinstance(item, dict) and item.get("extension_id")
    }
    deltas: list[dict[str, Any]] = []
    for extension in extensions:
        previous = by_id.get(extension.extension_id)
        if not previous:
            continue
        delta: dict[str, Any] = {
            "extension_id": extension.extension_id,
            "previous_version": previous.get("version"),
            "current_version": extension.version,
            "changes": [],
        }
        if previous.get("version") != extension.version:
            delta["changes"].append("version")
        if previous.get("verdict") != extension.verdict:
            delta["changes"].append("verdict")
        if int(previous.get("risk_score") or 0) != extension.risk_score:
            delta["changes"].append("risk_score")
        if int(previous.get("malware_score") or 0) != extension.malware_score:
            delta["changes"].append("malware_score")
        previous_deps = set((previous.get("dependencies") or {}).keys()) if isinstance(previous.get("dependencies"), dict) else set()
        current_deps = set(extension.dependencies.keys())
        added_deps = sorted(current_deps - previous_deps)
        removed_deps = sorted(previous_deps - current_deps)
        if added_deps or removed_deps:
            delta["changes"].append("dependencies")
            delta["added_dependencies"] = added_deps[:25]
            delta["removed_dependencies"] = removed_deps[:25]
        previous_artifacts = _artifact_paths(previous)
        current_artifacts = {str(item.get("path")) for item in extension.artifact_inventory.get("risky_artifacts", []) if isinstance(item, dict)}
        added_artifacts = sorted(current_artifacts - previous_artifacts)
        removed_artifacts = sorted(previous_artifacts - current_artifacts)
        if added_artifacts or removed_artifacts:
            delta["changes"].append("risky_artifacts")
            delta["added_risky_artifacts"] = added_artifacts[:25]
            delta["removed_risky_artifacts"] = removed_artifacts[:25]
        if delta["changes"]:
            deltas.append(delta)
    return deltas


def _artifact_paths(extension: dict[str, Any]) -> set[str]:
    inventory = extension.get("artifact_inventory")
    if not isinstance(inventory, dict):
        return set()
    artifacts = inventory.get("risky_artifacts")
    if not isinstance(artifacts, list):
        return set()
    return {str(item.get("path")) for item in artifacts if isinstance(item, dict)}


def _empty_artifact_inventory() -> dict[str, Any]:
    return {
        "hash_algorithm": "sha256",
        "package_hash": "",
        "files_hashed": 0,
        "total_bytes_hashed": 0,
        "risky_artifacts": [],
        "known_bad_matches": [],
        "vsix_signature": {"present": False, "verified": False, "reason": "not-vsix"},
        "_all_file_hashes": [],
    }


def _vsix_signature_status(root: Path) -> dict[str, Any]:
    signature_files = [
        item.relative_to(root).as_posix()
        for item in root.rglob("*")
        if item.is_file() and (
            item.name.lower().endswith((".signature.p7s", ".sig", ".p7s"))
            or item.relative_to(root).as_posix().lower().startswith("meta-inf/")
        )
    ]
    return {
        "present": bool(signature_files),
        "verified": False,
        "reason": "signature-file-found-verification-not-implemented" if signature_files else "signature-file-not-found",
        "files": signature_files[:10],
    }


def _artifact_inventory(path: Path, files: list[Path]) -> dict[str, Any]:
    inventory = _empty_artifact_inventory()
    package_digest = hashlib.sha256()
    all_hashes: list[dict[str, Any]] = []
    risky_artifacts: list[dict[str, Any]] = []
    total_bytes = 0

    for file in sorted(files):
        rel = file.relative_to(path).as_posix()
        digest, size = _hash_file(file)
        if not digest:
            continue
        total_bytes += size
        all_hashes.append({"path": rel, "sha256": digest, "size_bytes": size})
        package_digest.update(rel.encode("utf-8"))
        package_digest.update(b"\0")
        package_digest.update(digest.encode("ascii"))
        package_digest.update(b"\0")
        suffix = file.suffix.lower()
        if suffix in BINARY_RISK_EXTS or suffix in PACKED_RISK_EXTS:
            risky_artifacts.append({
                "path": rel,
                "sha256": digest,
                "size_bytes": size,
                "kind": "native" if suffix in BINARY_RISK_EXTS else "packed",
            })

    inventory["package_hash"] = package_digest.hexdigest() if all_hashes else ""
    inventory["files_hashed"] = len(all_hashes)
    inventory["total_bytes_hashed"] = total_bytes
    inventory["risky_artifacts"] = risky_artifacts
    inventory["_all_file_hashes"] = all_hashes
    return inventory


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                digest.update(chunk)
    except OSError:
        return "", 0
    return digest.hexdigest(), size


def _known_bad_matches(
    artifact_inventory: dict[str, Any],
    known_bad_hashes: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    if not known_bad_hashes:
        return []
    matches: list[dict[str, Any]] = []
    package_hash = str(artifact_inventory.get("package_hash") or "").lower()
    if package_hash in known_bad_hashes:
        matches.append(_known_bad_match("package", package_hash, known_bad_hashes[package_hash]))

    for item in artifact_inventory.get("_all_file_hashes", []):
        if not isinstance(item, dict):
            continue
        digest = str(item.get("sha256") or "").lower()
        if digest not in known_bad_hashes:
            continue
        match = _known_bad_match(str(item.get("path") or ""), digest, known_bad_hashes[digest])
        match["size_bytes"] = item.get("size_bytes", 0)
        matches.append(match)
    return matches


def _known_bad_match(path: str, digest: str, metadata: dict[str, Any]) -> dict[str, Any]:
    match = dict(metadata)
    match.update({
        "path": path,
        "sha256": digest,
        "evidence_class": "confirmed",
    })
    return match


def _load_known_bad_hashes(path: Path | str | None = None) -> dict[str, dict[str, Any]]:
    raw_path = str(path or os.environ.get("IDE_SCANNER_KNOWN_BAD_HASHES_FILE") or "")
    if not raw_path:
        return {}
    try:
        text = Path(raw_path).read_text(encoding="utf-8")
    except OSError:
        return {}

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return _load_line_based_hashes(text, raw_path)
    return _load_json_hashes(parsed, raw_path)


def _load_json_hashes(parsed: Any, source_path: str) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    if isinstance(parsed, dict):
        entries = parsed.get("hashes")
        if isinstance(entries, list):
            _collect_json_hash_entries(entries, out, source_path)
            return out
        for digest, metadata in parsed.items():
            if isinstance(digest, str) and SHA256_RE.fullmatch(digest.strip()):
                out[digest.lower()] = _hash_metadata(metadata, source_path)
    elif isinstance(parsed, list):
        _collect_json_hash_entries(parsed, out, source_path)
    return out


def _collect_json_hash_entries(entries: list[Any], out: dict[str, dict[str, Any]], source_path: str) -> None:
    for entry in entries:
        if isinstance(entry, str):
            digest = entry.strip().lower()
            if SHA256_RE.fullmatch(digest):
                out[digest] = {"source": source_path}
        elif isinstance(entry, dict):
            digest = str(entry.get("sha256") or entry.get("hash") or "").strip().lower()
            if SHA256_RE.fullmatch(digest):
                metadata = dict(entry)
                metadata.pop("sha256", None)
                metadata.pop("hash", None)
                out[digest] = _hash_metadata(metadata, source_path)


def _load_line_based_hashes(text: str, source_path: str) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for line in text.splitlines():
        match = SHA256_RE.search(line)
        if match:
            out[match.group(0).lower()] = {"source": source_path}
    return out


def _hash_metadata(metadata: Any, source_path: str) -> dict[str, Any]:
    if isinstance(metadata, dict):
        out = dict(metadata)
    else:
        out = {"label": str(metadata)} if metadata else {}
    out.setdefault("source", source_path)
    return out


def _safe_extract_vsix(vsix_path: Path, destination: Path) -> None:
    with zipfile.ZipFile(vsix_path) as archive:
        for member in archive.infolist():
            name = member.filename.replace("\\", "/")
            if not name or name.endswith("/"):
                continue
            target = (destination / name).resolve()
            if destination.resolve() not in target.parents and target != destination.resolve():
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source, target.open("wb") as handle:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    handle.write(chunk)


def _find_extracted_extension_root(root: Path) -> Path:
    preferred = root / "extension" / "package.json"
    if preferred.exists():
        return preferred.parent
    for package_json in root.rglob("package.json"):
        if "node_modules" in package_json.parts:
            continue
        return package_json.parent
    raise ValueError("VSIX did not contain an extension package.json")


def _apply_vsix_known_bad_match(report: ExtensionReport, known_bad_hashes: dict[str, dict[str, Any]]) -> None:
    vsix_hash = str(report.artifact_inventory.get("vsix_hash") or "").lower()
    if not vsix_hash or vsix_hash not in known_bad_hashes:
        return
    metadata = _known_bad_match("vsix", vsix_hash, known_bad_hashes[vsix_hash])
    finding = _finding(
        report.extension_id,
        report.version,
        "known-bad-artifact",
        "confirmed-intelligence",
        "CRITICAL",
        0.99,
        "VSIX hash matches a known-bad artifact entry.",
        [],
        "Block or remove this extension. The VSIX artifact hash matched confirmed malicious intelligence.",
        metadata,
    )
    report.findings.append(finding)
    report.artifact_inventory.setdefault("known_bad_matches", []).append(metadata)
    (
        report.verdict,
        report.verdict_reason,
        report.malware_authority,
        report.severity,
        report.malware_score,
        report.risk_score,
        report.score_details,
    ) = _classify_findings(report.findings)


def _walk_extension_files(path: Path) -> list[Path]:
    # os.walk with in-place dirname pruning so we never descend into huge
    # skipped trees (node_modules, dist, out, ...). rglob("*") would enumerate
    # every file inside those directories before filtering, which turns a scan
    # of a multi-GB extension install into minutes of wasted I/O.
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS]
        for filename in filenames:
            files.append(Path(dirpath, filename))
    return files


def _is_ignored_static_asset(rel: str) -> bool:
    normalized = rel.replace("\\", "/").lower()
    generated_prefixes = (
        "assets/pdf.js/build/",
        "bundled/libs/debugpy/_vendored/",
        "drawio/src/main/webapp/math/es5/",
        "lib/build/pdf.js",
        "python_files/lib/",
        "sqlite-viewer-core/vscode/build/assets/",
        "vendor/",
        "vendors/",
        "webview/assets/",
        "webviews/build/assets/",
    )
    generated_parts = (
        "/build/static/js/",
        "/dist/",
        "/node_modules/",
    )
    if normalized.startswith(generated_prefixes) or any(part in normalized for part in generated_parts):
        return True
    name = Path(rel).name.lower()
    return name.endswith((
        ".chunk.js",
        ".chunk.mjs",
        ".min.js",
        ".min.mjs",
        ".bundle.js",
        ".bundle.mjs",
        ".map",
    ))


def _is_generated_code_blob(rel: str, text: str) -> bool:
    normalized = rel.replace("\\", "/").lower()
    if normalized.endswith((".min.js", ".min.mjs", ".bundle.js", ".bundle.mjs", ".chunk.js", ".chunk.mjs")):
        return True
    newline_count = text.count("\n")
    if len(text) >= MAX_TEXT_BYTES and newline_count < 20:
        return True
    if len(text) >= MAX_TEXT_BYTES and len(text) / max(1, newline_count + 1) > 4000:
        return True
    return False


def _read_manifest(path: Path) -> dict[str, Any]:
    try:
        parsed = loads_jsonc(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _read_text(path: Path) -> str | None:
    try:
        data = path.read_bytes()[:MAX_TEXT_BYTES]
        return data.decode("utf-8", errors="replace")
    except OSError:
        return None


def _finding(
    extension_id: str,
    version: str,
    rule_id: str,
    category: str,
    severity: str,
    confidence: float,
    evidence_summary: str,
    file_refs: list[str],
    recommendation: str,
    evidence: dict[str, Any] | None = None,
) -> Finding:
    payload = f"{extension_id}:{version}:{rule_id}:{','.join(file_refs)}:{evidence_summary}"
    return Finding(
        finding_id=_stable_id(payload),
        extension_id=extension_id,
        version=version,
        rule_id=rule_id,
        category=category,
        severity=severity,  # type: ignore[arg-type]
        confidence=confidence,
        score=score_finding(severity, confidence),
        evidence_type="static",
        evidence_summary=evidence_summary,
        file_refs=file_refs,
        recommendation=recommendation,
        evidence=_evidence_with_class(rule_id, evidence),
    )


def _evidence_with_class(rule_id: str, evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    data = dict(evidence or {})
    data.setdefault("evidence_class", _evidence_class(rule_id, data))
    return data


def _evidence_class(rule_id: str, evidence: dict[str, Any] | None = None) -> str:
    if rule_id in CONFIRMED_RULES:
        return "confirmed"
    if rule_id == "marketplace-removed-package":
        return "confirmed" if _is_removed_malware(evidence) else "provenance"
    if rule_id in CORRELATED_RULES:
        return "correlated"
    if rule_id in CAPABILITY_RULES:
        return "capability"
    if rule_id in DEPENDENCY_RULES:
        return "dependency"
    if rule_id in PROVENANCE_RULES:
        return "provenance"
    if rule_id in POSTURE_RULES:
        return "posture"
    if rule_id in OBSERVED_RULES or rule_id == "observed-secret-read" or rule_id == "observed-unexpected-network":
        return "observed"
    if rule_id in REPUTATION_RULES:
        return "reputation"
    if rule_id.startswith("secret-reference:"):
        return "weak"
    return "weak"


def _classify_findings(findings: list[Finding]) -> tuple[str, str, str, str, int, int, dict[str, Any]]:
    score_details = _score_details(findings)
    if not findings:
        return "clean", "No suspicious extension behavior was detected by local static analysis.", "none", "INFO", 0, 0, score_details

    severity = "INFO"
    for finding in findings:
        severity = rank_severity(severity, finding.severity)
    malware_score = int(score_details["malware_score"])
    risk_score = int(score_details["risk_score"])

    confirmed = [finding for finding in findings if _is_confirmed_malware_finding(finding)]
    if confirmed:
        return (
            "malicious",
            "Confirmed registry or malicious-package evidence matched this extension.",
            "authoritative",
            severity,
            malware_score,
            risk_score,
            score_details,
        )

    high_correlated = [
        finding for finding in findings
        if _finding_evidence_class(finding) == "correlated" and finding.severity == "HIGH"
    ]
    if high_correlated:
        return (
            "suspicious",
            "Correlated static evidence matches a realistic abuse path and needs manual verification.",
            "non_authoritative",
            severity,
            malware_score,
            risk_score,
            score_details,
        )

    suspicious_removed = [finding for finding in findings if _is_suspicious_removed_finding(finding)]
    if suspicious_removed:
        return (
            "suspicious",
            "Marketplace removal evidence says this extension was removed as suspicious.",
            "non_authoritative",
            severity,
            malware_score,
            risk_score,
            score_details,
        )

    high_observed = [
        finding for finding in findings
        if _finding_evidence_class(finding) == "observed" and finding.severity in {"HIGH", "CRITICAL"}
    ]
    if high_observed:
        return (
            "suspicious",
            "Sandbox observation evidence matched a realistic abuse path and needs manual verification.",
            "non_authoritative",
            severity,
            malware_score,
            risk_score,
            score_details,
        )

    has_actionable_review = any(_is_actionable_review_finding(finding) for finding in findings)
    if has_actionable_review:
        return (
            "review",
            "The extension exposes sensitive capabilities or non-confirmed risk evidence that needs context.",
            "none",
            severity,
            malware_score,
            risk_score,
            score_details,
        )

    return (
        "clean",
        "No actionable malware, abuse-chain, dependency, provenance, or sensitive-capability evidence was identified.",
        "none",
        "INFO",
        0,
        0,
        _non_actionable_score_details(score_details),
    )


def _is_actionable_review_finding(finding: Finding) -> bool:
    evidence_class = _finding_evidence_class(finding)
    if evidence_class in {"correlated", "dependency", "observed", "posture", "provenance"}:
        return True
    if evidence_class == "capability":
        return finding.rule_id != "startup-activation"
    return False


def _non_actionable_score_details(score_details: dict[str, Any]) -> dict[str, Any]:
    details = dict(score_details)
    details["score"] = 0
    details["malware_score"] = 0
    details["risk_score"] = 0
    details["basis"] = "none"
    details["confidence"] = "high"
    return details


def _empty_score_details() -> dict[str, Any]:
    return {
        "score": 0,
        "malware_score": 0,
        "risk_score": 0,
        "confidence": "high",
        "basis": "none",
        "components": {
            "confirmed_intelligence": 0,
            "observed_behavior": 0,
            "correlated_behavior": 0,
            "sensitive_capability": 0,
            "provenance": 0,
            "dependency": 0,
            "posture": 0,
            "reputation": 0,
            "weak_context": 0,
        },
        "suppressors": [],
        "counts": {
            "confirmed": 0,
            "observed": 0,
            "correlated": 0,
            "capability": 0,
            "provenance": 0,
            "dependency": 0,
            "posture": 0,
            "reputation": 0,
            "weak": 0,
        },
    }


def _score_details(findings: list[Finding]) -> dict[str, Any]:
    details = _empty_score_details()
    counts = details["counts"]
    for finding in findings:
        evidence_class = _finding_evidence_class(finding)
        counts[evidence_class] = counts.get(evidence_class, 0) + 1

    confirmed_score = _confirmed_score(findings)
    correlated_score = _correlated_score(findings)
    capability_score = _capability_score(findings)
    provenance_score = _provenance_score(findings)
    dependency_score = _dependency_score(findings)
    observed_score = _observed_score(findings)
    posture_score = _posture_score(findings)
    reputation_score = _reputation_score(findings)
    has_actionable_context = correlated_score > 0 or capability_score > 0 or provenance_score > 0 or dependency_score > 0 or observed_score > 0 or posture_score > 0
    weak_score = _weak_score(findings, has_actionable_context)

    components = {
        "confirmed_intelligence": confirmed_score,
        "observed_behavior": observed_score,
        "correlated_behavior": correlated_score,
        "sensitive_capability": capability_score,
        "provenance": provenance_score,
        "dependency": dependency_score,
        "posture": posture_score,
        "reputation": reputation_score,
        "weak_context": weak_score,
    }
    malware_score = max(confirmed_score, correlated_score, observed_score)
    if malware_score < 100 and (correlated_score or observed_score):
        malware_score = min(89, malware_score + min(10, weak_score))

    risk_components = {
        name: score for name, score in components.items()
        if name != "reputation" or has_actionable_context
    }
    risk_score = max(risk_components.values())
    if risk_score < 100 and has_actionable_context:
        risk_score = min(99, risk_score + min(10, weak_score) + min(5, reputation_score))
        risk_score = max(0, risk_score - _suppressor_reduction(findings))

    basis, confidence = _score_basis(components)

    details["score"] = risk_score
    details["malware_score"] = malware_score
    details["risk_score"] = risk_score
    details["confidence"] = confidence
    details["basis"] = basis
    details["components"] = components
    details["suppressors"] = _suppressors(findings)
    return details


def _score_basis(components: dict[str, int]) -> tuple[str, str]:
    priority = [
        "confirmed_intelligence",
        "observed_behavior",
        "correlated_behavior",
        "dependency",
        "provenance",
        "sensitive_capability",
        "posture",
        "reputation",
        "weak_context",
    ]
    basis = max(priority, key=lambda name: (components.get(name, 0), -priority.index(name)))
    if components.get(basis, 0) == 0:
        return "none", "high"
    confidence = "high" if basis == "confirmed_intelligence" else "low" if basis in {"posture", "reputation", "weak_context"} else "medium"
    return basis, confidence


def _confirmed_score(findings: list[Finding]) -> int:
    if any(finding.rule_id == "known-bad-artifact" for finding in findings):
        return 100
    if any(finding.rule_id == "marketplace-removed-malware" for finding in findings):
        return 100
    if any(finding.rule_id == "marketplace-removed-package" and _is_removed_malware(finding.evidence) for finding in findings):
        return 100
    if any(finding.rule_id == "malicious-npm-dependency" for finding in findings):
        return 98
    if any(finding.rule_id == "trusted-threat-feed-hit" for finding in findings):
        return 100
    return 0


def _correlated_score(findings: list[Finding]) -> int:
    rule_ids = {finding.rule_id for finding in findings}
    score = 0
    if "install-secret-access" in rule_ids:
        score = max(score, 86)
    if "install-shell-obfuscation" in rule_ids:
        score = max(score, 84)
    if "install-download-execute" in rule_ids:
        score = max(score, 82)
    if "credential-exfiltration-chain" in rule_ids:
        score = max(score, 87)
    if "destructive-transfer-chain" in rule_ids:
        score = max(score, 83)
    if "obfuscation-execution-network" in rule_ids:
        score = max(score, 80)
    if "persistence-chain" in rule_ids:
        score = max(score, 82)
    if "agent-data-exfil-chain" in rule_ids:
        score = max(score, 84)
    if "supply-chain-dropper-chain" in rule_ids:
        score = max(score, 76)
    if "download-and-execute" in rule_ids:
        score = max(score, 72)
    return score


def _capability_score(findings: list[Finding]) -> int:
    score = 0
    for finding in findings:
        if finding.rule_id in {"agent-shell-tool", "agent-filesystem-tool", "agent-network-tool"}:
            score = max(score, 48)
        elif finding.rule_id == "mcp-server-command":
            score = max(score, 44)
        elif finding.rule_id == "agent-prompt-injection-sink":
            score = max(score, 42)
        elif finding.rule_id == "agentic-tooling":
            score = max(score, 41)
        elif finding.rule_id == "lifecycle-script":
            score = max(score, 38)
        elif finding.rule_id == "native-or-packed-artifact":
            score = max(score, 36)
        elif finding.rule_id == "dynamic-shell-execution":
            score = max(score, 40)
        elif finding.rule_id == "untrusted-input-execution":
            score = max(score, 38)
        elif finding.rule_id in {"broad-activation", "sensitive-activation", "powerful-ide-contribution"}:
            score = max(score, 30)
        elif finding.rule_id == "webview-csp-unsafe-directive":
            score = max(score, 34)
        elif finding.rule_id == "webview-csp-missing":
            score = max(score, 28)
        elif finding.rule_id == "startup-activation":
            score = max(score, 20)
    return score


def _provenance_score(findings: list[Finding]) -> int:
    score = 0
    for finding in findings:
        if finding.rule_id == "marketplace-removed-package":
            removal_type = _removal_type(finding.evidence)
            if removal_type in SUSPICIOUS_REMOVAL_TYPES:
                score = max(score, 88)
            elif removal_type:
                score = max(score, 82)
        elif _finding_evidence_class(finding) == "provenance":
            score = max(score, finding.score)
    return score


def _dependency_score(findings: list[Finding]) -> int:
    score = 0
    for finding in findings:
        if finding.category != "dependency":
            continue
        if finding.rule_id == "malicious-npm-dependency":
            score = max(score, 98)
        elif finding.rule_id == "vulnerable-npm-dependency":
            exact = bool((finding.evidence or {}).get("exact"))
            score = max(score, 65 if exact else 42)
        elif finding.rule_id == "mutable-dependency-source":
            score = max(score, 46)
        elif finding.rule_id == "unpinned-dependency":
            score = max(score, 28)
    return score


def _observed_score(findings: list[Finding]) -> int:
    rule_ids = {finding.rule_id for finding in findings}
    score = 0
    if "observed-secret-exfil" in rule_ids:
        score = max(score, 89)
    if "observed-destructive-behavior" in rule_ids:
        score = max(score, 88)
    if "observed-download-execute" in rule_ids:
        score = max(score, 84)
    if "observed-persistence" in rule_ids:
        score = max(score, 82)
    if "observed-secret-read" in rule_ids:
        score = max(score, 52)
    if "observed-unexpected-network" in rule_ids:
        score = max(score, 38)
    if "observed-process-exec" in rule_ids:
        score = max(score, 36)
    if "observed-filesystem-write" in rule_ids:
        score = max(score, 22)
    return score


def _posture_score(findings: list[Finding]) -> int:
    score = 0
    for finding in findings:
        if finding.rule_id == "dangerous-github-workflow":
            score = max(score, 44)
        elif finding.rule_id == "workflow-token-permissions-broad":
            score = max(score, 34)
        elif finding.rule_id == "repo-binary-artifacts":
            score = max(score, 32)
    return score


def _reputation_score(findings: list[Finding]) -> int:
    score = 0
    for finding in findings:
        if _finding_evidence_class(finding) != "reputation":
            continue
        if finding.rule_id == "marketplace-extension-not-found":
            score = max(score, 12)
        elif finding.rule_id == "marketplace-unverified-publisher":
            score = max(score, 8)
        elif finding.rule_id == "marketplace-low-install-count":
            score = max(score, 8)
        elif finding.rule_id == "marketplace-low-rating":
            score = max(score, 10)
        elif finding.rule_id == "marketplace-stale-extension":
            score = max(score, 8)
        elif finding.rule_id == "install-rating-mismatch":
            score = max(score, 10)
        elif finding.rule_id in {"repo-archived", "repo-stale"}:
            score = max(score, 8)
        elif finding.rule_id in {"repo-url-missing", "security-policy-missing", "license-missing"}:
            score = max(score, 6)
    return score


def _suppressors(findings: list[Finding]) -> list[dict[str, Any]]:
    suppressors: list[dict[str, Any]] = []
    if any(finding.rule_id == "marketplace-verified-publisher" for finding in findings):
        suppressors.append({
            "id": "verified-publisher",
            "reduction": 5,
            "reason": "Marketplace metadata reports a verified publisher. This reduces reputation risk only.",
        })
    return suppressors


def _suppressor_reduction(findings: list[Finding]) -> int:
    return sum(int(item["reduction"]) for item in _suppressors(findings))


def _weak_score(findings: list[Finding], has_actionable_context: bool) -> int:
    weak_count = sum(1 for finding in findings if _finding_evidence_class(finding) == "weak")
    if weak_count == 0 or not has_actionable_context:
        return 0
    return min(15, weak_count * 2)


def _finding_evidence_class(finding: Finding) -> str:
    evidence_class = (finding.evidence or {}).get("evidence_class")
    if isinstance(evidence_class, str):
        return evidence_class
    return _evidence_class(finding.rule_id, finding.evidence)


def _is_confirmed_malware_finding(finding: Finding) -> bool:
    if finding.rule_id == "known-bad-artifact":
        return True
    if finding.rule_id == "malicious-npm-dependency":
        return True
    if finding.rule_id == "trusted-threat-feed-hit":
        return True
    if finding.rule_id == "marketplace-removed-malware":
        return True
    return finding.rule_id == "marketplace-removed-package" and _is_removed_malware(finding.evidence)


def _is_suspicious_removed_finding(finding: Finding) -> bool:
    return finding.rule_id == "marketplace-removed-package" and _removal_type(finding.evidence) in SUSPICIOUS_REMOVAL_TYPES


def _is_removed_malware(evidence: dict[str, Any] | None) -> bool:
    return _removal_type(evidence) in MALWARE_REMOVAL_TYPES


def _removal_type(evidence: dict[str, Any] | None) -> str:
    if not evidence:
        return ""
    return str(evidence.get("type") or evidence.get("removal_type") or "").strip().lower()


def _stable_id(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _manifest_hash(path: Path) -> str:
    digest = hashlib.sha256()
    for file in sorted(path.glob("package*.json")):
        try:
            digest.update(file.read_bytes())
        except OSError:
            continue
    return digest.hexdigest()[:24]


def _repository_url(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return str(value.get("url") or "")
    return ""


def _dependencies(manifest: dict[str, Any], path: Path) -> dict[str, str]:
    locked = _package_lock_dependencies(path / "package-lock.json")
    if locked:
        return locked

    out = _manifest_runtime_dependencies(manifest)
    for name in list(out):
        installed_version = _installed_package_version(path, name)
        if installed_version:
            out[name] = installed_version
    return out


def _manifest_runtime_dependencies(manifest: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    deps = manifest.get("dependencies")
    if not isinstance(deps, dict):
        return out
    for name, version in deps.items():
        if isinstance(name, str) and isinstance(version, str):
            out[name] = version
    return out


def _package_lock_dependencies(path: Path) -> dict[str, str]:
    try:
        data = loads_jsonc(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}

    packages = data.get("packages")
    if isinstance(packages, dict):
        return _package_lock_v2_dependencies(packages)

    dependencies = data.get("dependencies")
    if isinstance(dependencies, dict):
        out: dict[str, str] = {}
        _collect_package_lock_v1_dependencies(dependencies, out)
        return out
    return {}


def _package_lock_v2_dependencies(packages: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for package_path, package_data in packages.items():
        if not isinstance(package_path, str) or not package_path.startswith("node_modules/"):
            continue
        if not isinstance(package_data, dict) or package_data.get("dev") is True:
            continue
        version = package_data.get("version")
        if not isinstance(version, str):
            continue
        name = _package_name_from_node_modules_path(package_path)
        if name:
            out[name] = version
    return out


def _collect_package_lock_v1_dependencies(dependencies: dict[str, Any], out: dict[str, str]) -> None:
    for name, package_data in dependencies.items():
        if not isinstance(name, str) or not isinstance(package_data, dict):
            continue
        if package_data.get("dev") is True:
            continue
        version = package_data.get("version")
        if isinstance(version, str):
            out[name] = version
        child_dependencies = package_data.get("dependencies")
        if isinstance(child_dependencies, dict):
            _collect_package_lock_v1_dependencies(child_dependencies, out)


def _package_name_from_node_modules_path(package_path: str) -> str:
    parts = package_path.split("/")
    try:
        index = parts.index("node_modules")
    except ValueError:
        return ""
    package_parts = parts[index + 1:]
    if not package_parts:
        return ""
    if package_parts[0].startswith("@"):
        if len(package_parts) < 2:
            return ""
        return f"{package_parts[0]}/{package_parts[1]}"
    return package_parts[0]


def _installed_package_version(root: Path, name: str) -> str:
    package_path = root / "node_modules" / Path(*name.split("/")) / "package.json"
    manifest = _read_manifest(package_path)
    version = manifest.get("version")
    return version if isinstance(version, str) else ""


def _is_mutable_dependency_spec(spec: str) -> bool:
    if spec.startswith(("git://", "git+", "github:", "http://", "https://", "file:", "link:", "workspace:")):
        return True
    if ".git" in spec:
        return True
    return bool(re.match(r"^[^@\s]+/[^@\s]+(?:#.+)?$", spec))
