from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from .models import MetricResult, MetricRunOutput, MetricSpec, higher_veto
from .spec import MCP_CATALOG_RISK_SPEC, leaf_specs


HIGH_SEVERITIES = {"HIGH", "CRITICAL"}
WEAK_TLS_VERSIONS = {"TLSv1", "TLSv1.0", "TLSv1.1", "TLS 1.0", "TLS 1.1"}
SCORE_UNKNOWN = 0.35


def scan_mcp_path(path: str | Path) -> dict[str, Any]:
    source = Path(path).expanduser().resolve()
    payload = _read_source(source)
    payload.setdefault("source", {})
    if isinstance(payload["source"], dict):
        payload["source"].update({"path": str(source), "mode": "local-static"})
    return scan_mcp_payload(payload)


def scan_mcp_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("MCP assessment input must be a JSON object.")
    raw = payload.get("server") if isinstance(payload.get("server"), dict) else payload
    subject = _normalize_subject(raw)
    runners: dict[str, Callable[[dict[str, Any]], MetricRunOutput]] = {
        "hosting_operator_class": _hosting_operator_class,
        "transport_security": _transport_security,
        "auth_strength": _auth_strength,
        "pkce_validation": _pkce_validation,
        "dynamic_client_registration": _dynamic_client_registration,
        "source_opacity": _source_opacity,
        "malicious_dependencies": _malicious_dependencies,
        "vulnerability_risk": _vulnerability_risk,
        "mcp_package_cves": _mcp_package_cves,
        "metadata_security": _metadata_security,
        "tool_source_code_security": _tool_source_code_security,
        "secrets_risk": _secrets_risk,
    }
    root = _evaluate(MCP_CATALOG_RISK_SPEC, subject, runners)
    leaves = list(_walk(root))
    assessed = [item for item in leaves if item.score is not None and item.status == "success"]
    unavailable = [item for item in leaves if item.score is None or item.status != "success"]
    veto = next((item.veto for item in sorted(leaves, key=lambda item: {"failure": 2, "warning": 1, None: 0}.get(item.veto, 0), reverse=True) if item.veto), None)
    risk_score = None if root.score is None else round(root.score * 100, 1)
    if veto == "failure":
        decision = "block"
    elif veto == "warning" or (root.score is not None and root.score >= 0.60):
        decision = "review"
    elif root.score is not None:
        decision = "allow"
    else:
        decision = "incomplete"
    coverage_percent = round((len(assessed) / len(leaves)) * 100, 1) if leaves else 0.0
    return {
        "schema_version": "guardrails.mcp-risk-report.v1",
        "scanner": {"name": "GuardRails MCP scanner", "mode": "static", "version": "1.0"},
        "subject": _public_subject(subject),
        "decision": decision,
        "risk_score": risk_score,
        "veto": veto,
        "coverage": {
            "percent": coverage_percent,
            "assessed_metrics": len(assessed),
            "total_metrics": len(leaves),
            "unavailable_metrics": len(unavailable),
            "unavailable": [item.name for item in unavailable],
        },
        "metrics": root.as_dict(),
    }


def _evaluate(spec: MetricSpec, subject: dict[str, Any], runners: dict[str, Callable[[dict[str, Any]], MetricRunOutput]]) -> MetricResult:
    if spec.is_module:
        children = [_evaluate(child, subject, runners) for child in spec.children]
        usable = [child for child in children if child.score is not None]
        score = _weighted_average(usable)
        veto = higher_veto(*(child.veto for child in children))
        veto_message = next((child.veto_message for child in children if child.veto == veto and child.veto_message), None)
        status = "success" if score is not None else "skipped"
        message = f"{len(usable)} of {len(children)} metrics assessed" if usable else "No evidence available for this module"
        return MetricResult(spec.name, spec.title, spec.weight, score, status, message, veto, veto_message, children=children)
    output = runners[spec.runner or ""](subject)
    return MetricResult(spec.name, spec.title, spec.weight, output.score, output.status, output.message, output.veto, output.veto_message, output.details)


def _weighted_average(results: list[MetricResult]) -> float | None:
    if not results:
        return None
    denominator = sum(item.weight for item in results)
    return sum(float(item.score or 0.0) * item.weight for item in results) / denominator if denominator else None


def _walk(result: MetricResult):
    for child in result.children:
        if child.children:
            yield from _walk(child)
        else:
            yield child


def _normalize_subject(raw: dict[str, Any]) -> dict[str, Any]:
    url = str(raw.get("url") or raw.get("mcp_url") or "").strip()
    transport = str(raw.get("transport") or raw.get("transport_type") or "").lower().strip()
    is_local = bool(raw.get("is_local")) or transport in {"stdio", "local", "command"} or not url
    officiality = str(raw.get("officiality") or raw.get("publisher_class") or "community").lower()
    official = officiality in {"official", "verified", "publisher"}
    source_repo = str(raw.get("source_repo") or raw.get("repository") or raw.get("repository_url") or "").strip()
    auth_modes = [_auth_mode(item) for item in (raw.get("auth_modes") or raw.get("authentication") or [])]
    if isinstance(raw.get("auth_modes"), str):
        auth_modes = [_auth_mode(raw["auth_modes"])]
    if not auth_modes and raw.get("auth"):
        auth_modes = [_auth_mode(raw["auth"])]
    tools = raw.get("tools") if isinstance(raw.get("tools"), list) else []
    dependencies = raw.get("dependencies") if isinstance(raw.get("dependencies"), list) else []
    vulnerabilities = raw.get("vulnerabilities") if isinstance(raw.get("vulnerabilities"), list) else []
    package_vulnerabilities = raw.get("mcp_vulnerabilities") if isinstance(raw.get("mcp_vulnerabilities"), list) else []
    source_files = raw.get("source_files") if isinstance(raw.get("source_files"), list) else []
    return {
        "name": str(raw.get("name") or raw.get("title") or "Unnamed MCP server"),
        "description": str(raw.get("description") or ""),
        "url": url,
        "transport": transport or ("stdio" if is_local else "streamable-http"),
        "is_local": is_local,
        "is_official": official,
        "officiality": "official" if official else "community",
        "has_repo": bool(source_repo or source_files or dependencies or vulnerabilities),
        "source_repo": source_repo,
        "auth_modes": auth_modes,
        "oauth_metadata": raw.get("oauth_metadata") if isinstance(raw.get("oauth_metadata"), dict) else None,
        "transport_level": str(raw.get("transport_level") or "").lower().strip() or None,
        "tls_version": str(raw.get("tls_version") or "").strip() or None,
        "legacy_tls_version": str(raw.get("legacy_tls_version") or "").strip() or None,
        "dynamic_client_registration": raw.get("dynamic_client_registration"),
        "pkce_methods": raw.get("pkce_methods") if isinstance(raw.get("pkce_methods"), list) else None,
        "dependencies": dependencies,
        "vulnerabilities": vulnerabilities,
        "package_name": str(raw.get("package_name") or ""),
        "package_version": str(raw.get("package_version") or raw.get("version") or ""),
        "package_vulnerabilities": package_vulnerabilities,
        "tools": tools,
        "source_files": source_files,
        "secrets": raw.get("secrets") if isinstance(raw.get("secrets"), list) else None,
    }


def _public_subject(subject: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in subject.items()
        if key not in {"secrets", "source_files", "tools", "vulnerabilities", "package_vulnerabilities", "dependencies"}
    } | {"tool_count": len(subject["tools"]), "source_file_count": len(subject["source_files"])}


def _hosting_operator_class(subject: dict[str, Any]) -> MetricRunOutput:
    if subject["is_official"] and not subject["is_local"]:
        label, score = "remote_official", 0.00
    elif subject["is_official"] and subject["is_local"]:
        label, score = "local_official", 0.15
    elif subject["is_local"]:
        label, score = "local_community", 0.50
    else:
        label, score = "remote_community", 1.00
    veto = "warning" if label == "remote_community" else None
    return MetricRunOutput(score, veto=veto, veto_message="Remote community MCP may proxy credentials/data through third-party infrastructure" if veto else None, message=f"Classified as {label.replace('_', ' ')}", details={"hosting_class": label})


def _transport_security(subject: dict[str, Any]) -> MetricRunOutput:
    if subject["is_local"]:
        return MetricRunOutput(None, status="skipped", message="Not applicable for local servers (no remote transport)", details={"reason": "local server"})
    url = subject["url"]
    parsed = urlparse(url)
    if not parsed.hostname:
        return MetricRunOutput(None, status="error", message="Invalid URL format", details={"reason": "URL has no hostname"})
    level = subject["transport_level"]
    if not level:
        level = "https_strong" if parsed.scheme == "https" else "http_only"
    scores = {"https_strong": 0.00, "https_safe_redirect": 0.00, "https_legacy_tls": 0.40, "http_fallback": 0.50, "https_unsafe_redirect": 0.60, "https_invalid_cert": 0.85, "http_only": 1.00}
    if level not in scores:
        return MetricRunOutput(None, status="error", message=f"Unknown transport level: {level}")
    veto = "failure" if level in {"https_invalid_cert", "http_only"} else "warning" if level == "https_legacy_tls" else None
    if level == "https_legacy_tls" and subject["tls_version"] is None:
        veto = "failure"
    messages = {
        "https_strong": "Strong HTTPS with no HTTP fallback",
        "https_safe_redirect": "HTTP redirects safely to HTTPS",
        "https_legacy_tls": "Legacy TLS accepted or negotiated",
        "http_fallback": "Server responds to unencrypted HTTP requests",
        "https_unsafe_redirect": "Unsafe HTTP redirect chain",
        "https_invalid_cert": "HTTPS certificate validation failed",
        "http_only": "HTTP-only server, no HTTPS available",
    }
    return MetricRunOutput(scores[level], status="success", veto=veto, veto_message=_transport_veto(level), message=messages[level], details={"transport_level": level, "tls_version": subject["tls_version"], "url_scheme": parsed.scheme})


def _transport_veto(level: str) -> str | None:
    return {
        "https_invalid_cert": "Invalid certificate - MitM attack possible",
        "http_only": "No HTTPS - credentials exposed in transit",
        "https_legacy_tls": "Legacy TLS accepted - downgrade attack possible",
    }.get(level)


def _auth_strength(subject: dict[str, Any]) -> MetricRunOutput:
    if subject["is_local"]:
        return MetricRunOutput(None, status="skipped", message="Not applicable for local servers")
    modes = subject["auth_modes"]
    if modes == ["oauth"]:
        return MetricRunOutput(0.00, message="OAuth is the only detected authentication mechanism", details={"auth_strength": "strong", "auth_modes": modes})
    if "oauth" in modes:
        return MetricRunOutput(0.60, message="OAuth is available alongside other authentication mechanisms", details={"auth_strength": "insecure_mechanisms", "auth_modes": modes})
    if "api_key" in modes or "pat" in modes:
        return MetricRunOutput(0.60, veto="warning", veto_message="Insecure authentication mechanisms in use with no OAuth", message="API key or personal access token detected without OAuth", details={"auth_strength": "insecure_mechanisms", "auth_modes": modes})
    label = "no_auth" if "no_auth" in modes else "unknown"
    return MetricRunOutput(1.00, veto="warning", veto_message="No authentication mechanism detected" if label == "no_auth" else "OAuth was not detected and other authentication mechanisms could not be detected", message="No authentication mechanism detected" if label == "no_auth" else "Authentication could not be confirmed", details={"auth_strength": label, "auth_modes": modes})


def _oauth_metadata(subject: dict[str, Any]) -> dict[str, Any] | None:
    metadata = subject["oauth_metadata"]
    if metadata is not None:
        return metadata
    if subject["pkce_methods"] is not None or subject["dynamic_client_registration"] is not None:
        return {"code_challenge_methods_supported": subject["pkce_methods"] or [], "registration_endpoint": "configured" if subject["dynamic_client_registration"] else None}
    return None


def _pkce_validation(subject: dict[str, Any]) -> MetricRunOutput:
    if subject["is_local"]:
        return MetricRunOutput(None, status="skipped", message="Not applicable for local servers")
    metadata = _oauth_metadata(subject)
    if metadata is None:
        return MetricRunOutput(SCORE_UNKNOWN, message="Could not determine PKCE configuration", details={"reason": "OAuth metadata unavailable"})
    methods = metadata.get("code_challenge_methods_supported") or []
    if "S256" not in methods:
        score, message = 1.00, "Mandatory PKCE method 'S256' is not supported"
    elif "plain" in methods:
        score, message = 0.60, "Insecure PKCE method 'plain' is supported alongside 'S256'"
    else:
        score, message = 0.00, "PKCE configuration is secure - 'S256' method is supported"
    return MetricRunOutput(score, message=message, details={"code_challenge_methods_supported": methods, "s256_supported": "S256" in methods, "plain_supported": "plain" in methods})


def _dynamic_client_registration(subject: dict[str, Any]) -> MetricRunOutput:
    if subject["is_local"]:
        return MetricRunOutput(None, status="skipped", message="Not applicable for local servers")
    metadata = _oauth_metadata(subject)
    if metadata is None:
        return MetricRunOutput(SCORE_UNKNOWN, message="Could not determine dynamic client registration support", details={"reason": "OAuth metadata unavailable"})
    available = bool(metadata.get("registration_endpoint"))
    return MetricRunOutput(0.00 if available else 1.00, message="Dynamic client registration endpoint is available" if available else "No dynamic client registration endpoint - manual registration required", details={"dcr_available": available, "registration_endpoint": metadata.get("registration_endpoint")})


def _source_opacity(subject: dict[str, Any]) -> MetricRunOutput:
    if subject["has_repo"]:
        level, score = "open_source", 0.00
    elif not subject["is_local"] and subject["is_official"]:
        level, score = "remote_official_closed", 0.00
    elif subject["is_local"] and subject["is_official"]:
        level, score = "local_official_closed", 0.40
    elif not subject["is_local"]:
        level, score = "remote_community_closed", 0.70
    else:
        level, score = "local_community_closed", 1.00
    return MetricRunOutput(score, message=level.replace("_", " ").title(), details={"opacity_level": level, "has_repo": subject["has_repo"]})


def _sca_available(subject: dict[str, Any]) -> bool:
    return subject["has_repo"] and bool(subject["dependencies"] or subject["vulnerabilities"])


def _malicious_dependencies(subject: dict[str, Any]) -> MetricRunOutput:
    if not subject["has_repo"]:
        return MetricRunOutput(None, status="skipped", message="Not applicable - no repository to scan")
    if not _sca_available(subject):
        return MetricRunOutput(None, status="skipped", message="Dependency evidence was not supplied")
    found = [item for item in subject["dependencies"] if isinstance(item, dict) and (item.get("malicious") or item.get("contains_malware"))]
    return MetricRunOutput(1.00 if found else 0.00, veto="failure" if found else None, veto_message="Malicious dependencies detected" if found else None, message=f"Malicious dependencies detected in {len(found)} package(s)" if found else "No malicious dependencies found", details={"malicious_count": len(found), "results": found})


def _vulnerability_risk(subject: dict[str, Any]) -> MetricRunOutput:
    if not subject["has_repo"]:
        return MetricRunOutput(None, status="skipped", message="Not applicable - no repository to scan")
    if not _sca_available(subject):
        return MetricRunOutput(None, status="skipped", message="Dependency vulnerability evidence was not supplied")
    worst = (0.00, "none_or_not_reachable")
    direct_count = 0
    transitive_count = 0
    reachable_direct = False
    reachable_transitive = False
    used_direct = False
    high_items: list[dict[str, Any]] = []
    for vulnerability in subject["vulnerabilities"]:
        if not isinstance(vulnerability, dict) or str(vulnerability.get("severity") or "").upper() not in HIGH_SEVERITIES:
            continue
        direct = not bool(vulnerability.get("transitive"))
        reachable = bool(vulnerability.get("reachable"))
        used = int(vulnerability.get("used_in_num_locations") or 0) > 0
        if direct:
            direct_count += 1
        else:
            transitive_count += 1
        if direct and reachable:
            current = (1.00, "direct_reachable")
            reachable_direct = True
        elif direct and used:
            current = (0.80, "direct_used")
            used_direct = True
        elif direct:
            current = (0.75, "direct_unknown_reachability")
        elif reachable:
            current = (0.60, "indirect_reachable")
            reachable_transitive = True
        else:
            current = (0.35, "indirect_unknown_reachability")
        worst = max(worst, current, key=lambda item: item[0])
        high_items.append(vulnerability)
    if not high_items:
        return MetricRunOutput(0.00, message="No high-severity vulnerabilities found", details={"vuln_reachability": "none_or_not_reachable", "high_severity_count": 0})
    veto = "failure" if reachable_direct or reachable_transitive else "warning" if direct_count >= 5 or used_direct else None
    return MetricRunOutput(worst[0], veto=veto, veto_message="Reachable HIGH severity vulnerability detected" if veto == "failure" else "High severity vulnerable dependency requires review" if veto else None, message=f"Found {len(high_items)} HIGH severity vulnerability(s); {direct_count} direct, {transitive_count} transitive", details={"vuln_reachability": worst[1], "high_severity_count": len(high_items), "direct_count": direct_count, "results": high_items})


def _mcp_package_cves(subject: dict[str, Any]) -> MetricRunOutput:
    if not subject["package_name"]:
        return MetricRunOutput(None, status="skipped", message="No queryable package identifier was supplied")
    if not subject["package_vulnerabilities"]:
        return MetricRunOutput(0.00, message="No known package CVEs found", details={"vulnerabilities": []})
    vulns = subject["package_vulnerabilities"]
    high = [item for item in vulns if isinstance(item, dict) and str(item.get("severity") or "").upper() == "HIGH"]
    latest = [item for item in vulns if isinstance(item, dict) and item.get("affects_latest_version")]
    latest_high = [item for item in latest if str(item.get("severity") or "").upper() == "HIGH"]
    if latest_high:
        score = 1.00
    elif latest:
        score = 0.70
    elif high:
        score = 0.80
    else:
        score = 0.40
    return MetricRunOutput(score, veto="warning" if latest else None, veto_message="Known CVE(s) affect the latest published package version" if latest else None, message=f"{len(vulns)} package CVE(s) reported", details={"package_name": subject["package_name"], "package_version": subject["package_version"], "vulnerabilities": vulns})


TOOL_POISONING_PATTERNS = {
    "hidden_directive": re.compile(r"ignore\s+(?:all|previous|prior)\s+instructions", re.I),
    "invisible_chars": re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]"),
    "encoded_instructions": re.compile(r"(?:base64|decode|rot13)\s+(?:this|the|following)", re.I),
    "sensitive_path_reference": re.compile(r"(?:\.env|id_rsa|credentials|secrets?\.json)", re.I),
    "exfiltration_instruction": re.compile(r"(?:upload|send|post|exfiltrat)\b.{0,80}(?:token|secret|credential|environment)", re.I),
}
TOOL_SOURCE_PATTERNS = {
    "code_execution": re.compile(r"(?:child_process|subprocess|os\.system|eval\s*\(|exec\s*\()", re.I),
    "network_egress": re.compile(r"(?:fetch\s*\(|requests?\.(?:get|post)|httpx\.|axios\.)", re.I),
    "secret_access": re.compile(r"(?:process\.env|os\.environ|\.env|credentials)", re.I),
    "path_traversal": re.compile(r"\.\./|path\.join\([^\n]*(?:user|input|arg)", re.I),
}


def _tool_text(tool: Any) -> str:
    if not isinstance(tool, dict):
        return str(tool)
    return json.dumps(tool, sort_keys=True, ensure_ascii=False)


def _metadata_security(subject: dict[str, Any]) -> MetricRunOutput:
    tools = subject["tools"]
    if not tools:
        return MetricRunOutput(None, status="error", message="Could not analyze tool metadata. No tools were provided.")
    findings = [{"category": category, "tool": str(tool.get("name") or "unnamed")} for tool in tools if isinstance(tool, dict) for category, pattern in TOOL_POISONING_PATTERNS.items() if pattern.search(_tool_text(tool))]
    return MetricRunOutput(1.00 if findings else 0.00, veto="failure" if findings else None, veto_message="Tool poisoning patterns detected in tool metadata" if findings else None, message=f"{len(findings)} tool poisoning pattern(s) detected" if findings else "No tool poisoning patterns detected", details={"tier1_findings": findings, "tier1_finding_count": len(findings), "tool_count": len(tools)})


def _tool_source_code_security(subject: dict[str, Any]) -> MetricRunOutput:
    if not subject["has_repo"]:
        return MetricRunOutput(None, status="skipped", message="Not applicable - no repository to scan")
    tools = subject["tools"]
    if not tools:
        return MetricRunOutput(None, status="error", message="Could not analyze source code for tools. No tools were provided.")
    source_text = "\n".join(_tool_text(tool) for tool in tools) + "\n" + "\n".join(str(item.get("content") or item) if isinstance(item, dict) else str(item) for item in subject["source_files"])
    findings = [{"category": category, "severity": "high" if category in {"code_execution", "secret_access"} else "medium"} for category, pattern in TOOL_SOURCE_PATTERNS.items() if pattern.search(source_text)]
    tier1 = [item for item in findings if item["severity"] == "high"]
    tier2 = [item for item in findings if item["severity"] != "high"]
    score = 0.00 if not findings else 1.00 if tier1 else 0.75 if tier2 else 0.60
    return MetricRunOutput(score, veto="failure" if tier1 else None, veto_message="High risk finding(s) detected in tool source code" if tier1 else None, message="No security issues detected in tools' source code" if not findings else f"{len(tier1)} high risk and {len(tier2)} medium risk finding(s) detected in tool source code", details={"tier1_count": len(tier1), "tier2_count": len(tier2), "findings": findings})


SECRET_PATTERNS = (
    re.compile(r"(?:api[_-]?key|secret|token|password)\s*[:=]\s*[\"'][^\"']{12,}[\"']", re.I),
    re.compile(r"(?:sk|ghp|xox[baprs])_[A-Za-z0-9_-]{12,}"),
)


def _secrets_risk(subject: dict[str, Any]) -> MetricRunOutput:
    if not subject["has_repo"]:
        return MetricRunOutput(None, status="skipped", message="Not applicable - no repository to scan")
    explicit = subject["secrets"] or []
    source_text = "\n".join(str(item.get("content") or item) if isinstance(item, dict) else str(item) for item in subject["source_files"])
    found = list(explicit) + [{"rule": "embedded_secret", "match": pattern.pattern} for pattern in SECRET_PATTERNS if pattern.search(source_text)]
    return MetricRunOutput(1.00 if found else 0.00, veto="failure" if found else None, veto_message="Hardcoded secrets found in source code" if found else None, message="Secrets found" if found else "No secrets found", details={"secrets_found": found})


def _auth_mode(value: Any) -> str:
    normalized = str(value).lower().replace("-", "_").replace(" ", "_")
    return {"apikey": "api_key", "api_key": "api_key", "personal_access_token": "pat", "pat": "pat", "oauth2": "oauth", "oauth": "oauth", "none": "no_auth", "no_auth": "no_auth"}.get(normalized, "unknown")


def _read_source(path: Path) -> dict[str, Any]:
    if path.is_dir():
        candidates = [path / name for name in ("mcp.json", "server.json", "manifest.json", "package.json")]
        source = next((candidate for candidate in candidates if candidate.is_file()), None)
        if source is None:
            raise ValueError(f"No MCP JSON manifest found in {path}")
    else:
        source = path
    try:
        text = source.read_text(encoding="utf-8")
        data = json.loads(_strip_json_comments(text))
    except OSError as exc:
        raise ValueError(f"Could not read MCP input: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"MCP input is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("MCP input must contain a JSON object.")
    return data


def _strip_json_comments(value: str) -> str:
    value = re.sub(r"/\*.*?\*/", "", value, flags=re.S)
    return re.sub(r"(^|\s)//.*$", r"\1", value, flags=re.M)


__all__ = ["scan_mcp_path", "scan_mcp_payload"]
