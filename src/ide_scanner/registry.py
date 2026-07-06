from __future__ import annotations

import json
import os
import re
import subprocess
import urllib.error
import urllib.request
from datetime import UTC, datetime
from difflib import SequenceMatcher
from urllib.parse import urlparse
from typing import Any

MARKETPLACE_EXTENSIONQUERY_URL = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery?api-version=7.2-preview.1"
REMOVED_PACKAGES_URL = "https://raw.githubusercontent.com/microsoft/vsmarketplace/main/RemovedPackages.md"
REMOVED_ROW = re.compile(r"^\|\s*(?P<id>[a-zA-Z0-9._-]+)\s*\|\s*(?P<date>[0-9/]+)\s*\|\s*(?P<type>[^|]+?)\s*\|", re.M)
LOW_INSTALL_THRESHOLD = 100
HIGH_INSTALL_RATING_MISMATCH_THRESHOLD = 50_000
STALE_EXTENSION_DAYS = 730
STALE_REPOSITORY_DAYS = 730
MARKETPLACE_BATCH_SIZE = 25
OSV_BATCH_SIZE = 100
IMPERSONATION_TARGETS = (
    ("microsoft", "python", "Python"),
    ("microsoft", "vscode-cpptools", "C/C++"),
    ("github", "copilot-chat", "GitHub Copilot"),
    ("openai", "chatgpt", "ChatGPT"),
    ("anthropic", "claude-code", "Claude Code"),
    ("ms-toolsai", "jupyter", "Jupyter"),
    ("ms-azuretools", "vscode-docker", "Docker"),
)


def enrich_registry(extensions: list[Any], online: bool = False) -> dict[str, Any]:
    if not online:
        return {"enabled": False, "findings": [], "errors": []}

    errors: list[dict[str, str]] = []
    removed, removed_error = _fetch_removed_packages()
    if removed_error:
        errors.append({"source": "removed-packages", "message": removed_error})

    marketplace_metadata, marketplace_errors = _fetch_marketplace_metadata_many([
        extension.extension_id for extension in extensions
    ])
    errors.extend(marketplace_errors)
    osv_by_extension, osv_errors = _check_osv_many(extensions)
    errors.extend(osv_errors)
    repo_metadata, repo_errors = _fetch_repository_metadata_many([
        str(getattr(extension, "repository", "") or "") for extension in extensions
    ])
    errors.extend(repo_errors)

    findings: list[dict[str, Any]] = []
    for extension in extensions:
        removed_entry = removed.get(extension.extension_id.lower())
        if removed_entry:
            removed_type = str(removed_entry["type"]).strip()
            removed_type_lower = removed_type.lower()
            removed_as_malware = removed_type_lower == "malware"
            if removed_as_malware:
                severity = "CRITICAL"
                confidence = 0.96
            elif removed_type_lower in {"suspicious", "untrustworthy", "impersonation"}:
                severity = "HIGH"
                confidence = 0.9
            else:
                severity = "MEDIUM"
                confidence = 0.82
            findings.append({
                "extension_id": extension.extension_id,
                "severity": severity,
                "confidence": confidence,
                "category": "registry",
                "rule_id": "marketplace-removed-malware" if removed_as_malware else "marketplace-removed-package",
                "evidence_summary": f"Extension appears in Microsoft's removed package list as {removed_type}.",
                "evidence": removed_entry,
            })
        findings.extend(osv_by_extension.get(extension.extension_id, []))
        findings.extend(_marketplace_metadata_findings(extension.extension_id, marketplace_metadata.get(extension.extension_id)))
        findings.extend(_repository_metadata_findings(
            extension.extension_id,
            repo_metadata.get(str(getattr(extension, "repository", "") or "")),
        ))
    return {"enabled": True, "mode": "batched", "findings": findings, "errors": errors}


def _fetch_removed_packages() -> tuple[dict[str, dict[str, str]], str | None]:
    try:
        cache_path = os.environ.get("IDE_SCANNER_REMOVED_PACKAGES_FILE")
        if cache_path:
            with open(cache_path, encoding="utf-8") as handle:
                text = handle.read()
        else:
            text = _http_get_text(REMOVED_PACKAGES_URL, timeout=15)
    except (OSError, urllib.error.URLError, subprocess.SubprocessError) as exc:
        return {}, str(exc)

    removed: dict[str, dict[str, str]] = {}
    for match in REMOVED_ROW.finditer(text):
        ext_id = match.group("id")
        if ext_id.lower() == "extension identifier":
            continue
        removed[ext_id.lower()] = {"date": match.group("date"), "type": match.group("type").strip()}
    return removed, None


def _check_osv(extension: Any) -> tuple[list[dict[str, Any]], str | None]:
    entries = [
        {"name": name, "version": _normalize_version(version), "exact": bool(re.match(r"^\d+\.\d+\.\d+", str(version)))}
        for name, version in extension.dependencies.items()
        if isinstance(version, str)
    ]
    entries = [entry for entry in entries if entry["version"]]
    if not entries:
        return [], None

    body = json.dumps({
        "queries": [
            {"package": {"name": entry["name"], "ecosystem": "npm"}, "version": entry["version"]}
            for entry in entries
        ]
    }).encode("utf-8")
    try:
        data = _http_post_json("https://api.osv.dev/v1/querybatch", body, timeout=15)
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        return [], str(exc)

    findings: list[dict[str, Any]] = []
    for index, result in enumerate(data.get("results", [])):
        vulns = result.get("vulns", [])
        if not vulns:
            continue
        dep = entries[index]
        malicious = any(str(vuln.get("id", "")).startswith("MAL-") for vuln in vulns)
        findings.append({
            "extension_id": extension.extension_id,
            "severity": "CRITICAL" if malicious else "HIGH" if dep["exact"] else "MEDIUM",
            "confidence": 0.94 if malicious else 0.82 if dep["exact"] else 0.58,
            "category": "dependency",
            "rule_id": "malicious-npm-dependency" if malicious else "vulnerable-npm-dependency",
            "evidence_summary": f"{dep['name']}@{dep['version']} has {len(vulns)} OSV finding(s). Version match: {'exact' if dep['exact'] else 'range-derived'}.",
            "evidence": {
                "package": dep["name"],
                "version": dep["version"],
                "exact": dep["exact"],
                "osv_ids": [vuln.get("id") for vuln in vulns if vuln.get("id")],
            },
        })
    return findings, None


def _check_osv_many(extensions: list[Any]) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, str]]]:
    entries_by_extension: dict[str, list[dict[str, Any]]] = {}
    unique: dict[tuple[str, str], dict[str, Any]] = {}
    for extension in extensions:
        entries = [
            {"name": name, "version": _normalize_version(version), "exact": bool(re.match(r"^\d+\.\d+\.\d+", str(version)))}
            for name, version in extension.dependencies.items()
            if isinstance(version, str)
        ]
        entries = [entry for entry in entries if entry["version"]]
        entries_by_extension[extension.extension_id] = entries
        for entry in entries:
            unique.setdefault((entry["name"], entry["version"]), entry)
    if not unique:
        return {}, []

    keys = list(unique)
    vulns_by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
    errors: list[dict[str, str]] = []
    for index in range(0, len(keys), OSV_BATCH_SIZE):
        chunk = keys[index:index + OSV_BATCH_SIZE]
        body = json.dumps({
            "queries": [
                {"package": {"name": name, "ecosystem": "npm"}, "version": version}
                for name, version in chunk
            ]
        }).encode("utf-8")
        try:
            data = _http_post_json("https://api.osv.dev/v1/querybatch", body, timeout=15)
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            errors.append({"source": "osv", "message": str(exc)})
            continue
        for offset, result in enumerate(data.get("results", [])):
            if index + offset >= len(keys):
                break
            vulns_by_key[keys[index + offset]] = result.get("vulns", [])

    findings_by_extension: dict[str, list[dict[str, Any]]] = {}
    for extension in extensions:
        extension_findings: list[dict[str, Any]] = []
        for dep in entries_by_extension.get(extension.extension_id, []):
            vulns = vulns_by_key.get((dep["name"], dep["version"]), [])
            if not vulns:
                continue
            malicious = any(str(vuln.get("id", "")).startswith("MAL-") for vuln in vulns)
            extension_findings.append({
                "extension_id": extension.extension_id,
                "severity": "CRITICAL" if malicious else "HIGH" if dep["exact"] else "MEDIUM",
                "confidence": 0.94 if malicious else 0.82 if dep["exact"] else 0.58,
                "category": "dependency",
                "rule_id": "malicious-npm-dependency" if malicious else "vulnerable-npm-dependency",
                "evidence_summary": f"{dep['name']}@{dep['version']} has {len(vulns)} OSV finding(s). Version match: {'exact' if dep['exact'] else 'range-derived'}.",
                "evidence": {
                    "package": dep["name"],
                    "version": dep["version"],
                    "exact": dep["exact"],
                    "osv_ids": [vuln.get("id") for vuln in vulns if vuln.get("id")],
                },
            })
        if extension_findings:
            findings_by_extension[extension.extension_id] = extension_findings
    return findings_by_extension, errors


def _fetch_marketplace_metadata_many(extension_ids: list[str]) -> tuple[dict[str, dict[str, Any] | None], list[dict[str, str]]]:
    unique_ids = list(dict.fromkeys(extension_ids))
    out: dict[str, dict[str, Any] | None] = {}
    errors: list[dict[str, str]] = []
    for index in range(0, len(unique_ids), MARKETPLACE_BATCH_SIZE):
        chunk = unique_ids[index:index + MARKETPLACE_BATCH_SIZE]
        body = json.dumps({
            "filters": [
                {
                    "criteria": [{"filterType": 7, "value": extension_id}],
                    "pageNumber": 1,
                    "pageSize": 1,
                }
                for extension_id in chunk
            ],
            "flags": 914,
        }).encode("utf-8")
        try:
            data = _http_post_json(MARKETPLACE_EXTENSIONQUERY_URL, body, timeout=15)
            results = data.get("results", [])
            for offset, extension_id in enumerate(chunk):
                result = results[offset] if offset < len(results) and isinstance(results[offset], dict) else {}
                extensions = result.get("extensions", []) if isinstance(result, dict) else []
                if extensions:
                    out[extension_id] = _normalize_marketplace_extension(extension_id, extensions[0])
                else:
                    out[extension_id] = {"extension_id": extension_id, "found": False}
        except (OSError, urllib.error.URLError, json.JSONDecodeError, AttributeError, IndexError) as exc:
            errors.append({"source": "marketplace", "message": str(exc), "extension_ids": ",".join(chunk)})
            for extension_id in chunk:
                metadata, error = _fetch_marketplace_metadata(extension_id)
                out[extension_id] = metadata
                if error:
                    errors.append({"source": "marketplace", "extension_id": extension_id, "message": error})
    return out, errors


def _fetch_marketplace_metadata(extension_id: str) -> tuple[dict[str, Any] | None, str | None]:
    body = json.dumps({
        "filters": [{
            "criteria": [{"filterType": 7, "value": extension_id}],
            "pageNumber": 1,
            "pageSize": 1,
        }],
        "flags": 914,
    }).encode("utf-8")
    try:
        data = _http_post_json(MARKETPLACE_EXTENSIONQUERY_URL, body, timeout=15)
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        return None, str(exc)
    try:
        extensions = data.get("results", [{}])[0].get("extensions", [])
    except (AttributeError, IndexError):
        return None, "Unexpected marketplace metadata response shape."
    if not extensions:
        return {"extension_id": extension_id, "found": False}, None
    return _normalize_marketplace_extension(extension_id, extensions[0]), None


def _fetch_repository_metadata_many(repo_urls: list[str]) -> tuple[dict[str, dict[str, Any] | None], list[dict[str, str]]]:
    unique = [url for url in dict.fromkeys(repo_urls) if url]
    out: dict[str, dict[str, Any] | None] = {}
    errors: list[dict[str, str]] = []
    for repo_url in unique:
        github = _github_repo_api_url(repo_url)
        if not github:
            out[repo_url] = None
            continue
        try:
            data = json.loads(_http_get_text(github, timeout=10))
            out[repo_url] = {
                "repository": repo_url,
                "found": True,
                "host": "github",
                "full_name": data.get("full_name") or "",
                "archived": bool(data.get("archived")),
                "disabled": bool(data.get("disabled")),
                "pushed_at": data.get("pushed_at") or "",
                "updated_at": data.get("updated_at") or "",
                "stargazers_count": int(data.get("stargazers_count") or 0),
                "fork": bool(data.get("fork")),
                "default_branch": data.get("default_branch") or "",
            }
        except (OSError, urllib.error.URLError, json.JSONDecodeError, ValueError) as exc:
            out[repo_url] = None
            errors.append({"source": "repository", "repository": repo_url, "message": str(exc)})
    return out, errors


def _github_repo_api_url(repo_url: str) -> str:
    raw = repo_url.strip()
    if raw.startswith("git+"):
        raw = raw[4:]
    raw = raw.removesuffix(".git")
    if raw.startswith("git@github.com:"):
        path = raw.split(":", 1)[1]
    else:
        parsed = urlparse(raw)
        if parsed.netloc.lower() not in {"github.com", "www.github.com"}:
            return ""
        path = parsed.path.strip("/")
    parts = [part for part in path.split("/") if part]
    if len(parts) < 2:
        return ""
    return f"https://api.github.com/repos/{parts[0]}/{parts[1]}"


def _normalize_marketplace_extension(extension_id: str, raw: dict[str, Any]) -> dict[str, Any]:
    publisher = raw.get("publisher") if isinstance(raw.get("publisher"), dict) else {}
    versions = raw.get("versions") if isinstance(raw.get("versions"), list) else []
    latest_version = versions[0] if versions and isinstance(versions[0], dict) else {}
    stats = _marketplace_stats(raw.get("statistics"))
    metadata = {
        "extension_id": extension_id,
        "found": True,
        "publisher": publisher.get("publisherName") or "",
        "publisher_display_name": publisher.get("displayName") or "",
        "publisher_verified": bool(publisher.get("isVerified") or publisher.get("verified")),
        "display_name": raw.get("displayName") or "",
        "extension_name": raw.get("extensionName") or "",
        "version": latest_version.get("version") or "",
        "last_updated": latest_version.get("lastUpdated") or raw.get("lastUpdated") or "",
        "install_count": int(stats.get("install") or stats.get("installs") or 0),
        "rating_average": float(stats.get("averagerating") or stats.get("averageRating") or 0),
        "rating_count": int(stats.get("ratingcount") or stats.get("ratingCount") or 0),
    }
    return metadata


def _marketplace_stats(raw_stats: Any) -> dict[str, float]:
    stats: dict[str, float] = {}
    if not isinstance(raw_stats, list):
        return stats
    for item in raw_stats:
        if not isinstance(item, dict):
            continue
        name = str(item.get("statisticName") or "").strip()
        if not name:
            continue
        try:
            stats[name] = float(item.get("value") or 0)
        except (TypeError, ValueError):
            continue
    return stats


def _marketplace_metadata_findings(extension_id: str, metadata: dict[str, Any] | None) -> list[dict[str, Any]]:
    if metadata is None:
        return []
    if not metadata.get("found"):
        return [_registry_finding(
            extension_id,
            "LOW",
            0.42,
            "reputation",
            "marketplace-extension-not-found",
            "Extension was not found in the VS Marketplace metadata query.",
            metadata,
        )]

    findings: list[dict[str, Any]] = []
    if metadata.get("publisher_verified"):
        findings.append(_registry_finding(
            extension_id,
            "INFO",
            0.95,
            "reputation",
            "marketplace-verified-publisher",
            "Marketplace metadata reports a verified publisher.",
            metadata,
        ))
    else:
        findings.append(_registry_finding(
            extension_id,
            "LOW",
            0.46,
            "reputation",
            "marketplace-unverified-publisher",
            "Marketplace metadata does not report a verified publisher.",
            metadata,
        ))

    install_count = int(metadata.get("install_count") or 0)
    if install_count and install_count < LOW_INSTALL_THRESHOLD:
        findings.append(_registry_finding(
            extension_id,
            "LOW",
            0.44,
            "reputation",
            "marketplace-low-install-count",
            f"Marketplace install count is low: {install_count}.",
            metadata,
        ))

    rating_count = int(metadata.get("rating_count") or 0)
    rating_average = float(metadata.get("rating_average") or 0)
    if rating_count >= 5 and rating_average and rating_average < 2.5:
        findings.append(_registry_finding(
            extension_id,
            "LOW",
            0.48,
            "reputation",
            "marketplace-low-rating",
            f"Marketplace rating is low: {rating_average:.2f} across {rating_count} ratings.",
            metadata,
        ))
    if (
        rating_count >= 5
        and rating_average
        and rating_average < 2.5
        and install_count >= HIGH_INSTALL_RATING_MISMATCH_THRESHOLD
    ):
        findings.append(_registry_finding(
            extension_id,
            "LOW",
            0.5,
            "reputation",
            "install-rating-mismatch",
            f"Marketplace install count is high ({install_count}) but rating is low ({rating_average:.2f} across {rating_count} ratings).",
            metadata,
        ))

    days_since_update = _days_since_update(metadata.get("last_updated"))
    if days_since_update is not None and days_since_update > STALE_EXTENSION_DAYS:
        evidence = dict(metadata)
        evidence["days_since_update"] = days_since_update
        findings.append(_registry_finding(
            extension_id,
            "LOW",
            0.5,
            "reputation",
            "marketplace-stale-extension",
            f"Marketplace metadata says the extension has not been updated for {days_since_update} days.",
            evidence,
        ))
    impersonation = _name_impersonation_evidence(metadata)
    if impersonation:
        findings.append(_registry_finding(
            extension_id,
            "LOW",
            0.52,
            "reputation",
            "marketplace-name-impersonation",
            f"Marketplace name is similar to {impersonation['target_display']} from {impersonation['target_publisher']}.",
            impersonation,
        ))
    return findings


def _repository_metadata_findings(extension_id: str, metadata: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not metadata:
        return []
    evidence = dict(metadata)
    evidence["evidence_class"] = "reputation"
    findings: list[dict[str, Any]] = []
    if metadata.get("archived") or metadata.get("disabled"):
        findings.append(_registry_finding(
            extension_id,
            "LOW",
            0.52,
            "reputation",
            "repo-archived",
            "Declared GitHub repository is archived or disabled.",
            evidence,
        ))
    days = _days_since_update(metadata.get("pushed_at") or metadata.get("updated_at"))
    if days is not None:
        if days > STALE_REPOSITORY_DAYS:
            stale_evidence = dict(evidence)
            stale_evidence["days_since_push"] = days
            findings.append(_registry_finding(
                extension_id,
                "LOW",
                0.48,
                "reputation",
                "repo-stale",
                f"Declared GitHub repository has not been pushed for {days} days.",
                stale_evidence,
            ))
        else:
            maintained = dict(evidence)
            maintained["days_since_push"] = days
            findings.append(_registry_finding(
                extension_id,
                "INFO",
                0.72,
                "reputation",
                "repo-maintained",
                f"Declared GitHub repository has recent activity within {days} days.",
                maintained,
            ))
    return findings


def _name_impersonation_evidence(metadata: dict[str, Any]) -> dict[str, Any] | None:
    publisher = str(metadata.get("publisher") or "").lower()
    extension_name = _normalize_name(metadata.get("extension_name"))
    display_name = _normalize_name(metadata.get("display_name"))
    install_count = int(metadata.get("install_count") or 0)
    for target_publisher, target_name, target_display in IMPERSONATION_TARGETS:
        if publisher == target_publisher:
            continue
        target_normalized = _normalize_name(target_name)
        display_normalized = _normalize_name(target_display)
        similarity = max(
            _similarity(extension_name, target_normalized),
            _similarity(display_name, display_normalized),
            _similarity(display_name, target_normalized),
        )
        if similarity >= 0.9 and install_count < 10000:
            evidence = dict(metadata)
            evidence.update({
                "target_publisher": target_publisher,
                "target_extension": target_name,
                "target_display": target_display,
                "similarity": round(similarity, 3),
                "evidence_class": "reputation",
            })
            return evidence
    return None


def _normalize_name(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def _similarity(left: str, right: str) -> float:
    if not left or not right:
        return 0.0
    return SequenceMatcher(None, left, right).ratio()


def _registry_finding(
    extension_id: str,
    severity: str,
    confidence: float,
    category: str,
    rule_id: str,
    evidence_summary: str,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    return {
        "extension_id": extension_id,
        "severity": severity,
        "confidence": confidence,
        "category": category,
        "rule_id": rule_id,
        "evidence_summary": evidence_summary,
        "evidence": evidence,
    }


def _days_since_update(value: Any) -> int | None:
    if not value:
        return None
    raw = str(value).strip().replace("Z", "+00:00")
    try:
        timestamp = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    return (datetime.now(UTC) - timestamp.astimezone(UTC)).days


def _normalize_version(range_value: str) -> str:
    value = str(range_value).strip()
    if value.startswith(("file:", "link:", "workspace:")):
        return ""
    match = re.search(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?|\d+\.\d+", value)
    return match.group(0) if match else ""


def _http_get_text(url: str, timeout: int) -> str:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return response.read().decode("utf-8", errors="replace")
    except (OSError, urllib.error.URLError):
        return _curl(["curl", "-L", "--max-time", str(timeout), "-s", url])


def _http_post_json(url: str, body: bytes, timeout: int) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=body,
        headers={"content-type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except (OSError, urllib.error.URLError):
        text = _curl([
            "curl",
            "-L",
            "--max-time",
            str(timeout),
            "-s",
            "-H",
            "content-type: application/json",
            "-d",
            body.decode("utf-8"),
            url,
        ])
        return json.loads(text)


def _curl(cmd: list[str]) -> str:
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        return result.stdout
    except subprocess.SubprocessError as exc:
        raise OSError(str(exc)) from exc
