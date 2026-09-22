"""Small HTTP guardrails for the GitHub Actions scan transport.

The queue and callback endpoints carry bearer tokens or signed reports.  The
standard urllib redirect handler can forward those headers to a different
host, so these requests only accept HTTPS URLs and same-origin redirects.
"""

from __future__ import annotations

import ipaddress
import os
import urllib.error
import urllib.request
from urllib.parse import SplitResult, urlsplit


def validate_endpoint_url(
    url: str,
    *,
    label: str,
    allowed_hosts_env: str | None = None,
) -> SplitResult:
    parsed = urlsplit(url)
    if parsed.scheme.lower() != "https":
        raise RuntimeError(f"{label} must use https")
    if parsed.username is not None or parsed.password is not None:
        raise RuntimeError(f"{label} must not contain credentials")
    if parsed.port not in (None, 443):
        raise RuntimeError(f"{label} must use port 443")
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if not hostname:
        raise RuntimeError(f"{label} must contain a hostname")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        raise RuntimeError(f"{label} must not target a non-public IP address")

    if allowed_hosts_env:
        configured = {
            item.strip().lower().rstrip(".")
            for item in os.environ.get(allowed_hosts_env, "").split(",")
            if item.strip()
        }
        if not configured:
            raise RuntimeError(f"{allowed_hosts_env} must contain at least one trusted host")
        if hostname not in configured:
            raise RuntimeError(f"{label} host is not in {allowed_hosts_env}")
    return parsed


def same_origin(left: str, right: str) -> bool:
    left_parts = urlsplit(left)
    right_parts = urlsplit(right)
    left_host = (left_parts.hostname or "").lower().rstrip(".")
    right_host = (right_parts.hostname or "").lower().rstrip(".")
    left_port = left_parts.port or 443 if left_parts.scheme.lower() == "https" else left_parts.port
    right_port = right_parts.port or 443 if right_parts.scheme.lower() == "https" else right_parts.port
    return (
        left_parts.scheme.lower() == right_parts.scheme.lower()
        and left_host == right_host
        and left_port == right_port
    )


class SameOriginPostRedirect(urllib.request.HTTPRedirectHandler):
    """Follow redirects only when the request remains on the same origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_endpoint_url(newurl, label="redirect URL")
        if not same_origin(req.full_url, newurl):
            raise urllib.error.URLError("Refusing to forward scan credentials across origins")
        return urllib.request.Request(
            newurl,
            data=req.data,
            method=req.get_method(),
            headers={**dict(req.header_items()), "User-Agent": req.get_header("User-Agent") or "guardrails-scan-worker/1"},
        )


def install_secure_opener() -> None:
    urllib.request.install_opener(urllib.request.build_opener(SameOriginPostRedirect()))
