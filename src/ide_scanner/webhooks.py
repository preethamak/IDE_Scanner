"""Signed, bounded job-terminal webhooks for the private scanner service."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import time
import urllib.error
import urllib.request
import uuid
from datetime import UTC, datetime
from typing import Any, Callable
from urllib.parse import urlsplit

WEBHOOK_ATTEMPTS = 3
WEBHOOK_RETRY_DELAYS_SECONDS = (1, 3)
WEBHOOK_RETRYABLE_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})


def configured_webhook() -> tuple[str, str, set[str]] | None:
    url = os.environ.get("IDE_SCANNER_WEBHOOK_URL", "").strip()
    secret = os.environ.get("IDE_SCANNER_WEBHOOK_SECRET", "")
    hosts = {item.strip().lower().rstrip(".") for item in os.environ.get("IDE_SCANNER_WEBHOOK_ALLOWED_HOSTS", "").split(",") if item.strip()}
    if not url and not secret and not hosts:
        return None
    if not url or not secret or not hosts:
        raise RuntimeError("IDE_SCANNER_WEBHOOK_URL, IDE_SCANNER_WEBHOOK_SECRET, and IDE_SCANNER_WEBHOOK_ALLOWED_HOSTS must be configured together")
    validate_webhook_url(url, hosts)
    return url, secret, hosts


def validate_webhook_url(url: str, allowed_hosts: set[str]) -> None:
    parsed = urlsplit(url)
    if parsed.scheme.lower() != "https" or parsed.username is not None or parsed.password is not None:
        raise RuntimeError("scanner webhook URL must be an HTTPS URL without credentials")
    if parsed.port not in (None, 443):
        raise RuntimeError("scanner webhook URL must use port 443")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host or host not in allowed_hosts:
        raise RuntimeError("scanner webhook host is not in IDE_SCANNER_WEBHOOK_ALLOWED_HOSTS")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return
    if not address.is_global:
        raise RuntimeError("scanner webhook URL must not target a non-public IP address")


def terminal_event(job: dict[str, Any]) -> tuple[str, bytes, dict[str, str]]:
    event_type = "scan.completed" if job.get("status") == "complete" else "scan.failed"
    delivery_id = f"delivery_{uuid.uuid4().hex}"
    occurred_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    payload = {
        "event": event_type,
        "delivery_id": delivery_id,
        "occurred_at": occurred_at,
        "job": {
            "id": job.get("id"),
            "status": job.get("status"),
            "stage": job.get("stage"),
            "extension_id": job.get("extension_id"),
            "version": job.get("version"),
            "target_platform": job.get("target_platform"),
            "report_ref": job.get("report_ref"),
            "error": job.get("error"),
        },
    }
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return delivery_id, body, {"X-GuardRails-Event": event_type, "X-GuardRails-Delivery": delivery_id, "X-GuardRails-Timestamp": occurred_at}


def deliver_terminal_webhook(
    job: dict[str, Any],
    *,
    urlopen: Callable[..., Any] = urllib.request.urlopen,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any] | None:
    settings = configured_webhook()
    if settings is None:
        return None
    url, secret, _ = settings
    delivery_id, body, headers = terminal_event(job)
    signature = hmac.new(secret.encode("utf-8"), headers["X-GuardRails-Timestamp"].encode("utf-8") + b"." + body, hashlib.sha256).hexdigest()
    headers.update({"Content-Type": "application/json", "User-Agent": "guardrails-scanner-service/1", "X-GuardRails-Signature": f"sha256={signature}"})
    last_error = ""
    for attempt in range(WEBHOOK_ATTEMPTS):
        try:
            request = urllib.request.Request(url, data=body, method="POST", headers=headers)
            with urlopen(request, timeout=15) as response:
                status = int(getattr(response, "status", response.getcode()))
                if 200 <= status < 300:
                    return {"delivery_id": delivery_id, "status": "delivered", "attempts": attempt + 1}
                last_error = f"Webhook returned HTTP {status}."
                if status not in WEBHOOK_RETRYABLE_STATUSES:
                    break
        except urllib.error.HTTPError as error:
            last_error = f"Webhook returned HTTP {error.code}."
            if error.code not in WEBHOOK_RETRYABLE_STATUSES:
                break
        except (urllib.error.URLError, TimeoutError) as error:
            last_error = f"Webhook transport failed: {error}"
        if attempt < WEBHOOK_ATTEMPTS - 1:
            sleep(WEBHOOK_RETRY_DELAYS_SECONDS[attempt])
    return {"delivery_id": delivery_id, "status": "failed", "attempts": WEBHOOK_ATTEMPTS, "error": last_error}
