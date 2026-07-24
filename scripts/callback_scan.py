from __future__ import annotations

import hashlib
import hmac
import gzip
import json
import os
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

CALLBACK_ATTEMPTS = 4
CALLBACK_RETRY_DELAYS_SECONDS = (2, 5, 10)
RETRYABLE_HTTP_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})
TRANSIENT_UPSTREAM_MARKERS = (
    "cloudflare",
    "gateway.supabase.co",
    "status 520",
    "temporarily unavailable",
    "web server is returning an unknown error",
)


def main() -> int:
    bundle_path = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    value = {"job_id": os.environ["SCAN_JOB_ID"]}
    if bundle_path and bundle_path.exists():
        value["bundle"] = json.loads(bundle_path.read_text(encoding="utf-8"))
    else:
        value["error"] = os.environ.get("SCAN_ERROR", "Deep Scan workflow failed before producing a report.")
    payload = encoded_payload(value)
    print(submit_callback(payload))
    return 0


def submit_callback(payload: bytes) -> str:
    last_error: BaseException | None = None
    for attempt in range(CALLBACK_ATTEMPTS):
        try:
            with urllib.request.urlopen(signed_request(payload), timeout=60) as response:
                return response.read().decode()
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")[:2000]
            last_error = RuntimeError(f"Scan callback returned HTTP {error.code}: {detail}")
            if not is_retryable_http_error(error.code, detail):
                raise last_error from error
        except (urllib.error.URLError, TimeoutError) as error:
            last_error = error
        if attempt < CALLBACK_ATTEMPTS - 1:
            time.sleep(CALLBACK_RETRY_DELAYS_SECONDS[attempt])
    raise RuntimeError(f"Scan callback failed after {CALLBACK_ATTEMPTS} attempts: {last_error}") from last_error


def is_retryable_http_error(status: int, detail: str) -> bool:
    if status in RETRYABLE_HTTP_STATUSES:
        return True
    normalized = detail.lower()
    return status == 422 and any(marker in normalized for marker in TRANSIENT_UPSTREAM_MARKERS)


def encoded_payload(value: dict[str, object]) -> bytes:
    return gzip.compress(json.dumps(value, separators=(",", ":")).encode(), compresslevel=9)


def signed_request(payload: bytes) -> urllib.request.Request:
    signature = hmac.new(os.environ["SCAN_CALLBACK_SECRET"].encode(), payload, hashlib.sha256).hexdigest()
    return urllib.request.Request(os.environ["SCAN_CALLBACK_URL"], data=payload, method="POST", headers={"Content-Type": "application/json", "Content-Encoding": "gzip", "X-IDE-Scanner-Signature": signature})


if __name__ == "__main__":
    raise SystemExit(main())
