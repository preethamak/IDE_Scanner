from __future__ import annotations

import hashlib
import hmac
import gzip
import json
import os
import sys
import urllib.request
import urllib.error
from pathlib import Path


def main() -> int:
    bundle_path = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    value = {"job_id": os.environ["SCAN_JOB_ID"]}
    if bundle_path and bundle_path.exists():
        value["bundle"] = json.loads(bundle_path.read_text(encoding="utf-8"))
    else:
        value["error"] = os.environ.get("SCAN_ERROR", "Deep Scan workflow failed before producing a report.")
    payload = encoded_payload(value)
    request = signed_request(payload)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            print(response.read().decode())
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")[:2000]
        failure = encoded_payload({"job_id": os.environ["SCAN_JOB_ID"], "error": f"Canonical report ingestion rejected: HTTP {error.code}: {detail}"})
        try:
            urllib.request.urlopen(signed_request(failure), timeout=60).read()
        except urllib.error.HTTPError:
            pass
        raise RuntimeError(f"Scan callback returned HTTP {error.code}: {detail}") from error
    return 0


def encoded_payload(value: dict[str, object]) -> bytes:
    return gzip.compress(json.dumps(value, separators=(",", ":")).encode(), compresslevel=9)


def signed_request(payload: bytes) -> urllib.request.Request:
    signature = hmac.new(os.environ["SCAN_CALLBACK_SECRET"].encode(), payload, hashlib.sha256).hexdigest()
    return urllib.request.Request(os.environ["SCAN_CALLBACK_URL"], data=payload, method="POST", headers={"Content-Type": "application/json", "Content-Encoding": "gzip", "X-IDE-Scanner-Signature": signature})


if __name__ == "__main__":
    raise SystemExit(main())
