from __future__ import annotations

import hashlib
import hmac
import gzip
import json
import os
import sys
import urllib.request
from pathlib import Path


def main() -> int:
    bundle_path = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    value = {"job_id": os.environ["SCAN_JOB_ID"]}
    if bundle_path and bundle_path.exists():
        value["bundle"] = json.loads(bundle_path.read_text(encoding="utf-8"))
    else:
        value["error"] = os.environ.get("SCAN_ERROR", "Deep Scan workflow failed before producing a report.")
    payload = gzip.compress(json.dumps(value, separators=(",", ":")).encode(), compresslevel=9)
    signature = hmac.new(os.environ["SCAN_CALLBACK_SECRET"].encode(), payload, hashlib.sha256).hexdigest()
    request = urllib.request.Request(os.environ["SCAN_CALLBACK_URL"], data=payload, method="POST", headers={"Content-Type": "application/json", "Content-Encoding": "gzip", "X-IDE-Scanner-Signature": signature})
    with urllib.request.urlopen(request, timeout=60) as response:
        print(response.read().decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
