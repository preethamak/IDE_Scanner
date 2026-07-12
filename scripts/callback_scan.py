from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import urllib.request
from pathlib import Path


def main() -> int:
    bundle_path = Path(sys.argv[1])
    payload = json.dumps({"job_id": os.environ["SCAN_JOB_ID"], "bundle": json.loads(bundle_path.read_text(encoding="utf-8"))}, separators=(",", ":")).encode()
    signature = hmac.new(os.environ["SCAN_CALLBACK_SECRET"].encode(), payload, hashlib.sha256).hexdigest()
    request = urllib.request.Request(os.environ["SCAN_CALLBACK_URL"], data=payload, method="POST", headers={"Content-Type": "application/json", "X-IDE-Scanner-Signature": signature})
    with urllib.request.urlopen(request, timeout=60) as response:
        print(response.read().decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
