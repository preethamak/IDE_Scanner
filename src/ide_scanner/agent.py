from __future__ import annotations

import json
import platform
import socket
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .core import ScanRequest, run_scan, summarize_report


def build_agent_report(
    *,
    paths: list[Path],
    all_local: bool,
    online: bool,
    previous_report_file: str | None = None,
) -> dict[str, Any]:
    report = run_scan(
        ScanRequest(
            paths=paths,
            all_local=all_local,
            online=online,
            previous_report_file=previous_report_file,
        )
    )
    return {
        "agent": {
            "schema_version": "0.1.0",
            "generated_at": int(time.time() * 1000),
            "hostname": socket.gethostname(),
            "platform": platform.system(),
            "platform_release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "summary": summarize_report(report, top_limit=50),
        "report": report,
    }


def upload_agent_report(server_url: str, payload: dict[str, Any], token: str | None = None, timeout: int = 30) -> dict[str, Any]:
    endpoint = server_url.rstrip("/") + "/api/agent/reports"
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "ide-scanner-agent/0.1.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(endpoint, data=body, headers=headers, method="POST")
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw.strip() else {}
    except HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"upload failed: HTTP {error.code} {detail}") from error
    except URLError as error:
        raise RuntimeError(f"upload failed: {error.reason}") from error
