from __future__ import annotations

import json
import os
import urllib.request


def main() -> int:
    extension_id = os.environ.get("SCAN_EXTENSION_ID", "").strip()
    version = os.environ.get("SCAN_EXTENSION_VERSION", "").strip()
    purpose = os.environ.get("SCAN_PURPOSE", "").strip()
    if not extension_id and not version:
        write_outputs({"has_job": "false"})
        return 0
    if not all((extension_id, version, purpose)):
        raise RuntimeError("extension id, version, and purpose must be provided together")
    payload = json.dumps({
        "jobs": [{
            "extension_id": extension_id,
            "version": version,
            "scan_purpose": purpose,
            "registry": os.environ.get("SCAN_REGISTRY", "vs-marketplace"),
            "scanner_build": os.environ.get("SCAN_GITHUB_SHA", ""),
        }]
    }).encode()
    request = urllib.request.Request(
        os.environ["SCAN_ENQUEUE_URL"],
        data=payload,
        method="POST",
        headers={
            "Authorization": f"Bearer {os.environ['SCAN_RUNNER_SECRET']}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        body = json.loads(response.read().decode())
    jobs = body.get("jobs") if isinstance(body, dict) else None
    if not isinstance(jobs, list) or not jobs or not jobs[0].get("id"):
        raise RuntimeError("Canonical enqueue response did not contain a scan job")
    job_id = str(jobs[0]["id"])
    write_outputs({"has_job": "true", "job_id": job_id})
    print(f"Queued {extension_id}@{version} as {purpose} job {job_id}")
    return 0


def write_outputs(values: dict[str, str]) -> None:
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        for key, value in values.items():
            output.write(f"{key}={value}\n")


if __name__ == "__main__":
    raise SystemExit(main())
