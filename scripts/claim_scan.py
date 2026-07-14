from __future__ import annotations

import json
import os
import urllib.error
import urllib.request


def main() -> int:
    request = urllib.request.Request(
        os.environ["SCAN_CLAIM_URL"],
        data=json.dumps({"runner_id": os.environ.get("SCAN_RUNNER_ID", "github-actions")}).encode(),
        method="POST",
        headers={
            "Authorization": f"Bearer {os.environ['SCAN_RUNNER_SECRET']}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            if response.status == 204:
                write_outputs({"has_job": "false"})
                return 0
            job = json.loads(response.read().decode())
    except urllib.error.HTTPError as error:
        if error.code == 204:
            write_outputs({"has_job": "false"})
            return 0
        raise RuntimeError(f"Scan claim returned HTTP {error.code}") from error

    required = ("id", "extension_id", "version", "callback_url")
    if not all(job.get(key) for key in required):
        raise RuntimeError("Scan claim response is incomplete")
    write_outputs({
        "has_job": "true",
        "job_id": str(job["id"]),
        "extension_id": str(job["extension_id"]),
        "version": str(job["version"]),
        "callback_url": str(job["callback_url"]),
    })
    print(f"Claimed {job['extension_id']}@{job['version']}")
    return 0


def write_outputs(values: dict[str, str]) -> None:
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        for key, value in values.items():
            output.write(f"{key}={value}\n")


if __name__ == "__main__":
    raise SystemExit(main())
