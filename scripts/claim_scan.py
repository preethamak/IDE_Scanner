from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
import re

try:
    from scripts.secure_http import SameOriginPostRedirect, validate_endpoint_url
except ModuleNotFoundError:  # Direct `python scripts/claim_scan.py` execution.
    from secure_http import SameOriginPostRedirect, validate_endpoint_url  # type: ignore[no-redef]

TARGET_PLATFORM_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
USER_AGENT = "ide-scanner-github-actions/1"


def main() -> int:
    urllib.request.install_opener(urllib.request.build_opener(_PostPreservingRedirect()))
    for claim_url in claim_urls():
        job = claim_job(claim_url)
        if job is None:
            continue
        required = ("id", "extension_id", "version", "callback_url")
        if not all(job.get(key) for key in required):
            raise RuntimeError("Scan claim response is incomplete")
        target_platform = str(job.get("target_platform") or "").strip().lower()
        if target_platform and not TARGET_PLATFORM_RE.fullmatch(target_platform):
            raise RuntimeError("Scan claim target platform is invalid")
        validate_endpoint_url(
            str(job["callback_url"]),
            label="scan callback URL",
            allowed_hosts_env="SCAN_INTERNAL_ALLOWED_HOSTS",
        )
        write_outputs({
            "has_job": "true",
            "job_id": str(job["id"]),
            "extension_id": str(job["extension_id"]),
            "version": str(job["version"]),
            "callback_url": str(job["callback_url"]),
            "target_platform": target_platform,
        })
        print(f"Claimed {job['extension_id']}@{job['version']} from {claim_url}")
        return 0

    write_outputs({"has_job": "false"})
    return 0


def claim_urls() -> list[str]:
    configured = os.environ.get("SCAN_CLAIM_URLS") or os.environ.get("SCAN_CLAIM_URL", "")
    urls = [url.strip() for url in configured.split(",") if url.strip()]
    if not urls:
        raise RuntimeError("SCAN_CLAIM_URLS or SCAN_CLAIM_URL is required")
    return urls


def claim_job(
    claim_url: str,
    *,
    job_id: str | None = None,
    runner_suffix: str = "",
) -> dict[str, object] | None:
    payload = {
        "runner_id": f"{os.environ.get('SCAN_RUNNER_ID', 'github-actions')}-{runner_suffix}".rstrip("-"),
        "job_id": job_id if job_id else (os.environ.get("SCAN_JOB_ID") or None),
        "github_run_id": os.environ.get("SCAN_GITHUB_RUN_ID") or None,
        "github_sha": os.environ.get("SCAN_GITHUB_SHA") or None,
    }
    validate_endpoint_url(claim_url, label="scan claim URL")
    request = urllib.request.Request(
        claim_url,
        data=json.dumps(payload).encode(),
        method="POST",
        headers={
            "Authorization": f"Bearer {os.environ['SCAN_RUNNER_SECRET']}",
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return None if response.status == 204 else json.loads(response.read().decode())
    except urllib.error.HTTPError as error:
        if error.code == 204:
            return None
        raise RuntimeError(f"Scan claim returned HTTP {error.code} from {claim_url}") from error


class _PostPreservingRedirect(SameOriginPostRedirect):
    """Compatibility name used by the worker and its transport tests."""


def write_outputs(values: dict[str, str]) -> None:
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        for key, value in values.items():
            output.write(f"{key}={value}\n")


if __name__ == "__main__":
    raise SystemExit(main())
