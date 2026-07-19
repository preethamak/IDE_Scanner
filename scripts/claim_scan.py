from __future__ import annotations

import json
import os
import urllib.error
import urllib.request


def main() -> int:
    urllib.request.install_opener(urllib.request.build_opener(_PostPreservingRedirect()))
    for claim_url in claim_urls():
        job = claim_job(claim_url)
        if job is None:
            continue
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


def claim_job(claim_url: str) -> dict[str, object] | None:
    payload = {
        "runner_id": os.environ.get("SCAN_RUNNER_ID", "github-actions"),
        "job_id": os.environ.get("SCAN_JOB_ID") or None,
        "github_run_id": os.environ.get("SCAN_GITHUB_RUN_ID") or None,
    }
    request = urllib.request.Request(
        claim_url,
        data=json.dumps(payload).encode(),
        method="POST",
        headers={
            "Authorization": f"Bearer {os.environ['SCAN_RUNNER_SECRET']}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return None if response.status == 204 else json.loads(response.read().decode())
    except urllib.error.HTTPError as error:
        if error.code == 204:
            return None
        raise RuntimeError(f"Scan claim returned HTTP {error.code} from {claim_url}") from error


class _PostPreservingRedirect(urllib.request.HTTPRedirectHandler):
    # urllib raises on a 307/308 answer to a POST instead of following it. The
    # claim endpoint sits behind hosts that can redirect to the canonical apex
    # domain, so re-issue the POST (method, body and headers preserved) to the
    # new location rather than crashing the claim step.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return urllib.request.Request(
            newurl,
            data=req.data,
            method=req.get_method(),
            headers=dict(req.header_items()),
        )


def write_outputs(values: dict[str, str]) -> None:
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        for key, value in values.items():
            output.write(f"{key}={value}\n")


if __name__ == "__main__":
    raise SystemExit(main())
