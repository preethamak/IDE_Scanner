#!/usr/bin/env python3
"""Submit and retrieve one exact Marketplace scan through GuardRails service."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--service-url", required=True)
    parser.add_argument("--token", required=True)
    parser.add_argument("--extension-id", required=True)
    parser.add_argument("--version", default="")
    parser.add_argument("--target-platform", default="")
    parser.add_argument("--idempotency-key", required=True)
    parser.add_argument("--poll-interval", type=float, default=5.0)
    parser.add_argument("--timeout", type=float, default=900.0)
    parser.add_argument("--out", type=Path, required=True)
    return parser.parse_args(argv)


def _service_base(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
        raise ValueError("service-url must be an absolute http(s) origin without embedded credentials")
    if parsed.path not in {"", "/"} or parsed.params or parsed.query or parsed.fragment:
        raise ValueError("service-url must be an origin, not a path or query")
    return f"{parsed.scheme}://{parsed.netloc}"


def _request_json(url: str, token: str, *, method: str = "GET", payload: dict[str, Any] | None = None, idempotency_key: str | None = None) -> tuple[int, dict[str, Any], dict[str, str], bytes]:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8") if payload is not None else None
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key
    request = Request(url, data=body, headers=headers, method=method)
    try:
        with urlopen(request, timeout=30) as response:
            raw = response.read()
            status = response.status
            headers = dict(response.headers.items())
    except HTTPError as error:
        raw = error.read()
        status = error.code
        headers = dict(error.headers.items())
    except URLError as error:
        raise RuntimeError(f"GuardRails service request failed: {error.reason}") from error
    try:
        value = json.loads(raw or b"{}")
    except json.JSONDecodeError as error:
        raise RuntimeError(f"GuardRails service returned non-JSON HTTP {status}") from error
    if not isinstance(value, dict):
        raise RuntimeError(f"GuardRails service returned invalid JSON HTTP {status}")
    return status, value, headers, raw


def _job_url(base: str, job_id: str) -> str:
    if not job_id.startswith("job_"):
        raise RuntimeError("GuardRails service returned an invalid job identifier")
    return urljoin(base + "/", f"v1/jobs/{job_id}")


def run(args: argparse.Namespace) -> dict[str, Any]:
    if not args.token:
        raise ValueError("token must not be empty")
    if not args.extension_id or "." not in args.extension_id:
        raise ValueError("extension-id must use publisher.extension format")
    if not args.idempotency_key:
        raise ValueError("idempotency-key must not be empty")
    if args.poll_interval <= 0 or args.poll_interval > 60:
        raise ValueError("poll-interval must be greater than 0 and at most 60 seconds")
    if args.timeout <= 0 or args.timeout > 3600:
        raise ValueError("timeout must be greater than 0 and at most 3600 seconds")

    base = _service_base(args.service_url)
    payload: dict[str, Any] = {"extension_id": args.extension_id}
    if args.version:
        payload["version"] = args.version
    if args.target_platform:
        payload["target_platform"] = args.target_platform
    status, job, _headers, _raw = _request_json(
        urljoin(base + "/", "v1/scans/marketplace"),
        args.token,
        method="POST",
        payload=payload,
        idempotency_key=args.idempotency_key,
    )
    if status != 202:
        raise RuntimeError(str(job.get("error") or f"GuardRails scan submission failed with HTTP {status}"))
    job_id = str(job.get("id") or "")
    job_endpoint = _job_url(base, job_id)
    deadline = time.monotonic() + args.timeout
    while job.get("status") in {"queued", "running"}:
        if time.monotonic() >= deadline:
            raise RuntimeError(f"GuardRails job {job_id} did not finish within {args.timeout:g} seconds")
        time.sleep(args.poll_interval)
        status, job, _headers, _raw = _request_json(job_endpoint, args.token)
        if status != 200:
            raise RuntimeError(str(job.get("error") or f"Could not poll GuardRails job {job_id}"))

    if job.get("status") != "complete":
        raise RuntimeError(str(job.get("error") or f"GuardRails job {job_id} ended as {job.get('status')!r}"))
    report_ref = str(job.get("report_ref") or "")
    if not report_ref.startswith("/v1/reports/"):
        raise RuntimeError(f"GuardRails job {job_id} did not return an authenticated report reference")
    status, report, headers, raw_report = _request_json(urljoin(base + "/", report_ref.lstrip("/")), args.token)
    if status != 200:
        raise RuntimeError(str(report.get("error") or f"Could not retrieve GuardRails report for {job_id}"))
    report_sha256 = hashlib.sha256(raw_report).hexdigest()
    etag = headers.get("ETag") or headers.get("Etag")
    expected_etag = f'"sha256-{report_sha256}"'
    if etag and etag != expected_etag:
        raise RuntimeError("GuardRails report ETag does not match the retrieved report bytes")
    job_digest = str(job.get("report_sha256") or "")
    if job_digest and job_digest != report_sha256:
        raise RuntimeError("GuardRails job report_sha256 does not match the retrieved report bytes")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"job_id": job_id, "report_file": str(args.out), "report_sha256": report_sha256}


def main(argv: list[str] | None = None) -> int:
    try:
        result = run(_parse_args(argv))
    except (RuntimeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    output_path = os.environ.get("GITHUB_OUTPUT")
    if output_path:
        with Path(output_path).open("a", encoding="utf-8") as output:
            for key, value in result.items():
                output.write(f"{key}={value}\n")
    else:
        print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
