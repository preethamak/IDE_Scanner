#!/usr/bin/env python3
"""Deterministic HTTP fixture for the Marketplace service action workflow."""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


JOB_ID = "job_" + "a" * 32


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/v1/scans/marketplace" or self.headers.get("authorization") != "Bearer test-token":
            self._json(401, {"error": "unauthorized"})
            return
        payload = json.loads(self.rfile.read(int(self.headers.get("content-length", "0"))) or b"{}")
        if payload != {"extension_id": "publisher.extension", "version": "1.2.3", "target_platform": "linux-x64"}:
            self._json(400, {"error": "unexpected exact release"})
            return
        self._json(202, {"id": JOB_ID, "status": "queued"})

    def do_GET(self) -> None:  # noqa: N802
        if self.headers.get("authorization") != "Bearer test-token":
            self._json(401, {"error": "unauthorized"})
        elif self.path == f"/v1/jobs/{JOB_ID}":
            self._json(200, {"id": JOB_ID, "status": "complete", "report_ref": f"/v1/reports/{JOB_ID}"})
        elif self.path == f"/v1/reports/{JOB_ID}":
            self._json(200, {"leaderboard": {"extensions": [{"decision": "review"}]}})
        else:
            self._json(404, {"error": "not found"})

    def log_message(self, _format: str, *args: object) -> None:
        return

    def _json(self, status: int, value: dict[str, object]) -> None:
        body = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
