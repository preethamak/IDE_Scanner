import argparse
import importlib.util
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ACTION_SCRIPT = Path(__file__).resolve().parents[1] / ".github" / "actions" / "marketplace-service-scan" / "scan.py"
SPEC = importlib.util.spec_from_file_location("marketplace_service_scan", ACTION_SCRIPT)
assert SPEC and SPEC.loader
marketplace_service_scan = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(marketplace_service_scan)


class _ServiceHandler(BaseHTTPRequestHandler):
    requests = []

    def do_POST(self):  # noqa: N802
        self.__class__.requests.append((
            self.path,
            self.headers.get("Authorization"),
            self.headers.get("Idempotency-Key"),
            json.loads(self.rfile.read(int(self.headers["Content-Length"]))),
        ))
        self._json(202, {"id": "job_" + "a" * 32, "status": "queued"})

    def do_GET(self):  # noqa: N802
        if self.path == "/v1/jobs/job_" + "a" * 32:
            self._json(200, {"id": "job_" + "a" * 32, "status": "complete", "report_ref": "/v1/reports/job_" + "a" * 32})
            return
        if self.path == "/v1/reports/job_" + "a" * 32:
            self._json(200, {"leaderboard": {"extensions": [{"decision": "review"}]}})
            return
        self._json(404, {"error": "not found"})

    def log_message(self, *_args):
        return

    def _json(self, status, value):
        body = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class MarketplaceServiceActionTests(unittest.TestCase):
    def setUp(self):
        _ServiceHandler.requests = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _ServiceHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_submits_exact_release_polls_and_writes_report(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "report.json"
            args = argparse.Namespace(
                service_url=f"http://127.0.0.1:{self.server.server_port}",
                token="test-token",
                extension_id="publisher.extension",
                version="1.2.3",
                target_platform="linux-x64",
                idempotency_key="release-1",
                poll_interval=0.01,
                timeout=1,
                out=out,
            )
            result = marketplace_service_scan.run(args)

            self.assertEqual(result["job_id"], "job_" + "a" * 32)
            self.assertEqual(json.loads(out.read_text())["leaderboard"]["extensions"][0]["decision"], "review")
            path, authorization, key, payload = _ServiceHandler.requests[0]
            self.assertEqual(path, "/v1/scans/marketplace")
            self.assertEqual(authorization, "Bearer test-token")
            self.assertEqual(key, "release-1")
            self.assertEqual(payload, {"extension_id": "publisher.extension", "version": "1.2.3", "target_platform": "linux-x64"})

    def test_rejects_service_urls_with_a_path_or_credentials(self):
        with self.assertRaises(ValueError):
            marketplace_service_scan._service_base("https://token@example.com")
        with self.assertRaises(ValueError):
            marketplace_service_scan._service_base("https://scanner.example/v1")
