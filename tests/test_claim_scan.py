from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).parents[1] / "scripts" / "claim_scan.py"
SPEC = importlib.util.spec_from_file_location("claim_scan", SCRIPT)
assert SPEC and SPEC.loader
claim_scan = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(claim_scan)


class Response:
    def __init__(self, status: int, payload: dict | None = None):
        self.status = status
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self) -> bytes:
        return json.dumps(self.payload or {}).encode()


class ClaimScanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.output = Path(self.temp.name) / "output"
        self.environment = {
            "SCAN_CLAIM_URL": "https://scanner.example/claim",
            "SCAN_RUNNER_ID": "github-actions-123",
            "SCAN_RUNNER_SECRET": "test-secret",
            "GITHUB_OUTPUT": str(self.output),
        }

    def tearDown(self):
        self.temp.cleanup()

    def test_empty_queue_writes_false(self):
        with patch.dict("os.environ", self.environment, clear=True), patch.object(claim_scan.urllib.request, "urlopen", return_value=Response(204)):
            self.assertEqual(claim_scan.main(), 0)
        self.assertEqual(self.output.read_text(), "has_job=false\n")

    def test_claim_writes_exact_artifact_outputs(self):
        payload = {"id": "job-1", "extension_id": "publisher.extension", "version": "1.2.3", "callback_url": "https://scanner.example/callback"}
        with patch.dict("os.environ", self.environment, clear=True), patch.object(claim_scan.urllib.request, "urlopen", return_value=Response(200, payload)):
            self.assertEqual(claim_scan.main(), 0)
        output = self.output.read_text()
        self.assertIn("has_job=true", output)
        self.assertIn("job_id=job-1", output)
        self.assertIn("extension_id=publisher.extension", output)
        self.assertIn("version=1.2.3", output)

    def test_claim_checks_the_next_url_when_the_first_queue_is_empty(self):
        environment = {**self.environment, "SCAN_CLAIM_URLS": "https://primary.example/claim,https://secondary.example/claim"}
        payload = {"id": "job-2", "extension_id": "publisher.extension", "version": "2.0.0", "callback_url": "https://scanner.example/callback"}
        with patch.dict("os.environ", environment, clear=True), patch.object(claim_scan.urllib.request, "urlopen", side_effect=[Response(204), Response(200, payload)]) as urlopen:
            self.assertEqual(claim_scan.main(), 0)
        self.assertEqual(urlopen.call_count, 2)
        self.assertIn("job_id=job-2", self.output.read_text())

    def test_incomplete_claim_is_rejected(self):
        with patch.dict("os.environ", self.environment, clear=True), patch.object(claim_scan.urllib.request, "urlopen", return_value=Response(200, {"id": "job-1"})):
            with self.assertRaisesRegex(RuntimeError, "incomplete"):
                claim_scan.main()


if __name__ == "__main__":
    unittest.main()
