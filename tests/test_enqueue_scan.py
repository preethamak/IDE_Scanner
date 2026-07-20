from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scripts.enqueue_scan import main


class _Response:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self) -> bytes:
        return json.dumps({"jobs": [{"id": "job-1"}]}).encode()


class EnqueueScanTests(unittest.TestCase):
    def test_no_maintenance_input_is_a_noop(self) -> None:
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / "output"
            with patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}, clear=True):
                self.assertEqual(main(), 0)
            self.assertEqual(output.read_text(encoding="utf-8"), "has_job=false\n")

    def test_exact_maintenance_job_is_enqueued(self) -> None:
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / "output"
            environment = {
                "GITHUB_OUTPUT": str(output),
                "SCAN_ENQUEUE_URL": "https://scanner.example/enqueue",
                "SCAN_EXTENSION_ID": "dbaeumer.vscode-eslint",
                "SCAN_EXTENSION_VERSION": "3.0.33",
                "SCAN_PURPOSE": "public_intelligence",
                "SCAN_RUNNER_SECRET": "secret",
            }
            with patch.dict(os.environ, environment, clear=True), patch("urllib.request.urlopen", return_value=_Response()) as urlopen:
                self.assertEqual(main(), 0)
            request = urlopen.call_args.args[0]
            self.assertEqual(request.get_header("Authorization"), "Bearer secret")
            self.assertIn(b'"version": "3.0.33"', request.data)
            self.assertEqual(output.read_text(encoding="utf-8"), "has_job=true\njob_id=job-1\n")


if __name__ == "__main__":
    unittest.main()
