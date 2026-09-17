import io
import unittest
from unittest.mock import MagicMock, patch
import urllib.error
import gzip
import json
import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts import callback_scan


class CallbackScanTests(unittest.TestCase):
    def test_callback_wrapper_contains_validated_target_platform(self) -> None:
        with TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle.json"
            bundle.write_text('{"extensions":[]}', encoding="utf-8")
            environment = {"SCAN_JOB_ID": "job-1", "SCAN_TARGET_PLATFORM": "Darwin-X64"}
            with patch.dict(os.environ, environment, clear=True), patch.object(
                sys, "argv", ["callback_scan.py", str(bundle)]
            ), patch.object(callback_scan, "submit_callback", return_value="ok") as submit:
                self.assertEqual(callback_scan.main(), 0)
            wrapper = json.loads(gzip.decompress(submit.call_args.args[0]))
            self.assertEqual(wrapper["target_platform"], "darwin-x64")
            self.assertEqual(wrapper["bundle"], {"extensions": []})

    def test_callback_rejects_invalid_target_platform(self) -> None:
        with patch.dict(os.environ, {"SCAN_JOB_ID": "job-1", "SCAN_TARGET_PLATFORM": "x\nevil=y"}, clear=True), patch.object(
            callback_scan, "submit_callback"
        ) as submit, self.assertRaisesRegex(RuntimeError, "target platform"):
            callback_scan.main()
        submit.assert_not_called()
    def test_retries_transient_upstream_failure(self) -> None:
        transient = urllib.error.HTTPError(
            "https://example.invalid/callback",
            503,
            "Service unavailable",
            {},
            io.BytesIO(b"temporary outage"),
        )
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b'{"scan_id":"scan-1"}'

        with (
            patch.dict(callback_scan.os.environ, {"SCAN_CALLBACK_SECRET": "secret", "SCAN_CALLBACK_URL": "https://example.invalid/callback"}),
            patch.object(callback_scan.urllib.request, "urlopen", side_effect=[transient, response]) as urlopen,
            patch.object(callback_scan.time, "sleep") as sleep,
        ):
            result = callback_scan.submit_callback(b"payload")

        self.assertEqual(result, '{"scan_id":"scan-1"}')
        self.assertEqual(urlopen.call_count, 2)
        sleep.assert_called_once_with(2)

    def test_recognizes_legacy_wrapped_supabase_520_as_transient(self) -> None:
        detail = "gateway.supabase.co | 520: Web server is returning an unknown error"

        self.assertTrue(callback_scan.is_retryable_http_error(422, detail))

    def test_does_not_retry_semantic_rejection(self) -> None:
        rejected = urllib.error.HTTPError(
            "https://example.invalid/callback",
            422,
            "Unprocessable Entity",
            {},
            io.BytesIO(b"invalid scan bundle"),
        )

        with (
            patch.dict(callback_scan.os.environ, {"SCAN_CALLBACK_SECRET": "secret", "SCAN_CALLBACK_URL": "https://example.invalid/callback"}),
            patch.object(callback_scan.urllib.request, "urlopen", side_effect=rejected) as urlopen,
            patch.object(callback_scan.time, "sleep") as sleep,
            self.assertRaisesRegex(RuntimeError, "HTTP 422"),
        ):
            callback_scan.submit_callback(b"payload")

        urlopen.assert_called_once()
        sleep.assert_not_called()
