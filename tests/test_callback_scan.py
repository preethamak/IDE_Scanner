import io
import unittest
from unittest.mock import MagicMock, patch
import urllib.error

from scripts import callback_scan


class CallbackScanTests(unittest.TestCase):
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
