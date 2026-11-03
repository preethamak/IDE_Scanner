from __future__ import annotations

import hashlib
import hmac
import json
import os
import unittest
import urllib.error
from unittest.mock import patch

from ide_scanner.webhooks import configured_webhook, deliver_terminal_webhook, validate_webhook_url


class _Response:
    status = 204

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def getcode(self):
        return self.status


class WebhookTests(unittest.TestCase):
    def setUp(self) -> None:
        self.environment = {
            "IDE_SCANNER_WEBHOOK_URL": "https://events.example.test/guardrails",
            "IDE_SCANNER_WEBHOOK_SECRET": "delivery-secret",
            "IDE_SCANNER_WEBHOOK_ALLOWED_HOSTS": "events.example.test",
        }
        self.job = {
            "id": "job_" + "a" * 32,
            "status": "complete",
            "stage": "complete",
            "extension_id": "publisher.extension",
            "version": "1.2.3",
            "target_platform": "linux-x64",
            "report_ref": "/v1/reports/job_" + "a" * 32,
            "error": None,
            "idempotency_key": "must-not-leak",
            "request_fingerprint": "must-not-leak",
        }

    def test_delivery_is_signed_minimal_and_does_not_include_request_secrets(self) -> None:
        observed = {}

        def urlopen(request, timeout):
            observed["request"] = request
            observed["timeout"] = timeout
            return _Response()

        with patch.dict(os.environ, self.environment, clear=False):
            result = deliver_terminal_webhook(self.job, urlopen=urlopen, sleep=lambda _delay: None)

        request = observed["request"]
        body = request.data
        payload = json.loads(body)
        self.assertEqual(result["status"], "delivered")
        self.assertEqual(payload["event"], "scan.completed")
        self.assertNotIn("idempotency_key", json.dumps(payload))
        self.assertEqual(observed["timeout"], 15)
        timestamp = request.get_header("X-guardrails-timestamp")
        expected = hmac.new(b"delivery-secret", timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
        self.assertEqual(request.get_header("X-guardrails-signature"), f"sha256={expected}")

    def test_transient_delivery_retries_but_permanent_rejection_does_not(self) -> None:
        attempts = []

        def transient(_request, timeout):
            self.assertEqual(timeout, 15)
            attempts.append("call")
            if len(attempts) == 1:
                raise urllib.error.HTTPError("https://events.example.test/guardrails", 503, "unavailable", {}, None)
            return _Response()

        with patch.dict(os.environ, self.environment, clear=False):
            result = deliver_terminal_webhook(self.job, urlopen=transient, sleep=lambda delay: attempts.append(delay))
        self.assertEqual(result["attempts"], 2)
        self.assertEqual(attempts, ["call", 1, "call"])

    def test_configuration_and_target_validation_fail_closed(self) -> None:
        with patch.dict(os.environ, {"IDE_SCANNER_WEBHOOK_URL": "https://events.example.test/guardrails"}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "must be configured together"):
                configured_webhook()
        with self.assertRaisesRegex(RuntimeError, "not in"):
            validate_webhook_url("https://other.example.test/hook", {"events.example.test"})
        with self.assertRaisesRegex(RuntimeError, "non-public"):
            validate_webhook_url("https://127.0.0.1/hook", {"127.0.0.1"})
