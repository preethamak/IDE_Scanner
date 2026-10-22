import os
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from http.server import ThreadingHTTPServer

from ide_scanner.service import (
    JobStore,
    MAINTENANCE_INTERVAL_SECONDS,
    JOB_RETENTION_SECONDS,
    ScanWorkerPool,
    ScannerServiceHandler,
    cleanup_stale_jobs,
    configured_api_tokens,
    execute_marketplace_job,
    health_payload,
    readiness_payload,
    maintain_store,
    openapi_payload,
    retry_failed_webhook_deliveries,
    serve,
)


class ScannerServiceTests(unittest.TestCase):
    def test_configured_api_tokens_combines_compatible_and_rotation_settings(self) -> None:
        with patch.dict(
            os.environ,
            {"IDE_SCANNER_API_TOKEN": "current", "IDE_SCANNER_API_TOKENS": " previous , current, , next "},
            clear=True,
        ):
            self.assertEqual(configured_api_tokens(), ("current", "previous", "next"))

    def test_job_store_persists_jobs_and_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = JobStore(Path(temp))
            job = store.create("publisher.extension")
            report_ref = store.write_report(job["id"], {"metadata": {"scan_id": "scan-1"}})

            self.assertEqual(store.get(job["id"])["extension_id"], "publisher.extension")
            self.assertEqual(report_ref, f"/v1/reports/{job['id']}")
            self.assertEqual(store.get_report(job["id"])["metadata"]["scan_id"], "scan-1")

    def test_job_store_persists_exact_marketplace_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = JobStore(Path(temp))
            job = store.create("publisher.extension", version="1.2.3", target_platform="linux-x64")
            persisted = store.get(job["id"])
            self.assertEqual(persisted["version"], "1.2.3")
            self.assertEqual(persisted["target_platform"], "linux-x64")

    def test_job_history_is_bounded_and_excludes_request_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = JobStore(Path(temp))
            job = store.create("publisher.extension")
            job["idempotency_key"] = "not-for-history"
            job["request_fingerprint"] = "not-for-history"
            store.write(job)
            other = store.create("other.extension")
            self.assertTrue(store.try_fail(other["id"], "failed scan"))
            history = store.list_summaries()
            publisher_history = store.list_summaries(extension_id="publisher.extension")
            self.assertEqual(publisher_history[0]["id"], job["id"])
            self.assertNotIn("idempotency_key", publisher_history[0])
            self.assertNotIn("request_fingerprint", publisher_history[0])
            self.assertEqual(len(publisher_history), 1)
            self.assertEqual(store.list_summaries(status="failed")[0]["id"], other["id"])

    def test_marketplace_job_writes_canonical_bundle(self) -> None:
        fixture = Path(__file__).resolve().parents[1] / "fixtures" / "benign-formatter"
        observed = {}

        def fake_scan(**kwargs: object):
            from ide_scanner.scanner import scan_targets

            observed.update(kwargs)
            return scan_targets(paths=[fixture], include_posture=False)

        with tempfile.TemporaryDirectory() as temp:
            store = JobStore(Path(temp))
            job = store.create("publisher.extension")
            job["version"] = "1.2.3"
            store.write(job)
            execute_marketplace_job(store, job, scan=fake_scan)
            completed = store.get(job["id"])
            report = store.get_report(job["id"])

            self.assertEqual(completed["status"], "complete")
            self.assertIn("summary", report)
            self.assertIn("leaderboard", report)
            self.assertIn("rules", report)
            self.assertIn("extensions", report)
            self.assertEqual(observed["marketplace_version"], "1.2.3")
            self.assertEqual(
                observed["required_providers"],
                frozenset({"semgrep", "yara", "dependency_intelligence"}),
            )

    def test_health_identifies_optional_providers(self) -> None:
        health = health_payload()

        self.assertEqual(health["status"], "ok")
        self.assertEqual(health["providers"]["semgrep"], "optional")
        self.assertEqual(health["providers"]["yara"], "optional")
        self.assertEqual(health["operations"]["job_retention_seconds"], JOB_RETENTION_SECONDS)
        self.assertEqual(health["operations"]["maintenance_interval_seconds"], MAINTENANCE_INTERVAL_SECONDS)

    def test_readiness_requires_storage_workers_and_queue_capacity(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = JobStore(Path(temp))
            pool = ScanWorkerPool(store, max_workers=1, max_queue=1)
            ready = readiness_payload(store, pool)

            self.assertEqual(ready["status"], "ready")
            self.assertEqual(ready["storage"], "available")
            self.assertEqual(ready["workers"], {"configured": 1, "alive": 1})
            self.assertEqual(ready["queue"], {"queued": 0, "capacity": 1})

    def test_openapi_contract_covers_public_and_authenticated_routes(self) -> None:
        contract = openapi_payload()

        self.assertEqual(contract["openapi"], "3.1.0")
        paths = contract["paths"]
        self.assertIn("/health", paths)
        self.assertIn("/v1/openapi.json", paths)
        self.assertIn("/readyz", paths)
        self.assertIn("/v1/rules", paths)
        self.assertIn("/v1/scans/marketplace", paths)
        self.assertIn("/v1/scans/mcp", paths)
        self.assertIn("/v1/jobs/{job_id}", paths)
        self.assertIn("/v1/jobs", paths)
        self.assertIn("/v1/reports/{job_id}", paths)
        self.assertNotIn("security", paths["/health"]["get"])
        self.assertIn("503", paths["/readyz"]["get"]["responses"])
        self.assertEqual(paths["/v1/scans/marketplace"]["post"]["security"], [{"bearerAuth": []}])
        self.assertIn("429", paths["/v1/scans/marketplace"]["post"]["responses"])
        self.assertIn("409", paths["/v1/scans/marketplace"]["post"]["responses"])
        self.assertEqual(paths["/v1/scans/marketplace"]["post"]["parameters"][0]["name"], "Idempotency-Key")
        self.assertEqual(paths["/v1/jobs/{job_id}"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]["properties"]["status"]["enum"], ["queued", "running", "complete", "failed", "cancelled"])
        self.assertEqual(paths["/v1/jobs/{job_id}"]["delete"]["security"], [{"bearerAuth": []}])
        self.assertIn("409", paths["/v1/jobs/{job_id}"]["delete"]["responses"])

    def test_openapi_contract_is_served_over_http_without_a_token(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = JobStore(Path(temp))
            server = ThreadingHTTPServer(("127.0.0.1", 0), ScannerServiceHandler)
            server.job_store = store  # type: ignore[attr-defined]
            server.scan_pool = ScanWorkerPool(store, max_workers=1, max_queue=1)  # type: ignore[attr-defined]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with urlopen(f"http://127.0.0.1:{server.server_port}/v1/openapi.json", timeout=2) as response:
                    payload = json.loads(response.read())
                self.assertEqual(response.status, 200)
                self.assertEqual(payload["openapi"], "3.1.0")
                self.assertIn("/v1/scans/marketplace", payload["paths"])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_http_job_history_requires_authentication_and_redacts_request_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = JobStore(Path(temp))
            job = store.create("publisher.extension")
            job.update({"idempotency_key": "private-key", "request_fingerprint": "private-request"})
            store.write(job)
            server = ThreadingHTTPServer(("127.0.0.1", 0), ScannerServiceHandler)
            server.job_store = store  # type: ignore[attr-defined]
            server.scan_pool = ScanWorkerPool(store, max_workers=1, max_queue=1)  # type: ignore[attr-defined]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            endpoint = f"http://127.0.0.1:{server.server_port}/v1/jobs"
            try:
                with patch.dict(os.environ, {"IDE_SCANNER_API_TOKEN": "service-token"}):
                    with self.assertRaises(HTTPError) as rejected:
                        urlopen(endpoint, timeout=2)
                    self.assertEqual(rejected.exception.code, 401)
                    request = Request(endpoint + "?extension_id=publisher.extension&limit=1", headers={"Authorization": "Bearer service-token"})
                    with urlopen(request, timeout=2) as response:
                        payload = json.loads(response.read())
                self.assertEqual(response.status, 200)
                self.assertEqual(payload["jobs"][0]["id"], job["id"])
                self.assertNotIn("idempotency_key", payload["jobs"][0])
                self.assertNotIn("request_fingerprint", payload["jobs"][0])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_http_accepts_each_configured_rotation_token_and_rejects_other_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = JobStore(Path(temp))
            server = ThreadingHTTPServer(("127.0.0.1", 0), ScannerServiceHandler)
            server.job_store = store  # type: ignore[attr-defined]
            server.scan_pool = ScanWorkerPool(store, max_workers=1, max_queue=1)  # type: ignore[attr-defined]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            endpoint = f"http://127.0.0.1:{server.server_port}/v1/jobs"
            try:
                with patch.dict(os.environ, {"IDE_SCANNER_API_TOKENS": "previous,current"}, clear=True):
                    for token in ("previous", "current"):
                        with urlopen(Request(endpoint, headers={"Authorization": f"Bearer {token}"}), timeout=2) as response:
                            self.assertEqual(response.status, 200)
                    with self.assertRaises(HTTPError) as rejected:
                        urlopen(Request(endpoint, headers={"Authorization": "Bearer invalid"}), timeout=2)
                    self.assertEqual(rejected.exception.code, 401)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_readiness_is_served_without_a_token(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = JobStore(Path(temp))
            server = ThreadingHTTPServer(("127.0.0.1", 0), ScannerServiceHandler)
            server.job_store = store  # type: ignore[attr-defined]
            server.scan_pool = ScanWorkerPool(store, max_workers=1, max_queue=1)  # type: ignore[attr-defined]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with urlopen(f"http://127.0.0.1:{server.server_port}/readyz", timeout=2) as response:
                    payload = json.loads(response.read())
                self.assertEqual(response.status, 200)
                self.assertEqual(payload["status"], "ready")
                self.assertNotIn("job", json.dumps(payload))
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_http_delete_cancels_a_queued_job_and_rejects_a_repeat(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = JobStore(Path(temp))
            job = store.create("publisher.cancelled")
            server = ThreadingHTTPServer(("127.0.0.1", 0), ScannerServiceHandler)
            server.job_store = store  # type: ignore[attr-defined]
            server.scan_pool = ScanWorkerPool(store, max_workers=1, max_queue=1)  # type: ignore[attr-defined]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            endpoint = f"http://127.0.0.1:{server.server_port}/v1/jobs/{job['id']}"
            try:
                with urlopen(Request(endpoint, method="DELETE"), timeout=2) as response:
                    payload = json.loads(response.read())
                self.assertEqual(response.status, 200)
                self.assertEqual(payload["status"], "cancelled")
                with self.assertRaises(HTTPError) as rejected:
                    urlopen(Request(endpoint, method="DELETE"), timeout=2)
                self.assertEqual(rejected.exception.code, 409)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_marketplace_submission_reuses_an_idempotency_key_only_for_the_same_request(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = JobStore(Path(temp))
            started = threading.Event()

            def blocking_runner(_store, _job):
                started.set()
                time.sleep(0.5)

            server = ThreadingHTTPServer(("127.0.0.1", 0), ScannerServiceHandler)
            server.job_store = store  # type: ignore[attr-defined]
            server.scan_pool = ScanWorkerPool(store, max_workers=1, max_queue=2, runner=blocking_runner)  # type: ignore[attr-defined]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            endpoint = f"http://127.0.0.1:{server.server_port}/v1/scans/marketplace"
            headers = {"Content-Type": "application/json", "Idempotency-Key": "release-review-42"}
            try:
                request = Request(endpoint, data=b'{"extension_id":"publisher.extension","version":"1.2.3"}', headers=headers, method="POST")
                with urlopen(request, timeout=2) as response:
                    first = json.loads(response.read())
                    self.assertEqual(response.status, 202)
                    self.assertIsNone(response.headers.get("Idempotent-Replayed"))
                self.assertTrue(started.wait(2))
                with urlopen(request, timeout=2) as response:
                    replay = json.loads(response.read())
                    self.assertEqual(response.status, 202)
                    self.assertEqual(response.headers.get("Idempotent-Replayed"), "true")
                self.assertEqual(replay["id"], first["id"])

                changed = Request(endpoint, data=b'{"extension_id":"publisher.extension","version":"1.2.4"}', headers=headers, method="POST")
                with self.assertRaises(HTTPError) as raised:
                    urlopen(changed, timeout=2)
                self.assertEqual(raised.exception.code, 409)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_rejected_submission_replays_its_retryable_capacity_response(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = JobStore(Path(temp))
            server = ThreadingHTTPServer(("127.0.0.1", 0), ScannerServiceHandler)
            server.job_store = store  # type: ignore[attr-defined]

            class FullPool:
                @staticmethod
                def submit(_job):
                    return False

            server.scan_pool = FullPool()  # type: ignore[attr-defined]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            request = Request(
                f"http://127.0.0.1:{server.server_port}/v1/scans/marketplace",
                data=b'{"extension_id":"publisher.extension"}',
                headers={"Content-Type": "application/json", "Idempotency-Key": "capacity-42"},
                method="POST",
            )
            try:
                for replay in (False, True):
                    with self.assertRaises(HTTPError) as raised:
                        urlopen(request, timeout=2)
                    self.assertEqual(raised.exception.code, 429)
                    self.assertEqual(raised.exception.headers.get("Retry-After"), "30")
                    self.assertEqual(raised.exception.headers.get("Idempotent-Replayed"), "true" if replay else None)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


class ScanWorkerPoolTests(unittest.TestCase):
    def test_queue_backpressure_rejects_when_full(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = JobStore(Path(temp))
            release = threading.Event()
            started = threading.Event()

            def blocking_runner(_store, job):
                started.set()
                release.wait(5)

            pool = ScanWorkerPool(store, max_workers=1, max_queue=1, runner=blocking_runner)
            first = store.create("publisher.one")
            self.assertTrue(pool.submit(first))
            started.wait(2)
            # One running + one queued fills capacity; further submits are rejected.
            self.assertTrue(pool.submit(store.create("publisher.two")))
            rejected = pool.submit(store.create("publisher.three"))
            self.assertFalse(rejected)
            release.set()

    def test_job_timeout_marks_failed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = JobStore(Path(temp))

            def slow_runner(_store, job):
                time.sleep(2)

            pool = ScanWorkerPool(store, max_workers=1, max_queue=2, job_timeout=1, runner=slow_runner)
            job = store.create("publisher.slow")
            pool.submit(job)
            time.sleep(1.5)
            record = store.get(job["id"])
            self.assertEqual(record["status"], "failed")
            self.assertEqual(record["stage"], "timeout")

    def test_late_runner_cannot_overwrite_a_timeout(self) -> None:
        fixture = Path(__file__).resolve().parents[1] / "fixtures" / "benign-formatter"
        with tempfile.TemporaryDirectory() as temp:
            store = JobStore(Path(temp))
            started = threading.Event()
            release = threading.Event()

            def slow_scan(**_kwargs: object):
                from ide_scanner.scanner import scan_targets

                started.set()
                release.wait(2)
                return scan_targets(paths=[fixture], include_posture=False)

            def runner(job_store, job):
                execute_marketplace_job(job_store, job, scan=slow_scan)

            pool = ScanWorkerPool(store, max_workers=1, max_queue=1, job_timeout=1, runner=runner)
            job = store.create("publisher.late")
            self.assertTrue(pool.submit(job))
            self.assertTrue(started.wait(2))
            time.sleep(1.2)
            self.assertEqual(store.get(job["id"])["stage"], "timeout")
            release.set()
            time.sleep(1.5)
            record = store.get(job["id"])
            self.assertEqual(record["status"], "failed")
            self.assertEqual(record["stage"], "timeout")
            self.assertIsNone(record.get("report_ref"))

    def test_cleanup_marks_interrupted_running_jobs(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = JobStore(Path(temp))
            job = store.create("publisher.stuck")
            job["status"] = "running"
            store.write(job)
            cleanup_stale_jobs(store)
            self.assertEqual(store.get(job["id"])["status"], "failed")

    def test_cancelled_queued_job_is_not_claimed_by_a_late_worker(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = JobStore(Path(temp))
            job = store.create("publisher.cancelled")
            cancelled, did_cancel = store.cancel(job["id"])

            self.assertTrue(did_cancel)
            self.assertEqual(cancelled["status"], "cancelled")
            self.assertIsNone(store.try_start(job["id"]))
            self.assertEqual(store.get(job["id"])["stage"], "cancelled")

    def test_cancelling_running_job_prevents_late_report_publication(self) -> None:
        fixture = Path(__file__).resolve().parents[1] / "fixtures" / "benign-formatter"
        with tempfile.TemporaryDirectory() as temp:
            store = JobStore(Path(temp))
            job = store.create("publisher.cancelled")
            self.assertIsNotNone(store.try_start(job["id"]))
            cancelled, did_cancel = store.cancel(job["id"])

            from ide_scanner.scanner import scan_targets

            report = scan_targets(paths=[fixture], include_posture=False)
            self.assertTrue(did_cancel)
            self.assertEqual(cancelled["status"], "cancelled")
            self.assertFalse(store.try_complete(job["id"], {"decision": "review"}, report))
            self.assertIsNone(store.get_report(job["id"]))

    def test_execution_does_not_publish_after_scan_is_cancelled(self) -> None:
        fixture = Path(__file__).resolve().parents[1] / "fixtures" / "benign-formatter"
        with tempfile.TemporaryDirectory() as temp:
            store = JobStore(Path(temp))
            job = store.create("publisher.cancelled")

            def cancelling_scan(**_kwargs: object):
                from ide_scanner.scanner import scan_targets

                store.cancel(job["id"])
                return scan_targets(paths=[fixture], include_posture=False)

            with patch("ide_scanner.service.deliver_terminal_webhook") as deliver:
                execute_marketplace_job(store, job, scan=cancelling_scan)
            self.assertEqual(store.get(job["id"])["status"], "cancelled")
            self.assertIsNone(store.get_report(job["id"]))
            deliver.assert_not_called()

    def test_terminal_job_cannot_be_cancelled(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = JobStore(Path(temp))
            job = store.create("publisher.complete")
            self.assertIsNotNone(store.try_start(job["id"]))
            self.assertTrue(store.try_fail(job["id"], "scanner failed"))

            persisted, did_cancel = store.cancel(job["id"])
            self.assertFalse(did_cancel)
            self.assertEqual(persisted["status"], "failed")

    def test_restart_retries_failed_terminal_webhooks_with_a_bounded_total(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = JobStore(Path(temp))
            job = store.create("publisher.extension")
            job.update({"status": "complete", "stage": "complete", "webhook_delivery": {"status": "failed", "attempts": 3, "total_attempts": 3}})
            store.write(job)
            with patch("ide_scanner.service.deliver_terminal_webhook", return_value={"delivery_id": "delivery_retry", "status": "delivered", "attempts": 2}) as deliver:
                self.assertEqual(retry_failed_webhook_deliveries(store), 1)
            persisted = store.get(job["id"])["webhook_delivery"]
            self.assertEqual(deliver.call_count, 1)
            self.assertEqual(persisted["status"], "delivered")
            self.assertEqual(persisted["total_attempts"], 5)

    def test_restart_dead_letters_delivery_that_exhausted_its_retry_budget(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = JobStore(Path(temp))
            job = store.create("publisher.extension")
            job.update({"status": "failed", "stage": "timeout", "webhook_delivery": {"status": "failed", "attempts": 3, "total_attempts": 9}})
            store.write(job)
            with patch("ide_scanner.service.deliver_terminal_webhook") as deliver:
                self.assertEqual(retry_failed_webhook_deliveries(store), 0)
            self.assertEqual(deliver.call_count, 0)
            self.assertEqual(store.get(job["id"])["webhook_delivery"]["status"], "dead_lettered")

    def test_maintenance_expires_old_state_and_recovers_webhooks(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = JobStore(Path(temp))
            expired = store.create("publisher.expired")
            expired_path = store.jobs_dir / f"{expired['id']}.json"
            old = time.time() - 120
            os.utime(expired_path, (old, old))
            retry = store.create("publisher.retry")
            retry.update({"status": "complete", "stage": "complete", "webhook_delivery": {"status": "failed", "attempts": 1, "total_attempts": 1}})
            store.write(retry)
            with patch("ide_scanner.service.deliver_terminal_webhook", return_value={"delivery_id": "delivery_recovered", "status": "delivered", "attempts": 1}):
                result = maintain_store(store, retention_seconds=60)
            self.assertEqual(result["removed"], 1)
            self.assertEqual(result["webhooks_retried"], 1)
            self.assertEqual(store.get(retry["id"])["webhook_delivery"]["status"], "delivered")


class ServeSecureDefaultTests(unittest.TestCase):
    def test_refuses_public_bind_without_token(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            env = {k: v for k, v in os.environ.items() if k not in {"IDE_SCANNER_API_TOKEN", "IDE_SCANNER_API_TOKENS", "IDE_SCANNER_ALLOW_INSECURE_BIND"}}
            with patch.dict(os.environ, env, clear=True):
                with self.assertRaises(SystemExit):
                    serve(host="0.0.0.0", port=8790, data_dir=Path(temp))
