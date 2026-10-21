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
    ScanWorkerPool,
    ScannerServiceHandler,
    cleanup_stale_jobs,
    execute_marketplace_job,
    health_payload,
    openapi_payload,
    serve,
)


class ScannerServiceTests(unittest.TestCase):
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

    def test_openapi_contract_covers_public_and_authenticated_routes(self) -> None:
        contract = openapi_payload()

        self.assertEqual(contract["openapi"], "3.1.0")
        paths = contract["paths"]
        self.assertIn("/health", paths)
        self.assertIn("/v1/openapi.json", paths)
        self.assertIn("/v1/rules", paths)
        self.assertIn("/v1/scans/marketplace", paths)
        self.assertIn("/v1/scans/mcp", paths)
        self.assertIn("/v1/jobs/{job_id}", paths)
        self.assertIn("/v1/reports/{job_id}", paths)
        self.assertNotIn("security", paths["/health"]["get"])
        self.assertEqual(paths["/v1/scans/marketplace"]["post"]["security"], [{"bearerAuth": []}])
        self.assertIn("429", paths["/v1/scans/marketplace"]["post"]["responses"])
        self.assertIn("409", paths["/v1/scans/marketplace"]["post"]["responses"])
        self.assertEqual(paths["/v1/scans/marketplace"]["post"]["parameters"][0]["name"], "Idempotency-Key")
        self.assertEqual(paths["/v1/jobs/{job_id}"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]["properties"]["status"]["enum"], ["queued", "running", "complete", "failed"])

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


class ServeSecureDefaultTests(unittest.TestCase):
    def test_refuses_public_bind_without_token(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            env = {k: v for k, v in os.environ.items() if k not in {"IDE_SCANNER_API_TOKEN", "IDE_SCANNER_ALLOW_INSECURE_BIND"}}
            with patch.dict(os.environ, env, clear=True):
                with self.assertRaises(SystemExit):
                    serve(host="0.0.0.0", port=8790, data_dir=Path(temp))
