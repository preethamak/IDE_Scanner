import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from ide_scanner.service import (
    JobStore,
    ScanWorkerPool,
    cleanup_stale_jobs,
    execute_marketplace_job,
    health_payload,
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
