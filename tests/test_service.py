import tempfile
import unittest
from pathlib import Path

from ide_scanner.service import JobStore, execute_marketplace_job, health_payload


class ScannerServiceTests(unittest.TestCase):
    def test_job_store_persists_jobs_and_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = JobStore(Path(temp))
            job = store.create("publisher.extension")
            report_ref = store.write_report(job["id"], {"metadata": {"scan_id": "scan-1"}})

            self.assertEqual(store.get(job["id"])["extension_id"], "publisher.extension")
            self.assertEqual(report_ref, f"/v1/reports/{job['id']}")
            self.assertEqual(store.get_report(job["id"])["metadata"]["scan_id"], "scan-1")

    def test_marketplace_job_writes_canonical_bundle(self) -> None:
        fixture = Path(__file__).resolve().parents[1] / "fixtures" / "benign-formatter"

        def fake_scan(**_: object):
            from ide_scanner.scanner import scan_targets

            return scan_targets(paths=[fixture], include_posture=False)

        with tempfile.TemporaryDirectory() as temp:
            store = JobStore(Path(temp))
            job = store.create("publisher.extension")
            execute_marketplace_job(store, job, scan=fake_scan)
            completed = store.get(job["id"])
            report = store.get_report(job["id"])

            self.assertEqual(completed["status"], "complete")
            self.assertIn("summary", report)
            self.assertIn("leaderboard", report)
            self.assertIn("rules", report)
            self.assertIn("extensions", report)

    def test_health_identifies_optional_providers(self) -> None:
        health = health_payload()

        self.assertEqual(health["status"], "ok")
        self.assertEqual(health["providers"]["semgrep"], "optional")
        self.assertEqual(health["providers"]["yara"], "optional")
