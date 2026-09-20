from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from scripts import run_scan_worker


def test_bounded_jobs_rejects_unbounded_worker_drain() -> None:
    assert run_scan_worker.bounded_jobs("8") == 8
    for value in ("0", "33", "not-a-number"):
        try:
            run_scan_worker.bounded_jobs(value)
        except RuntimeError:
            pass
        else:
            raise AssertionError(f"expected {value!r} to be rejected")


def test_worker_drains_until_claim_endpoint_is_empty(tmp_path: Path) -> None:
    job = {
        "id": "job-1",
        "extension_id": "publisher.extension",
        "version": "1.0.0",
        "callback_url": "https://example.invalid/callback",
    }
    with patch.dict(
        "os.environ",
        {
            "SCAN_CLAIM_URLS": "https://example.invalid/claim",
            "SCAN_RUNNER_ID": "runner-1",
            "SCAN_JOBS_PER_WORKER": "4",
            "IDE_SCANNER_WORKER_ARTIFACTS": str(tmp_path),
        },
        clear=True,
    ), patch.object(run_scan_worker.claim_scan, "urllib") as urllib_module, patch.object(
        run_scan_worker.claim_scan, "claim_job", side_effect=[job, None]
    ) as claim_job, patch.object(run_scan_worker, "run_scan", return_value=True) as run_scan, patch.object(
        run_scan_worker, "submit_result", return_value=True
    ) as submit_result:
        assert run_scan_worker.main() == 0

    assert claim_job.call_count == 2
    assert run_scan.call_count == 1
    assert submit_result.call_count == 1
    urllib_module.request.install_opener.assert_called_once()


def test_failed_scan_is_reported_and_worker_returns_failure(tmp_path: Path) -> None:
    job = {
        "id": "job-1",
        "extension_id": "publisher.extension",
        "version": "1.0.0",
        "callback_url": "https://example.invalid/callback",
    }
    with patch.dict(
        "os.environ",
        {
            "SCAN_CLAIM_URLS": "https://example.invalid/claim",
            "SCAN_RUNNER_ID": "runner-1",
            "SCAN_JOBS_PER_WORKER": "1",
            "IDE_SCANNER_WORKER_ARTIFACTS": str(tmp_path),
        },
        clear=True,
    ), patch.object(run_scan_worker.claim_scan, "urllib") as urllib_module, patch.object(
        run_scan_worker.claim_scan, "claim_job", return_value=job
    ), patch.object(run_scan_worker, "run_scan", return_value=False), patch.object(
        run_scan_worker, "submit_result", return_value=True
    ) as submit_result:
        assert run_scan_worker.main() == 1

    submit_result.assert_called_once_with(job, None)
    urllib_module.request.install_opener.assert_called_once()
