from __future__ import annotations

import subprocess
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


def test_bounded_retries_rejects_unbounded_claim_retries() -> None:
    assert run_scan_worker.bounded_retries("5") == 5
    for value in ("-1", "17", "not-a-number"):
        try:
            run_scan_worker.bounded_retries(value)
        except RuntimeError:
            pass
        else:
            raise AssertionError(f"expected {value!r} to be rejected")


def test_bounded_job_timeout_rejects_unbounded_scan_processes() -> None:
    assert run_scan_worker.bounded_job_timeout("300") == 300
    for value in ("59", "1801", "not-a-number"):
        try:
            run_scan_worker.bounded_job_timeout(value)
        except RuntimeError:
            pass
        else:
            raise AssertionError(f"expected {value!r} to be rejected")


def test_scan_timeout_kills_the_entire_process_group(tmp_path: Path) -> None:
    class TimedOutProcess:
        pid = 1234

        def __init__(self) -> None:
            self.wait_calls = 0

        def wait(self, timeout: int) -> int:
            self.wait_calls += 1
            if self.wait_calls == 1:
                raise subprocess.TimeoutExpired("scanner", timeout)
            return -9

    process = TimedOutProcess()
    job = {
        "id": "job-timeout",
        "extension_id": "publisher.extension",
        "version": "1.0.0",
    }
    with patch.dict("os.environ", {"IDE_SCANNER_ARTIFACT_STORE": str(tmp_path)}, clear=True), patch.object(
        run_scan_worker.subprocess, "Popen", return_value=process
    ) as popen, patch.object(run_scan_worker.os, "killpg") as killpg:
        assert run_scan_worker.run_scan(job, tmp_path / "scan.json", timeout_seconds=60) is False

    popen.assert_called_once()
    assert popen.call_args.kwargs["start_new_session"] is False
    killpg.assert_called_once_with(1234, run_scan_worker.signal.SIGKILL)
    assert process.wait_calls == 2


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
            "SCAN_EMPTY_CLAIM_RETRIES": "0",
            "IDE_SCANNER_WORKER_ARTIFACTS": str(tmp_path),
        },
        clear=True,
    ), patch.object(run_scan_worker.claim_scan, "urllib") as urllib_module, patch.object(
        run_scan_worker.claim_scan, "claim_job", side_effect=[job, None]
    ) as claim_job, patch.object(run_scan_worker, "run_scan", return_value=True) as run_scan, patch.object(
        run_scan_worker, "submit_result", return_value=True
    ) as submit_result, patch.object(run_scan_worker, "sandbox_preflight", return_value={"status": "ready"}):
        assert run_scan_worker.main() == 0

    assert claim_job.call_count == 2
    assert run_scan.call_count == 1
    assert submit_result.call_count == 1
    urllib_module.request.install_opener.assert_called_once()


def test_worker_retries_transient_empty_claim(tmp_path: Path) -> None:
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
            "SCAN_EMPTY_CLAIM_RETRIES": "1",
            "IDE_SCANNER_WORKER_ARTIFACTS": str(tmp_path),
        },
        clear=True,
    ), patch.object(run_scan_worker.claim_scan, "urllib") as urllib_module, patch.object(
        run_scan_worker.claim_scan, "claim_job", side_effect=[None, job]
    ) as claim_job, patch.object(run_scan_worker, "run_scan", return_value=True), patch.object(
        run_scan_worker, "submit_result", return_value=True
    ), patch.object(run_scan_worker.time, "sleep") as sleep, patch.object(
        run_scan_worker, "sandbox_preflight", return_value={"status": "ready"}
    ):
        assert run_scan_worker.main() == 0

    assert claim_job.call_count == 2
    sleep.assert_called_once_with(0.2)
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
    ) as submit_result, patch.object(run_scan_worker, "sandbox_preflight", return_value={"status": "ready"}):
        assert run_scan_worker.main() == 1

    submit_result.assert_called_once_with(job, None)
    urllib_module.request.install_opener.assert_called_once()


def test_worker_refuses_to_claim_when_runtime_preflight_is_unavailable() -> None:
    with patch.object(
        run_scan_worker,
        "sandbox_preflight",
        return_value={"status": "unavailable", "error": "namespace denied"},
    ):
        try:
            run_scan_worker.require_runtime_preflight()
        except RuntimeError as error:
            assert "namespace denied" in str(error)
        else:
            raise AssertionError("worker must refuse an unavailable runtime sandbox")


def test_worker_exits_before_claiming_when_runtime_preflight_is_unavailable() -> None:
    with patch.dict("os.environ", {}, clear=True), patch.object(
        run_scan_worker,
        "sandbox_preflight",
        return_value={"status": "unavailable", "error": "namespace denied"},
    ), patch.object(run_scan_worker.claim_scan, "claim_job") as claim_job:
        assert run_scan_worker.main() == 2
    claim_job.assert_not_called()
