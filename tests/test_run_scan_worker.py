from __future__ import annotations

import json
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


def test_public_scan_worker_omits_raw_evidence_to_bound_public_storage(tmp_path: Path) -> None:
    class CompletedProcess:
        pid = 1234

        def wait(self, timeout: int) -> int:
            return 0

        def poll(self) -> int:
            return 0

    with patch.dict("os.environ", {"IDE_SCANNER_ARTIFACT_STORE": str(tmp_path)}, clear=True), patch.object(
        run_scan_worker.subprocess, "Popen", return_value=CompletedProcess()
    ) as popen, patch.object(run_scan_worker, "bundle_has_immutable_identity", return_value=True):
        (tmp_path / "scan.json").touch()
        assert run_scan_worker.run_scan(
            {
                "id": "public-job",
                "extension_id": "publisher.extension",
                "version": "1.0.0",
                "scan_purpose": "public_intelligence",
            },
            tmp_path / "scan.json",
            timeout_seconds=60,
        ) is True

    command = popen.call_args.args[0]
    assert "--include-raw-evidence" not in command


def test_user_scan_worker_keeps_raw_evidence_opt_in(tmp_path: Path) -> None:
    class CompletedProcess:
        pid = 1234

        def wait(self, timeout: int) -> int:
            return 0

        def poll(self) -> int:
            return 0

    with patch.dict("os.environ", {"IDE_SCANNER_ARTIFACT_STORE": str(tmp_path)}, clear=True), patch.object(
        run_scan_worker.subprocess, "Popen", return_value=CompletedProcess()
    ) as popen, patch.object(run_scan_worker, "bundle_has_immutable_identity", return_value=True):
        (tmp_path / "scan.json").touch()
        assert run_scan_worker.run_scan(
            {
                "id": "user-job",
                "extension_id": "publisher.extension",
                "version": "1.0.0",
                "scan_purpose": "user_request",
            },
            tmp_path / "scan.json",
            timeout_seconds=60,
        ) is True

    command = popen.call_args.args[0]
    assert "--include-raw-evidence" in command


def test_bundle_identity_contract_rejects_acquisition_failure(tmp_path: Path) -> None:
    bundle = tmp_path / "scan.json"
    bundle.write_text(
        json.dumps({
            "extensions": {
                "extensions/example.unknown.json": {
                    "extension_id": "example.extension",
                    "version": "unknown",
                    "source": "marketplace-error",
                }
            }
        }),
        encoding="utf-8",
    )
    assert run_scan_worker.bundle_has_immutable_identity(
        bundle,
        {"extension_id": "example.extension", "version": "1.0.0"},
    ) is False


def test_bundle_identity_contract_accepts_exact_artifact(tmp_path: Path) -> None:
    bundle = tmp_path / "scan.json"
    digest = "a" * 64
    bundle.write_text(
        json.dumps({
            "extensions": {
                "extensions/example.extension-1.0.0.json": {
                    "extension_id": "example.extension",
                    "version": "1.0.0",
                    "artifact_identity": {
                        "extension_id": "example.extension",
                        "version": "1.0.0",
                        "sha256": digest,
                    },
                }
            }
        }),
        encoding="utf-8",
    )
    assert run_scan_worker.bundle_has_immutable_identity(
        bundle,
        {"extension_id": "example.extension", "version": "1.0.0"},
    ) is True


def test_scan_failure_reason_exposes_bounded_manifest_failure(tmp_path: Path) -> None:
    bundle = tmp_path / "scan.json"
    bundle.write_text(
        json.dumps({
            "extensions": [{
                "extension_id": "Codium.qodogen",
                "version": "0.14.2",
                "artifact_inventory": {
                    "skipped_reason": "VSIX did not contain an extension package.json",
                },
            }]
        }),
        encoding="utf-8",
    )
    reason = run_scan_worker.scan_failure_reason(
        bundle,
        {"extension_id": "Codium.qodogen", "version": "0.14.2"},
    )
    assert reason == (
        "Deep Scan failed before a canonical report was produced for "
        "Codium.qodogen@0.14.2: VSIX did not contain an extension package.json"
    )


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


def test_worker_retries_transient_claim_error(tmp_path: Path) -> None:
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
            "SCAN_CLAIM_ERROR_RETRIES": "1",
            "IDE_SCANNER_WORKER_ARTIFACTS": str(tmp_path),
        },
        clear=True,
    ), patch.object(run_scan_worker.claim_scan, "urllib") as urllib_module, patch.object(
        run_scan_worker.claim_scan, "claim_job", side_effect=[RuntimeError("Scan claim returned HTTP 503"), job]
    ) as claim_job, patch.object(run_scan_worker, "run_scan", return_value=True), patch.object(
        run_scan_worker, "submit_result", return_value=True
    ), patch.object(run_scan_worker.time, "sleep") as sleep, patch.object(
        run_scan_worker, "sandbox_preflight", return_value={"status": "ready"}
    ):
        assert run_scan_worker.main() == 0

    assert claim_job.call_count == 2
    sleep.assert_called_once_with(0.5)
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
        run_scan_worker,
        "scan_failure_reason",
        return_value="bounded reason",
    ), patch.object(
        run_scan_worker, "submit_result", return_value=True
    ) as submit_result, patch.object(run_scan_worker, "sandbox_preflight", return_value={"status": "ready"}):
        assert run_scan_worker.main() == 1

    submit_result.assert_called_once_with(job, None, error_message="bounded reason")
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
