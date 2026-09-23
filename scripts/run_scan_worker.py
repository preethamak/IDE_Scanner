from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

try:
    from scripts import callback_scan, claim_scan
except ModuleNotFoundError:  # Direct `python scripts/run_scan_worker.py` execution.
    import callback_scan  # type: ignore[no-redef]
    import claim_scan  # type: ignore[no-redef]

from ide_scanner.sandbox_runner import sandbox_preflight


TARGET_PLATFORM_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")


def main() -> int:
    try:
        require_runtime_preflight()
    except RuntimeError as error:
        print(f"Deep Scan worker not started: {error}", file=sys.stderr)
        return 2
    max_jobs = bounded_jobs(os.environ.get("SCAN_JOBS_PER_WORKER", "1"))
    empty_claim_retries = bounded_retries(os.environ.get("SCAN_EMPTY_CLAIM_RETRIES", "5"))
    artifact_root = Path(
        os.environ.get(
            "IDE_SCANNER_WORKER_ARTIFACTS",
            os.path.join(os.environ.get("RUNNER_TEMP", "/tmp"), "ide-scanner-worker-artifacts"),
        )
    )
    artifact_root.mkdir(parents=True, exist_ok=True)
    claim_scan.urllib.request.install_opener(
        claim_scan.urllib.request.build_opener(urllib_redirect_handler())
    )

    exact_job_id = os.environ.get("SCAN_JOB_ID", "").strip() or None
    enqueued_job_id = os.environ.get("SCAN_ENQUEUED_JOB_ID", "").strip() or None
    job_timeout = bounded_job_timeout(os.environ.get("SCAN_JOB_TIMEOUT_SECONDS", "300"))
    failures = 0
    completed = 0

    for index in range(max_jobs):
        job_id = exact_job_id if index == 0 and exact_job_id else None
        if index == 0 and not job_id and enqueued_job_id:
            job_id = enqueued_job_id
        job = claim_with_retries(
            claim_url(),
            job_id=job_id,
            runner_suffix=str(index),
            retries=0 if job_id else empty_claim_retries,
        )
        if job is None:
            break

        try:
            bundle_path = artifact_root / f"{safe_name(str(job['id']))}.json"
            scan_result = run_scan(job, bundle_path, timeout_seconds=job_timeout)
            callback_result = submit_result(job, bundle_path if scan_result else None)
            if not scan_result or not callback_result:
                failures += 1
            else:
                completed += 1
        except Exception as error:  # noqa: BLE001 - report one bad artifact, then drain the queue.
            failures += 1
            report_failure(job, f"Deep Scan worker failed: {type(error).__name__}: {error}")
        if exact_job_id:
            break

    print(json.dumps({"completed": completed, "failures": failures, "max_jobs": max_jobs}, sort_keys=True))
    return 1 if failures else 0


def require_runtime_preflight() -> None:
    """Refuse to claim production jobs unless runtime isolation is ready."""
    result = sandbox_preflight()
    if result.get("status") != "ready":
        detail = str(result.get("error") or "runtime isolation preflight did not complete")
        raise RuntimeError(f"Production scan worker requires a ready runtime sandbox: {detail}")


def run_scan(job: dict[str, object], bundle_path: Path, *, timeout_seconds: int = 300) -> bool:
    extension_id = str(job["extension_id"])
    version = str(job["version"])
    target_platform = str(job.get("target_platform") or "").strip().lower()
    if target_platform and not TARGET_PLATFORM_RE.fullmatch(target_platform):
        raise RuntimeError("Scan claim target platform is invalid")

    command = [
        sys.executable,
        "-m",
        "ide_scanner",
        "scan",
        "--extension-id",
        extension_id,
        "--version",
        version,
        "--profile",
        "deep",
        "--online",
        "--runtime",
        "--runtime-timeout",
        os.environ.get("IDE_SCANNER_RUNTIME_TIMEOUT", "20"),
        "--format",
        "bundle.json",
        "--include-raw-evidence",
        "--artifact-store",
        os.environ["IDE_SCANNER_ARTIFACT_STORE"],
        "--output",
        str(bundle_path),
    ]
    if target_platform:
        command.extend(["--target-platform", target_platform])

    environment = os.environ.copy()
    environment["IDE_SCANNER_BUILD_SHA"] = os.environ.get("IDE_SCANNER_BUILD_SHA", "")
    environment["SCAN_TARGET_PLATFORM"] = target_platform
    process = subprocess.Popen(
        isolated_worker_command(command),
        env=environment,
        start_new_session=False,
    )
    try:
        returncode = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        terminate_process_group(process)
        print(
            f"Scan job {job.get('id', 'unknown')} exceeded the {timeout_seconds}-second worker timeout.",
            file=sys.stderr,
        )
        return False
    return returncode == 0 and bundle_path.exists()


def isolated_worker_command(command: list[str]) -> list[str]:
    """Launch the scanner through a clean session before importing analyzers."""
    launcher = Path(__file__).with_name("exec_scan_worker.py")
    return [sys.executable, str(launcher), "--", *command]


def terminate_process_group(process: subprocess.Popen[object]) -> None:
    """Stop the scanner and any provider children after a job timeout."""
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    else:  # pragma: no cover - production workers are Linux
        try:
            process.kill()
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def submit_result(job: dict[str, object], bundle_path: Path | None) -> bool:
    with temporary_environment(
        {
            "SCAN_JOB_ID": str(job["id"]),
            "SCAN_CALLBACK_URL": str(job["callback_url"]),
            "SCAN_TARGET_PLATFORM": str(job.get("target_platform") or ""),
            "SCAN_ERROR": "Deep Scan failed before a canonical report was produced.",
        }
    ):
        try:
            callback_scan.main([str(bundle_path)] if bundle_path else [])
            return True
        except Exception as error:  # noqa: BLE001 - callback status is reflected in D1 and the run summary.
            print(f"Callback failed for {job['id']}: {error}", file=sys.stderr)
            return False


def report_failure(job: dict[str, object], error_message: str) -> None:
    with temporary_environment(
        {
            "SCAN_JOB_ID": str(job["id"]),
            "SCAN_CALLBACK_URL": str(job["callback_url"]),
            "SCAN_TARGET_PLATFORM": str(job.get("target_platform") or ""),
            "SCAN_ERROR": error_message,
        }
    ):
        try:
            callback_scan.main([])
        except Exception as error:  # noqa: BLE001 - preserve the original failure and continue draining.
            print(f"Failure callback failed for {job['id']}: {error}", file=sys.stderr)


def claim_url() -> str:
    configured = os.environ.get("SCAN_CLAIM_URLS") or os.environ.get("SCAN_CLAIM_URL", "")
    urls = [url.strip() for url in configured.split(",") if url.strip()]
    if not urls:
        raise RuntimeError("SCAN_CLAIM_URLS or SCAN_CLAIM_URL is required")
    return urls[0]


def safe_name(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9_.-]", "_", value)
    return normalized[:180] or "scan"


def bounded_jobs(value: str) -> int:
    try:
        jobs = int(value)
    except ValueError as error:
        raise RuntimeError("SCAN_JOBS_PER_WORKER must be an integer between 1 and 32") from error
    if not 1 <= jobs <= 32:
        raise RuntimeError("SCAN_JOBS_PER_WORKER must be an integer between 1 and 32")
    return jobs


def bounded_retries(value: str) -> int:
    try:
        retries = int(value)
    except ValueError as error:
        raise RuntimeError("SCAN_EMPTY_CLAIM_RETRIES must be an integer between 0 and 16") from error
    if not 0 <= retries <= 16:
        raise RuntimeError("SCAN_EMPTY_CLAIM_RETRIES must be an integer between 0 and 16")
    return retries


def bounded_job_timeout(value: str) -> int:
    try:
        timeout = int(value)
    except ValueError as error:
        raise RuntimeError("SCAN_JOB_TIMEOUT_SECONDS must be an integer between 60 and 1800") from error
    if not 60 <= timeout <= 1800:
        raise RuntimeError("SCAN_JOB_TIMEOUT_SECONDS must be an integer between 60 and 1800")
    return timeout


def claim_with_retries(
    url: str,
    *,
    job_id: str | None,
    runner_suffix: str,
    retries: int,
) -> dict[str, object] | None:
    """Retry empty claims briefly to absorb concurrent conditional-update races."""
    for attempt in range(retries + 1):
        job = claim_scan.claim_job(url, job_id=job_id, runner_suffix=runner_suffix)
        if job is not None:
            return job
        if attempt >= retries:
            break
        time.sleep(min(1.0, 0.2 * (2**attempt)))
    return None


class temporary_environment:
    def __init__(self, values: dict[str, str]):
        self.values = values
        self.previous: dict[str, str | None] = {}

    def __enter__(self):
        for key, value in self.values.items():
            self.previous[key] = os.environ.get(key)
            os.environ[key] = value
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        for key, previous in self.previous.items():
            if previous is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = previous
        return False


def urllib_redirect_handler():
    return claim_scan._PostPreservingRedirect()


if __name__ == "__main__":
    raise SystemExit(main())
