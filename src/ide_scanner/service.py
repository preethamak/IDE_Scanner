from __future__ import annotations

import argparse
import hmac
import json
import os
import queue
import re
import sys
import threading
import time
import uuid
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, urlsplit

from .artifact_store import TARGET_PLATFORM_RE
from .report_bundle import build_report_bundle
from .rule_registry import RULESET_VERSION, rules_json
from .mcp import scan_mcp_payload
from .scanner import scan_targets
from .webhooks import configured_webhook, deliver_terminal_webhook

SERVICE_VERSION = "0.1.0"
DEFAULT_DATA_DIR = Path(os.environ.get("IDE_SCANNER_DATA_DIR", ".ide-scanner-data"))
MARKETPLACE_ID = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_.-]+$")
IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def configured_api_tokens() -> tuple[str, ...]:
    """Return active bearer credentials without exposing their values.

    ``IDE_SCANNER_API_TOKEN`` remains the backwards-compatible single-token
    setting. ``IDE_SCANNER_API_TOKENS`` is a comma-separated overlap set for a
    controlled rotation. Empty entries, whitespace, and duplicates are ignored.
    """
    values = (os.environ.get("IDE_SCANNER_API_TOKEN", ""), *os.environ.get("IDE_SCANNER_API_TOKENS", "").split(","))
    return tuple(dict.fromkeys(value.strip() for value in values if value.strip()))


def _bounded_env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, value))


# Bounded worker pool + queue so a burst of scan requests cannot spawn
# unbounded threads or downloads. Excess requests are rejected with 429 rather
# than silently queued forever.
MAX_SCAN_WORKERS = _bounded_env_int("IDE_SCANNER_MAX_WORKERS", 2, 1, 16)
MAX_SCAN_QUEUE = _bounded_env_int("IDE_SCANNER_MAX_QUEUE", 32, 1, 1024)
JOB_TIMEOUT_SECONDS = _bounded_env_int("IDE_SCANNER_JOB_TIMEOUT", 600, 30, 3600)
MCP_REQUEST_MAX_BYTES = _bounded_env_int("IDE_SCANNER_MCP_MAX_BYTES", 512 * 1024, 16 * 1024, 2 * 1024 * 1024)
WEBHOOK_MAX_TOTAL_ATTEMPTS = 9
JOB_RETENTION_SECONDS = _bounded_env_int("IDE_SCANNER_JOB_RETENTION_SECONDS", 7 * 24 * 3600, 3600, 90 * 24 * 3600)
MAINTENANCE_INTERVAL_SECONDS = _bounded_env_int("IDE_SCANNER_MAINTENANCE_INTERVAL_SECONDS", 3600, 60, 24 * 3600)


class JobStore:
    def __init__(self, root: Path = DEFAULT_DATA_DIR) -> None:
        self.root = root
        self.jobs_dir = root / "jobs"
        self.reports_dir = root / "reports"
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def readiness(self) -> dict[str, Any]:
        """Return a non-mutating check of durable local state availability."""
        directories = {"jobs": self.jobs_dir, "reports": self.reports_dir}
        available = all(path.is_dir() and os.access(path, os.R_OK | os.W_OK) for path in directories.values())
        return {"ready": available, "storage": "available" if available else "unavailable"}

    def create(self, extension_id: str, *, version: str | None = None, target_platform: str | None = None) -> dict[str, Any]:
        job, _, _ = self.create_or_reuse(extension_id, version=version, target_platform=target_platform)
        return job

    def create_or_reuse(
        self,
        extension_id: str,
        *,
        version: str | None = None,
        target_platform: str | None = None,
        idempotency_key: str | None = None,
    ) -> tuple[dict[str, Any], bool, bool]:
        """Atomically reserve a job for a client request.

        A retry with the same key and exact release request returns the original
        job. A key bound to different request data is a client conflict instead
        of a potentially surprising scan of another artifact.
        """
        fingerprint = _request_fingerprint(extension_id, version, target_platform)
        with self._lock:
            if idempotency_key:
                for path in self.jobs_dir.glob("job_*.json"):
                    current = self._read_json_locked(path)
                    if not isinstance(current, dict) or current.get("idempotency_key") != idempotency_key:
                        continue
                    if current.get("request_fingerprint") == fingerprint:
                        return current, False, False
                    return current, False, True
            now = _now()
            job = {
                "id": f"job_{uuid.uuid4().hex}",
                "status": "queued",
                "extension_id": extension_id,
                "version": version,
                "target_platform": target_platform,
                "created_at": now,
                "updated_at": now,
                "error": None,
                "report_ref": None,
                "idempotency_key": idempotency_key,
                "request_fingerprint": fingerprint if idempotency_key else None,
            }
            self._write_json_locked(self.jobs_dir / f"{job['id']}.json", job)
            return job, True, False

    def get(self, job_id: str) -> dict[str, Any] | None:
        if not re.fullmatch(r"job_[a-f0-9]{32}", job_id):
            return None
        path = self.jobs_dir / f"{job_id}.json"
        if not path.exists():
            return None
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return value if isinstance(value, dict) else None

    def list_summaries(self, *, extension_id: str | None = None, status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        """List bounded, non-secret job metadata for evidence discovery."""
        rows: list[dict[str, Any]] = []
        for path in self.jobs_dir.glob("job_*.json"):
            item = self._read_json_locked(path)
            if not isinstance(item, dict):
                continue
            if extension_id and item.get("extension_id") != extension_id:
                continue
            if status and item.get("status") != status:
                continue
            rows.append({key: item.get(key) for key in (
                "id", "status", "stage", "extension_id", "version", "target_platform",
                "created_at", "updated_at", "report_ref", "error",
            )})
        return sorted(rows, key=lambda item: str(item.get("updated_at") or ""), reverse=True)[:max(1, min(limit, 100))]

    def write(self, job: dict[str, Any]) -> None:
        job["updated_at"] = _now()
        path = self.jobs_dir / f"{job['id']}.json"
        with self._lock:
            self._write_json_locked(path, job)

    def try_start(self, job_id: str) -> dict[str, Any] | None:
        """Atomically claim a queued job for a worker.

        A queued job may be cancelled after it has entered the worker queue.
        Claiming it through the store, rather than mutating the stale queue
        copy, keeps cancellation authoritative.
        """
        path = self.jobs_dir / f"{job_id}.json"
        with self._lock:
            current = self._read_json_locked(path)
            if not isinstance(current, dict) or current.get("status") != "queued":
                return None
            current.update({"status": "running", "stage": "downloading", "updated_at": _now()})
            self._write_json_locked(path, current)
            return current

    def cancel(self, job_id: str) -> tuple[dict[str, Any] | None, bool]:
        """Cancel a queued or running job without deleting its audit record.

        The scanner thread cannot be forcibly stopped safely. A cancellation
        therefore prevents report publication and terminal webhooks even when
        a running scan finishes after the request.
        """
        path = self.jobs_dir / f"{job_id}.json"
        with self._lock:
            current = self._read_json_locked(path)
            if not isinstance(current, dict):
                return None, False
            if current.get("status") not in {"queued", "running"}:
                return current, False
            current.update({
                "status": "cancelled",
                "stage": "cancelled",
                "error": "Cancelled by an authorized client.",
                "updated_at": _now(),
            })
            self._write_json_locked(path, current)
            return current, True

    def write_report(self, job_id: str, report: dict[str, Any]) -> str:
        path = self.reports_dir / f"{job_id}.json"
        with self._lock:
            self._write_json_locked(path, report, separators=(",", ":"))
        return f"/v1/reports/{job_id}"

    def try_complete(self, job_id: str, summary: dict[str, Any], report: dict[str, Any]) -> bool:
        """Commit a report only if this job is still owned by its runner.

        Timeout handling deliberately cannot kill a Python thread. A late
        runner must therefore lose the terminal-state race instead of turning
        a previously failed job back into a successful one.
        """
        job_path = self.jobs_dir / f"{job_id}.json"
        report_path = self.reports_dir / f"{job_id}.json"
        with self._lock:
            current = self._read_json_locked(job_path)
            if not isinstance(current, dict) or current.get("status") != "running":
                return False
            self._write_json_locked(report_path, report, separators=(",", ":"))
            current.update({
                "status": "complete",
                "stage": "complete",
                "summary": summary,
                "report_ref": f"/v1/reports/{job_id}",
                "updated_at": _now(),
            })
            self._write_json_locked(job_path, current)
            return True

    def try_fail(self, job_id: str, error: str, *, stage: str = "failed") -> bool:
        """Fail a non-terminal job without overwriting a prior terminal state."""
        path = self.jobs_dir / f"{job_id}.json"
        with self._lock:
            current = self._read_json_locked(path)
            if not isinstance(current, dict) or current.get("status") not in {"queued", "running"}:
                return False
            current.update({
                "status": "failed",
                "stage": stage,
                "error": error,
                "updated_at": _now(),
            })
            self._write_json_locked(path, current)
            return True

    def get_report(self, job_id: str) -> dict[str, Any] | None:
        if not re.fullmatch(r"job_[a-f0-9]{32}", job_id):
            return None
        path = self.reports_dir / f"{job_id}.json"
        if not path.exists():
            return None
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return value if isinstance(value, dict) else None

    @staticmethod
    def _read_json_locked(path: Path) -> Any:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    @staticmethod
    def _write_json_locked(path: Path, value: Any, *, separators: tuple[str, str] | None = None) -> None:
        temp = path.with_suffix(".tmp")
        kwargs: dict[str, Any] = {"sort_keys": True}
        if separators is not None:
            kwargs["separators"] = separators
        temp.write_text(json.dumps(value, indent=None if separators else 2, **kwargs) + ("" if separators else "\n"), encoding="utf-8")
        temp.replace(path)


def execute_marketplace_job(
    store: JobStore,
    job: dict[str, Any],
    scan: Callable[..., dict[str, Any]] = scan_targets,
) -> None:
    from .scanner import DEEP_REQUIRED_PROVIDERS

    claimed = store.try_start(str(job.get("id") or ""))
    if not claimed:
        return
    try:
        report = scan(
            marketplace_scan_ids=[claimed["extension_id"]],
            marketplace_version=claimed.get("version"),
            marketplace_target_platform=claimed.get("target_platform"),
            online=True,
            include_posture=False,
            required_providers=DEEP_REQUIRED_PROVIDERS,
            dynamic_runtime=True,
            runtime_timeout_seconds=20,
        )
        bundle = build_report_bundle(report, profile="deep", source="marketplace")
        extension_rows = bundle.get("leaderboard", {}).get("extensions", [])
        if not extension_rows:
            raise RuntimeError("Scanner completed without an extension result.")
        if store.try_complete(claimed["id"], bundle["summary"], bundle):
            _notify_terminal_job(store, claimed["id"])
    except Exception as exc:  # noqa: BLE001 - job records must surface scanner/network failures
        if store.try_fail(claimed["id"], str(exc)):
            _notify_terminal_job(store, claimed["id"])


class ScanWorkerPool:
    """Fixed-size worker pool with a bounded queue and per-job timeout.

    A burst of scan submissions is capped: at most ``max_workers`` scans run
    concurrently, at most ``max_queue`` wait, and anything beyond that is
    rejected so the process cannot be driven into unbounded thread/download
    fan-out. Each job is watched by a timeout that marks it ``failed`` if it
    overruns, so a wedged download or analyzer cannot occupy a worker forever."""

    def __init__(
        self,
        store: JobStore,
        max_workers: int = MAX_SCAN_WORKERS,
        max_queue: int = MAX_SCAN_QUEUE,
        job_timeout: int = JOB_TIMEOUT_SECONDS,
        runner: Callable[[JobStore, dict[str, Any]], None] = execute_marketplace_job,
    ) -> None:
        self.store = store
        self.job_timeout = job_timeout
        self._runner = runner
        self._queue: "queue.Queue[dict[str, Any] | None]" = queue.Queue(maxsize=max_queue)
        self._threads: list[threading.Thread] = []
        for index in range(max_workers):
            thread = threading.Thread(target=self._worker, name=f"scan-worker-{index}", daemon=True)
            thread.start()
            self._threads.append(thread)

    def submit(self, job: dict[str, Any]) -> bool:
        try:
            self._queue.put_nowait(job)
            return True
        except queue.Full:
            return False

    def readiness(self) -> dict[str, Any]:
        """Describe capacity without exposing queued job identities."""
        workers_alive = sum(thread.is_alive() for thread in self._threads)
        queued = self._queue.qsize()
        capacity = self._queue.maxsize
        return {
            "ready": workers_alive == len(self._threads) and queued < capacity,
            "workers": {"configured": len(self._threads), "alive": workers_alive},
            "queue": {"queued": queued, "capacity": capacity},
        }

    def _worker(self) -> None:
        while True:
            job = self._queue.get()
            if job is None:
                return
            try:
                self._run_with_timeout(job)
            finally:
                self._queue.task_done()

    def _run_with_timeout(self, job: dict[str, Any]) -> None:
        done = threading.Event()

        def _invoke() -> None:
            try:
                self._runner(self.store, job)
            finally:
                done.set()

        worker = threading.Thread(target=_invoke, name=f"scan-run-{job['id']}", daemon=True)
        worker.start()
        if not done.wait(self.job_timeout):
            # The scan overran its budget. Record the timeout; the orphaned
            # daemon thread cannot be force-killed in CPython, but the bounded
            # pool prevents it from starving new work indefinitely.
            if self.store.try_fail(
                job["id"],
                f"Scan exceeded the {self.job_timeout}s job timeout and was abandoned.",
                stage="timeout",
            ):
                _notify_terminal_job(self.store, job["id"])


def cleanup_stale_jobs(store: JobStore, max_age_seconds: int = 7 * 24 * 3600) -> int:
    """Remove job/report files older than ``max_age_seconds`` and mark any
    ``running``/``queued`` job left over from a previous process as failed, so
    a restart does not leave jobs wedged in a non-terminal state forever."""
    removed = 0
    cutoff = time.time() - max_age_seconds
    for directory in (store.jobs_dir, store.reports_dir):
        for path in directory.glob("*.json"):
            try:
                if path.stat().st_mtime < cutoff:
                    path.unlink(missing_ok=True)
                    removed += 1
            except OSError:
                continue
    for path in store.jobs_dir.glob("job_*.json"):
        try:
            job = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(job, dict) and job.get("status") in {"queued", "running"}:
            job["status"] = "failed"
            job["stage"] = "interrupted"
            job["error"] = "Service restarted while the job was in progress."
            store.write(job)
            _notify_terminal_job(store, str(job.get("id") or ""))
    return removed


def _notify_terminal_job(store: JobStore, job_id: str) -> None:
    job = store.get(job_id)
    if not job:
        return
    previous = job.get("webhook_delivery") if isinstance(job.get("webhook_delivery"), dict) else {}
    if previous.get("status") in {"delivered", "dead_lettered"}:
        return
    delivery = deliver_terminal_webhook(job)
    if delivery is None:
        return
    total_attempts = _delivery_attempts(previous) + _delivery_attempts(delivery)
    delivery["total_attempts"] = total_attempts
    if delivery.get("status") == "failed" and total_attempts >= WEBHOOK_MAX_TOTAL_ATTEMPTS:
        delivery["status"] = "dead_lettered"
        delivery["error"] = str(delivery.get("error") or "Webhook delivery exhausted its retry budget.")
    job["webhook_delivery"] = delivery
    store.write(job)


def retry_failed_webhook_deliveries(store: JobStore) -> int:
    """Retry persisted terminal webhook failures once when the service starts.

    The job record is the durable outbox. Delivery IDs remain per attempt, so
    recipients must deduplicate them; the bounded total prevents restart loops
    from creating an unbounded retry stream.
    """
    retried = 0
    for path in sorted(store.jobs_dir.glob("job_*.json")):
        job_id = path.stem
        job = store.get(job_id)
        if not job or job.get("status") not in {"complete", "failed"}:
            continue
        delivery = job.get("webhook_delivery")
        if not isinstance(delivery, dict) or delivery.get("status") != "failed":
            continue
        if _delivery_attempts(delivery) >= WEBHOOK_MAX_TOTAL_ATTEMPTS:
            delivery["status"] = "dead_lettered"
            job["webhook_delivery"] = delivery
            store.write(job)
            continue
        _notify_terminal_job(store, job_id)
        retried += 1
    return retried


def _delivery_attempts(delivery: dict[str, Any]) -> int:
    try:
        return max(0, int(delivery.get("total_attempts", delivery.get("attempts", 0))))
    except (TypeError, ValueError):
        return 0


def maintain_store(store: JobStore, *, retention_seconds: int = JOB_RETENTION_SECONDS) -> dict[str, int]:
    """Run bounded service maintenance without changing completed scan evidence."""
    return {
        "removed": cleanup_stale_jobs(store, max_age_seconds=retention_seconds),
        "webhooks_retried": retry_failed_webhook_deliveries(store),
    }


def start_maintenance_loop(
    store: JobStore,
    *,
    interval_seconds: int = MAINTENANCE_INTERVAL_SECONDS,
    retention_seconds: int = JOB_RETENTION_SECONDS,
    stop_event: threading.Event | None = None,
) -> threading.Thread:
    """Maintain local durable state on a daemon interval for long-lived service processes."""
    stop_event = stop_event or threading.Event()

    def run() -> None:
        while not stop_event.wait(interval_seconds):
            maintain_store(store, retention_seconds=retention_seconds)

    thread = threading.Thread(target=run, name="scanner-maintenance", daemon=True)
    thread.start()
    return thread


class ScannerServiceHandler(BaseHTTPRequestHandler):
    server_version = "IDEScannerService/0.1"

    @property
    def store(self) -> JobStore:
        return self.server.job_store  # type: ignore[attr-defined]

    @property
    def pool(self) -> "ScanWorkerPool":
        return self.server.scan_pool  # type: ignore[attr-defined]

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self._cors_headers()
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        path = parsed.path
        if path == "/health":
            self._json(200, health_payload())
            return
        if path == "/readyz":
            payload = readiness_payload(self.store, self.pool)
            self._json(200 if payload["status"] == "ready" else 503, payload)
            return
        if path == "/v1/openapi.json":
            self._json(200, openapi_payload())
            return
        if path == "/v1/rules":
            self._json(200, rules_json())
            return
        if not self._authorized():
            self._json(401, {"error": "Scanner service authorization failed."})
            return
        if path == "/v1/jobs":
            query = parse_qs(parsed.query, keep_blank_values=True)
            extension_id = _one_query_value(query, "extension_id")
            status = _one_query_value(query, "status")
            limit_value = _one_query_value(query, "limit")
            if extension_id and not MARKETPLACE_ID.fullmatch(extension_id):
                self._json(400, {"error": "extension_id must use publisher.extension format."})
                return
            if status and status not in {"queued", "running", "complete", "failed", "cancelled"}:
                self._json(400, {"error": "status is invalid."})
                return
            try:
                limit = int(limit_value or "100")
            except ValueError:
                self._json(400, {"error": "limit must be an integer from 1 through 100."})
                return
            if not 1 <= limit <= 100:
                self._json(400, {"error": "limit must be an integer from 1 through 100."})
                return
            self._json(200, {"jobs": self.store.list_summaries(extension_id=extension_id or None, status=status or None, limit=limit)})
            return
        if path.startswith("/v1/jobs/"):
            job = self.store.get(path.rsplit("/", 1)[-1])
            self._json(200, job) if job else self._json(404, {"error": "Scan job not found."})
            return
        if path.startswith("/v1/reports/"):
            report = self.store.get_report(path.rsplit("/", 1)[-1])
            self._json(200, report) if report else self._json(404, {"error": "Scan report not found."})
            return
        self._json(404, {"error": "Route not found."})

    def do_POST(self) -> None:  # noqa: N802
        if not self._authorized():
            self._json(401, {"error": "Scanner service authorization failed."})
            return
        path = self.path.split("?", 1)[0]
        if path == "/v1/scans/mcp":
            payload = self._read_json(max_bytes=MCP_REQUEST_MAX_BYTES)
            if not payload:
                self._json(400, {"error": "MCP assessment input must be a JSON object."})
                return
            try:
                self._json(200, scan_mcp_payload(payload))
            except Exception as exc:  # noqa: BLE001 - service returns bounded client-safe errors
                self._json(422, {"error": str(exc) or "MCP assessment failed."})
            return
        if path != "/v1/scans/marketplace":
            self._json(404, {"error": "Route not found."})
            return
        payload = self._read_json()
        extension_id = str(payload.get("extension_id") or "").strip()
        if not MARKETPLACE_ID.fullmatch(extension_id):
            self._json(400, {"error": "extension_id must use publisher.extension format."})
            return
        version = str(payload.get("version") or "").strip() or None
        target_platform = str(payload.get("target_platform") or "").strip().lower() or None
        if target_platform and not TARGET_PLATFORM_RE.fullmatch(target_platform):
            self._json(400, {"error": "target_platform is invalid."})
            return
        idempotency_key = self.headers.get("idempotency-key", "").strip() or None
        if idempotency_key and not IDEMPOTENCY_KEY.fullmatch(idempotency_key):
            self._json(400, {"error": "Idempotency-Key must be 1-128 URL-safe characters."})
            return
        job, created, conflict = self.store.create_or_reuse(
            extension_id,
            version=version,
            target_platform=target_platform,
            idempotency_key=idempotency_key,
        )
        if conflict:
            self._json(409, {"error": "Idempotency-Key is already bound to a different scan request.", "job": job})
            return
        if not created:
            if job.get("stage") == "rejected":
                self._json(
                    429,
                    {"error": "Scanner is at capacity; retry later.", "job": job},
                    headers={"Idempotent-Replayed": "true", "Retry-After": "30"},
                )
                return
            self._json(202, job, headers={"Idempotent-Replayed": "true"})
            return
        if not self.pool.submit(job):
            job["status"] = "failed"
            job["stage"] = "rejected"
            job["error"] = "Scanner is at capacity; retry later."
            self.store.write(job)
            self._json(429, {"error": "Scanner is at capacity; retry later.", "job": job}, headers={"Retry-After": "30"})
            return
        self._json(202, job)

    def do_DELETE(self) -> None:  # noqa: N802
        if not self._authorized():
            self._json(401, {"error": "Scanner service authorization failed."})
            return
        path = self.path.split("?", 1)[0]
        if not path.startswith("/v1/jobs/"):
            self._json(404, {"error": "Route not found."})
            return
        job, cancelled = self.store.cancel(path.rsplit("/", 1)[-1])
        if not job:
            self._json(404, {"error": "Scan job not found."})
            return
        if not cancelled:
            self._json(409, {"error": "Only queued or running scan jobs can be cancelled.", "job": job})
            return
        self._json(200, job)

    def log_message(self, format: str, *args: object) -> None:
        if os.environ.get("IDE_SCANNER_QUIET") != "1":
            super().log_message(format, *args)

    def _read_json(self, *, max_bytes: int = 16_384) -> dict[str, Any]:
        try:
            content_length = int(self.headers.get("content-length", "0"))
            if content_length <= 0 or content_length > max_bytes:
                return {}
            length = min(content_length, max_bytes)
            value = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
            return {}
        return value if isinstance(value, dict) else {}

    def _authorized(self) -> bool:
        tokens = configured_api_tokens()
        if not tokens:
            return True
        supplied = self.headers.get("authorization", "")
        # Evaluate every candidate to avoid revealing a matching token's
        # position within a short rotation-overlap set.
        matched = False
        for token in tokens:
            matched = hmac.compare_digest(supplied, f"Bearer {token}") or matched
        return matched

    def _json(self, status: int, payload: Any, *, headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self._cors_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _cors_headers(self) -> None:
        origin = os.environ.get("IDE_SCANNER_ALLOWED_ORIGIN", "http://127.0.0.1:8765")
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Headers", "content-type, authorization, idempotency-key")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")


def health_payload() -> dict[str, Any]:
    return {
        "status": "ok",
        "service_version": SERVICE_VERSION,
        "ruleset_version": RULESET_VERSION,
        "providers": {
            "native_static": "available",
            "javascript_ast": "available",
            "semgrep": "optional",
            "yara": "optional",
            "dependency_intelligence": "online",
        },
        "operations": {
            "job_retention_seconds": JOB_RETENTION_SECONDS,
            "maintenance_interval_seconds": MAINTENANCE_INTERVAL_SECONDS,
            "webhook_max_total_attempts": WEBHOOK_MAX_TOTAL_ATTEMPTS,
        },
    }


def readiness_payload(store: JobStore, pool: ScanWorkerPool) -> dict[str, Any]:
    """Return safe admission readiness, separate from process liveness.

    Readiness is intentionally false when the bounded queue is full. This
    allows a platform to stop sending more requests to an overloaded instance;
    callers that already reach it still receive the explicit `429` contract.
    """
    storage = store.readiness()
    workers = pool.readiness()
    ready = bool(storage["ready"] and workers["ready"])
    return {
        "status": "ready" if ready else "not_ready",
        "service_version": SERVICE_VERSION,
        "storage": storage["storage"],
        "workers": workers["workers"],
        "queue": workers["queue"],
    }


def openapi_payload() -> dict[str, Any]:
    """Return the stable public contract for the local scanner service.

    Report bundles deliberately remain an open JSON object here: their detailed
    evidence schema is versioned by the bundle itself, and consumers must check
    its scanner/policy/ruleset identity before making a decision.
    """
    error = {"type": "object", "required": ["error"], "properties": {"error": {"type": "string"}}}
    job = {
        "type": "object",
        "required": ["id", "status", "extension_id", "created_at", "updated_at"],
        "properties": {
            "id": {"type": "string", "pattern": "^job_[a-f0-9]{32}$"},
            "status": {"type": "string", "enum": ["queued", "running", "complete", "failed", "cancelled"]},
            "stage": {"type": "string", "description": "Terminal failures use rejected, timeout, or interrupted when applicable."},
            "extension_id": {"type": "string", "pattern": "^[A-Za-z0-9_-]+\\.[A-Za-z0-9_.-]+$"},
            "version": {"type": ["string", "null"]},
            "target_platform": {"type": ["string", "null"]},
            "idempotency_key": {"type": ["string", "null"], "description": "Accepted request key; never use this field as an authorization secret."},
            "created_at": {"type": "string", "format": "date-time"},
            "updated_at": {"type": "string", "format": "date-time"},
            "report_ref": {"type": ["string", "null"], "description": "Present only after a complete job; fetch with the same bearer token."},
            "error": {"type": ["string", "null"]},
            "webhook_delivery": {"type": "object", "description": "Bounded webhook delivery receipt when configured; it contains no webhook secret."},
        },
    }
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "GuardRails Scanner Service",
            "version": SERVICE_VERSION,
            "description": "Private exact-artifact scanning service. A completed report is evidence, not a safety guarantee.",
        },
        "paths": {
            "/health": {
                "get": {
                    "summary": "Read service health and provider availability",
                    "responses": {"200": {"description": "Service health", "content": {"application/json": {"schema": {"type": "object"}}}}},
                },
            },
            "/readyz": {
                "get": {
                    "summary": "Read scanner service admission readiness",
                    "description": "Returns 503 when durable state or bounded worker capacity cannot accept another scan. It exposes no job identities or secrets.",
                    "responses": {"200": {"description": "Service can accept work", "content": {"application/json": {"schema": {"type": "object"}}}}, "503": {"description": "Service is alive but cannot accept work", "content": {"application/json": {"schema": {"type": "object"}}}}},
                },
            },
            "/v1/openapi.json": {
                "get": {
                    "summary": "Read this service contract",
                    "responses": {"200": {"description": "OpenAPI document", "content": {"application/json": {"schema": {"type": "object"}}}}},
                },
            },
            "/v1/rules": {
                "get": {
                    "summary": "Read the versioned scanner rule catalog",
                    "responses": {"200": {"description": "Rules and ruleset identity", "content": {"application/json": {"schema": {"type": "object"}}}}},
                },
            },
            "/v1/scans/marketplace": {
                "post": {
                    "summary": "Queue a deep scan for one Marketplace extension",
                    "security": [{"bearerAuth": []}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["extension_id"],
                                    "properties": {
                                        "extension_id": {"type": "string", "pattern": "^[A-Za-z0-9_-]+\\.[A-Za-z0-9_.-]+$"},
                                        "version": {"type": "string"},
                                        "target_platform": {"type": "string"},
                                    },
                                },
                            },
                        },
                    },
                    "parameters": [{"in": "header", "name": "Idempotency-Key", "required": False, "schema": {"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"}, "description": "Reuse a prior job only for an identical extension/version/platform request."}],
                    "responses": {"202": {"description": "Job accepted or replayed; it is not an approval result.", "headers": {"Idempotent-Replayed": {"schema": {"type": "string", "enum": ["true"]}, "description": "Present when the key returned an existing job."}}, "content": {"application/json": {"schema": job}}}, "400": {"description": "Invalid request", "content": {"application/json": {"schema": error}}}, "401": {"description": "Authorization failed", "content": {"application/json": {"schema": error}}}, "409": {"description": "Idempotency key belongs to a different request", "content": {"application/json": {"schema": error}}}, "429": {"description": "Queue capacity exhausted; retry later.", "headers": {"Retry-After": {"schema": {"type": "integer"}, "description": "Seconds before a new-key retry is appropriate."}}, "content": {"application/json": {"schema": error}}}},
                },
            },
            "/v1/scans/mcp": {
                "post": {
                    "summary": "Assess one MCP server payload synchronously",
                    "security": [{"bearerAuth": []}],
                    "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "description": "MCP assessment input. The service enforces a bounded request size."}}}},
                    "responses": {"200": {"description": "Assessment result", "content": {"application/json": {"schema": {"type": "object"}}}}, "400": {"description": "Malformed or oversized input", "content": {"application/json": {"schema": error}}}, "401": {"description": "Authorization failed", "content": {"application/json": {"schema": error}}}, "422": {"description": "Assessment could not complete", "content": {"application/json": {"schema": error}}}},
                },
            },
            "/v1/jobs": {
                "get": {
                    "summary": "List retained Marketplace scan job metadata",
                    "description": "Returns at most 100 newest job summaries. Report bodies and request idempotency data are not included.",
                    "security": [{"bearerAuth": []}],
                    "parameters": [
                        {"in": "query", "name": "extension_id", "schema": {"type": "string", "pattern": "^[A-Za-z0-9_-]+\\.[A-Za-z0-9_.-]+$"}},
                        {"in": "query", "name": "status", "schema": {"type": "string", "enum": ["queued", "running", "complete", "failed", "cancelled"]}},
                        {"in": "query", "name": "limit", "schema": {"type": "integer", "minimum": 1, "maximum": 100, "default": 100}},
                    ],
                    "responses": {"200": {"description": "Bounded job history", "content": {"application/json": {"schema": {"type": "object"}}}}, "401": {"description": "Authorization failed", "content": {"application/json": {"schema": error}}}},
                },
            },
            "/v1/jobs/{job_id}": {
                "get": {
                    "summary": "Poll a Marketplace scan job",
                    "security": [{"bearerAuth": []}],
                    "parameters": [{"in": "path", "name": "job_id", "required": True, "schema": {"type": "string", "pattern": "^job_[a-f0-9]{32}$"}}],
                    "responses": {"200": {"description": "Job record", "content": {"application/json": {"schema": job}}}, "401": {"description": "Authorization failed", "content": {"application/json": {"schema": error}}}, "404": {"description": "Job not found", "content": {"application/json": {"schema": error}}}},
                },
                "delete": {
                    "summary": "Cancel a queued or running Marketplace scan job",
                    "description": "Cancellation preserves the job audit record and prevents a late worker from publishing a report or terminal webhook.",
                    "security": [{"bearerAuth": []}],
                    "parameters": [{"in": "path", "name": "job_id", "required": True, "schema": {"type": "string", "pattern": "^job_[a-f0-9]{32}$"}}],
                    "responses": {"200": {"description": "Job cancelled", "content": {"application/json": {"schema": job}}}, "401": {"description": "Authorization failed", "content": {"application/json": {"schema": error}}}, "404": {"description": "Job not found", "content": {"application/json": {"schema": error}}}, "409": {"description": "Job is already terminal", "content": {"application/json": {"schema": error}}}},
                },
            },
            "/v1/reports/{job_id}": {
                "get": {
                    "summary": "Fetch the canonical bundle for a completed job",
                    "security": [{"bearerAuth": []}],
                    "parameters": [{"in": "path", "name": "job_id", "required": True, "schema": {"type": "string", "pattern": "^job_[a-f0-9]{32}$"}}],
                    "responses": {"200": {"description": "Versioned canonical report bundle", "content": {"application/json": {"schema": {"type": "object", "additionalProperties": True}}}}, "401": {"description": "Authorization failed", "content": {"application/json": {"schema": error}}}, "404": {"description": "Report not found", "content": {"application/json": {"schema": error}}}},
                },
            },
        },
        "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "API token"}}},
    }


def serve(host: str = "127.0.0.1", port: int = 8787, data_dir: Path = DEFAULT_DATA_DIR) -> None:
    configured_webhook()
    tokens = configured_api_tokens()
    non_loopback = host not in {"127.0.0.1", "::1", "localhost"}
    if non_loopback and not tokens:
        if os.environ.get("IDE_SCANNER_ALLOW_INSECURE_BIND") != "1":
            raise SystemExit(
                f"Refusing to bind {host}:{port} without IDE_SCANNER_API_TOKEN or IDE_SCANNER_API_TOKENS. "
                "Set a token, bind to 127.0.0.1, or explicitly set "
                "IDE_SCANNER_ALLOW_INSECURE_BIND=1 for a trusted local network only."
            )
        print(
            f"WARNING: binding {host}:{port} with no API token; scan endpoints are unauthenticated.",
            file=sys.stderr,
        )
    store = JobStore(data_dir)
    maintain_store(store)
    start_maintenance_loop(store)
    server = ThreadingHTTPServer((host, port), ScannerServiceHandler)
    server.job_store = store  # type: ignore[attr-defined]
    server.scan_pool = ScanWorkerPool(store)  # type: ignore[attr-defined]
    server.serve_forever()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ide-scanner-service", description="Run the IDE Scanner HTTP job service.")
    parser.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8787")))
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    args = parser.parse_args(argv)
    serve(args.host, args.port, args.data_dir)
    return 0


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _one_query_value(query: dict[str, list[str]], name: str) -> str:
    values = query.get(name) or []
    return values[0].strip() if len(values) == 1 else ""


def _request_fingerprint(extension_id: str, version: str | None, target_platform: str | None) -> str:
    return json.dumps(
        {"extension_id": extension_id, "target_platform": target_platform, "version": version},
        separators=(",", ":"),
        sort_keys=True,
    )


if __name__ == "__main__":
    raise SystemExit(main())
