#!/usr/bin/env python3
"""Run a bounded, reproducible extension corpus scan.

Each artifact gets its own child process and wall-clock budget. A timeout or
child failure becomes an explicit incomplete extension, never a clean result.
This is intentionally separate from the in-process scanner API: a hostile or
pathological artifact must not be able to hold an entire corpus hostage.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

SHA256 = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)

from ide_scanner.discovery import discover_from_path, discover_local_installations  # noqa: E402
from ide_scanner.report_bundle import _extension_from_dict  # noqa: E402
from ide_scanner.scanner import _build_report, _degzip_if_needed, _hash_file, _local_error_extension  # noqa: E402


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scan a VS Code-compatible extension corpus with per-artifact isolation.")
    parser.add_argument("--all", action="store_true", help="Scan locally installed extensions.")
    parser.add_argument("--path", action="append", default=[], help="Extension folder, extensions directory, or VSIX file to scan.")
    parser.add_argument("--manifest", type=Path, help="JSON manifest of exact VSIX artifacts with path, extension_id, version, and canonical scanner sha256.")
    parser.add_argument("--jobs", type=int, default=4, help="Maximum concurrent artifact processes, from 1 to 32.")
    parser.add_argument("--timeout", type=int, default=45, help="Wall-clock timeout per artifact in seconds.")
    parser.add_argument("--profile", choices=["quick", "standard", "benchmark"], default="quick", help="Static scan profile label.")
    parser.add_argument("--runtime", action="store_true", help="Run the required dynamic providers in an isolated Bubblewrap sandbox for each artifact.")
    parser.add_argument("--runtime-timeout", type=int, default=20, help="Dynamic runtime budget per artifact in seconds, from 1 to 120.")
    parser.add_argument("--with-posture", action="store_true", help="Include local IDE/client posture once in the aggregate report.")
    parser.add_argument("--out", "--output", required=True, help="Aggregate JSON report path.")
    return parser


def _targets(args: argparse.Namespace) -> list[dict[str, str]]:
    discovered: list[dict[str, str]] = []
    if args.all:
        discovered.extend(discover_local_installations())
    for raw_path in args.path:
        discovered.extend(discover_from_path(raw_path))
    if args.manifest:
        discovered.extend(_manifest_targets(args.manifest))
    unique: dict[str, dict[str, str]] = {}
    for target in discovered:
        unique[str(target["path"])] = target
    return list(unique.values())


def _manifest_targets(manifest_path: Path) -> list[dict[str, str]]:
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"corpus manifest could not be read: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != "guardrails.corpus-manifest.v1":
        raise ValueError("corpus manifest must use schema_version guardrails.corpus-manifest.v1")
    artifacts = payload.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ValueError("corpus manifest must contain a non-empty artifacts array")
    targets: list[dict[str, str]] = []
    seen_paths: set[str] = set()
    for index, item in enumerate(artifacts):
        if not isinstance(item, dict):
            raise ValueError(f"corpus manifest artifact {index} is not an object")
        raw_path = str(item.get("path") or "").strip()
        extension_id = str(item.get("extension_id") or "").strip()
        version = str(item.get("version") or "").strip()
        sha256 = str(item.get("sha256") or "").strip().lower()
        if not raw_path or not extension_id or not version or not SHA256.fullmatch(sha256):
            raise ValueError(f"corpus manifest artifact {index} requires path, extension_id, version, and a SHA-256")
        target_path = Path(raw_path)
        if not target_path.is_absolute():
            target_path = manifest_path.parent / target_path
        target_path = target_path.expanduser().resolve()
        if not target_path.is_file():
            raise ValueError(f"corpus manifest artifact {index} must be a file: {target_path}")
        key = str(target_path)
        if key in seen_paths:
            raise ValueError(f"corpus manifest contains duplicate path: {target_path}")
        seen_paths.add(key)
        targets.append({
            "path": key,
            "type": "vsix" if target_path.suffix.lower() == ".vsix" else "manifest",
            "manifest_expected_extension_id": extension_id,
            "manifest_expected_version": version,
            "manifest_expected_sha256": sha256,
        })
    return targets


def _terminate(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        process.kill()
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.kill()
    except ProcessLookupError:
        pass


def _wait_for_worker(process: subprocess.Popen[str], timeout: int) -> bool:
    """Wait for a worker and reap it without an unbounded post-timeout wait."""
    try:
        process.wait(timeout=timeout)
        return True
    except subprocess.TimeoutExpired:
        _terminate(process)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                return False
        return False


def _scan_one(
    target: dict[str, str],
    *,
    timeout: int,
    profile: str,
    runtime: bool = False,
    runtime_timeout: int = 20,
) -> dict[str, Any]:
    path = Path(target["path"])
    source = target.get("type", "vscode")
    expected_id = target.get("manifest_expected_extension_id")
    expected_version = target.get("manifest_expected_version")
    expected_sha256 = target.get("manifest_expected_sha256")
    if expected_sha256:
        try:
            digest = _canonical_artifact_sha256(path)
        except Exception as exc:  # noqa: BLE001 - preserve per-artifact isolation
            return _manifest_error(path, source, target, f"artifact could not be hashed: {exc}")
        if digest != expected_sha256.lower():
            return _manifest_error(path, source, target, f"manifest SHA-256 {expected_sha256} does not match canonical artifact bytes {digest}")
    with tempfile.TemporaryDirectory(prefix="guardrails-corpus-") as temp_dir:
        output = Path(temp_dir) / "report.json"
        stderr_path = Path(temp_dir) / "worker.stderr"
        command = _worker_command(path, profile, output, runtime=runtime, runtime_timeout=runtime_timeout)
        environment = os.environ.copy()
        existing_pythonpath = environment.get("PYTHONPATH", "")
        environment["PYTHONPATH"] = os.pathsep.join(item for item in (str(ROOT / "src"), existing_pythonpath) if item)
        with stderr_path.open("wb") as stderr_handle:
            process = subprocess.Popen(
                command,
                cwd=str(ROOT),
                env=environment,
                stdout=subprocess.DEVNULL,
                stderr=stderr_handle,
                start_new_session=os.name != "nt",
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
            )
            completed = _wait_for_worker(process, timeout)
        stderr = stderr_path.read_text(encoding="utf-8", errors="replace") if stderr_path.exists() else ""
        if not completed:
            return _worker_error(
                path,
                source,
                target,
                f"Corpus worker exceeded the {timeout}-second per-artifact timeout.",
            )
        if process.returncode != 0 or not output.exists():
            detail = (stderr or "child scanner exited without a report").strip().splitlines()[-1]
            return _worker_error(path, source, target, f"Corpus worker failed: {detail[:500]}")
        try:
            payload = json.loads(output.read_text(encoding="utf-8"))
            extensions = payload.get("extensions") if isinstance(payload, dict) else None
            if not isinstance(extensions, list) or len(extensions) != 1 or not isinstance(extensions[0], dict):
                raise ValueError("child scanner did not return exactly one extension")
            extension = extensions[0]
            if expected_id or expected_version or expected_sha256:
                actual_id = str(extension.get("extension_id") or "")
                actual_version = str(extension.get("version") or "")
                inventory = extension.get("artifact_inventory") if isinstance(extension.get("artifact_inventory"), dict) else {}
                actual_sha256 = str(extension.get("artifact_hash") or (extension.get("artifact_identity") or {}).get("sha256") or "").lower()
                if actual_id.lower() != str(expected_id or "").lower():
                    return _manifest_error(path, source, target, f"manifest extension_id {expected_id} does not match scanned identity {actual_id}")
                if actual_version != str(expected_version or ""):
                    return _manifest_error(path, source, target, f"manifest version {expected_version} does not match scanned version {actual_version}")
                if actual_sha256 != str(expected_sha256 or "").lower():
                    return _manifest_error(path, source, target, f"manifest SHA-256 {expected_sha256} does not match scanned artifact identity {actual_sha256}")
                inventory["corpus_manifest"] = {
                    "verified": True,
                    "expected_extension_id": expected_id,
                    "expected_version": expected_version,
                    "expected_sha256": expected_sha256,
                }
                extension["artifact_inventory"] = inventory
            return extension
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return _worker_error(path, source, target, f"Corpus worker returned an invalid report: {exc}")


def _worker_command(path: Path, profile: str, output: Path, *, runtime: bool, runtime_timeout: int) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "ide_scanner",
        "scan",
        "--path",
        str(path),
        "--profile",
        profile,
        "--jobs",
        "1",
        "--skip-posture",
        "--format",
        "json",
        "--out",
        str(output),
    ]
    if runtime:
        command.extend(["--runtime", "--runtime-timeout", str(runtime_timeout)])
    return command


def _canonical_artifact_sha256(path: Path) -> str:
    """Hash the same canonical VSIX bytes used for scanner artifact identity.

    Marketplace ``vspackage`` responses are sometimes gzip-wrapped. The
    scanner hashes the unwrapped VSIX, so the corpus manifest must verify that
    identity rather than the transport encoding's raw bytes.
    """
    if path.suffix.lower() != ".vsix":
        return _sha256_file(path)
    with tempfile.TemporaryDirectory(prefix="guardrails-corpus-hash-") as temp_dir:
        canonical = Path(temp_dir) / path.name
        shutil.copyfile(path, canonical)
        _degzip_if_needed(canonical)
        digest, _ = _hash_file(canonical)
        if not digest:
            raise OSError(f"could not read canonical artifact {path}")
        return digest


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest_error(path: Path, source: str, target: dict[str, str], message: str) -> dict[str, Any]:
    return _manifest_failure(path, source, target, f"Corpus manifest identity check failed: {message}")


def _worker_error(path: Path, source: str, target: dict[str, str], message: str) -> dict[str, Any]:
    if target.get("manifest_expected_sha256"):
        return _manifest_failure(path, source, target, message)
    return _local_error_extension(path, source, message).to_dict()


def _manifest_failure(path: Path, source: str, target: dict[str, str], message: str) -> dict[str, Any]:
    error = _local_error_extension(path, source, message)
    error.artifact_inventory["corpus_manifest"] = {
        "verified": False,
        "expected_extension_id": target.get("manifest_expected_extension_id", ""),
        "expected_version": target.get("manifest_expected_version", ""),
        "expected_sha256": target.get("manifest_expected_sha256", ""),
    }
    return error.to_dict()


def run(args: argparse.Namespace) -> dict[str, Any]:
    if not 1 <= args.jobs <= 32:
        raise ValueError("jobs must be between 1 and 32")
    if args.timeout < 1:
        raise ValueError("timeout must be at least 1 second")
    if not 1 <= args.runtime_timeout <= 120:
        raise ValueError("runtime-timeout must be between 1 and 120 seconds")
    targets = _targets(args)
    if not targets:
        raise ValueError("no extension artifacts were discovered")

    extensions_by_index: dict[int, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=min(args.jobs, len(targets))) as executor:
        futures = {
            executor.submit(
                _scan_one,
                target,
                timeout=args.timeout,
                profile=args.profile,
                runtime=args.runtime,
                runtime_timeout=args.runtime_timeout,
            ): index
            for index, target in enumerate(targets)
        }
        for future in as_completed(futures):
            extensions_by_index[futures[future]] = future.result()

    extensions = [_extension_from_dict(extensions_by_index[index]) for index in range(len(targets))]
    report = _build_report(
        extensions,
        {
            "enabled": False,
            "mode": "disabled",
            "findings": [],
            "errors": [],
            "snapshot": {"schema_version": "1", "source": "corpus-runner", "sha256": ""},
        },
        include_posture=args.with_posture,
        intelligence={
            "corpus_execution": {
                "mode": "isolated-subprocess",
                "jobs": args.jobs,
                "timeout_seconds": args.timeout,
                "profile": args.profile,
                "runtime_enabled": args.runtime,
                "runtime_timeout_seconds": args.runtime_timeout if args.runtime else 0,
                "target_count": len(targets),
                "incomplete_count": sum(item.analysis_status != "complete" for item in extensions),
                "manifest": str(args.manifest.resolve()) if args.manifest else "",
                "manifest_artifact_count": sum(
                    1 for item in extensions
                    if isinstance(item.artifact_inventory.get("corpus_manifest"), dict)
                ) if args.manifest else 0,
                "manifest_verified_count": sum(
                    1 for item in extensions
                    if isinstance(item.artifact_inventory.get("corpus_manifest"), dict)
                    and item.artifact_inventory["corpus_manifest"].get("verified") is True
                ) if args.manifest else 0,
            }
        },
    )
    report["corpus_execution"] = report["intelligence"]["corpus_execution"]
    return report


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        report = run(args)
    except ValueError as exc:
        _parser().error(str(exc))
    output = Path(args.out)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "summary": report["summary"], "corpus_execution": report["corpus_execution"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
