from __future__ import annotations

import tempfile
from pathlib import Path

from ide_scanner.service import JobStore, execute_marketplace_job


def test_marketplace_service_uses_exact_version_and_deep_provider_contract() -> None:
    fixture = Path(__file__).resolve().parents[1] / "fixtures" / "benign-formatter"
    observed: dict[str, object] = {}

    def fake_scan(**kwargs: object):
        from ide_scanner.scanner import scan_targets

        observed.update(kwargs)
        return scan_targets(paths=[fixture], include_posture=False)

    with tempfile.TemporaryDirectory() as temp:
        store = JobStore(Path(temp))
        job = store.create("publisher.extension")
        job["version"] = "1.2.3"
        execute_marketplace_job(store, job, scan=fake_scan)

    assert observed["marketplace_version"] == "1.2.3"
    assert observed["required_providers"] == frozenset(
        {"semgrep", "yara", "dependency_intelligence"}
    )
