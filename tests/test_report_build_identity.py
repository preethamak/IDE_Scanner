from __future__ import annotations

from ide_scanner.report_bundle import build_report_bundle


def test_bundle_records_ci_build_identity(monkeypatch):
    monkeypatch.setenv("IDE_SCANNER_BUILD_SHA", "0123456789abcdef")
    bundle = build_report_bundle({"extensions": []})
    assert bundle["metadata"]["scanner_build"] == "0123456789abcdef"


def test_bundle_does_not_claim_a_build_for_local_runs(monkeypatch):
    monkeypatch.delenv("IDE_SCANNER_BUILD_SHA", raising=False)
    bundle = build_report_bundle({"extensions": []})
    assert bundle["metadata"]["scanner_build"] == "unknown"
