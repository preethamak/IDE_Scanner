from __future__ import annotations

from ide_scanner.report_bundle import build_report_bundle
from extension_scanner_cli.scanner_adapter import display_report


def test_bundle_records_guardlens_distribution_version(monkeypatch):
    monkeypatch.setattr("ide_scanner.report_bundle.version", lambda name: "0.1.0" if name == "guardlens" else "unexpected")
    bundle = build_report_bundle({"extensions": []})
    assert bundle["metadata"]["scanner_version"] == "0.1.0"


def test_bundle_records_ci_build_identity(monkeypatch):
    monkeypatch.setenv("IDE_SCANNER_BUILD_SHA", "0123456789abcdef0123456789abcdef01234567")
    bundle = build_report_bundle({"extensions": []})
    assert bundle["metadata"]["scanner_build"] == "0123456789abcdef0123456789abcdef01234567"


def test_bundle_resolves_the_source_checkout_build_for_local_runs(monkeypatch):
    monkeypatch.delenv("IDE_SCANNER_BUILD_SHA", raising=False)
    bundle = build_report_bundle({"extensions": []})
    assert len(bundle["metadata"]["scanner_build"]) == 40


def test_invalid_ci_build_fails_closed(monkeypatch):
    monkeypatch.setenv("IDE_SCANNER_BUILD_SHA", "short-ref")
    bundle = build_report_bundle({"extensions": []})
    assert bundle["metadata"]["scanner_build"] == "unknown"


def test_presentation_cli_uses_the_same_build_identity(monkeypatch):
    monkeypatch.setenv("IDE_SCANNER_BUILD_SHA", "fedcba9876543210fedcba9876543210fedcba98")
    view = display_report({"extensions": [], "summary": {}})
    assert view["metadata"]["scanner_build"] == "fedcba9876543210fedcba9876543210fedcba98"
