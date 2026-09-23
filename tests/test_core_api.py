from unittest.mock import sentinel, patch

from ide_scanner.core import ScanRequest, run_scan, summarize_report


def test_run_scan_forwards_exact_marketplace_identity_and_store() -> None:
    request = ScanRequest(
        marketplace_scan_ids=["publisher.extension"], marketplace_version="1.2.3",
        marketplace_target_platform="linux-x64", marketplace_artifact_store=sentinel.store,
    )
    with patch("ide_scanner.core.scan_targets", return_value={"extensions": []}) as scan:
        assert run_scan(request) == {"extensions": []}

    assert scan.call_args.kwargs["marketplace_version"] == "1.2.3"
    assert scan.call_args.kwargs["marketplace_target_platform"] == "linux-x64"
    assert scan.call_args.kwargs["marketplace_artifact_store"] is sentinel.store


def test_summary_uses_policy_severity_and_preserves_detector_severity() -> None:
    report = {
        "extensions": [{
            "extension_id": "example.agent",
            "verdict": "clean",
            "severity": "INFO",
            "findings": [{
                "finding_id": "finding-1",
                "rule_id": "encoded-dynamic-execution",
                "category": "code",
                "severity": "HIGH",
                "effective_severity": "INFO",
                "evidence_class": "weak",
                "actionability": "contextual",
                "confidence": 0.8,
                "evidence_summary": "Encoded execution markers.",
                "file_refs": ["extension.js"],
            }],
        }],
    }

    result = summarize_report(report)

    assert result["finding_counts"]["by_severity"] == {"INFO": 1}
    assert result["finding_counts"]["by_detector_severity"] == {"HIGH": 1}
    assert result["finding_counts"]["by_actionability"] == {"contextual": 1}
    assert result["top_risk_extensions"][0]["top_findings"][0] == {
        "finding_id": "finding-1",
        "rule_id": "encoded-dynamic-execution",
        "category": "code",
        "severity": "INFO",
        "detector_severity": "HIGH",
        "evidence_class": "weak",
        "actionability": "contextual",
        "confidence": 0.8,
        "evidence_summary": "Encoded execution markers.",
        "file_refs": ["extension.js"],
        "recommendation": "",
    }
