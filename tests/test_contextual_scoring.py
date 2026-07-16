from ide_scanner.scanner import _classify_findings, _finding


def test_weak_encoded_execution_does_not_become_malware_or_overall_high() -> None:
    weak_high = _finding(
        "example.extension", "1.0.0", "encoded-dynamic-execution", "code", "HIGH", 0.68,
        "Encoded and execution markers coexist in a bundle.", ["dist/extension.js"], "Review context.",
        {"evidence_class": "weak"},
    )
    dependency = _finding(
        "example.extension", "1.0.0", "vulnerable-npm-dependency", "dependency", "MEDIUM", 0.8,
        "A dependency advisory needs review.", ["package-lock.json"], "Upgrade the dependency.",
        {"evidence_class": "dependency"},
    )

    verdict, _, _, severity, malware_score, _, _ = _classify_findings([weak_high, dependency])

    assert verdict == "review"
    assert severity == "MEDIUM"
    assert malware_score == 0
