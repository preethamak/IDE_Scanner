from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from ide_scanner.bundle_analysis import analyze_generated_bundle
from ide_scanner.scanner import scan_extension


def _obfuscator_shell(payload: str) -> str:
    identifiers = ",".join(f"_0x{i:04x}=0x{i:x}" for i in range(80))
    computed = ",".join(f"o[_0x{i:04x}]" for i in range(30))
    rotation = "while(!![]){a.push(a.shift());break;}"
    return f"var {identifiers};var refs=[{computed!r}];{rotation}{payload}" + "x" * 300_000


def _scan_bundle(source: str):
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "package.json").write_text(
            '{"publisher":"example","name":"bundle","version":"1.0.0","main":"extension.js"}',
            encoding="utf-8",
        )
        (root / "extension.js").write_text(source, encoding="utf-8")
        return scan_extension(root)


def test_obfuscated_multi_family_harvester_is_preventively_blocked() -> None:
    source = _obfuscator_shell(
        "var targets=['/.ssh/id_rsa','/.aws/credentials','/.npmrc','wallet.dat'];"
        "var ops=['homedir','readdir','readFile','request','write','form-data'];"
    )

    report = _scan_bundle(source)
    finding = next(
        item for item in report.findings
        if item.rule_id == "obfuscated-credential-harvesting-exfiltration"
    )

    assert report.decision == "block"
    assert report.public_outcome == "preventive_block"
    assert report.malware_authority == "non_authoritative"
    assert report.risk_score >= 90
    assert finding.evidence["correlation"] == "obfuscation-resistant-semantic-feature-chain"
    assert len(finding.evidence["credential_families"]) >= 3


def test_heavy_obfuscation_without_harvesting_requires_review_not_block() -> None:
    source = _obfuscator_shell(
        "var theme=['colors','request','write','stringify'];var home='homedir';var files='readFile readdir';"
    )

    report = _scan_bundle(source)
    rule_ids = {item.rule_id for item in report.findings}

    assert "executable-heavy-obfuscation" in rule_ids
    assert "obfuscated-credential-harvesting-exfiltration" not in rule_ids
    assert report.decision == "review"


def test_credentials_and_network_without_obfuscation_do_not_invent_bundle_chain() -> None:
    source = (
        "var targets=['/.ssh/id_rsa','/.aws/credentials','/.npmrc','wallet.dat'];"
        "var ops=['homedir','readdir','readFile','request','write','form-data'];"
        + "const ordinaryBundle = true;" * 20_000
    )

    profile = analyze_generated_bundle(source)

    assert profile["strong_obfuscation"] is False
    assert profile["harvesting_exfiltration"] is False


def test_obfuscation_without_collection_or_exfiltration_does_not_invent_chain() -> None:
    profile = analyze_generated_bundle(_obfuscator_shell("var labels=['wallet','seed phrase'];"))

    assert profile["strong_obfuscation"] is True
    assert profile["harvesting_exfiltration"] is False


def test_alternate_obfuscator_without_hex_identifier_names_is_detected() -> None:
    numeric_table = ",".join(hex(index) for index in range(100))
    computed = ",".join(f"obj[key{index}]" for index in range(30))
    encoded = "".join(r"\x61" for _ in range(120))
    source = (
        f"var table=[{numeric_table}], refs=[{computed!r}], encoded='{encoded}';"
        "while(true){table['push'](table['shift']());break;}"
        "var targets=['/.ssh/id_rsa','/.aws/credentials','/.npmrc'];"
        "var ops=['homedir','readdir','readFile','request','write','stringify'];"
        + "x" * 300_000
    )

    profile = analyze_generated_bundle(source)

    assert profile["strong_obfuscation"] is True
    assert profile["harvesting_exfiltration"] is True
    assert "systematic-hex-identifiers" not in profile["obfuscation_indicators"]


def test_unrelated_polling_loop_and_array_calls_do_not_form_rotation_scaffold() -> None:
    source = (
        "while (true) { await client.messages.create({tools}); break; }"
        "var docs=['/.ssh/id_rsa','/.aws/credentials','/.npmrc','wallet.dat'];"
        "var ops=['homedir','readdir','readFile','request','write','stringify'];"
        + r"\x61" * 120
        + "obj[key];" * 40
        + "x" * 5_000
        + "queue.push(item); values.shift();"
    )

    profile = analyze_generated_bundle(source)

    assert "rotating-string-array" not in profile["obfuscation_indicators"]
    assert profile["strong_obfuscation"] is False
    assert profile["harvesting_exfiltration"] is False


def test_parser_loop_with_separate_push_and_shift_is_not_array_rotation() -> None:
    source = (
        "while (true) { switch (token()) { case 1: comments.push(text); break; } }"
        + "x" * 3_000
        + "comments.shift();"
        + r"\x61" * 120
        + "obj[key];" * 40
    )

    profile = analyze_generated_bundle(source)

    assert "rotating-string-array" not in profile["obfuscation_indicators"]
    assert profile["strong_obfuscation"] is False
