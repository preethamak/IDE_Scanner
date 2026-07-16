from ide_scanner.providers.static_analysis import _ignore_yara_match


def test_embedded_pe_ignores_source_maps_and_metadata() -> None:
    for path in ("dist/extension.js.map", "README.md", "package.json"):
        assert _ignore_yara_match("ide_scanner_embedded_pe", path)


def test_embedded_pe_keeps_binary_and_executable_targets() -> None:
    for path in ("bin/tool.exe", "assets/payload.bin", "dist/extension.js"):
        assert not _ignore_yara_match("ide_scanner_embedded_pe", path)


def test_other_yara_rules_are_not_suppressed_by_path() -> None:
    assert not _ignore_yara_match("ide_scanner_encoded_dynamic_execution", "dist/extension.js.map")
