from pathlib import Path

from ide_scanner.providers.static_analysis import _ignore_yara_match


def test_embedded_pe_ignores_source_maps_and_metadata(tmp_path: Path) -> None:
    for relative in ("dist/extension.js.map", "README.md", "package.json"):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("MZ is documentation, not a binary", encoding="utf-8")
        assert _ignore_yara_match("ide_scanner_embedded_pe", relative, path)


def test_embedded_pe_requires_a_valid_pe_header(tmp_path: Path) -> None:
    path = tmp_path / "payload.bin"
    content = bytearray(132)
    content[4:6] = b"MZ"
    content[64:68] = (64).to_bytes(4, "little")
    content[68:72] = b"PE\0\0"
    path.write_bytes(content)

    assert not _ignore_yara_match("ide_scanner_embedded_pe", "payload.bin", path)


def test_code_rules_only_apply_to_executable_source(tmp_path: Path) -> None:
    source_map = tmp_path / "extension.js.map"
    source_map.write_text("eval(atob(value))", encoding="utf-8")
    source = tmp_path / "extension.js"
    source.write_text("eval(atob(value))", encoding="utf-8")

    assert _ignore_yara_match("ide_scanner_encoded_dynamic_execution", "extension.js.map", source_map)
    assert not _ignore_yara_match("ide_scanner_encoded_dynamic_execution", "extension.js", source)
