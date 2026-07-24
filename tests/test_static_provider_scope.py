from __future__ import annotations

import struct
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from ide_scanner.providers.static_analysis import (
    _has_valid_embedded_pe,
    _ignore_yara_match,
    _resolved_targets,
)


class StaticProviderScopeTests(unittest.TestCase):
    def test_targets_cannot_escape_artifact_root(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "extension.js").write_text("const value = 1;", encoding="utf-8")
            selected = _resolved_targets(
                root,
                {"semgrep": ["extension.js", "../outside.js"]},
                "semgrep",
            )
        self.assertEqual([path.name for path in selected or []], ["extension.js"])

    def test_text_yara_rules_do_not_apply_to_binary_media(self) -> None:
        with TemporaryDirectory() as tmp:
            image = Path(tmp) / "image.webp"
            image.write_bytes(b"base64 eval(")
            self.assertTrue(_ignore_yara_match("ide_scanner_encoded_dynamic_execution", "image.webp", image))
            self.assertTrue(_ignore_yara_match("ide_scanner_unicode_evasion", "image.webp", image))

    def test_marker_cooccurrence_is_not_a_valid_embedded_pe(self) -> None:
        with TemporaryDirectory() as tmp:
            binary = Path(tmp) / "linux-host"
            binary.write_bytes(b"\x7fELF" + b"MZ" + b"x" * 62 + b"PE\0\0")
            self.assertFalse(_has_valid_embedded_pe(binary))
            self.assertTrue(_ignore_yara_match("ide_scanner_embedded_pe", "linux-host", binary))

    def test_structurally_valid_embedded_pe_is_retained(self) -> None:
        with TemporaryDirectory() as tmp:
            binary = Path(tmp) / "container.bin"
            payload = bytearray(b"prefix!!" + b"MZ" + b"\0" * 126)
            mz_offset = 8
            struct.pack_into("<I", payload, mz_offset + 60, 64)
            payload[mz_offset + 64:mz_offset + 68] = b"PE\0\0"
            binary.write_bytes(payload)
            self.assertTrue(_has_valid_embedded_pe(binary))
            self.assertFalse(_ignore_yara_match("ide_scanner_embedded_pe", "container.bin", binary))
