from __future__ import annotations

import json
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from ide_scanner.cli import main
from ide_scanner.report_bundle import verify_report_bundle, write_report_bundle


class ReportBundleIntegrityTests(unittest.TestCase):
    def test_report_bundle_verifies_all_expected_members(self) -> None:
        with TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "report.zip"
            write_report_bundle({"extensions": []}, bundle)

            result = verify_report_bundle(bundle)

            self.assertTrue(result["valid"])
            self.assertFalse(result["authenticated"])
            with zipfile.ZipFile(bundle) as archive:
                manifest = json.loads(archive.read("integrity.json"))
            self.assertIn("cyclonedx.json", manifest["files"])
            self.assertEqual(manifest["authentication"], "none")

    def test_report_bundle_rejects_changed_duplicate_and_unlisted_members(self) -> None:
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            bundle = directory / "report.zip"
            write_report_bundle({"extensions": []}, bundle)

            altered = directory / "altered.zip"
            with zipfile.ZipFile(bundle) as source, zipfile.ZipFile(altered, "w") as destination:
                for name in source.namelist():
                    destination.writestr(name, b"{}\n" if name == "summary.json" else source.read(name))
            with self.assertRaisesRegex(ValueError, "summary.json"):
                verify_report_bundle(altered)

            with zipfile.ZipFile(bundle, "a") as archive:
                archive.writestr("unexpected.json", "{}\n")
                archive.writestr("summary.json", "{}\n")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                verify_report_bundle(bundle)

    def test_report_verify_cli_fails_closed_for_a_missing_manifest(self) -> None:
        with TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "not-a-report.zip"
            with zipfile.ZipFile(bundle, "w") as archive:
                archive.writestr("summary.json", "{}\n")

            self.assertEqual(main(["report", "verify", "--bundle", str(bundle)]), 2)

    def test_report_bundle_rejects_members_before_decompression_when_limits_are_exceeded(self) -> None:
        with TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "report.zip"
            write_report_bundle({"extensions": []}, bundle)

            with patch("ide_scanner.report_bundle.MAX_REPORT_BUNDLE_MEMBER_BYTES", 1):
                with self.assertRaisesRegex(ValueError, "per-member size limit"):
                    verify_report_bundle(bundle)
