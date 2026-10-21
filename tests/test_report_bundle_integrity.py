from __future__ import annotations

import json
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

import unittest

from ide_scanner.report_bundle import verify_report_bundle, write_report_bundle


class ReportBundleIntegrityTests(unittest.TestCase):
    def test_report_bundle_integrity_detects_changed_members_and_explains_its_boundary(self) -> None:
        with TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "report.zip"
            write_report_bundle({"extensions": []}, bundle)

            result = verify_report_bundle(bundle)

            self.assertTrue(result["valid"])
            self.assertFalse(result["authenticated"])
            with zipfile.ZipFile(bundle) as archive:
                manifest = json.loads(archive.read("integrity.json"))
                self.assertEqual(manifest["authentication"], "none")
                self.assertIn("metadata.json", manifest["files"])

            altered = Path(tmp) / "altered.zip"
            with zipfile.ZipFile(bundle) as source, zipfile.ZipFile(altered, "w") as destination:
                for name in source.namelist():
                    payload = source.read(name)
                    destination.writestr(name, b"{}\n" if name == "summary.json" else payload)
            with self.assertRaisesRegex(ValueError, "summary.json"):
                verify_report_bundle(altered)


    def test_report_bundle_integrity_rejects_unlisted_members(self) -> None:
        with TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "report.zip"
            write_report_bundle({"extensions": []}, bundle)
            with zipfile.ZipFile(bundle, "a") as archive:
                archive.writestr("unexpected.json", "{}\n")
            with self.assertRaisesRegex(ValueError, "members"):
                verify_report_bundle(bundle)
