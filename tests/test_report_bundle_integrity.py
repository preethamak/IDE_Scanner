from __future__ import annotations

import json
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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

    def test_signed_provenance_requires_the_matching_trusted_key(self) -> None:
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            private = Ed25519PrivateKey.generate()
            private_path = directory / "signer.pem"
            public_path = directory / "signer.pub.pem"
            private_path.write_bytes(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            public_path.write_bytes(private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
            bundle = directory / "signed.zip"
            write_report_bundle({"extensions": []}, bundle, signing_key=private_path, signing_key_id="guardrails-prod")
            self.assertTrue(verify_report_bundle(bundle, public_key=public_path, expected_key_id="guardrails-prod", require_signature=True)["authenticated"])
            other = Ed25519PrivateKey.generate().public_key()
            other_path = directory / "other.pub.pem"
            other_path.write_bytes(other.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
            with self.assertRaisesRegex(ValueError, "does not match"):
                verify_report_bundle(bundle, public_key=other_path, require_signature=True)
            unsigned = directory / "unsigned.zip"
            write_report_bundle({"extensions": []}, unsigned)
            with self.assertRaisesRegex(ValueError, "no signed provenance"):
                verify_report_bundle(unsigned, public_key=public_path, require_signature=True)
