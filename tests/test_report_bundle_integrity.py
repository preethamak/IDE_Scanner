from __future__ import annotations

import json
import os
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ide_scanner.report_bundle import generate_report_signing_keypair, verify_report_bundle, write_report_bundle


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

    def test_signed_provenance_authenticates_the_integrity_manifest(self) -> None:
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            private_key = Ed25519PrivateKey.generate()
            private_key_path = directory / "signing-key.pem"
            private_key_path.write_bytes(private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
            public_key_path = directory / "signing-key.pub.pem"
            public_key_path.write_bytes(private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
            bundle = directory / "signed-report.zip"
            receipt = write_report_bundle(
                {"extensions": []},
                bundle,
                signing_key=private_key_path,
                signing_key_id="guardrails-prod-2026",
            )

            result = verify_report_bundle(
                bundle,
                public_key=public_key_path,
                expected_key_id="guardrails-prod-2026",
                require_signature=True,
            )

            self.assertTrue(receipt["provenance"]["signed"])
            self.assertTrue(result["authenticated"])
            self.assertEqual(result["provenance"]["status"], "verified")

            altered = directory / "altered-signature.zip"
            with zipfile.ZipFile(bundle) as source, zipfile.ZipFile(altered, "w") as destination:
                for name in source.namelist():
                    payload = source.read(name)
                    if name == "provenance.json":
                        provenance = json.loads(payload)
                        provenance["signature_base64"] = "AAAAAAAA"
                        payload = (json.dumps(provenance, indent=2, sort_keys=True) + "\n").encode("utf-8")
                    destination.writestr(name, payload)
            with self.assertRaisesRegex(ValueError, "signature is invalid"):
                verify_report_bundle(altered, public_key=public_key_path, require_signature=True)

    def test_signature_requirement_rejects_unsigned_and_wrong_trusted_keys(self) -> None:
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            unsigned = directory / "unsigned.zip"
            write_report_bundle({"extensions": []}, unsigned)
            with self.assertRaisesRegex(ValueError, "no signed provenance"):
                verify_report_bundle(unsigned, require_signature=True)

            signing_key = Ed25519PrivateKey.generate()
            signing_key_path = directory / "signing-key.pem"
            signing_key_path.write_bytes(signing_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
            trusted_other_key = Ed25519PrivateKey.generate().public_key()
            trusted_other_key_path = directory / "other-key.pub.pem"
            trusted_other_key_path.write_bytes(trusted_other_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
            signed = directory / "signed.zip"
            write_report_bundle({"extensions": []}, signed, signing_key=signing_key_path)
            with self.assertRaisesRegex(ValueError, "does not match"):
                verify_report_bundle(signed, public_key=trusted_other_key_path, require_signature=True)

    def test_key_generation_writes_a_reusable_owner_only_private_key(self) -> None:
        with TemporaryDirectory() as tmp:
            directory = Path(tmp)
            private_path = directory / "keys" / "report-signing.pem"
            public_path = directory / "keys" / "report-signing.pub.pem"

            receipt = generate_report_signing_keypair(
                private_path,
                public_path,
                signing_key_id="guardrails-prod-2026",
            )
            bundle = directory / "signed.zip"
            write_report_bundle({"extensions": []}, bundle, signing_key=private_path, signing_key_id=receipt["signing_key_id"])

            result = verify_report_bundle(bundle, public_key=public_path, expected_key_id="guardrails-prod-2026", require_signature=True)
            self.assertTrue(result["authenticated"])
            self.assertEqual(receipt["algorithm"], "ed25519")
            self.assertEqual(receipt["signing_key_id"], "guardrails-prod-2026")
            self.assertEqual(os.stat(private_path).st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(ValueError, "Refusing to overwrite"):
                generate_report_signing_keypair(private_path, public_path)
