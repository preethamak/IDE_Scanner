from __future__ import annotations

import hashlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ide_scanner.artifact_input import ArtifactInputError, acquire_https_vsix


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


class ArtifactInputTests(unittest.TestCase):
    def test_hash_pinned_public_https_artifact_is_acquired(self) -> None:
        content = b"PK\x03\x04vsix"
        digest = hashlib.sha256(content).hexdigest()
        opener = type("Opener", (), {"open": lambda self, request, timeout: _Response(content)})()
        with tempfile.TemporaryDirectory() as tmp, patch(
            "ide_scanner.artifact_input.socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("93.184.216.34", 443))],
        ), patch("ide_scanner.artifact_input.urllib.request.build_opener", return_value=opener):
            path = acquire_https_vsix("https://example.com/archive.vsix", digest, Path(tmp))
            self.assertEqual(path.read_bytes(), content)

    def test_private_network_destination_is_rejected(self) -> None:
        with patch(
            "ide_scanner.artifact_input.socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("127.0.0.1", 443))],
        ):
            with self.assertRaisesRegex(ArtifactInputError, "non-public"):
                acquire_https_vsix("https://localhost/archive.vsix", "a" * 64)

    def test_digest_mismatch_removes_download(self) -> None:
        opener = type("Opener", (), {"open": lambda self, request, timeout: _Response(b"wrong")})()
        with tempfile.TemporaryDirectory() as tmp, patch(
            "ide_scanner.artifact_input.socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("93.184.216.34", 443))],
        ), patch("ide_scanner.artifact_input.urllib.request.build_opener", return_value=opener):
            with self.assertRaisesRegex(ArtifactInputError, "does not match"):
                acquire_https_vsix("https://example.com/archive.vsix", "a" * 64, Path(tmp))
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_credentials_non_https_and_nonstandard_ports_are_rejected(self) -> None:
        for url in (
            "http://example.com/a.vsix",
            "https://user:pass@example.com/a.vsix",
            "https://example.com:8443/a.vsix",
        ):
            with self.subTest(url=url), self.assertRaises(ArtifactInputError):
                acquire_https_vsix(url, "a" * 64)


if __name__ == "__main__":
    unittest.main()
