import json
import gzip
import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ide_scanner.registry import MarketplaceDownloadError, _degzip_if_needed, _fetch_openvsx_metadata, _normalize_marketplace_extension, download_marketplace_vsix, search_marketplace_extensions


OPENVSX_EXTENSION = {
    "name": "vscode-vyper",
    "namespace": "tintinweb",
    "namespaceDisplayName": "tintinweb",
    "version": "0.1.0",
    "displayName": "Vyper",
    "description": "Ethereum Vyper language support for Visual Studio Code",
    "verified": True,
    "downloadCount": 1009,
    "timestamp": "2024-12-09T08:48:12Z",
    "files": {"download": "https://open-vsx.org/vscode-vyper.vsix", "icon": "https://open-vsx.org/icon.png"},
}


class RegistryTests(unittest.TestCase):
    def test_gzip_unwrapping_runs_in_bounded_worker(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            artifact = Path(temp) / "wrapped.vsix"
            artifact.write_bytes(gzip.compress(b"PK\x03\x04payload"))

            def worker(command, **kwargs):
                output = Path(command[command.index("--output") + 1])
                output.write_bytes(b"PK\x03\x04payload")
                return subprocess.CompletedProcess(
                    command,
                    0,
                    '{"schema_version":"1","status":"complete","gzip":{"expanded_bytes":11}}',
                    "",
                )

            with patch("ide_scanner.registry.run_bounded_process", side_effect=worker) as bounded:
                _degzip_if_needed(artifact)

        self.assertEqual(bounded.call_args.kwargs["timeout"], 180)
        self.assertEqual(bounded.call_args.kwargs["memory_limit_mb"], 512)
        self.assertEqual(bounded.call_args.kwargs["file_size_limit_mb"], 2048)
        self.assertIn("unwrap-gzip", bounded.call_args.args[0])

    def test_gzip_worker_failure_is_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            artifact = Path(temp) / "wrapped.vsix"
            original = gzip.compress(b"PK\x03\x04payload")
            artifact.write_bytes(original)
            failed = subprocess.CompletedProcess(
                [], 1, '{"schema_version":"1","status":"failed","error":"ratio exceeded"}', ""
            )
            with patch("ide_scanner.registry.run_bounded_process", return_value=failed):
                with self.assertRaisesRegex(MarketplaceDownloadError, "ratio exceeded"):
                    _degzip_if_needed(artifact)
            self.assertEqual(artifact.read_bytes(), original)

    def test_marketplace_domain_verified_publisher_is_preserved(self) -> None:
        metadata = _normalize_marketplace_extension("dbaeumer.vscode-eslint", {
            "displayName": "ESLint",
            "extensionName": "vscode-eslint",
            "publisher": {
                "publisherName": "dbaeumer",
                "displayName": "Microsoft",
                "flags": "verified",
                "isDomainVerified": True,
            },
            "versions": [{"version": "3.0.33"}],
            "statistics": [],
        })

        self.assertTrue(metadata["publisher_verified"])

    def test_marketplace_integrity_assets_are_preserved(self) -> None:
        digest = "a" * 64
        metadata = _normalize_marketplace_extension("publisher.extension", {
            "extensionName": "extension",
            "publisher": {"publisherName": "publisher"},
            "versions": [{
                "version": "1.2.3",
                "files": [{
                    "assetType": "Microsoft.VisualStudio.Services.VsixSignature",
                    "source": "https://cdn.example/signature",
                }],
                "properties": [{
                    "key": "Microsoft.VisualStudio.Services.VsixSha256",
                    "value": digest.upper(),
                }],
            }],
            "statistics": [],
        })

        self.assertEqual(metadata["vsix_sha256"], digest)
        self.assertTrue(metadata["signature_asset_declared"])
        self.assertEqual(metadata["signature_asset_url"], "https://cdn.example/signature")

    @patch("ide_scanner.registry._http_get_text", return_value=json.dumps(OPENVSX_EXTENSION))
    def test_openvsx_metadata_provides_exact_download(self, _get) -> None:
        metadata, error = _fetch_openvsx_metadata("tintinweb.vscode-vyper")

        self.assertIsNone(error)
        self.assertTrue(metadata["found"])
        self.assertEqual(metadata["registry"], "openvsx")
        self.assertEqual(metadata["version"], "0.1.0")
        self.assertEqual(metadata["download_url"], "https://open-vsx.org/vscode-vyper.vsix")

    @patch("ide_scanner.registry._http_get_text")
    @patch("ide_scanner.registry._http_post_json", return_value={"results": [{"extensions": []}]})
    def test_search_includes_openvsx_only_extension(self, _post, get) -> None:
        get.return_value = json.dumps({"extensions": [OPENVSX_EXTENSION]})

        results = search_marketplace_extensions("vyper")

        self.assertEqual(results[0]["extension_id"], "tintinweb.vscode-vyper")
        self.assertEqual(results[0]["registry"], "openvsx")

    @patch("ide_scanner.registry._fetch_openvsx_metadata")
    @patch("ide_scanner.registry._fetch_marketplace_metadata")
    def test_download_falls_back_to_openvsx_artifact(self, marketplace, openvsx) -> None:
        marketplace.return_value = ({
            "found": True, "publisher": "tintinweb", "extension_name": "vscode-vyper",
            "version": "0.1.0", "registry": "vs-marketplace", "vsix_sha256": "0" * 64,
            "signature_asset_declared": True,
        }, None)
        openvsx.return_value = ({"found": True, "download_url": "https://open-vsx.org/vscode-vyper.vsix", "registry": "openvsx"}, None)

        def download(url, handle, **_):
            if "marketplace.visualstudio.com" in url:
                raise MarketplaceDownloadError("VS Marketplace package endpoint failed")
            handle.write(b"PK\x03\x04openvsx")

        with tempfile.TemporaryDirectory() as temp, patch("ide_scanner.registry._download_to_file", side_effect=download):
            source = {}
            result = download_marketplace_vsix("tintinweb.vscode-vyper", destination_dir=Path(temp), registry_out=source)

            self.assertTrue(result.read_bytes().startswith(b"PK"))
            self.assertEqual(source["registry"], "openvsx")

    @patch("ide_scanner.registry._fetch_openvsx_metadata")
    @patch("ide_scanner.registry._fetch_marketplace_metadata")
    def test_pinned_marketplace_download_never_falls_back_to_different_openvsx_version(self, marketplace, openvsx) -> None:
        marketplace.return_value = ({"found": True, "publisher": "dbaeumer", "extension_name": "vscode-eslint", "version": "3.0.34", "registry": "vs-marketplace"}, None)
        openvsx.return_value = ({"found": True, "version": "3.0.34", "download_url": "https://open-vsx.org/latest.vsix", "registry": "openvsx"}, None)

        with tempfile.TemporaryDirectory() as temp, patch("ide_scanner.registry._download_to_file", side_effect=MarketplaceDownloadError("marketplace unavailable")) as download:
            with self.assertRaises(MarketplaceDownloadError):
                download_marketplace_vsix("dbaeumer.vscode-eslint", version="3.0.33", destination_dir=Path(temp))

        self.assertEqual(download.call_count, 1)
        self.assertNotIn("open-vsx.org", str(download.call_args.args[0]))

    @patch("ide_scanner.registry._fetch_openvsx_metadata")
    @patch("ide_scanner.registry._fetch_marketplace_metadata")
    def test_target_platform_qualifies_marketplace_artifact_url(self, marketplace, openvsx) -> None:
        marketplace.return_value = ({"found": True, "publisher": "ms-python", "extension_name": "python", "version": "1.0.0", "registry": "vs-marketplace"}, None)
        openvsx.return_value = ({"found": False}, None)
        with tempfile.TemporaryDirectory() as temp, patch("ide_scanner.registry._download_to_file") as download:
            download.side_effect = lambda _url, handle, **_kwargs: handle.write(b"PK\x03\x04platform")
            source = {}
            download_marketplace_vsix(
                "ms-python.python",
                version="1.0.0",
                target_platform="darwin-x64",
                destination_dir=Path(temp),
                registry_out=source,
            )

        self.assertTrue(download.call_args.args[0].endswith("/vspackage?targetPlatform=darwin-x64"))
        self.assertEqual(download.call_count, 1)
        self.assertEqual(source, {
            "extension_id": "ms-python.python",
            "version": "1.0.0",
            "registry": "vs-marketplace",
            "target_platform": "darwin-x64",
            "download_url": download.call_args.args[0],
            "signature_asset_declared": "false",
            "signature_asset_url": "",
            "integrity_metadata_matches_artifact": "false",
        })

    @patch("ide_scanner.registry._fetch_openvsx_metadata", return_value=({"found": False}, None))
    @patch("ide_scanner.registry._fetch_marketplace_metadata")
    def test_download_verifies_registry_sha256(self, marketplace, _openvsx) -> None:
        payload = b"PK\x03\x04signed-package"
        digest = hashlib.sha256(payload).hexdigest()
        marketplace.return_value = ({
            "found": True,
            "publisher": "publisher",
            "extension_name": "extension",
            "version": "1.2.3",
            "registry": "vs-marketplace",
            "vsix_sha256": digest,
            "signature_asset_declared": True,
            "signature_asset_url": "https://cdn.example/signature",
        }, None)
        with tempfile.TemporaryDirectory() as temp, patch("ide_scanner.registry._download_to_file") as download:
            download.side_effect = lambda _url, handle, **_kwargs: handle.write(payload)
            source = {}
            result = download_marketplace_vsix("publisher.extension", destination_dir=Path(temp), registry_out=source)
            downloaded = result.read_bytes()

        self.assertEqual(downloaded, payload)
        self.assertEqual(source["expected_sha256"], digest)
        self.assertEqual(source["sha256_verified"], "true")
        self.assertEqual(source["signature_asset_declared"], "true")
        self.assertEqual(source["integrity_metadata_matches_artifact"], "true")

    @patch("ide_scanner.registry._fetch_openvsx_metadata", return_value=({"found": False}, None))
    @patch("ide_scanner.registry._fetch_marketplace_metadata")
    def test_download_rejects_registry_sha256_mismatch(self, marketplace, _openvsx) -> None:
        marketplace.return_value = ({
            "found": True,
            "publisher": "publisher",
            "extension_name": "extension",
            "version": "1.2.3",
            "registry": "vs-marketplace",
            "vsix_sha256": "0" * 64,
        }, None)
        with tempfile.TemporaryDirectory() as temp, patch("ide_scanner.registry._download_to_file") as download:
            download.side_effect = lambda _url, handle, **_kwargs: handle.write(b"PK\x03\x04tampered")
            with self.assertRaisesRegex(MarketplaceDownloadError, "SHA-256 check"):
                download_marketplace_vsix("publisher.extension", destination_dir=Path(temp))

            self.assertEqual(list(Path(temp).glob("*.vsix")), [])

    @patch("ide_scanner.registry._fetch_openvsx_metadata", return_value=({"found": False}, None))
    @patch("ide_scanner.registry._fetch_marketplace_metadata")
    def test_pinned_older_version_does_not_use_latest_version_digest(self, marketplace, _openvsx) -> None:
        marketplace.return_value = ({
            "found": True,
            "publisher": "publisher",
            "extension_name": "extension",
            "version": "2.0.0",
            "registry": "vs-marketplace",
            "vsix_sha256": "0" * 64,
            "signature_asset_declared": True,
        }, None)
        with tempfile.TemporaryDirectory() as temp, patch("ide_scanner.registry._download_to_file") as download:
            download.side_effect = lambda _url, handle, **_kwargs: handle.write(b"PK\x03\x04older")
            source = {}
            result = download_marketplace_vsix(
                "publisher.extension", version="1.0.0", destination_dir=Path(temp), registry_out=source
            )
            self.assertTrue(result.exists())

        self.assertEqual(source["integrity_metadata_matches_artifact"], "false")
        self.assertNotIn("expected_sha256", source)
        self.assertEqual(source["signature_asset_declared"], "false")

    def test_target_platform_rejects_untrusted_url_input(self) -> None:
        with self.assertRaisesRegex(MarketplaceDownloadError, "target platform"):
            download_marketplace_vsix("ms-python.python", target_platform="darwin-x64&redirect=1")

    @patch("ide_scanner.registry._fetch_openvsx_metadata")
    @patch("ide_scanner.registry._fetch_marketplace_metadata")
    def test_cloud_worker_can_raise_bounded_download_limit(self, marketplace, openvsx) -> None:
        marketplace.return_value = ({"found": True, "publisher": "publisher", "extension_name": "large", "version": "1.0.0", "registry": "vs-marketplace"}, None)
        openvsx.return_value = ({"found": False}, None)
        environment = {"IDE_SCANNER_MAX_VSIX_BYTES": "268435456", "IDE_SCANNER_VSIX_DOWNLOAD_TIMEOUT": "180"}
        with tempfile.TemporaryDirectory() as temp, patch.dict("os.environ", environment, clear=False), patch("ide_scanner.registry._download_to_file") as download:
            download.side_effect = lambda _url, handle, **_kwargs: handle.write(b"PK\x03\x04large")
            download_marketplace_vsix("publisher.large", destination_dir=Path(temp))

        self.assertEqual(download.call_args.kwargs["max_bytes"], 268435456)
        self.assertEqual(download.call_args.kwargs["timeout"], 180)
