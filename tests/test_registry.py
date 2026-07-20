import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ide_scanner.registry import MarketplaceDownloadError, _fetch_openvsx_metadata, _normalize_marketplace_extension, download_marketplace_vsix, search_marketplace_extensions


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
        marketplace.return_value = ({"found": True, "publisher": "tintinweb", "extension_name": "vscode-vyper", "version": "0.1.0", "registry": "vs-marketplace"}, None)
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
    def test_cloud_worker_can_raise_bounded_download_limit(self, marketplace, openvsx) -> None:
        marketplace.return_value = ({"found": True, "publisher": "publisher", "extension_name": "large", "version": "1.0.0", "registry": "vs-marketplace"}, None)
        openvsx.return_value = ({"found": False}, None)
        environment = {"IDE_SCANNER_MAX_VSIX_BYTES": "268435456", "IDE_SCANNER_VSIX_DOWNLOAD_TIMEOUT": "180"}
        with tempfile.TemporaryDirectory() as temp, patch.dict("os.environ", environment, clear=False), patch("ide_scanner.registry._download_to_file") as download:
            download.side_effect = lambda _url, handle, **_kwargs: handle.write(b"PK\x03\x04large")
            download_marketplace_vsix("publisher.large", destination_dir=Path(temp))

        self.assertEqual(download.call_args.kwargs["max_bytes"], 268435456)
        self.assertEqual(download.call_args.kwargs["timeout"], 180)
