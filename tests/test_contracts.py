from pathlib import Path
import unittest

from ide_scanner.contracts import ScanRequest


class ScanRequestTests(unittest.TestCase):
    def test_create_normalizes_provider_names_and_freezes_collections(self) -> None:
        request = ScanRequest.create(
            paths=[Path("fixture")],
            extension_ids=["publisher.extension"],
            required_providers={" Semgrep ", "YARA", ""},
        )

        self.assertEqual(request.paths, (Path("fixture"),))
        self.assertEqual(request.extension_ids, ("publisher.extension",))
        self.assertEqual(request.required_providers, frozenset({"semgrep", "yara"}))

    def test_create_preserves_relationship_expansion_limits(self) -> None:
        request = ScanRequest.create(
            expand_extension_relationships=True,
            max_related_extensions=7,
        )

        self.assertTrue(request.expand_extension_relationships)
        self.assertEqual(request.max_related_extensions, 7)


if __name__ == "__main__":
    unittest.main()
