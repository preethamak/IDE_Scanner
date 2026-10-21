from types import SimpleNamespace
import unittest
from unittest.mock import patch

from ide_scanner.scanner import _expand_declared_extension_relationships


def report(extension_id: str, version: str, relationships: list[dict[str, str]]):
    return SimpleNamespace(
        extension_id=extension_id,
        version=version,
        artifact_inventory={"declared_extension_relationships": relationships},
        artifact_identity={},
    )


class ExtensionRelationshipExpansionTests(unittest.TestCase):
    def test_walks_related_releases_once_and_records_unpinned_provenance(self) -> None:
        root = report("vendor.root", "1.0.0", [{"extension_id": "vendor.child", "relationship": "extension_pack"}])
        child = report("vendor.child", "2.0.0", [
            {"extension_id": "vendor.root", "relationship": "extension_dependency"},
            {"extension_id": "vendor.leaf", "relationship": "extension_dependency"},
        ])
        leaf = report("vendor.leaf", "3.0.0", [])
        by_id = {"vendor.child": child, "vendor.leaf": leaf}
        extensions = [root]

        with patch("ide_scanner.scanner.scan_marketplace_extension", side_effect=lambda identifier, **_: by_id[identifier]) as scan:
            _expand_declared_extension_relationships(
                extensions,
                known_bad_hashes={}, artifact_store=None, dynamic_runtime=False,
                runtime_timeout_seconds=15, runtime_bundle=None, max_related_extensions=20,
            )

        self.assertEqual([item.extension_id for item in extensions], ["vendor.root", "vendor.child", "vendor.leaf"])
        self.assertEqual(scan.call_args_list[0].args[0], "vendor.child")
        self.assertEqual(scan.call_args_list[1].args[0], "vendor.leaf")
        self.assertEqual(child.artifact_inventory["relationship_scan"], {
            "parent_extension_id": "vendor.root", "parent_version": "1.0.0",
            "relationship": "extension_pack", "selection": "latest_available",
            "version_pinned": False, "depth": 1,
        })
        self.assertFalse(root.artifact_inventory["relationship_expansion"]["truncated"])

    def test_stops_at_the_related_release_budget_and_discloses_truncation(self) -> None:
        root = report("vendor.root", "1.0.0", [
            {"extension_id": "vendor.one", "relationship": "extension_pack"},
            {"extension_id": "vendor.two", "relationship": "extension_dependency"},
            {"extension_id": "vendor.three", "relationship": "extension_dependency"},
        ])
        by_id = {identifier: report(identifier, "1.0.0", []) for identifier in ("vendor.one", "vendor.two", "vendor.three")}
        extensions = [root]

        with patch("ide_scanner.scanner.scan_marketplace_extension", side_effect=lambda identifier, **_: by_id[identifier]) as scan:
            _expand_declared_extension_relationships(
                extensions,
                known_bad_hashes={}, artifact_store=None, dynamic_runtime=False,
                runtime_timeout_seconds=15, runtime_bundle=None, max_related_extensions=2,
            )

        self.assertEqual([call.args[0] for call in scan.call_args_list], ["vendor.one", "vendor.two"])
        self.assertEqual(root.artifact_inventory["relationship_expansion"], {
            "requested": True, "max_related_extensions": 2,
            "scanned_related_extensions": 2, "truncated": True,
        })


if __name__ == "__main__":
    unittest.main()
