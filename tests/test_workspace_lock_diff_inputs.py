import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from ide_scanner.workspace_lock_diff import compare_workspace_locks


class RequiredLockInputsTests(unittest.TestCase):
    def test_missing_comparison_inputs_fail_closed(self):
        with TemporaryDirectory() as root:
            valid = Path(root) / "valid.json"
            missing = Path(root) / "missing.json"
            valid.write_text(json.dumps({"extensions": {}}))
            for before, after in [(missing, valid), (valid, missing), (missing, missing)]:
                with self.subTest(before=before, after=after):
                    with self.assertRaisesRegex(ValueError, "Required workspace lock"):
                        compare_workspace_locks(before, after)

    def test_directory_cannot_be_used_as_a_lock(self):
        with TemporaryDirectory() as root:
            with self.assertRaises(ValueError):
                compare_workspace_locks(root, root)
