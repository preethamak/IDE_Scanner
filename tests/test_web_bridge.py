from contextlib import redirect_stdout
from io import StringIO
import json
import sys
import unittest
from unittest.mock import patch

from ide_scanner.web_bridge import main


class WebBridgeTests(unittest.TestCase):
    def test_scan_forwards_bounded_relationship_expansion_options(self) -> None:
        output = StringIO()
        with (
            patch.object(
                sys,
                "stdin",
                StringIO(
                    json.dumps(
                        {
                            "extension_paths": [],
                            "marketplace_ids": ["publisher.extension"],
                            "expand_extension_relationships": True,
                            "max_related_extensions": 7,
                        }
                    )
                ),
            ),
            patch("ide_scanner.web_bridge.run_scan", return_value={"extensions": []}) as scan,
            patch("ide_scanner.web_bridge.summarize_report", return_value={}),
        ):
            with redirect_stdout(output):
                self.assertEqual(main(["scan"]), 0)

        request = scan.call_args.args[0]
        self.assertTrue(request.expand_extension_relationships)
        self.assertEqual(request.max_related_extensions, 7)

    def test_scan_rejects_non_boolean_or_unbounded_relationship_options(self) -> None:
        for payload, expected in [
            ({"extension_paths": [], "expand_extension_relationships": "yes"}, "expand_extension_relationships"),
            ({"extension_paths": [], "max_related_extensions": 101}, "max_related_extensions"),
        ]:
            with self.subTest(payload=payload), patch.object(sys, "stdin", StringIO(json.dumps(payload))):
                output = StringIO()
                with redirect_stdout(output):
                    self.assertEqual(main(["scan"]), 2)
                self.assertIn(expected, json.loads(output.getvalue())["error"])


if __name__ == "__main__":
    unittest.main()
