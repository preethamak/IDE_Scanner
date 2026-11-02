from __future__ import annotations

import unittest
from pathlib import Path


class ProductionGateWorkflowTests(unittest.TestCase):
    def test_exact_artifact_cache_is_present_before_acquisition_and_hash_validation(self) -> None:
        workflow = (Path(__file__).resolve().parents[1] / ".github" / "workflows" / "production-gate.yml").read_text(encoding="utf-8")

        self.assertIn("uses: actions/cache@v4", workflow)
        self.assertIn("path: benchmarks/external/artifacts", workflow)
        self.assertIn("key: scanner-production-calibration-artifacts-v1", workflow)
        self.assertLess(workflow.index("Restore exact real-artifact calibration cache"), workflow.index("Acquire exact real-artifact calibration input"))
        self.assertIn("Existing BCAI calibration artifact has SHA-256", workflow)
        self.assertIn("Existing safe-control artifact has SHA-256", workflow)
