import json
from pathlib import Path


def test_publication_holdout_workflow_requires_exact_deep_runtime_evidence() -> None:
    workflow = (Path(__file__).parents[1] / ".github" / "workflows" / "publication-holdout.yml").read_text(encoding="utf-8")

    assert "scripts/freeze_accuracy_holdout.py" in workflow
    assert "--source benchmarks/holdouts/real-evidence-2026-source.json" in workflow
    assert "--profile deep" in workflow
    assert "--runtime" in workflow
    assert "--jobs 1" in workflow
    assert "--timeout 180" in workflow
    assert "benchmark holdout" in workflow
    assert "build_publication_accuracy_gate.py" in workflow
    assert "activate-scan-publication" not in workflow


def test_real_evidence_source_has_minimum_label_balance_before_acquisition() -> None:
    source_path = Path(__file__).parents[1] / "benchmarks" / "holdouts" / "real-evidence-2026-source.json"
    source = json.loads(source_path.read_text(encoding="utf-8"))
    artifacts = source["artifacts"]
    assert sum(item["label"] == "known_safe" for item in artifacts) >= 5
    assert sum(item["label"] == "known_malicious" for item in artifacts) >= 5
    assert all(len(item["sha256"]) == 64 for item in artifacts)
    assert all(item["artifact_url"].startswith("https://") for item in artifacts)
