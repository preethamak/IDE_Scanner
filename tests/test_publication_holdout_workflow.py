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
