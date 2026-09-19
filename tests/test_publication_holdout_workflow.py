import json
from pathlib import Path


def test_publication_holdout_workflow_requires_exact_deep_runtime_evidence() -> None:
    workflow = (Path(__file__).parents[1] / ".github" / "workflows" / "publication-holdout.yml").read_text(encoding="utf-8")

    assert 'workflows: ["Scanner production gate"]' in workflow
    assert "types: [completed]" in workflow
    assert "workflow_run.event == 'push'" in workflow
    assert "workflow_run.head_repository.full_name == github.repository" in workflow
    assert "workflow_run.head_sha || github.sha" in workflow
    assert "ref: ${{ github.event.workflow_run.head_sha || github.sha }}" in workflow
    assert "scripts/freeze_accuracy_holdout.py" in workflow
    assert "--source benchmarks/holdouts/real-evidence-2026-source.json" in workflow
    assert "--profile deep" in workflow
    assert "--runtime" in workflow
    assert "sandbox-preflight" in workflow
    assert "--jobs 1" in workflow
    assert "--timeout 180" in workflow
    assert "strace" in workflow
    assert "GUARDRAILS_RUNTIME_EXTERNAL_TRACE" in workflow
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

    by_identity = {(item["extension_id"], item["version"]): item for item in artifacts}
    nx = by_identity[("nrwl.angular-console", "18.95.0")]
    assert nx["sha256"] == "1a4afce34918bdc74ae3f31edaffffaa0ee074d83618f53edfd88137927340b8"
    assert nx["artifact_mirrors"] == [
        "https://github.com/trailofbits/vsix-zoo/raw/refs/heads/main/samples/teampcp/nrwl.angular-console-18.95.0.vsix"
    ]
    glassworm = by_identity[("Iconkieftwo.icon-theme-materiall", "5.29.1")]
    assert glassworm["sha256"] == "0878f3c59755ffaf0b639c1b2f6e8fed552724a50eb2878c3ba21cf8eb4e2ab6"
