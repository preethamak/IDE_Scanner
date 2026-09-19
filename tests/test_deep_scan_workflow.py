from pathlib import Path


def test_worker_uses_supported_scanner_module_entrypoint() -> None:
    workflow = (Path(__file__).parents[1] / ".github" / "workflows" / "deep-scan.yml").read_text(encoding="utf-8")

    assert "python -m ide_scanner scan" in workflow
    assert "\n          ide-scanner scan" not in workflow


def test_worker_verifies_real_bubblewrap_namespace_isolation() -> None:
    workflow = (Path(__file__).parents[1] / ".github" / "workflows" / "deep-scan.yml").read_text(encoding="utf-8")

    assert "Verify runtime namespace isolation" in workflow
    assert "--unshare-net" in workflow
    assert "--unshare-user" in workflow
    assert "-- /usr/bin/true" in workflow


def test_production_gate_runs_a_deep_runtime_smoke_corpus() -> None:
    workflow = (Path(__file__).parents[1] / ".github" / "workflows" / "production-gate.yml").read_text(encoding="utf-8")

    assert "Acquire exact real-artifact calibration input" in workflow
    assert "b1b9785cdc7be479061f121f282391fba9be013d896d9a54f395621634709216" in workflow
    assert "open-vsx.org/api/bingcha/bcai-tools/4.0.37" in workflow
    assert "runtime-smoke:" in workflow
    assert "scripts/scan_corpus.py" in workflow
    assert "--path fixtures/credential-exfil" in workflow
    assert "--profile deep" in workflow
    assert "--runtime" in workflow
    assert "sandbox-preflight" in workflow
    assert '"secret_exfil" not in observed_kinds.get("unknown.shadow-helper", [])' in workflow
    assert 'provider.get("status") != "completed"' in workflow


def test_worker_preserves_claimed_platform_artifact_for_90_days() -> None:
    workflow = (Path(__file__).parents[1] / ".github" / "workflows" / "deep-scan.yml").read_text(encoding="utf-8")

    assert "SCAN_TARGET_PLATFORM: ${{ inputs.target_platform }}" in workflow
    assert "SCAN_TARGET_PLATFORM: ${{ steps.claim.outputs.target_platform }}" in workflow
    assert "IDE_SCANNER_ARTIFACT_STORE: ${{ runner.temp }}/ide-scanner-artifacts" in workflow
    assert "${{ runner.temp }}/ide-scanner-artifacts" in workflow
    assert "retention-days: 90" in workflow
    assert "retention-days: 7" not in workflow
