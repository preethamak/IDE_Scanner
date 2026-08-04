from pathlib import Path


def test_worker_uses_supported_scanner_module_entrypoint() -> None:
    workflow = (Path(__file__).parents[1] / ".github" / "workflows" / "deep-scan.yml").read_text(encoding="utf-8")

    assert "python -m ide_scanner scan" in workflow
    assert "\n          ide-scanner scan" not in workflow


def test_worker_preserves_claimed_platform_artifact_for_90_days() -> None:
    workflow = (Path(__file__).parents[1] / ".github" / "workflows" / "deep-scan.yml").read_text(encoding="utf-8")

    assert "SCAN_TARGET_PLATFORM: ${{ inputs.target_platform }}" in workflow
    assert "SCAN_TARGET_PLATFORM: ${{ steps.claim.outputs.target_platform }}" in workflow
    assert "IDE_SCANNER_ARTIFACT_STORE: ${{ runner.temp }}/ide-scanner-artifacts" in workflow
    assert "${{ runner.temp }}/ide-scanner-artifacts" in workflow
    assert "retention-days: 90" in workflow
    assert "retention-days: 7" not in workflow
