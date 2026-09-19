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
    assert "strace" in workflow
    assert "GUARDRAILS_RUNTIME_EXTERNAL_TRACE: \"1\"" in workflow


def test_production_gate_runs_a_deep_runtime_smoke_corpus() -> None:
    workflow = (Path(__file__).parents[1] / ".github" / "workflows" / "production-gate.yml").read_text(encoding="utf-8")

    assert "Acquire exact real-artifact calibration input" in workflow
    assert "b1b9785cdc7be479061f121f282391fba9be013d896d9a54f395621634709216" in workflow
    assert "Scan exact Nx Console supply-chain calibration input" in workflow
    assert "nrwl.angular-console-18.95.0.vsix" in workflow
    assert "1a4afce34918bdc74ae3f31edaffffaa0ee074d83618f53edfd88137927340b8" in workflow
    assert 'extension.get("extension_id") != "nrwl.angular-console"' in workflow
    assert 'extension.get("version") != "18.95.0"' in workflow
    assert "open-vsx.org/api/bingcha/bcai-tools/4.0.37" in workflow
    assert "Scan exact real-artifact calibration input" in workflow
    assert "--path benchmarks/external/artifacts/bcai-rosetta-4.0.37/bcai-rosetta-4.0.37.vsix" in workflow
    assert 'extension.get("decision") != "block"' in workflow
    assert 'extension.get("verdict") != "malicious"' in workflow
    assert 'item.get("rule_id") == "known-malicious-extension"' in workflow
    assert "bcai-calibration.json" in workflow
    assert "code-runner-cve-calibration.json" in workflow
    assert "formulahendry-code-runner-0.12.2/*.vsix" in workflow
    assert "4c8e4aea7dd07c9c20173e71869759fb2ce2f55b9819c4b374172467af03b144" in workflow
    assert 'item.get("rule_id") == "known-vulnerable-extension"' in workflow
    assert "Acquire exact safe-control inputs" in workflow
    assert "228a2cf081d4cbea9b91cde14a8f9c4a4d003e7f32431496953fd6bac266f5a3" in workflow
    assert "b271bd7ebc445960ecb3cb730da57f22f55abc7411ac94806ab8fe44df8a5c44" in workflow
    assert "0668758312a7fa6beda259ca5a6849d90c5d519df6415edbe246c135e06d7168" in workflow
    assert "34ac3f72a70a04d2dea5c900c413a651e58c0e8745851aaf5966a951552e22aa" in workflow
    assert "95d8af5d113124f8795a31fffe9eae75fafc7ed4de73ae1a90656cf166aebefa" in workflow
    assert "runtime-smoke:" in workflow
    assert "sudo apt-get install -y bubblewrap strace" in workflow
    assert "GUARDRAILS_RUNTIME_EXTERNAL_TRACE: \"1\"" in workflow
    assert "scripts/scan_corpus.py" in workflow
    assert "--path fixtures/credential-exfil" in workflow
    assert "--profile deep" in workflow
    assert "--runtime" in workflow
    assert "sandbox-preflight" in workflow
    assert '"secret_exfil" not in observed_kinds.get("unknown.shadow-helper", [])' in workflow
    assert 'provider.get("status") != "completed"' in workflow
    assert 'execution.get("external_syscall_trace") is not True' in workflow


def test_worker_preserves_claimed_platform_artifact_for_90_days() -> None:
    workflow = (Path(__file__).parents[1] / ".github" / "workflows" / "deep-scan.yml").read_text(encoding="utf-8")

    assert "SCAN_TARGET_PLATFORM: ${{ inputs.target_platform }}" in workflow
    assert "SCAN_TARGET_PLATFORM: ${{ steps.claim.outputs.target_platform }}" in workflow
    assert "IDE_SCANNER_ARTIFACT_STORE: ${{ runner.temp }}/ide-scanner-artifacts" in workflow
    assert "${{ runner.temp }}/ide-scanner-artifacts" in workflow
    assert "retention-days: 90" in workflow
    assert "retention-days: 7" not in workflow
