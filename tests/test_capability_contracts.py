from types import SimpleNamespace

from ide_scanner.capability_contracts import classify_extension, load_contracts


def test_contract_policy_is_packaged_and_versioned():
    policy = load_contracts()
    assert policy["policy_version"] == "capability-contracts-1.0.0"
    assert "coding_agent" in policy["classes"]


def test_classifier_exposes_signals_without_granting_identity_trust():
    extension = SimpleNamespace(
        name="Example Coding Agent",
        description="AI assistant for coding",
        capabilities=[{"id": "agent_tools"}, {"id": "process_execution"}],
    )
    classification = classify_extension(extension)
    assert classification["primary"] == "coding_agent"
    assert classification["confidence"] > 0
    assert "capability:agent_tools" in classification["signals"]
