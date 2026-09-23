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


def test_coding_agent_contract_allows_explicit_credential_input_flows():
    policy = load_contracts()
    contract = policy["classes"]["coding_agent"]

    assert "credential_input" in contract["expected"]
    assert "credential_input" not in contract["forbidden"]


def test_functional_language_description_outranks_incidental_icon_theme_surface():
    extension = SimpleNamespace(
        name="A-LSP",
        description="Official language development kit with syntax highlighting and static type checking.",
        capabilities=[
            {"id": "theme_surface"},
            {"id": "native_code"},
            {"id": "process_execution"},
        ],
    )

    classification = classify_extension(extension)

    assert classification["primary"] == "language_tool"
    assert "text:syntax highlighting" in classification["signals"]


def test_cloud_developer_tools_do_not_inherit_theme_forbidden_capabilities():
    extension = SimpleNamespace(
        name="Azure Runbooks Workbench",
        description="Cloud automation and DevOps runbook development experience.",
        capabilities=[
            {"id": "theme_surface"},
            {"id": "network"},
            {"id": "process_execution"},
            {"id": "credential_input"},
        ],
    )

    classification = classify_extension(extension)

    assert classification["primary"] == "cloud_developer_tool"
