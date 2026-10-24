import asyncio

from ide_scanner.mcp import scan_mcp_payload
from ide_scanner.mcp.extractors.auth_modes import AuthModesResult
from ide_scanner.mcp.extractors.classification import ClassificationResult
from ide_scanner.mcp.extractors.fingerprint import FingerprintResult, TransportLevelEnum
from ide_scanner.mcp.extractors.tool_analysis import (
    ToolAnalysisResult,
    ToolPoisoningFinding,
    ToolPoisoningCategory,
    _coerce_tool_model,
    _tool_declaration_evidence,
)
from ide_scanner.mcp.runners.auth_strength import AuthStrengthRunner
from ide_scanner.mcp.runners.hosting_operator_class import HostingOperatorClassRunner
from ide_scanner.mcp.runners.metadata_security import MetadataSecurityRunner
from ide_scanner.mcp.runners.transport_security import TransportSecurityRunner
from ide_scanner.mcp.types import AuthModeEnum, OfficialityEnum, VetoLevelEnum


def _leaf_reports(report):
    def walk(node):
        children = node.get("children") or []
        if not children:
            return [node]
        return [item for child in children for item in walk(child)]

    return walk(report["metrics"])


def test_mcp_metric_contract_has_twelve_weighted_leaves():
    report = scan_mcp_payload({"name": "local-server", "transport": "stdio", "tools": []})
    leaves = _leaf_reports(report)
    assert len(leaves) == 12
    assert {item["name"] for item in leaves} >= {"auth-strength", "metadata-security", "secrets-risk"}
    assert report["schema_version"] == "guardrails.mcp-risk-report.v1"
    assert report["scanner"]["mode"] == "full"


def test_reference_auth_and_hosting_scores_are_preserved():
    auth = AuthModesResult(modes=[AuthModeEnum.OAUTH], summary="oauth only", is_local=False)
    auth_output = asyncio.run(AuthStrengthRunner().run(auth, {}))
    assert auth_output.score == 0.0
    assert auth_output.veto is None

    classification = ClassificationResult(
        officiality=OfficialityEnum.OFFICIAL,
        is_local=False,
        has_repo=True,
        message="official",
    )
    hosting_output = asyncio.run(HostingOperatorClassRunner().run(classification, {}))
    assert hosting_output.score == 0.0
    assert hosting_output.veto is None


def test_reference_transport_and_metadata_vetoes_are_preserved():
    fingerprint = FingerprintResult(
        mcp_url="http://server.invalid/mcp",
        is_local=False,
        transport_level=TransportLevelEnum.HTTP_ONLY,
        probe_error="no https",
    )
    transport_output = asyncio.run(TransportSecurityRunner().run(fingerprint, {}))
    assert transport_output.score == 1.0
    assert transport_output.veto == VetoLevelEnum.FAILURE

    finding = ToolPoisoningFinding.model_construct(
        finding_id="T1-POISON-01-001",
        tool_name="sync",
        category=ToolPoisoningCategory.HIDDEN_DIRECTIVE,
        location="description",
        evidence="hidden instruction",
        explanation="metadata poisoning",
    )
    tool_analysis = ToolAnalysisResult.model_construct(tools=[object()], tier1_findings=[finding], tier2_findings=[], tool_tags=[])
    metadata_output = asyncio.run(MetadataSecurityRunner().run(tool_analysis, {}))
    assert metadata_output.score == 1.0
    assert metadata_output.veto == VetoLevelEnum.FAILURE


def test_tool_declarations_are_preserved_without_becoming_a_verdict():
    tool = _coerce_tool_model({
        "name": "lookup",
        "title": "Lookup customer",
        "description": "Fetches a customer record.",
        "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}},
        "outputSchema": {"type": "object", "properties": {"email": {"type": "string"}}},
        "annotations": {"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False},
    })

    evidence = _tool_declaration_evidence(tool)

    assert evidence.title == "Lookup customer"
    assert evidence.annotations is not None
    assert evidence.annotations.readOnlyHint is True
    assert evidence.output_schema == {"type": "object", "properties": {"email": {"type": "string"}}}
    assert evidence.sha256 is not None
    assert len(evidence.sha256) == 64
    assert evidence.issues == []


def test_conflicting_mcp_safety_hints_are_disclosed_as_declaration_evidence():
    tool = _coerce_tool_model({
        "name": "delete_all",
        "description": "Deletes records.",
        "inputSchema": {"type": "object"},
        "annotations": {"readOnlyHint": True, "destructiveHint": True},
    })

    evidence = _tool_declaration_evidence(tool)

    assert [issue.code for issue in evidence.issues] == ["conflicting-safety-hints"]


def test_tool_declaration_fingerprint_is_order_independent_and_detects_interface_drift():
    base = {
        "name": "lookup",
        "description": "Fetches a customer record.",
        "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}, "region": {"type": "string"}}},
        "annotations": {"readOnlyHint": True, "idempotentHint": True},
    }
    reordered = {
        "annotations": {"idempotentHint": True, "readOnlyHint": True},
        "inputSchema": {"properties": {"region": {"type": "string"}, "id": {"type": "string"}}, "type": "object"},
        "description": "Fetches a customer record.",
        "name": "lookup",
    }
    changed = {**base, "inputSchema": {"type": "object", "properties": {"id": {"type": "integer"}}}}

    base_fingerprint = _tool_declaration_evidence(_coerce_tool_model(base)).sha256
    reordered_fingerprint = _tool_declaration_evidence(_coerce_tool_model(reordered)).sha256
    changed_fingerprint = _tool_declaration_evidence(_coerce_tool_model(changed)).sha256

    assert base_fingerprint == reordered_fingerprint
    assert base_fingerprint != changed_fingerprint
