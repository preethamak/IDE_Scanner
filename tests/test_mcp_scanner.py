import asyncio

from ide_scanner.mcp import scan_mcp_payload
from ide_scanner.mcp.extractors.auth_modes import AuthModesResult
from ide_scanner.mcp.extractors.classification import ClassificationResult
from ide_scanner.mcp.extractors.fingerprint import FingerprintResult, TransportLevelEnum
from ide_scanner.mcp.extractors.tool_analysis import ToolAnalysisResult, ToolPoisoningFinding, ToolPoisoningCategory
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

