from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Severity = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
Verdict = Literal["clean", "review", "suspicious", "malicious"]
Status = Literal["success", "warning", "failure", "skipped"]


@dataclass
class Finding:
    finding_id: str
    extension_id: str
    version: str
    rule_id: str
    category: str
    severity: Severity
    confidence: float
    score: int
    evidence_type: str
    evidence_summary: str
    file_refs: list[str] = field(default_factory=list)
    recommendation: str = ""
    evidence: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if data["evidence"] is None:
            data.pop("evidence")
        return data


@dataclass
class Recommendation:
    priority: Literal["low", "medium", "high", "critical"]
    title: str
    description: str
    action: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ExtensionReport:
    instance_id: str
    extension_id: str
    name: str
    publisher: str
    version: str
    description: str
    repository: str
    install_path: str
    source: str
    artifact_hash: str
    severity: Severity
    verdict: Verdict
    malware_authority: str
    verdict_reason: str
    malware_score: int
    risk_score: int
    score_details: dict[str, Any]
    capabilities: list[dict[str, Any]]
    artifact_inventory: dict[str, Any]
    findings: list[Finding]
    scanned_files: int
    dependencies: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["artifact_inventory"] = dict(self.artifact_inventory)
        data["artifact_inventory"].pop("_all_file_hashes", None)
        data["findings"] = [finding.to_dict() for finding in self.findings]
        return data


@dataclass
class ReportMetadata:
    schema_version: str
    scan_id: str
    created_at: str
    scanner_version: str
    ruleset_version: str
    profile: str
    source: str
    total_extensions: int
    completed_extensions: int
    incomplete_extensions: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ExtensionSummary:
    extension_id: str
    name: str
    publisher: str
    version: str
    source: str
    verdict: Verdict
    severity: Severity
    risk_score: int
    malware_score: int
    grade: str
    top_findings: list[str]
    finding_count: int
    dependency_count: int
    activation_summary: str
    detail_ref: str
    icon_ref: str = ""
    from_cache: bool = False
    scan_incomplete: bool = False
    skipped_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ExtensionDetail:
    extension_id: str
    name: str
    publisher: str
    version: str
    description: str
    repository: str
    source: str
    verdict: Verdict
    severity: Severity
    risk_score: int
    malware_score: int
    grade: str
    score_details: dict[str, Any]
    score_explanation: list[str]
    verdict_reason: str
    recommendations: list[Recommendation]
    findings: list[dict[str, Any]]
    evidence: dict[str, Any]
    manifest: dict[str, Any]
    dependencies: dict[str, str]
    artifact_inventory: dict[str, Any]
    capabilities: dict[str, Any]
    from_cache: bool = False
    scan_incomplete: bool = False
    skipped_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["recommendations"] = [item.to_dict() if isinstance(item, Recommendation) else item for item in self.recommendations]
        return data


@dataclass
class RuleMetadata:
    rule_id: str
    title: str
    category: str
    evidence_class: str
    default_severity: Severity
    description: str
    recommendation: str
    false_positive_notes: str = ""
    benchmark_tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReportBundleManifest:
    metadata: ReportMetadata
    summary_ref: str = "summary.json"
    leaderboard_ref: str = "leaderboard.json"
    posture_ref: str = "posture.json"
    rules_ref: str = "rules.json"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["metadata"] = self.metadata.to_dict()
        return data


@dataclass
class BenchmarkBundle:
    metadata: dict[str, Any]
    leaderboard: dict[str, Any]
    benchmark_summary: dict[str, Any]
    rule_coverage: dict[str, Any]
    comparisons: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PostureMetric:
    id: str
    status: Status
    reason: str
    evidence: dict[str, Any] = field(default_factory=dict)
    client: str = "system"
    category: str = "posture"
    score: int = 0
    weight: float = 1.0
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
