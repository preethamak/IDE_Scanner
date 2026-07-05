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
