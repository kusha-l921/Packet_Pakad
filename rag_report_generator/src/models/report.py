"""Structured Report JSON schema models."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ReportMetadata:
    """Metadata describing the report generation environment and provenance."""
    report_id: str
    generated_at: str
    report_schema_version: str = "1.0"
    input_schema_version: str = "1.0"
    rag_knowledge_base_version: str = "1.0"
    llm_provider: str = "mock"
    llm_model: str = "mock-deterministic"

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "generated_at": self.generated_at,
            "report_schema_version": self.report_schema_version,
            "input_schema_version": self.input_schema_version,
            "rag_knowledge_base_version": self.rag_knowledge_base_version,
            "llm_provider": self.llm_provider,
            "llm_model": self.llm_model,
        }


@dataclass
class CaptureOverviewReport:
    """Capture overview section of the report."""
    packet_count: int
    flow_count: int
    duration_seconds: float
    total_bytes: int
    summary_text: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "packet_count": self.packet_count,
            "flow_count": self.flow_count,
            "duration_seconds": self.duration_seconds,
            "total_bytes": self.total_bytes,
            "summary_text": self.summary_text,
        }


@dataclass
class IPsecReport:
    """IPsec and encryption analysis section."""
    detected: bool
    esp_detected: bool
    ah_detected: bool
    ike_detected: bool
    nat_t_detected: bool
    domain_validation_status: str
    explanation: str
    evidence_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "detected": self.detected,
            "esp_detected": self.esp_detected,
            "ah_detected": self.ah_detected,
            "ike_detected": self.ike_detected,
            "nat_t_detected": self.nat_t_detected,
            "domain_validation_status": self.domain_validation_status,
            "explanation": self.explanation,
            "evidence_ids": list(self.evidence_ids),
        }


@dataclass
class ClassificationReport:
    """Traffic-category resemblance classification section."""
    predicted_category: str
    confidence: float
    probabilities: dict[str, float]
    resemblance_explanation: str
    evidence_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "predicted_category": self.predicted_category,
            "confidence": self.confidence,
            "probabilities": self.probabilities,
            "resemblance_explanation": self.resemblance_explanation,
            "evidence_ids": list(self.evidence_ids),
        }


@dataclass
class BehavioralReport:
    """Behavioral risk evaluation section."""
    risk_score: int
    risk_level: str
    triggered_indicators: list[str]
    explanation: str
    non_malice_disclaimer: str
    evidence_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "triggered_indicators": list(self.triggered_indicators),
            "explanation": self.explanation,
            "non_malice_disclaimer": self.non_malice_disclaimer,
            "evidence_ids": list(self.evidence_ids),
        }


@dataclass
class FlowFindingReport:
    """Individual notable flow observation summary."""
    flow_id: str
    description: str
    risk_score: int
    indicators: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "description": self.description,
            "risk_score": self.risk_score,
            "indicators": list(self.indicators),
        }


@dataclass
class UncertaintyReport:
    """Model uncertainty quantification section."""
    uncertainty_level: str
    explanation: str
    risk_separation_statement: str
    evidence_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "uncertainty_level": self.uncertainty_level,
            "explanation": self.explanation,
            "risk_separation_statement": self.risk_separation_statement,
            "evidence_ids": list(self.evidence_ids),
        }


@dataclass
class LimitationItem:
    """Specific technical boundary or evaluation caveat."""
    topic: str
    statement: str
    evidence_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "topic": self.topic,
            "statement": self.statement,
            "evidence_ids": list(self.evidence_ids),
        }


@dataclass
class EvidenceCitation:
    """Reference item for an explanatory knowledge piece cited in the report."""
    evidence_id: str
    title: str
    source: str
    section: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "title": self.title,
            "source": self.source,
            "section": self.section,
        }


@dataclass
class Report:
    """Root structured report model."""
    report_metadata: ReportMetadata
    executive_summary: str
    capture_overview: CaptureOverviewReport
    ipsec_analysis: IPsecReport
    traffic_classification: ClassificationReport
    behavioral_analysis: BehavioralReport
    flow_findings: list[FlowFindingReport]
    model_uncertainty: UncertaintyReport
    limitations: list[LimitationItem]
    technical_evidence: list[EvidenceCitation]
    review_areas: list[str]
    conclusion: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_metadata": self.report_metadata.to_dict(),
            "executive_summary": self.executive_summary,
            "capture_overview": self.capture_overview.to_dict(),
            "ipsec_analysis": self.ipsec_analysis.to_dict(),
            "traffic_classification": self.traffic_classification.to_dict(),
            "behavioral_analysis": self.behavioral_analysis.to_dict(),
            "flow_findings": [f.to_dict() for f in self.flow_findings],
            "model_uncertainty": self.model_uncertainty.to_dict(),
            "limitations": [l.to_dict() for l in self.limitations],
            "technical_evidence": [e.to_dict() for e in self.technical_evidence],
            "review_areas": list(self.review_areas),
            "conclusion": self.conclusion,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Report":
        meta = ReportMetadata(**data["report_metadata"])
        cap = CaptureOverviewReport(**data["capture_overview"])
        ipsec = IPsecReport(**data["ipsec_analysis"])
        cls_rep = ClassificationReport(**data["traffic_classification"])
        beh = BehavioralReport(**data["behavioral_analysis"])
        flows = [FlowFindingReport(**f) for f in data.get("flow_findings", [])]
        unc = UncertaintyReport(**data["model_uncertainty"])
        lims = [LimitationItem(**l) for l in data.get("limitations", [])]
        ev_items = [EvidenceCitation(**e) for e in data.get("technical_evidence", [])]
        return cls(
            report_metadata=meta,
            executive_summary=data["executive_summary"],
            capture_overview=cap,
            ipsec_analysis=ipsec,
            traffic_classification=cls_rep,
            behavioral_analysis=beh,
            flow_findings=flows,
            model_uncertainty=unc,
            limitations=lims,
            technical_evidence=ev_items,
            review_areas=data.get("review_areas", []),
            conclusion=data["conclusion"],
        )
