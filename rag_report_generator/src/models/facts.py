"""Authoritative facts model extracted from Phase 5 Unified JSON."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CaptureFacts:
    """Authoritative capture-level network metrics."""
    packet_count: int
    flow_count: int
    duration_seconds: float
    total_bytes: int
    protocols: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "packet_count": self.packet_count,
            "flow_count": self.flow_count,
            "duration_seconds": self.duration_seconds,
            "total_bytes": self.total_bytes,
            "protocols": self.protocols,
        }


@dataclass
class IPsecFacts:
    """Authoritative IPsec protocol observations and domain validation state."""
    detected: bool
    esp_detected: bool
    ah_detected: bool
    ike_detected: bool
    nat_t_detected: bool
    domain_validation_status: str
    allow_unverified_domain: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "detected": self.detected,
            "esp_detected": self.esp_detected,
            "ah_detected": self.ah_detected,
            "ike_detected": self.ike_detected,
            "nat_t_detected": self.nat_t_detected,
            "domain_validation_status": self.domain_validation_status,
            "allow_unverified_domain": self.allow_unverified_domain,
        }


@dataclass
class ClassificationFacts:
    """Authoritative ML traffic-category resemblance observations."""
    predicted_category: str
    confidence: float
    confidence_tier: str  # HIGH, MEDIUM, LOW
    category_probabilities: dict[str, float] = field(default_factory=dict)
    prediction_status: str = "COMPLETED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "predicted_category": self.predicted_category,
            "confidence": self.confidence,
            "confidence_tier": self.confidence_tier,
            "category_probabilities": self.category_probabilities,
            "prediction_status": self.prediction_status,
        }


@dataclass
class BehavioralFacts:
    """Authoritative Phase 4 deterministic risk scoring and indicator observations."""
    risk_score: int  # 0 - 100
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    triggered_indicators: list[str] = field(default_factory=list)
    indicator_points: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "triggered_indicators": list(self.triggered_indicators),
            "indicator_points": self.indicator_points,
        }


@dataclass
class UncertaintyFacts:
    """Authoritative model uncertainty observations."""
    level: str  # HIGH, MEDIUM, LOW
    entropy: float | None = None
    margin: float | None = None
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "entropy": self.entropy,
            "margin": self.margin,
            "reason": self.reason,
        }


@dataclass
class EvaluationFacts:
    """Authoritative dataset evaluation mode and audit context."""
    evaluation_mode: str  # GROUP_ISOLATED, WITHIN_CAPTURE_HOLDOUT, OVERALL_MIXED_EVALUATION
    dataset_provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evaluation_mode": self.evaluation_mode,
            "dataset_provenance": self.dataset_provenance,
        }


@dataclass
class FlowFact:
    """Notable individual flow observation."""
    flow_id: str
    five_tuple: dict[str, Any]
    packets: int
    bytes: int
    duration_seconds: float
    risk_score: int
    indicators: list[str] = field(default_factory=list)
    features: dict[str, Any] = field(default_factory=dict)
    is_ipsec: bool = False
    predicted_category: str | None = None
    protocol: str = ""
    endpoints: dict[str, str] = field(default_factory=dict)
    confidence: float | None = None
    prediction_status: str | None = None
    probabilities: dict[str, float] = field(default_factory=dict)
    uncertainty_present: bool = False
    uncertainty_flags: list[Any] = field(default_factory=list)
    risk_level: str = "LOW"
    explainability_summary: str | None = None
    summary: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "five_tuple": self.five_tuple,
            "protocol": self.protocol,
            "endpoints": self.endpoints,
            "packets": self.packets,
            "bytes": self.bytes,
            "duration_seconds": self.duration_seconds,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "indicators": list(self.indicators),
            "features": self.features,
            "is_ipsec": self.is_ipsec,
            "predicted_category": self.predicted_category,
            "confidence": self.confidence,
            "prediction_status": self.prediction_status,
            "probabilities": self.probabilities,
            "uncertainty_present": self.uncertainty_present,
            "uncertainty_flags": self.uncertainty_flags,
            "explainability_summary": self.explainability_summary,
            "summary": self.summary,
        }


@dataclass
class AnalysisFacts:
    """Root container of authoritative analysis facts extracted from Phase 5 JSON."""
    capture: CaptureFacts
    ipsec: IPsecFacts
    classification: ClassificationFacts
    behavioral: BehavioralFacts
    model_uncertainty: UncertaintyFacts
    evaluation: EvaluationFacts
    selected_flows: list[FlowFact] = field(default_factory=list)
    raw_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "capture": self.capture.to_dict(),
            "ipsec": self.ipsec.to_dict(),
            "classification": self.classification.to_dict(),
            "behavioral": self.behavioral.to_dict(),
            "model_uncertainty": self.model_uncertainty.to_dict(),
            "evaluation": self.evaluation.to_dict(),
            "selected_flows": [f.to_dict() for f in self.selected_flows],
            "raw_metadata": self.raw_metadata,
        }
