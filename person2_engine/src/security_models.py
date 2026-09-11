"""Data models and standardized containers for Phase 4 AI Security Assessment.

Defines typed structures for flow-level and capture-level security assessments,
behavioral profiles, risk indicators, score contributions, and JSON integration output
for Person 3's dashboard, reports, and scoring system.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
import json
from pathlib import Path
from typing import Any, Dict, List, Optional


class ConfidenceLevel(str, Enum):
    """Qualitative assessment of classification prediction confidence."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class RiskLevel(str, Enum):
    """Categorical risk tiers based on transparent behavioral indicator scores."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Threshold constants (configurable)
CONFIDENCE_HIGH_THRESHOLD: float = 0.80
CONFIDENCE_MEDIUM_THRESHOLD: float = 0.50

RISK_MEDIUM_THRESHOLD: int = 25
RISK_HIGH_THRESHOLD: int = 50
RISK_CRITICAL_THRESHOLD: int = 75

SECURITY_SCHEMA_VERSION: str = "1.0"


def determine_confidence_level(confidence: float) -> str:
    """Map numerical prediction confidence into a qualitative confidence level.

    Args:
        confidence: Confidence probability [0.0, 1.0].

    Returns:
        String matching ConfidenceLevel enum ('HIGH', 'MEDIUM', 'LOW').
    """
    if confidence >= CONFIDENCE_HIGH_THRESHOLD:
        return ConfidenceLevel.HIGH.value
    elif confidence >= CONFIDENCE_MEDIUM_THRESHOLD:
        return ConfidenceLevel.MEDIUM.value
    else:
        return ConfidenceLevel.LOW.value


def determine_risk_level(score: int) -> str:
    """Map a numerical risk score (0-100) into a qualitative risk tier.

    Args:
        score: Clamped risk score between 0 and 100.

    Returns:
        String matching RiskLevel enum ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL').
    """
    if score >= RISK_CRITICAL_THRESHOLD:
        return RiskLevel.CRITICAL.value
    elif score >= RISK_HIGH_THRESHOLD:
        return RiskLevel.HIGH.value
    elif score >= RISK_MEDIUM_THRESHOLD:
        return RiskLevel.MEDIUM.value
    else:
        return RiskLevel.LOW.value


@dataclass
class ScoreContribution:
    """Traceable point contribution from an individual indicator to the risk score."""

    indicator: str
    points: int
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert score contribution to dictionary."""
        return {
            "indicator": self.indicator,
            "points": int(self.points),
            "reason": self.reason,
        }


@dataclass
class RiskScore:
    """Transparent numerical risk assessment composed of distinct indicator points."""

    total_score: int
    risk_level: str
    contributions: List[ScoreContribution] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert risk score to dictionary."""
        return {
            "total_score": int(self.total_score),
            "risk_level": self.risk_level,
            "contributions": [c.to_dict() for c in self.contributions],
        }


@dataclass
class SecurityIndicator:
    """Explainable behavioral security indicator triggering risk attribution."""

    indicator_id: str
    severity: str  # "LOW", "MEDIUM", "HIGH"
    reason: str
    supporting_features: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert security indicator to dictionary."""
        clean_features = {}
        for k, v in self.supporting_features.items():
            if isinstance(v, float):
                clean_features[k] = round(v, 4)
            else:
                clean_features[k] = v

        return {
            "indicator_id": self.indicator_id,
            "severity": self.severity,
            "reason": self.reason,
            "supporting_features": clean_features,
        }


@dataclass
class BehaviorProfile:
    """Descriptive behavioral characteristics extracted from 25 Phase 2 features."""

    traffic_pattern: str
    observations: List[str] = field(default_factory=list)
    metrics_summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert behavior profile to dictionary."""
        clean_metrics = {}
        for k, v in self.metrics_summary.items():
            if isinstance(v, float):
                clean_metrics[k] = round(v, 4)
            else:
                clean_metrics[k] = v

        return {
            "traffic_pattern": self.traffic_pattern,
            "observations": list(self.observations),
            "metrics_summary": clean_metrics,
        }


@dataclass
class FlowSecurityResult:
    """Standardized security assessment outcome for an individual flow."""

    flow_id: str
    endpoints: str
    protocol: str
    prediction: Dict[str, Any]
    behavior: BehaviorProfile
    security_assessment: Dict[str, Any]
    explainability: Dict[str, Any]
    model_uncertainty: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert flow security result to dictionary."""
        return {
            "flow_id": self.flow_id,
            "endpoints": self.endpoints,
            "protocol": self.protocol,
            "prediction": self.prediction,
            "model_uncertainty": self.model_uncertainty,
            "behavior": self.behavior.to_dict(),
            "security_assessment": self.security_assessment,
            "explainability": self.explainability,
        }


@dataclass
class CaptureSecuritySummary:
    """Aggregate security and traffic metrics for an entire capture."""

    total_flows: int = 0
    risk_distribution: Dict[str, int] = field(
        default_factory=lambda: {
            "LOW": 0,
            "MEDIUM": 0,
            "HIGH": 0,
            "CRITICAL": 0,
        }
    )
    traffic_distribution: Dict[str, int] = field(default_factory=dict)
    average_confidence: float = 0.0
    overall_risk_score: int = 0
    overall_risk_level: str = "LOW"
    top_indicators: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert capture summary to dictionary."""
        return {
            "total_flows": int(self.total_flows),
            "risk_distribution": {k: int(v) for k, v in self.risk_distribution.items()},
            "traffic_distribution": {k: int(v) for k, v in self.traffic_distribution.items()},
            "average_confidence": round(float(self.average_confidence), 4),
            "overall_risk_score": int(self.overall_risk_score),
            "overall_risk_level": self.overall_risk_level,
            "top_indicators": self.top_indicators,
        }


@dataclass
class CaptureSecurityResult:
    """Top-level capture outcome uniting Phase 1, Phase 2, Phase 3, and Phase 4."""

    analysis_metadata: Dict[str, Any]
    model_information: Dict[str, Any]
    capture_summary: CaptureSecuritySummary
    flows: List[FlowSecurityResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize complete security assessment to dictionary."""
        return {
            "schema_version": SECURITY_SCHEMA_VERSION,
            "analysis_metadata": self.analysis_metadata,
            "model_information": self.model_information,
            "capture_summary": self.capture_summary.to_dict(),
            "flows": [f.to_dict() for f in self.flows],
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize complete security assessment to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def to_json_file(self, path: str | Path, indent: int = 2) -> None:
        """Save formatted JSON representation to file."""
        p = Path(path).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(self.to_json(indent=indent))
