"""Prediction data models and standardized output containers for Phase 3.

Defines typed structures for individual flow predictions, prediction summaries,
and capture-level combined results adhering to the Phase 3 schema contract.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from typing import Any, Dict, List, Optional

from person2_engine.src.flow_models import CaptureFeaturesResult


@dataclass
class Prediction:
    """Class prediction, confidence, and class probability distribution."""

    label: str
    class_index: int
    confidence: float
    probabilities: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert prediction to dictionary."""
        return {
            "label": self.label,
            "class_index": self.class_index,
            "confidence": round(self.confidence, 4),
            "probabilities": {k: round(v, 4) for k, v in self.probabilities.items()},
        }


@dataclass
class FlowPredictionResult:
    """Standardized prediction outcome for an individual flow."""

    model_status: str
    model_info: Optional[Dict[str, Any]] = None
    prediction: Optional[Prediction] = None
    reason: Optional[str] = None
    compatibility_errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    domain_status: Dict[str, Any] = field(default_factory=lambda: {"ipsec_validation": "unverified"})
    feature_importance: Dict[str, float] = field(default_factory=dict)

    @property
    def status(self) -> str:
        """Alias for model_status string/enum."""
        return self.model_status

    def to_dict(self) -> Dict[str, Any]:
        """Convert flow prediction result to dictionary."""
        return {
            "model_status": self.model_status,
            "model_info": self.model_info,
            "prediction": self.prediction.to_dict() if self.prediction else None,
            "reason": self.reason,
            "compatibility_errors": self.compatibility_errors,
            "warnings": self.warnings,
            "domain_status": self.domain_status,
            "feature_importance": self.feature_importance,
        }



@dataclass
class PredictionSummary:
    """Aggregate statistics of prediction outcomes across flows in a capture."""

    total_flows: int = 0
    predictions_successful: int = 0
    model_unavailable: int = 0
    incompatible: int = 0
    domain_unverified: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert prediction summary to dictionary."""
        return asdict(self)


@dataclass
class CapturePredictionResult:
    """Top-level capture result uniting Phase 1, Phase 2, and Phase 3 intelligence."""

    capture_features: CaptureFeaturesResult
    prediction_summary: PredictionSummary
    predictions: List[FlowPredictionResult]

    @property
    def summary(self) -> PredictionSummary:
        """Alias for prediction_summary."""
        return self.prediction_summary

    def to_dict(self) -> Dict[str, Any]:
        """Serialize complete capture analysis and prediction data to a dictionary."""
        base_dict = self.capture_features.to_dict()

        # Augment each flow with its prediction record
        enriched_flows: List[Dict[str, Any]] = []
        for flow_dict, pred_res in zip(base_dict.get("flows", []), self.predictions):
            f_copy = dict(flow_dict)
            f_copy["prediction"] = pred_res.to_dict()
            enriched_flows.append(f_copy)

        base_dict["flows"] = enriched_flows
        base_dict["prediction_summary"] = self.prediction_summary.to_dict()
        return base_dict

    def to_json(self, indent: int = 2) -> str:
        """Serialize complete capture prediction results to formatted JSON."""
        return json.dumps(self.to_dict(), indent=indent)
