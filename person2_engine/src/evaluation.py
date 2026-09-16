"""Evaluation and domain verification scaffold for Person 1 StrongSwan labeled captures.

Provides clean interfaces to evaluate verified models against labeled testbed
data without performing fake evaluations or requiring data prior to availability.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from person2_engine.src.prediction_models import CapturePredictionResult

logger = logging.getLogger(__name__)


@dataclass
class ScenarioManifest:
    """Ground truth metadata manifest provided by Person 1 for a StrongSwan testbed capture."""

    scenario_id: str
    ground_truth_label: str
    application_details: str = ""
    ipsec_mode: str = "tunnel"  # "tunnel" or "transport"
    ipsec_protocol: str = "ESP"  # "ESP" or "AH"
    ike_version: Optional[str] = "IKEv2"
    cipher_suite: str = ""
    initiator_endpoint: Optional[str] = None
    responder_endpoint: Optional[str] = None
    start_timestamp: Optional[float] = None
    end_timestamp: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert manifest to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ScenarioManifest:
        """Instantiate from dictionary."""
        return cls(
            scenario_id=str(data.get("scenario_id", "unknown_scenario")),
            ground_truth_label=str(data.get("ground_truth_label", "")).lower(),
            application_details=str(data.get("application_details", "")),
            ipsec_mode=str(data.get("ipsec_mode", "tunnel")),
            ipsec_protocol=str(data.get("ipsec_protocol", "ESP")),
            ike_version=data.get("ike_version"),
            cipher_suite=str(data.get("cipher_suite", "")),
            initiator_endpoint=data.get("initiator_endpoint"),
            responder_endpoint=data.get("responder_endpoint"),
            start_timestamp=data.get("start_timestamp"),
            end_timestamp=data.get("end_timestamp"),
            metadata=dict(data.get("metadata", {})),
        )

    @classmethod
    def from_file(cls, path: str | Path) -> ScenarioManifest:
        """Load manifest from JSON file."""
        content = Path(path).read_text(encoding="utf-8")
        return cls.from_dict(json.loads(content))


@dataclass
class EvaluationReport:
    """Outcome of evaluating a model against a labeled capture."""

    scenario_id: str
    ground_truth_label: str
    model_id: str
    total_flows: int
    evaluated_flows: int
    correct_predictions: int
    accuracy: float
    confusion: Dict[str, int]
    flow_predictions: List[Dict[str, Any]]
    evaluation_possible: bool = True
    reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert evaluation report to dictionary."""
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        """Serialize report to JSON."""
        return json.dumps(self.to_dict(), indent=indent)


def evaluate_capture_predictions(
    prediction_result: CapturePredictionResult,
    manifest: ScenarioManifest,
) -> EvaluationReport:
    """Evaluate capture-level model predictions against Person 1's ground truth manifest.

    Args:
        prediction_result: CapturePredictionResult from analyze_capture_with_predictions().
        manifest: ScenarioManifest providing ground truth label.

    Returns:
        Populated EvaluationReport.
    """
    total_flows = len(prediction_result.predictions)
    expected_label = manifest.ground_truth_label.lower().strip()

    evaluated_flows = 0
    correct = 0
    confusion: Dict[str, int] = {}
    flow_preds: List[Dict[str, Any]] = []

    model_id = "unknown"

    for i, pred_res in enumerate(prediction_result.predictions, 1):
        if pred_res.model_info:
            model_id = pred_res.model_info.get("model_id", model_id)

        if pred_res.prediction is None:
            flow_preds.append({
                "flow_index": i,
                "predicted": None,
                "expected": expected_label,
                "match": False,
                "status": pred_res.model_status,
            })
            continue

        predicted_label = pred_res.prediction.label.lower().strip()
        evaluated_flows += 1
        is_match = predicted_label == expected_label

        if is_match:
            correct += 1

        confusion[predicted_label] = confusion.get(predicted_label, 0) + 1

        flow_preds.append({
            "flow_index": i,
            "predicted": predicted_label,
            "expected": expected_label,
            "match": is_match,
            "confidence": pred_res.prediction.confidence,
        })

    if evaluated_flows == 0:
        return EvaluationReport(
            scenario_id=manifest.scenario_id,
            ground_truth_label=expected_label,
            model_id=model_id,
            total_flows=total_flows,
            evaluated_flows=0,
            correct_predictions=0,
            accuracy=0.0,
            confusion=confusion,
            flow_predictions=flow_preds,
            evaluation_possible=False,
            reason="No flows had successful predictions (model unavailable or incompatible).",
        )

    acc = round(float(correct) / evaluated_flows, 4)

    return EvaluationReport(
        scenario_id=manifest.scenario_id,
        ground_truth_label=expected_label,
        model_id=model_id,
        total_flows=total_flows,
        evaluated_flows=evaluated_flows,
        correct_predictions=correct,
        accuracy=acc,
        confusion=confusion,
        flow_predictions=flow_preds,
        evaluation_possible=True,
    )
