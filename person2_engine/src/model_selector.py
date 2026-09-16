"""Model selector and persistence manager for Phase 3 lightweight ML models.

Compares candidate evaluation reports, selects the best model using Macro F1 and latency,
and persists trained weights (.joblib) and standardized metadata (.json) to disk.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import joblib

from person2_engine.src.feature_schema import FEATURE_ORDER, FEATURE_SCHEMA_VERSION
from person2_engine.src.model_evaluator import ModelEvaluationReport
from person2_engine.src.model_metadata import (
    IPsecCompatibilityLevel,
    InputType,
    ModelMetadata,
    PredictionTask,
)
from person2_engine.src.model_trainer import CandidateTrainingResult

logger = logging.getLogger(__name__)


def compare_candidates(
    evaluations: Dict[str, ModelEvaluationReport],
) -> str:
    """Format a side-by-side comparison table of all evaluated candidate models.

    Args:
        evaluations: Mapping from candidate key to ModelEvaluationReport.

    Returns:
        Formatted multi-line text table.
    """
    lines = [
        "=" * 85,
        "   PHASE 3: CANDIDATE MODEL COMPARISON SUMMARY",
        "=" * 85,
        f"{'Model Key':<22} {'Accuracy':<10} {'Macro F1':<10} {'Weighted F1':<13} {'Train (s)':<11} {'Latency (ms)':<12}",
        "-" * 85,
    ]

    for key, rep in evaluations.items():
        lines.append(
            f"{key:<22} {rep.accuracy:<10.4f} {rep.f1_macro:<10.4f} {rep.f1_weighted:<13.4f} "
            f"{rep.training_time_seconds:<11.3f} {rep.inference_latency_ms:<12.3f}"
        )

    lines.append("=" * 85)
    return "\n".join(lines)


def select_best_candidate(
    evaluations: Dict[str, ModelEvaluationReport],
) -> str:
    """Select the best candidate model primarily by Macro F1 and secondarily by inference latency.

    Args:
        evaluations: Mapping from candidate key to ModelEvaluationReport.

    Returns:
        Key of the optimal candidate model.

    Raises:
        ValueError: If evaluations dictionary is empty.
    """
    if not evaluations:
        raise ValueError("Cannot select best model from empty evaluations dictionary.")

    # Sort candidates by:
    # 1. Macro F1 descending
    # 2. Inference latency ascending (lower is faster)
    ranked = sorted(
        evaluations.items(),
        key=lambda item: (item[1].f1_macro, -item[1].inference_latency_ms),
        reverse=True,
    )

    winner_key, winner_rep = ranked[0]
    logger.info(
        "Selected best model: '%s' (Macro F1: %.4f, Accuracy: %.4f, Latency: %.3fms)",
        winner_key,
        winner_rep.f1_macro,
        winner_rep.accuracy,
        winner_rep.inference_latency_ms,
    )
    return winner_key


def save_trained_model_and_metadata(
    candidate: CandidateTrainingResult,
    evaluation: ModelEvaluationReport,
    output_dir: Optional[Path] = None,
    model_id: Optional[str] = None,
    dataset_name: str = "benchmark_encrypted_flows",
    traffic_type: str = "encrypted_application_flows",
    is_ipsec_dataset: bool = False,
) -> Tuple[Path, Path]:
    """Persist trained model weights and JSON contract metadata to disk.

    Saves:
    1. <model_id>.joblib in models/trained/ (containing estimator, scaler, classes).
    2. <model_id>.json in models/metadata/ (conforming strictly to Phase 3 ModelMetadata).
    3. Mirror into models/registry/<model_id>/ for seamless ModelRegistry discovery.

    Args:
        candidate: CandidateTrainingResult instance.
        evaluation: ModelEvaluationReport instance.
        output_dir: Base project directory (defaults to repo root).
        model_id: Optional custom model ID (defaults to <model_name>_v1).
        dataset_name: Source dataset name.
        traffic_type: Type of network traffic trained on.
        is_ipsec_dataset: Whether dataset contains real IPsec traffic.

    Returns:
        Tuple of (model_artifact_path, metadata_file_path).
    """
    base = output_dir or Path(__file__).parent.parent.parent
    mid = model_id or f"{candidate.model_name}_traffic_classifier_v1"

    trained_dir = base / "models" / "trained"
    meta_dir = base / "models" / "metadata"
    registry_dir = base / "models" / "registry" / mid

    trained_dir.mkdir(parents=True, exist_ok=True)
    meta_dir.mkdir(parents=True, exist_ok=True)
    registry_dir.mkdir(parents=True, exist_ok=True)

    model_path = trained_dir / f"{mid}.joblib"
    meta_path = meta_dir / f"{mid}.json"
    registry_model_path = registry_dir / f"{mid}.joblib"
    registry_meta_path = registry_dir / "metadata.json"

    # 1. Save artifact bundle with joblib
    artifact_payload = {
        "model_id": mid,
        "model_type": candidate.model_type,
        "estimator": candidate.estimator,
        "scaler": candidate.scaler,
        "scaler_type": candidate.scaler_type,
        "classes": candidate.split_data.classes,
        "feature_names": list(FEATURE_ORDER),
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
    }
    joblib.dump(artifact_payload, model_path)
    joblib.dump(artifact_payload, registry_model_path)

    # 2. Extract scaler parameters for Phase 3 ModelMetadata contract
    scaler = candidate.scaler
    if candidate.scaler_type == "standard_scaler" and scaler is not None:
        preprocessing_dict = {
            "type": "standard_scaler",
            "parameters": {
                "mean": [round(float(m), 6) for m in scaler.mean_],
                "std": [round(float(s), 6) for s in scaler.scale_],
            },
        }
    elif candidate.scaler_type == "min_max_scaler" and scaler is not None:
        preprocessing_dict = {
            "type": "min_max_scaler",
            "parameters": {
                "min": [round(float(mn), 6) for mn in scaler.data_min_],
                "max": [round(float(mx), 6) for mx in scaler.data_max_],
            },
        }
    else:
        preprocessing_dict = {"type": "identity"}

    # 3. Label mapping dictionary
    labels_dict = {str(i): c for i, c in enumerate(candidate.split_data.classes)}

    # 4. Domain verification status
    if is_ipsec_dataset:
        ipsec_level = IPsecCompatibilityLevel.VERIFIED.value
        ipsec_reason = "Trained and validated on real IPsec/StrongSwan ground-truth captures."
    else:
        ipsec_level = IPsecCompatibilityLevel.UNVERIFIED.value
        ipsec_reason = (
            "Trained on proxy encrypted application flows (HTTPS/TLS/SSH). "
            "Real StrongSwan IPsec data required for domain validation."
        )

    meta = ModelMetadata(
        model_id=mid,
        model_name=f"{candidate.model_name.replace('_', ' ').title()} Flow Classifier",
        model_version="1.0.0",
        model_type=candidate.model_type,
        prediction_task=PredictionTask.APPLICATION_CATEGORY.value,
        input_type=InputType.FLOW_FEATURES.value,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        feature_names=list(FEATURE_ORDER),
        feature_count=len(FEATURE_ORDER),
        preprocessing=preprocessing_dict,
        labels=labels_dict,
        training_domain={
            "dataset": dataset_name,
            "traffic_type": traffic_type,
            "sample_count": len(candidate.split_data.X_train) + len(candidate.split_data.X_test),
            "classes": candidate.split_data.classes,
            "split_strategy": candidate.split_data.split_strategy,
            "metrics": {
                "accuracy": evaluation.accuracy,
                "f1_macro": evaluation.f1_macro,
                "precision_macro": evaluation.precision_macro,
                "recall_macro": evaluation.recall_macro,
                "f1_weighted": evaluation.f1_weighted,
            },
        },
        ipsec_compatibility={
            "level": ipsec_level,
            "reason": ipsec_reason,
        },
        artifact_path=str(model_path.resolve()),
        is_test_only=False,
    )

    meta_json = meta.to_json(indent=2)
    meta_path.write_text(meta_json, encoding="utf-8")

    # In the registry directory, reference local relative artifact path
    reg_meta_dict = meta.to_dict()
    reg_meta_dict["artifact_path"] = f"{mid}.joblib"
    registry_meta_path.write_text(json.dumps(reg_meta_dict, indent=2), encoding="utf-8")

    logger.info("Saved trained model weights to: %s", model_path)
    logger.info("Saved model metadata contract to: %s", meta_path)

    return model_path, meta_path
