"""Inference engine coordinating feature validation, model retrieval, and prediction.

Executes inference strictly when a compatible, verified model is available,
or safely reports MODEL_UNAVAILABLE/INCOMPATIBLE without fabricating predictions.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple, Union

from person2_engine.src.feature_extractor import flow_features_to_vector
from person2_engine.src.flow_models import FlowResult
from person2_engine.src.model_metadata import ModelStatus
from person2_engine.src.model_registry import ModelRegistry, default_registry
from person2_engine.src.prediction_models import (
    FlowPredictionResult,
    Prediction,
    PredictionSummary,
)

logger = logging.getLogger(__name__)


def predict_flow(
    flow_result: Union[FlowResult, Dict[str, Any]],
    model_id: Optional[str] = None,
    registry: Optional[ModelRegistry] = None,
    allow_unverified_domain: bool = False,
    allow_test_models: bool = False,
) -> FlowPredictionResult:
    """Execute prediction on a single flow using a verified model from registry.

    Enforces:
    1. Phase 2 flow validation must pass.
    2. Model compatibility must be verified.
    3. Preprocessing must be faithfully applied.
    4. Deterministic feature vector generation.
    5. Clean reporting if model is unavailable or incompatible.

    Args:
        flow_result: FlowResult object or its dictionary representation.
        model_id: Optional specific model ID. If None, queries default registry.
        registry: ModelRegistry to use (defaults to default_registry).
        allow_unverified_domain: Whether to allow inference when IPsec domain is unverified.
        allow_test_models: Whether test-only models may be used (strictly for CI/testing).

    Returns:
        FlowPredictionResult conforming to the Phase 3 contract.
    """
    reg = registry or default_registry

    # 1. Inspect Flow validation status
    if isinstance(flow_result, FlowResult):
        val_status = flow_result.validation
        is_valid = val_status.valid
        errors = val_status.errors
    elif isinstance(flow_result, dict):
        val_dict = flow_result.get("validation", {})
        is_valid = val_dict.get("valid", False)
        errors = val_dict.get("errors", [])
    else:
        return FlowPredictionResult(
            model_status=ModelStatus.INCOMPATIBLE.value,
            reason=f"Invalid flow result object type: {type(flow_result).__name__}",
            compatibility_errors=["Input object is not FlowResult or dict."],
        )

    if not is_valid:
        flow_errs = [f"Flow validation failed: {e}" for e in errors] if errors else ["Flow validation failed."]
        return FlowPredictionResult(
            model_status=ModelStatus.INCOMPATIBLE.value,
            reason="Flow features failed Phase 2 feature validation.",
            compatibility_errors=flow_errs,
        )


    # 1.5 Determine whether this specific flow is IPsec encapsulated
    is_ipsec_flow = False
    if isinstance(flow_result, FlowResult):
        is_ipsec_flow = bool(flow_result.ipsec_metadata.is_ipsec_related)
    elif isinstance(flow_result, dict):
        is_ipsec_flow = bool(
            flow_result.get("ipsec_metadata", {}).get("is_ipsec_related", False)
            or flow_result.get("flow_metadata", {}).get("is_ipsec_related", False)
            or flow_result.get("is_ipsec_related", False)
        )

    # 2. Discover / retrieve model from registry
    # For non-IPsec flows, model operates in its native tabular domain
    query_allow_unverified = allow_unverified_domain if is_ipsec_flow else True
    adapter, status, reason, warnings = reg.get_model(
        model_id=model_id,
        allow_unverified_domain=query_allow_unverified,
        allow_test_models=allow_test_models,
    )

    if status == ModelStatus.MODEL_UNAVAILABLE:
        return FlowPredictionResult(
            model_status=ModelStatus.MODEL_UNAVAILABLE.value,
            reason=reason,
            warnings=warnings,
            prediction=None,
        )

    if status == ModelStatus.INCOMPATIBLE:
        return FlowPredictionResult(
            model_status=ModelStatus.INCOMPATIBLE.value,
            reason=reason,
            compatibility_errors=warnings or [reason],
            prediction=None,
        )

    meta = adapter.get_metadata() if adapter else None
    ipsec_level = str(meta.ipsec_compatibility.get("level", "unknown")).lower() if meta and isinstance(meta.ipsec_compatibility, dict) else "unknown"
    is_model_verified_ipsec = ipsec_level in {"verified", "verified_ipsec"}

    # CASE B: IPsec traffic + unverified model + opt-in False -> Inference BLOCKED
    if is_ipsec_flow and not is_model_verified_ipsec and not allow_unverified_domain:
        block_msg = (
            f"Model '{meta.model_id if meta else 'model'}' is technically compatible with Schema 1.0, "
            f"but has NOT been validated on real IPsec/StrongSwan encrypted traffic. "
            f"Inference blocked without explicit opt-in (allow_unverified_domain=True)."
        )
        return FlowPredictionResult(
            model_status=ModelStatus.TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED.value,
            model_info={
                "model_id": meta.model_id,
                "model_version": meta.model_version,
                "prediction_task": meta.prediction_task,
            } if meta else None,
            reason=block_msg,
            warnings=list(warnings) + [block_msg],
            domain_status={"ipsec_validation": "unverified"},
            prediction=None,
        )

    if adapter is None:
        return FlowPredictionResult(
            model_status=ModelStatus.MODEL_UNAVAILABLE.value,
            reason="No model adapter could be instantiated.",
        )

    # 3. Model is ready for inference
    model_info = {
        "model_id": meta.model_id,
        "model_version": meta.model_version,
        "prediction_task": meta.prediction_task,
    }

    # Determine domain verification status and effective model_status
    if is_ipsec_flow:
        if is_model_verified_ipsec:
            effective_status = ModelStatus.READY_FOR_INFERENCE.value
            domain_status = {
                "ipsec_validation": "verified_ipsec",
                "reason": meta.ipsec_compatibility.get("reason", "Validated on IPsec traffic"),
            }
        else:
            # CASE C: Explicit opt-in override active
            effective_status = ModelStatus.TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED.value
            domain_status = {
                "ipsec_validation": "unverified",
                "reason": meta.ipsec_compatibility.get("reason", "Domain evaluation unverified; running via explicit override"),
                "override_used": True,
            }
    else:
        effective_status = ModelStatus.READY_FOR_INFERENCE.value
        domain_status = {
            "ipsec_validation": "not_applicable_non_ipsec",
            "reason": "Traffic is not IPsec encapsulated; model operating in native domain",
        }

    pred_warnings = list(warnings)
    if is_ipsec_flow and not is_model_verified_ipsec:
        pred_warnings.append(
            f"Model '{meta.model_id}' inference allowed via configuration override for unverified domain. "
            "Predictions are not IPsec-domain validated."
        )

    if meta.is_test_only:
        pred_warnings.append(
            f"Model '{meta.model_id}' is flagged as TEST ONLY and should not be treated as a real AI prediction."
        )

    try:
        raw_vector = flow_features_to_vector(flow_result)
        preprocessed_vector = adapter.preprocess(raw_vector)
        prediction = adapter.predict(preprocessed_vector)
        feat_importance = (
            adapter.get_feature_importances()
            if hasattr(adapter, "get_feature_importances")
            else {}
        )

        return FlowPredictionResult(
            model_status=effective_status,
            model_info=model_info,
            prediction=prediction,
            reason=reason,
            warnings=pred_warnings,
            domain_status=domain_status,
            feature_importance=feat_importance,
        )


    except Exception as e:
        logger.error("Inference execution error: %s", e)
        return FlowPredictionResult(
            model_status=ModelStatus.INCOMPATIBLE.value,
            model_info=model_info,
            reason=f"Inference error during model execution: {e}",
            compatibility_errors=[str(e)],
            warnings=warnings,
            domain_status=domain_status,
        )


def predict_flows(
    flows: List[FlowResult],
    model_id: Optional[str] = None,
    registry: Optional[ModelRegistry] = None,
    allow_unverified_domain: bool = False,
    allow_test_models: bool = False,
) -> Tuple[List[FlowPredictionResult], PredictionSummary]:
    """Execute inference across a collection of flows and summarize results.

    Args:
        flows: List of FlowResult objects.
        model_id: Optional model ID.
        registry: Optional model registry.
        allow_unverified_domain: Whether to proceed on unverified domain.
        allow_test_models: Whether test-only models may be used.

    Returns:
        Tuple of (list of FlowPredictionResult, PredictionSummary).
    """
    predictions: List[FlowPredictionResult] = []
    successful = 0
    unavailable = 0
    incompatible = 0
    domain_unverified = 0

    for flow in flows:
        pred_res = predict_flow(
            flow_result=flow,
            model_id=model_id,
            registry=registry,
            allow_unverified_domain=allow_unverified_domain,
            allow_test_models=allow_test_models,
        )
        predictions.append(pred_res)

        if pred_res.prediction is not None:
            successful += 1
        elif pred_res.model_status == ModelStatus.MODEL_UNAVAILABLE.value:
            unavailable += 1
        elif pred_res.model_status == ModelStatus.INCOMPATIBLE.value:
            incompatible += 1
        elif pred_res.model_status == ModelStatus.TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED.value:
            domain_unverified += 1

    summary = PredictionSummary(
        total_flows=len(flows),
        predictions_successful=successful,
        model_unavailable=unavailable,
        incompatible=incompatible,
        domain_unverified=domain_unverified,
    )

    return predictions, summary
