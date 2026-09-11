"""Security analysis coordinator and capture-level aggregator for Phase 4.

Provides the primary public entry point `analyze_capture_security()` and per-flow
security evaluation, connecting Phase 1 packet analysis, Phase 2 feature extraction,
Phase 3 ML inference, and Phase 4 risk assessment into an integration-ready result.
"""

from __future__ import annotations

from collections import Counter
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import numpy as np

from person2_engine.src.behavior_engine import BehaviorEngine
from person2_engine.src.flow_models import FlowResult
from person2_engine.src.indicator_engine import IndicatorEngine
from person2_engine.src.packet_analyzer import analyze_capture_with_predictions
from person2_engine.src.prediction_models import (
    CapturePredictionResult,
    FlowPredictionResult,
    PredictionSummary,
)
from person2_engine.src.risk_engine import RiskEngine
from person2_engine.src.security_models import (
    CaptureSecurityResult,
    CaptureSecuritySummary,
    FlowSecurityResult,
    SECURITY_SCHEMA_VERSION,
    determine_confidence_level,
    determine_risk_level,
)

logger = logging.getLogger(__name__)


def analyze_flow_security(
    flow_result: FlowResult,
    flow_prediction: FlowPredictionResult,
    behavior_engine: Optional[BehaviorEngine] = None,
    indicator_engine: Optional[IndicatorEngine] = None,
) -> FlowSecurityResult:
    """Perform security assessment on an individual flow.

    Fuses Phase 2 features and Phase 3 prediction results into a structured
    FlowSecurityResult containing predictions, behavioral observations, explainable
    security indicators, risk scores, and human-readable narratives.

    Args:
        flow_result: FlowResult from Phase 2.
        flow_prediction: FlowPredictionResult from Phase 3.
        behavior_engine: Optional BehaviorEngine instance.
        indicator_engine: Optional IndicatorEngine instance.

    Returns:
        FlowSecurityResult conforming to the Phase 4 schema.
    """
    b_engine = behavior_engine or BehaviorEngine()
    i_engine = indicator_engine or IndicatorEngine()

    # 1. Format prediction metadata
    pred = flow_prediction.prediction
    model_info = flow_prediction.model_info or {}
    model_name = model_info.get("model_id", "unknown_model")
    model_version = model_info.get("model_version", "1.0")

    if pred:
        confidence = float(pred.confidence)
        conf_level = determine_confidence_level(confidence)
        traffic_cat = pred.label
        pred_status = f"{conf_level}_CONFIDENCE"
        probabilities = {k: round(float(v), 4) for k, v in pred.probabilities.items()}
    else:
        confidence = 0.0
        conf_level = "LOW"
        traffic_cat = "unclassified"
        pred_status = flow_prediction.model_status
        probabilities = {}

    prediction_dict = {
        "traffic_category": traffic_cat,
        "confidence": round(confidence, 4),
        "confidence_level": conf_level,
        "model_name": model_name,
        "model_version": model_version,
        "prediction_status": pred_status,
        "probabilities": probabilities,
    }

    # Model uncertainty reported independently from behavioral security risk
    is_uncertain = (conf_level == "LOW" or pred_status == "LOW_CONFIDENCE")
    uncertainty_flags = []
    if is_uncertain:
        uncertainty_flags.append({
            "code": "LOW_CLASSIFICATION_CONFIDENCE",
            "severity": "INFO",
            "message": (
                f"The traffic does not strongly resemble any category currently known to the classification model "
                f"(top resemblance: '{traffic_cat}' at {confidence:.2%} confidence). This represents classification "
                f"uncertainty and is not itself evidence of elevated behavioral risk."
            ),
        })

    model_uncertainty = {
        "present": is_uncertain,
        "flags": uncertainty_flags,
    }

    # 2. Evaluate behavioral profile from 25 Phase 2 features
    behavior = b_engine.analyze_flow_behavior(flow_result.features)

    # 3. Evaluate security indicators and point contributions
    indicators, contributions = i_engine.evaluate_indicators(
        flow_result.features,
        prediction_dict=prediction_dict,
    )

    # 4. Compute risk score and level (calculated exclusively from behavioral indicators; low confidence adds 0 points)
    risk_score = RiskEngine.calculate_risk_score(contributions)

    # 5. Extract top feature importances from model (where available)
    feature_importance_raw = flow_prediction.feature_importance or {}
    # Sort by descending importance, take top 5
    sorted_features = sorted(
        feature_importance_raw.items(),
        key=lambda item: abs(item[1]),
        reverse=True,
    )[:5]
    top_features = [
        {"feature_name": name, "importance": round(float(imp), 4)}
        for name, imp in sorted_features
    ]

    # 6. Generate human-readable explanation
    explanation_narrative = RiskEngine.generate_flow_explanation(
        prediction_dict=prediction_dict,
        behavior=behavior,
        indicators=indicators,
        risk_score=risk_score,
    )

    # Endpoints string
    meta = flow_result.flow_metadata
    endpoints = f"{meta.endpoint_a} <--> {meta.endpoint_b}"

    return FlowSecurityResult(
        flow_id=meta.flow_id,
        endpoints=endpoints,
        protocol=meta.protocol,
        prediction=prediction_dict,
        behavior=behavior,
        security_assessment={
            "risk_score": risk_score.total_score,
            "risk_level": risk_score.risk_level,
            "indicators": [ind.to_dict() for ind in indicators],
            "score_contributions": [c.to_dict() for c in contributions],
        },
        explainability={
            "important_features": top_features,
            "summary": explanation_narrative,
        },
        model_uncertainty=model_uncertainty,
    )


def aggregate_capture_security(
    flows: List[FlowSecurityResult],
    prediction_summary: PredictionSummary,
) -> CaptureSecuritySummary:
    """Aggregate individual flow assessments into a capture-level security summary.

    Computes categorical risk distribution, traffic category distribution,
    average prediction confidence, overall capture risk score, and top triggered indicators.

    The overall risk score uses an intelligent percentile blend:
        overall_score = min(100, int(round(0.70 * 90th_percentile + 0.30 * mean_score)))
    ensuring that high-risk outlier flows are not diluted away by large volumes of
    benign background flows.

    Args:
        flows: List of analyzed FlowSecurityResult items.
        prediction_summary: Aggregate prediction summary from Phase 3.

    Returns:
        CaptureSecuritySummary instance.
    """
    total = len(flows)
    if total == 0:
        return CaptureSecuritySummary(total_flows=0)

    # 1. Distributions
    risk_counts: Dict[str, int] = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    traffic_counts: Counter[str] = Counter()
    confidences: List[float] = []
    scores: List[int] = []
    all_indicators: List[str] = []

    for f in flows:
        # Risk level
        r_level = f.security_assessment.get("risk_level", "LOW")
        risk_counts[r_level] = risk_counts.get(r_level, 0) + 1

        # Score
        score = int(f.security_assessment.get("risk_score", 0))
        scores.append(score)

        # Category
        cat = f.prediction.get("traffic_category", "unknown")
        traffic_counts[cat] += 1

        # Confidence
        conf = float(f.prediction.get("confidence", 0.0))
        confidences.append(conf)

        # Indicators
        for ind_dict in f.security_assessment.get("indicators", []):
            all_indicators.append(ind_dict.get("indicator_id", "UNKNOWN"))

    avg_conf = float(np.mean(confidences)) if confidences else 0.0

    # 2. Overall capture risk score (Percentile-blend aggregation)
    p90 = float(np.percentile(scores, 90))
    mean_s = float(np.mean(scores))
    max_s = int(np.max(scores))

    # If any high-risk or critical flow exists (score >= 50), overall score reflects high-risk presence
    if max_s >= 50:
        blended_score = max(max_s, int(round(0.70 * p90 + 0.30 * mean_s)))
    else:
        blended_score = int(round(0.70 * p90 + 0.30 * mean_s))

    overall_score = max(0, min(100, blended_score))
    overall_level = determine_risk_level(overall_score)

    # 3. Top triggered indicators across capture
    ind_freq = Counter(all_indicators)
    top_indicators = [
        {"indicator_id": ind_id, "occurrences": count, "frequency_pct": round(count / total, 4)}
        for ind_id, count in ind_freq.most_common(5)
    ]

    return CaptureSecuritySummary(
        total_flows=total,
        risk_distribution=risk_counts,
        traffic_distribution=dict(traffic_counts),
        average_confidence=round(avg_conf, 4),
        overall_risk_score=overall_score,
        overall_risk_level=overall_level,
        top_indicators=top_indicators,
    )


def analyze_capture_security(
    file_path: Union[str, Path],
    model_id: Optional[str] = None,
    output_json: Optional[Union[str, Path]] = None,
    allow_unverified_domain: bool = True,
    allow_test_models: bool = False,
) -> CaptureSecurityResult:
    """Analyze a network capture file end-to-end and produce a complete security assessment.

    Executes Phase 1 packet analysis, Phase 2 flow feature extraction, Phase 3 ML inference,
    and Phase 4 behavioral security risk assessment, serializing to JSON if requested.

    Args:
        file_path: Path to the .pcap or .pcapng capture file.
        model_id: Optional specific model ID from the model registry.
        output_json: Optional destination path to write the formatted security assessment JSON.
        allow_unverified_domain: Allow inference when domain is unverified (defaults to True).
        allow_test_models: Allow test/dummy models (for CI and automated testing only).

    Returns:
        CaptureSecurityResult instance containing capture summary and detailed flow assessments.
    """
    p = Path(file_path).resolve()

    # 1. Run Phase 3 prediction pipeline (which runs Phase 1 & Phase 2)
    pred_result: CapturePredictionResult = analyze_capture_with_predictions(
        file_path=p,
        model_id=model_id,
        output_json=None,
        allow_unverified_domain=allow_unverified_domain,
        allow_test_models=allow_test_models,
    )

    cap_features = pred_result.capture_features
    analysis = cap_features.analysis
    flows_p2 = cap_features.flows
    preds_p3 = pred_result.predictions

    # 2. Package analysis metadata and model information
    analysis_metadata = {
        "file_name": p.name,
        "file_path": str(p),
        "file_type": analysis.capture_info.file_type if hasattr(analysis, "capture_info") else p.suffix.lstrip("."),
        "total_packets": analysis.capture_info.total_packets if hasattr(analysis, "capture_info") else 0,
        "ipsec_traffic_detected": analysis.ipsec_analysis.ipsec_detected if hasattr(analysis, "ipsec_analysis") else False,
        "esp_detected": analysis.ipsec_analysis.esp_detected if hasattr(analysis, "ipsec_analysis") else False,
        "ike_detected": analysis.ipsec_analysis.ike_related_traffic_detected if hasattr(analysis, "ipsec_analysis") else False,
        "analysis_status": "SUCCESS" if analysis.status.success else "FAILED",
        "errors": analysis.status.errors,
        "warnings": analysis.status.warnings,
    }

    first_pred_info = preds_p3[0].model_info if preds_p3 and preds_p3[0].model_info else {}
    model_information = {
        "model_id": first_pred_info.get("model_id", model_id or "default_registry_model"),
        "model_version": first_pred_info.get("model_version", "1.0"),
        "feature_schema_version": cap_features.feature_schema_version,
        "domain_status": preds_p3[0].domain_status if preds_p3 else {"ipsec_validation": "unverified"},
    }

    # 3. Analyze security for each flow
    b_engine = BehaviorEngine()
    i_engine = IndicatorEngine()
    flow_security_results: List[FlowSecurityResult] = []

    for flow_res, pred_res in zip(flows_p2, preds_p3):
        f_sec = analyze_flow_security(
            flow_result=flow_res,
            flow_prediction=pred_res,
            behavior_engine=b_engine,
            indicator_engine=i_engine,
        )
        flow_security_results.append(f_sec)

    # 4. Generate capture-level security summary
    summary = aggregate_capture_security(flow_security_results, pred_result.prediction_summary)

    sec_result = CaptureSecurityResult(
        analysis_metadata=analysis_metadata,
        model_information=model_information,
        capture_summary=summary,
        flows=flow_security_results,
    )

    # 5. Persist JSON if requested
    if output_json:
        out_p = Path(output_json).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            f.write(sec_result.to_json(indent=2))
        logger.info("Saved Phase 4 security assessment JSON to: %s", out_p)

    return sec_result
