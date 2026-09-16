"""Unified integration engine and single public entry point for Phase 5.

Connects Phase 1 (packet analysis & IPsec detection), Phase 2 (flow construction & 25 features),
Phase 3 (traffic classification), Phase 4 (explainable behavioral risk assessment), and
Phase 5 (unified output assembly & validation) into `analyze_capture_complete()`.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from person2_engine.src.behavior_engine import BehaviorEngine
from person2_engine.src.flow_builder import FlowBuilder
from person2_engine.src.feature_extractor import extract_flow_features
from person2_engine.src.feature_schema import FEATURE_SCHEMA_VERSION
from person2_engine.src.feature_validator import validate_flow_features
from person2_engine.src.indicator_engine import IndicatorEngine
from person2_engine.src.inference_engine import predict_flows
from person2_engine.src.model_metadata import ModelStatus
from person2_engine.src.integration_models import (
    INTEGRATION_SCHEMA_VERSION,
    UnifiedCaptureResult,
    UnifiedFlowResult,
)
from person2_engine.src.integration_validator import validate_integration_result
from person2_engine.src.packet_analyzer import analyze_capture
from person2_engine.src.prediction_models import FlowPredictionResult, PredictionSummary
from person2_engine.src.risk_engine import RiskEngine
from person2_engine.src.security_analyzer import aggregate_capture_security
from person2_engine.src.security_models import (
    FlowSecurityResult,
    determine_confidence_level,
    determine_risk_level,
)

logger = logging.getLogger(__name__)


def analyze_capture_complete(
    file_path: Union[str, Path],
    model_id: Optional[str] = None,
    output_json: Optional[Union[str, Path]] = None,
    allow_unverified_domain: bool = False,
    allow_test_models: bool = False,
    validate_output: bool = True,
) -> UnifiedCaptureResult:
    """Analyze a network capture end-to-end through the complete 5-phase pipeline.

    Unified public API for Person 3 handoff. Executes Phase 1 packet analysis,
    Phase 2 flow construction & 25-feature extraction, Phase 3 ML classification,
    Phase 4 behavioral security risk assessment, and Phase 5 schema assembly & validation.

    Args:
        file_path: Path to the .pcap or .pcapng capture file.
        model_id: Optional specific model ID from the model registry.
        output_json: Optional destination path to write the formatted JSON result.
        allow_unverified_domain: Allow inference when domain is unverified (defaults to False for safety).
        allow_test_models: Allow test/dummy models (for CI and automated testing only).
        validate_output: Execute integration validator before returning (defaults to True).

    Returns:
        UnifiedCaptureResult containing metadata, capture summary, IPsec analysis,
        and per-flow records conforming to INTEGRATION_SCHEMA_VERSION = "1.0".

    Raises:
        FileNotFoundError: If the specified capture file does not exist.
        ValueError: If capture format is unsupported or validation fails critically.
    """
    p = Path(file_path).resolve()
    if not p.exists():
        raise FileNotFoundError(f"Capture file not found: {p}")

    if p.is_dir():
        raise ValueError(f"Path is a directory, not a capture file: {p}")

    suffix = p.suffix.lower()
    if suffix not in [".pcap", ".pcapng", ".cap"]:
        logger.warning("Uncommon capture file extension: %s. Attempting to parse.", suffix)

    logger.info("Executing Phase 5 unified analysis on: %s", p.name)

    # --------------------------------------------------------------------------
    # 1. Phase 1: Packet Reading, Protocol Breakdown, IPsec Detection
    # --------------------------------------------------------------------------
    p1_result = analyze_capture(file_path=p, output_json=None, include_packets_in_json=False)

    ipsec_analysis_dict = p1_result.ipsec_analysis.to_dict()
    cap_info = p1_result.capture_info

    # --------------------------------------------------------------------------
    # 2. Handle Empty Capture
    # --------------------------------------------------------------------------
    if cap_info.total_packets == 0 or not p1_result.packets:
        logger.info("Capture file %s contains 0 packets.", p.name)
        empty_metadata = {
            "file_name": p.name,
            "file_path": str(p),
            "file_type": cap_info.file_type or suffix.lstrip("."),
            "total_packets": 0,
            "analysis_status": "SUCCESS",
            "errors": p1_result.status.errors,
            "warnings": p1_result.status.warnings + ["Empty capture: zero packets read"],
            "model_information": {
                "model_id": model_id or "default_registry_model",
                "model_version": "1.0",
                "feature_schema_version": FEATURE_SCHEMA_VERSION,
                "domain_status": {"ipsec_validation": "unverified"},
            },
        }
        empty_summary = {
            "total_flows": 0,
            "overall_risk_score": 0,
            "overall_risk_level": "LOW",
            "risk_distribution": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
            "traffic_distribution": {},
            "average_confidence": 0.0,
            "top_indicators": [],
        }
        res = UnifiedCaptureResult(
            integration_schema_version=INTEGRATION_SCHEMA_VERSION,
            analysis_metadata=empty_metadata,
            capture_summary=empty_summary,
            ipsec_analysis=ipsec_analysis_dict,
            flows=[],
        )
        if output_json:
            res.to_json_file(output_json)
        return res

    # --------------------------------------------------------------------------
    # 3. Phase 2: Flow Building and 25-Feature Extraction
    # --------------------------------------------------------------------------
    flow_builder = FlowBuilder()
    flow_builder.process_packets(p1_result.packets)
    phase2_flow_results, flow_summary = flow_builder.build_flow_results()

    # If capture contains no IP flows (e.g. non-IP, ARP, pure Ethernet broadcast)
    if not phase2_flow_results:
        logger.info("No IP flows formed from %d packets.", cap_info.total_packets)
        no_flows_metadata = {
            "file_name": p.name,
            "file_path": str(p),
            "file_type": cap_info.file_type or suffix.lstrip("."),
            "total_packets": cap_info.total_packets,
            "readable": cap_info.readable,
            "analysis_status": "SUCCESS",
            "errors": p1_result.status.errors,
            "warnings": p1_result.status.warnings + ["No IP flows detected in capture"],
            "model_information": {
                "model_id": model_id or "default_registry_model",
                "model_version": "1.0",
                "feature_schema_version": FEATURE_SCHEMA_VERSION,
                "domain_status": {"ipsec_validation": "unverified"},
            },
        }
        no_flows_summary = {
            "total_flows": 0,
            "overall_risk_score": 0,
            "overall_risk_level": "LOW",
            "risk_distribution": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
            "traffic_distribution": {},
            "average_confidence": 0.0,
            "top_indicators": [],
        }
        res = UnifiedCaptureResult(
            integration_schema_version=INTEGRATION_SCHEMA_VERSION,
            analysis_metadata=no_flows_metadata,
            capture_summary=no_flows_summary,
            ipsec_analysis=ipsec_analysis_dict,
            flows=[],
        )
        if output_json:
            res.to_json_file(output_json)
        return res

    # --------------------------------------------------------------------------
    # 4. Phase 3: Traffic Category Resemblance Inference
    # --------------------------------------------------------------------------
    predictions, pred_summary = predict_flows(
        phase2_flow_results,
        model_id=model_id,
        allow_unverified_domain=allow_unverified_domain,
        allow_test_models=allow_test_models,
    )

    first_pred_info = predictions[0].model_info if predictions and predictions[0].model_info else {}
    model_information = {
        "model_id": first_pred_info.get("model_id", model_id or "default_registry_model"),
        "model_version": first_pred_info.get("model_version", "1.0"),
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "domain_status": predictions[0].domain_status if predictions else {"ipsec_validation": "unverified"},
    }

    # --------------------------------------------------------------------------
    # 5. Phase 4: Behavioral Analysis & Explainable Behavioral Risk Assessment
    # --------------------------------------------------------------------------
    b_engine = BehaviorEngine()
    i_engine = IndicatorEngine()
    unified_flows: List[UnifiedFlowResult] = []
    phase4_flow_security_results: List[FlowSecurityResult] = []

    for flow_res, pred_res in zip(phase2_flow_results, predictions):
        # A. Prediction metadata
        pred = pred_res.prediction
        if pred:
            conf = float(pred.confidence)
            conf_level = determine_confidence_level(conf)
            traffic_cat = pred.label
            if pred_res.model_status == ModelStatus.TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED.value:
                pred_status = ModelStatus.TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED.value
            else:
                pred_status = f"{conf_level}_CONFIDENCE"
            probabilities = {k: round(float(v), 4) for k, v in pred.probabilities.items()}
        else:
            conf = 0.0
            conf_level = "LOW"
            traffic_cat = "unclassified"
            pred_status = pred_res.model_status
            probabilities = {}

        prediction_dict = {
            "traffic_category": traffic_cat,
            "confidence": round(conf, 4),
            "confidence_level": conf_level,
            "prediction_status": pred_status,
            "probabilities": probabilities,
            "model_name": model_information["model_id"],
            "model_version": model_information["model_version"],
            "domain_status": pred_res.domain_status,
            "warnings": pred_res.warnings,
        }

        # B. Model Uncertainty Path (Decoupled from behavioral risk)
        is_uncertain = (conf_level == "LOW" or pred_status == "LOW_CONFIDENCE")
        uncertainty_flags = []
        if is_uncertain:
            uncertainty_flags.append({
                "code": "LOW_CLASSIFICATION_CONFIDENCE",
                "severity": "INFO",
                "message": (
                    f"The traffic does not strongly resemble any category currently known to the classification model "
                    f"(top resemblance: '{traffic_cat}' at {conf:.2%} confidence). This represents classification "
                    f"uncertainty and is not itself evidence of elevated behavioral risk."
                ),
            })
        model_uncertainty_dict = {
            "present": is_uncertain,
            "flags": uncertainty_flags,
        }

        # C. Behavioral Profile
        behavior = b_engine.analyze_flow_behavior(flow_res.features)

        # D. Behavioral Security Indicators & Score (pure behavioral risk)
        indicators, contributions = i_engine.evaluate_indicators(flow_res.features)
        risk_score = RiskEngine.calculate_risk_score(contributions)

        # E. Feature importance
        feature_importance_raw = pred_res.feature_importance or {}
        sorted_features = sorted(
            feature_importance_raw.items(),
            key=lambda item: abs(item[1]),
            reverse=True,
        )[:5]
        top_features = [
            {"feature_name": name, "importance": round(float(imp), 4)}
            for name, imp in sorted_features
        ]

        # F. Explanation Narrative
        summary_narrative = RiskEngine.generate_flow_explanation(
            prediction_dict=prediction_dict,
            behavior=behavior,
            indicators=indicators,
            risk_score=risk_score,
        )

        # Build FlowSecurityResult for capture-level aggregation
        meta = flow_res.flow_metadata
        endpoints = f"{meta.endpoint_a} <--> {meta.endpoint_b}"
        p4_sec = FlowSecurityResult(
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
                "summary": summary_narrative,
            },
            model_uncertainty=model_uncertainty_dict,
        )
        phase4_flow_security_results.append(p4_sec)

        # Build UnifiedFlowResult
        flow_meta_dict = meta.to_dict()
        flow_meta_dict["is_ipsec_related"] = flow_res.ipsec_metadata.is_ipsec_related
        flow_meta_dict["esp_detected"] = flow_res.ipsec_metadata.esp_detected
        flow_meta_dict["ah_detected"] = flow_res.ipsec_metadata.ah_detected
        flow_meta_dict["ike_related"] = flow_res.ipsec_metadata.ike_related
        flow_meta_dict["nat_t_related"] = flow_res.ipsec_metadata.nat_t_related

        unified_f = UnifiedFlowResult(
            flow_id=meta.flow_id,
            flow_metadata=flow_meta_dict,
            features={k: round(float(v), 4) for k, v in flow_res.features.items()},
            prediction=prediction_dict,
            model_uncertainty=model_uncertainty_dict,
            behavior=behavior.to_dict(),
            security_assessment={
                "risk_score": risk_score.total_score,
                "risk_level": risk_score.risk_level,
                "indicators": [ind.to_dict() for ind in indicators],
                "score_contributions": [c.to_dict() for c in contributions],
            },
            explainability={
                "important_features": top_features,
                "summary": summary_narrative,
            },
            summary=summary_narrative,
        )
        unified_flows.append(unified_f)

    # --------------------------------------------------------------------------
    # 6. Capture-Level Aggregation
    # --------------------------------------------------------------------------
    cap_sec_summary = aggregate_capture_security(phase4_flow_security_results, pred_summary)
    capture_summary_dict = cap_sec_summary.to_dict()

    analysis_metadata = {
        "file_name": p.name,
        "file_path": str(p),
        "file_type": cap_info.file_type or suffix.lstrip("."),
        "total_packets": cap_info.total_packets,
        "readable": cap_info.readable,
        "analysis_status": "SUCCESS" if p1_result.status.success else "FAILED",
        "errors": p1_result.status.errors,
        "warnings": p1_result.status.warnings,
        "model_information": model_information,
    }

    # --------------------------------------------------------------------------
    # 7. Assemble Unified Phase 5 Result
    # --------------------------------------------------------------------------
    unified_result = UnifiedCaptureResult(
        integration_schema_version=INTEGRATION_SCHEMA_VERSION,
        analysis_metadata=analysis_metadata,
        capture_summary=capture_summary_dict,
        ipsec_analysis=ipsec_analysis_dict,
        flows=unified_flows,
    )

    # --------------------------------------------------------------------------
    # 8. Integration Validation
    # --------------------------------------------------------------------------
    if validate_output:
        val_report = validate_integration_result(unified_result)
        if not val_report.valid:
            err_summary = "; ".join(val_report.errors[:5])
            logger.error("Phase 5 validation failed: %s", err_summary)
            raise ValueError(f"Integration validation failed with {len(val_report.errors)} error(s): {err_summary}")

    # --------------------------------------------------------------------------
    # 9. Output Persistence
    # --------------------------------------------------------------------------
    if output_json:
        unified_result.to_json_file(output_json)
        logger.info("Saved Phase 5 unified JSON output to: %s", output_json)

    return unified_result


def render_complete_terminal_summary(result: UnifiedCaptureResult) -> str:
    """Render a comprehensive executive terminal summary for Phase 5 integration results.

    Args:
        result: UnifiedCaptureResult instance.

    Returns:
        Formatted multi-line summary string for CLI display.
    """
    meta = result.analysis_metadata
    summary = result.capture_summary
    ipsec = result.ipsec_analysis
    model_info = meta.get("model_information", {})

    lines = [
        "=" * 70,
        "   PHASE 5: UNIFIED NETWORK TRAFFIC ANALYSIS & SECURITY REPORT",
        "=" * 70,
        f"Integration Schema Version: {result.integration_schema_version}",
        f"File Name:                  {meta.get('file_name', 'Unknown')}",
        f"Total Packets Analyzed:     {meta.get('total_packets', 0):,}",
        f"Total Flows Extracted:      {summary.get('total_flows', 0)}",
        f"Overall Behavioral Risk:    {summary.get('overall_risk_level', 'LOW')} (Score: {summary.get('overall_risk_score', 0)}/100)",
        f"Average ML Confidence:      {summary.get('average_confidence', 0.0):.1%}",
        f"Model In Use:               {model_info.get('model_id', 'Unknown')}",
        "-" * 70,
        "IPSEC & TUNNEL ENCRYPTION STATUS:",
        f"  IPsec Detected:           {ipsec.get('ipsec_detected', False)}",
        f"  ESP Encrypted Packets:    {ipsec.get('esp_detected', False)} ({ipsec.get('esp_packets', 0)} pkts)",
        f"  AH Authenticated Packets: {ipsec.get('ah_detected', False)} ({ipsec.get('ah_packets', 0)} pkts)",
        f"  IKE Key Exchange:         {ipsec.get('ike_related_traffic_detected', False)} (v{ipsec.get('ike_version', 'None')})",
        f"  NAT Traversal (NAT-T):    {ipsec.get('nat_traversal_related_traffic_detected', False)}",
    ]

    # IPsec domain status diagnostic line
    if ipsec.get("ipsec_detected", False):
        unverified_blocked = any(
            f.prediction.get("prediction_status") == "TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED"
            and f.prediction.get("traffic_category") == "unclassified"
            for f in result.flows
        )
        unverified_override = any(
            f.prediction.get("prediction_status") == "TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED"
            and f.prediction.get("traffic_category") != "unclassified"
            for f in result.flows
        )
        if unverified_blocked:
            lines.append("  IPsec ML Domain Status:   BLOCKED (Unverified IPsec domain; use --allow-unverified-domain to evaluate)")
        elif unverified_override:
            lines.append("  IPsec ML Domain Status:   UNVERIFIED OVERRIDE (Inference allowed via configuration; NOT IPsec-validated)")
        else:
            lines.append("  IPsec ML Domain Status:   VERIFIED (Model validated for IPsec traffic)")
    else:
        lines.append("  IPsec ML Domain Status:   N/A (Non-IPsec traffic; in-domain model inference)")

    lines.extend([
        "-" * 70,
        "BEHAVIORAL RISK TIER DISTRIBUTION:",
    ])
    r_dist = summary.get("risk_distribution", {})
    for tier in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        lines.append(f"  {tier:<10} (tier): {r_dist.get(tier, 0)} flows")

    lines.extend([
        "-" * 70,
        "TRAFFIC CATEGORY RESEMBLANCE:",
    ])
    t_dist = summary.get("traffic_distribution", {})
    if t_dist:
        for cat, count in sorted(t_dist.items()):
            lines.append(f"  {cat:<18}: {count} flows")
    else:
        lines.append("  (No flow traffic categories recorded)")

    top_indicators = summary.get("top_indicators", [])
    if top_indicators:
        lines.extend([
            "-" * 70,
            "TOP OBSERVED BEHAVIORAL RISK INDICATORS:",
        ])
        for ind in top_indicators:
            lines.append(
                f"  [!] {ind.get('indicator_id', 'UNKNOWN'):<32} : "
                f"{ind.get('occurrences', 0)} occurrences ({ind.get('frequency_pct', 0.0):.1%})"
            )

    if result.flows:
        lines.extend([
            "-" * 70,
            "PER-FLOW BEHAVIORAL FINDINGS & MODEL UNCERTAINTY (Top Flows):",
        ])
        sorted_flows = sorted(
            result.flows,
            key=lambda x: x.security_assessment.get("risk_score", 0),
            reverse=True,
        )
        for i, f in enumerate(sorted_flows[:5], 1):
            pred = f.prediction
            sec = f.security_assessment
            beh = f.behavior
            unc = f.model_uncertainty
            meta_f = f.flow_metadata
            ep = f"{meta_f.get('endpoint_a', 'A')} <--> {meta_f.get('endpoint_b', 'B')}"

            if pred.get("prediction_status") == "TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED":
                if pred.get("traffic_category") == "unclassified":
                    cat_line = "BLOCKED (IPsec domain unverified; pass --allow-unverified-domain to evaluate)"
                else:
                    cat_line = f"{pred.get('traffic_category')} ({pred.get('confidence_level')}, Conf: {pred.get('confidence', 0.0):.1%}) [UNVERIFIED IPSEC OVERRIDE]"
            else:
                cat_line = f"{pred.get('traffic_category')} ({pred.get('confidence_level')}, Conf: {pred.get('confidence', 0.0):.1%})"

            lines.extend([
                f"  Flow #{i}: {f.flow_id} [{ep}]",
                f"    Category Resemblance: {cat_line}",
                f"    Observed Pattern:     {beh.get('traffic_pattern')}",
                f"    BEHAVIORAL RISK:      {sec.get('risk_level')} (Score: {sec.get('risk_score')}/100)",
            ])
            if unc.get("present"):
                lines.append("    MODEL UNCERTAINTY:    PRESENT (Traffic does not strongly match known classes; 0 risk pts added)")
            else:
                lines.append("    MODEL UNCERTAINTY:    NONE")

            indicators = sec.get("indicators", [])
            if indicators:
                lines.append(f"    Risk Indicators:      {', '.join(ind.get('indicator_id', '') for ind in indicators)}")
            lines.append(f"    Summary:              {f.summary}")
            lines.append("")

    lines.append("=" * 70)
    return "\n".join(lines)
