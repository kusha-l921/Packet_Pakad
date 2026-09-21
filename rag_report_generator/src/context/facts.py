"""Fact extraction layer converting real Phase 5 Unified JSON to authoritative AnalysisFacts."""

from typing import Any
from ..models.facts import (
    AnalysisFacts,
    BehavioralFacts,
    CaptureFacts,
    ClassificationFacts,
    EvaluationFacts,
    IPsecFacts,
    UncertaintyFacts,
)
from .flow_selector import FlowSelector


def extract_analysis_facts(
    phase5_data: dict[str, Any],
    max_flows: int = 5,
) -> AnalysisFacts:
    """Extract authoritative facts from Phase 5 Unified JSON.
    
    Supports both real Phase 5 IntegrationCaptureResult schema and legacy fixtures.
    Strictly preserves numeric precision, indicator lists, and protocol states without rounding.
    """
    if not isinstance(phase5_data, dict):
        raise ValueError("Phase 5 input must be a dictionary.")

    meta_data = phase5_data.get("analysis_metadata") or {}
    capture_data = phase5_data.get("capture_summary") or phase5_data.get("capture") or {}
    ipsec_data = phase5_data.get("ipsec_analysis") or phase5_data.get("ipsec") or {}
    raw_flows = phase5_data.get("flows", phase5_data.get("selected_flows", []))

    # 1. Flow Extraction (parse all flows first to enable deterministic capture-level rollups)
    selected_flows = FlowSelector.select_notable_flows(raw_flows, max_flows=max_flows)

    # 2. Capture Summary
    # In real Phase 5, total_packets is in analysis_metadata; total_flows is in capture_summary
    packet_count = int(
        capture_data.get("packet_count")
        or capture_data.get("total_packets")
        or meta_data.get("total_packets")
        or sum(f.get("features", {}).get("total_packets", 0) for f in raw_flows)
        or 0
    )

    flow_count = int(
        capture_data.get("flow_count")
        or capture_data.get("total_flows")
        or len(raw_flows)
    )

    # Total bytes
    if "total_bytes" in capture_data:
        total_bytes = int(capture_data["total_bytes"])
    elif "bytes" in capture_data:
        total_bytes = int(capture_data["bytes"])
    else:
        total_bytes = int(sum(f.get("features", {}).get("total_bytes", 0) for f in raw_flows))

    # Duration
    if "duration_seconds" in capture_data:
        duration_seconds = float(capture_data["duration_seconds"])
    elif "duration" in capture_data:
        duration_seconds = float(capture_data["duration"])
    else:
        # Calculate from flow features or timestamps
        max_flow_dur = max([f.get("features", {}).get("flow_duration_seconds", 0.0) for f in raw_flows], default=0.0)
        first_ts = [f.get("flow_metadata", {}).get("first_timestamp") for f in raw_flows if f.get("flow_metadata", {}).get("first_timestamp") is not None]
        last_ts = [f.get("flow_metadata", {}).get("last_timestamp") for f in raw_flows if f.get("flow_metadata", {}).get("last_timestamp") is not None]
        if first_ts and last_ts and (max(last_ts) - min(first_ts)) > 0:
            duration_seconds = float(max(last_ts) - min(first_ts))
        else:
            duration_seconds = float(max_flow_dur)

    # Protocols breakdown
    protocols = dict(capture_data.get("protocols", {}))
    if not protocols and raw_flows:
        for f in raw_flows:
            p = str(f.get("flow_metadata", {}).get("protocol", f.get("protocol", "UNKNOWN"))).upper()
            protocols[p] = protocols.get(p, 0) + int(f.get("features", {}).get("total_packets", 1))

    capture_facts = CaptureFacts(
        packet_count=packet_count,
        flow_count=flow_count,
        duration_seconds=duration_seconds,
        total_bytes=total_bytes,
        protocols=protocols,
    )

    # 3. IPsec Analysis
    detected = bool(ipsec_data.get("ipsec_detected", ipsec_data.get("detected", False)))
    esp_detected = bool(ipsec_data.get("esp_detected", False))
    ah_detected = bool(ipsec_data.get("ah_detected", False))
    ike_detected = bool(ipsec_data.get("ike_related_traffic_detected", ipsec_data.get("ike_detected", False)))
    nat_t_detected = bool(ipsec_data.get("nat_traversal_related_traffic_detected", ipsec_data.get("nat_t_detected", False)))

    # Determine domain validation status
    model_info = meta_data.get("model_information", {})
    domain_status_info = model_info.get("domain_status", {})
    ipsec_val = domain_status_info.get("ipsec_validation")

    if "domain_validation_status" in ipsec_data:
        domain_status = str(ipsec_data["domain_validation_status"])
    elif ipsec_val == "unverified":
        domain_status = "TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED"
    elif ipsec_val == "verified_ipsec":
        domain_status = "VERIFIED_IPSEC"
    elif ipsec_val == "not_applicable_non_ipsec":
        domain_status = "NOT_APPLICABLE"
    elif detected:
        domain_status = "TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED"
    else:
        domain_status = "NOT_APPLICABLE"

    allow_unverified = bool(
        ipsec_data.get("allow_unverified_domain", False)
        or domain_status_info.get("override_used", False)
        or any("override" in str(w).lower() for w in meta_data.get("warnings", []))
    )

    ipsec_facts = IPsecFacts(
        detected=detected,
        esp_detected=esp_detected,
        ah_detected=ah_detected,
        ike_detected=ike_detected,
        nat_t_detected=nat_t_detected,
        domain_validation_status=domain_status,
        allow_unverified_domain=allow_unverified,
    )

    # 4. Classification (Prediction)
    pred_data = phase5_data.get("prediction") or phase5_data.get("classification") or {}
    if not pred_data and raw_flows:
        # Real Phase 5 puts predictions inside flows, with capture summary having traffic_distribution and average_confidence
        traffic_dist = capture_data.get("traffic_distribution", {})
        if traffic_dist:
            dominant_cat = max(traffic_dist.items(), key=lambda x: x[1])[0]
        else:
            dominant_cat = selected_flows[0].predicted_category if selected_flows else "unknown"

        confidence = float(capture_data.get("average_confidence", selected_flows[0].confidence if selected_flows and selected_flows[0].confidence is not None else 0.0))
        predicted_category = dominant_cat or "unknown"
        pred_status = selected_flows[0].prediction_status if selected_flows and selected_flows[0].prediction_status else "COMPLETED"
        probabilities = dict(selected_flows[0].probabilities) if selected_flows else {}
    else:
        predicted_category = str(pred_data.get("predicted_category", pred_data.get("category", pred_data.get("traffic_category", "unknown"))))
        confidence = float(pred_data.get("confidence", 0.0))
        pred_status = str(pred_data.get("prediction_status", "COMPLETED"))
        probabilities = {k: float(v) for k, v in pred_data.get("category_probabilities", pred_data.get("probabilities", {})).items()}

    # Assign confidence tier
    tier = str(pred_data.get("confidence_tier", pred_data.get("confidence_level", "")))
    if not tier:
        if confidence >= 0.80:
            tier = "HIGH"
        elif confidence >= 0.50:
            tier = "MEDIUM"
        else:
            tier = "LOW"

    classification_facts = ClassificationFacts(
        predicted_category=predicted_category,
        confidence=confidence,
        confidence_tier=tier,
        category_probabilities=probabilities,
        prediction_status=pred_status,
    )

    # 5. Behavioral Analysis & Security Assessment
    sec_data = phase5_data.get("security_assessment") or phase5_data.get("risk") or {}
    beh_data = phase5_data.get("behavioral_analysis") or {}

    risk_score = int(
        capture_data.get("overall_risk_score")
        if "overall_risk_score" in capture_data
        else sec_data.get("risk_score", sec_data.get("score", beh_data.get("risk_score", 0)))
    )

    risk_level = str(
        capture_data.get("overall_risk_level")
        if "overall_risk_level" in capture_data
        else sec_data.get("risk_level", sec_data.get("level", sec_data.get("severity", "LOW")))
    ).upper()

    # Extract indicators
    indicators: list[str] = []
    # From capture_summary top_indicators
    for item in capture_data.get("top_indicators", []):
        if isinstance(item, dict) and "indicator_id" in item:
            indicators.append(str(item["indicator_id"]))
        elif isinstance(item, str):
            indicators.append(item)

    # From explicit behavioral_analysis / security_assessment
    for item in beh_data.get("triggered_indicators", sec_data.get("indicators", beh_data.get("indicators", []))):
        if isinstance(item, dict) and "indicator_id" in item:
            ind_id = str(item["indicator_id"])
            if ind_id not in indicators:
                indicators.append(ind_id)
        elif isinstance(item, str) and item not in indicators:
            indicators.append(item)

    # Also collect from all flows
    for f in selected_flows:
        for ind in f.indicators:
            if ind not in indicators:
                indicators.append(ind)

    # Indicator points
    indicator_points = {k: int(v) for k, v in beh_data.get("indicator_points", {}).items()}
    if not indicator_points:
        for f in raw_flows:
            for sc in f.get("security_assessment", {}).get("score_contributions", []):
                if "indicator" in sc and "points" in sc:
                    indicator_points[str(sc["indicator"])] = int(sc["points"])

    behavioral_facts = BehavioralFacts(
        risk_score=risk_score,
        risk_level=risk_level,
        triggered_indicators=indicators,
        indicator_points=indicator_points,
    )

    # 6. Model Uncertainty
    unc_data = phase5_data.get("model_uncertainty") or {}
    if not unc_data and raw_flows:
        unc_data = raw_flows[0].get("model_uncertainty", {})

    entropy = float(unc_data["entropy"]) if "entropy" in unc_data and unc_data["entropy"] is not None else None
    margin = float(unc_data["margin"]) if "margin" in unc_data and unc_data["margin"] is not None else None
    unc_reason = unc_data.get("reason")

    if "level" in unc_data or "uncertainty_level" in unc_data:
        unc_level = str(unc_data.get("level", unc_data.get("uncertainty_level", "LOW"))).upper()
    else:
        # Check flow uncertainty
        has_unc = any(f.uncertainty_present for f in selected_flows)
        if has_unc:
            unc_level = "HIGH" if any("HIGH" in str(flag) for f in selected_flows for flag in f.uncertainty_flags) else "MEDIUM"
            if not unc_reason:
                unc_reason = "Model uncertainty flags observed in active flows."
        else:
            unc_level = "LOW"

    uncertainty_facts = UncertaintyFacts(
        level=unc_level,
        entropy=entropy,
        margin=margin,
        reason=unc_reason,
    )

    # 7. Evaluation Facts
    eval_mode = str(meta_data.get("evaluation_mode", phase5_data.get("evaluation_mode", "GROUP_ISOLATED")))
    provenance = dict(meta_data.get("dataset_provenance", {}))

    evaluation_facts = EvaluationFacts(
        evaluation_mode=eval_mode,
        dataset_provenance=provenance,
    )

    return AnalysisFacts(
        capture=capture_facts,
        ipsec=ipsec_facts,
        classification=classification_facts,
        behavioral=behavioral_facts,
        model_uncertainty=uncertainty_facts,
        evaluation=evaluation_facts,
        selected_flows=selected_flows,
        raw_metadata=meta_data,
    )
