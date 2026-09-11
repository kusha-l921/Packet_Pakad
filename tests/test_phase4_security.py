"""Comprehensive test suite for Phase 4 AI Analysis, Security Assessment, and Integration.

Covers all 20 required specifications:
1. High confidence classification
2. Medium confidence classification
3. Low confidence classification
4. High packet-rate detection
5. High throughput detection
6. Directional asymmetry detection
7. Periodic behavior detection
8. Burst detection
9. Risk score bounds (0-100 clamping)
10. Risk level boundaries (LOW, MEDIUM, HIGH, CRITICAL)
11. Multiple indicator score aggregation and contribution traceability
12. No-indicator baseline case
13. Human-readable explanation generation
14. Feature importance exposure and fallback
15. Capture-level aggregation and percentile blend
16. Strict JSON serialization without NumPy scalar leakage
17. Full Phase 1 -> Phase 4 end-to-end integration
18. Backward compatibility of Phase 1
19. Backward compatibility of Phase 2
20. Backward compatibility of Phase 3
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict
import pytest

from person2_engine.src.behavior_engine import BehaviorEngine
from person2_engine.src.feature_schema import FEATURE_MAP, FEATURE_ORDER, FEATURE_SCHEMA_VERSION
from person2_engine.src.flow_models import (
    FlowMetadata,
    FlowResult,
    FlowSummary,
    FlowValidationResult,
    IPsecFlowMetadata,
)
from person2_engine.src.indicator_engine import IndicatorEngine
from person2_engine.src.packet_analyzer import (
    analyze_capture,
    analyze_capture_with_features,
    analyze_capture_with_predictions,
)
from person2_engine.src.prediction_models import FlowPredictionResult, Prediction
from person2_engine.src.risk_engine import RiskEngine
from person2_engine.src.security_analyzer import (
    aggregate_capture_security,
    analyze_capture_security,
    analyze_flow_security,
)
from person2_engine.src.security_models import (
    BehaviorProfile,
    CaptureSecurityResult,
    CaptureSecuritySummary,
    ConfidenceLevel,
    FlowSecurityResult,
    RiskLevel,
    RiskScore,
    ScoreContribution,
    SecurityIndicator,
    determine_confidence_level,
    determine_risk_level,
)


def make_dummy_features(**overrides) -> Dict[str, float]:
    """Create a canonical 25-feature dictionary using schema defaults and overrides."""
    feats = {name: float(FEATURE_MAP[name].default_value) for name in FEATURE_ORDER}
    for k, v in overrides.items():
        if k in feats:
            feats[k] = float(v)

    # Automatically derive ratios if packet/byte counts are provided and ratios not explicitly given
    if "total_bytes" in overrides and overrides["total_bytes"] > 0:
        tot_b = float(overrides["total_bytes"])
        if "forward_bytes" in overrides and "forward_byte_ratio" not in overrides:
            feats["forward_byte_ratio"] = float(overrides["forward_bytes"]) / tot_b
        if "backward_bytes" in overrides and "backward_byte_ratio" not in overrides:
            feats["backward_byte_ratio"] = float(overrides["backward_bytes"]) / tot_b

    if "total_packets" in overrides and overrides["total_packets"] > 0:
        tot_p = float(overrides["total_packets"])
        if "forward_packets" in overrides and "forward_packet_ratio" not in overrides:
            feats["forward_packet_ratio"] = float(overrides["forward_packets"]) / tot_p
        if "backward_packets" in overrides and "backward_packet_ratio" not in overrides:
            feats["backward_packet_ratio"] = float(overrides["backward_packets"]) / tot_p

    return feats


def make_dummy_flow_result(features: Dict[str, float], flow_id: str = "flow_test_01") -> FlowResult:
    """Construct a mock FlowResult with the provided feature dictionary."""
    meta = FlowMetadata(
        flow_id=flow_id,
        ip_version=4,
        protocol="TCP",
        endpoint_a="192.168.1.100:45000",
        endpoint_b="10.0.0.1:443",
        first_timestamp=1000.0,
        last_timestamp=1010.0,
    )
    ipsec_meta = IPsecFlowMetadata(is_ipsec_related=False)
    return FlowResult(
        flow_metadata=meta,
        ipsec_metadata=ipsec_meta,
        features=features,
        validation=FlowValidationResult(valid=True, errors=[], warnings=[]),
    )


def make_dummy_prediction(
    predicted_category: str = "web",
    confidence: float = 0.85,
    feature_importance: dict | None = None,
) -> FlowPredictionResult:
    """Construct a mock FlowPredictionResult with desired confidence and class."""
    pred = Prediction(
        label=predicted_category,
        class_index=0,
        confidence=float(confidence),
        probabilities={
            "web": 0.85,
            "video": 0.05,
            "voip": 0.05,
            "file_transfer": 0.03,
            "interactive": 0.02,
        },
    )
    return FlowPredictionResult(
        model_status="READY_FOR_INFERENCE",
        prediction=pred,
        model_info={"model_id": "test_rf_model", "model_version": "1.0"},
        domain_status={"ipsec_validation": "unverified"},
        feature_importance=feature_importance if feature_importance is not None else {"bytes_per_second": 0.35, "mean_packet_size": 0.25},
    )


# --------------------------------------------------------------------------
# Requirement 1, 2, 3: Confidence Level Categorization
# --------------------------------------------------------------------------

def test_01_high_confidence_classification():
    """Verify confidence >= 0.80 maps deterministically to HIGH."""
    assert determine_confidence_level(0.80) == ConfidenceLevel.HIGH
    assert determine_confidence_level(0.95) == ConfidenceLevel.HIGH
    assert determine_confidence_level(1.0) == ConfidenceLevel.HIGH


def test_02_medium_confidence_classification():
    """Verify 0.50 <= confidence < 0.80 maps deterministically to MEDIUM."""
    assert determine_confidence_level(0.50) == ConfidenceLevel.MEDIUM
    assert determine_confidence_level(0.7999) == ConfidenceLevel.MEDIUM
    assert determine_confidence_level(0.65) == ConfidenceLevel.MEDIUM


def test_03_low_confidence_classification():
    """Verify confidence < 0.50 maps to LOW and populates model_uncertainty without affecting behavioral risk."""
    assert determine_confidence_level(0.49) == ConfidenceLevel.LOW
    assert determine_confidence_level(0.12) == ConfidenceLevel.LOW
    assert determine_confidence_level(0.0) == ConfidenceLevel.LOW

    # Indicator engine evaluates ONLY behavioral features (returns no behavioral indicators for quiet flows)
    i_engine = IndicatorEngine()
    feats = make_dummy_features()
    indicators, contribs = i_engine.evaluate_indicators(feats)
    assert len(indicators) == 0
    assert len(contribs) == 0

    # Flow security assessment evaluates model_uncertainty in an independent path
    flow = make_dummy_flow_result(feats)
    pred = make_dummy_prediction(predicted_category="unknown", confidence=0.35)
    f_sec = analyze_flow_security(flow, pred)

    assert f_sec.model_uncertainty["present"] is True
    assert f_sec.model_uncertainty["flags"][0]["code"] == "LOW_CLASSIFICATION_CONFIDENCE"
    assert f_sec.security_assessment["risk_score"] == 0
    assert len(f_sec.security_assessment["indicators"]) == 0


# --------------------------------------------------------------------------
# Requirement 4: High Packet-Rate Detection
# --------------------------------------------------------------------------

def test_04_high_packet_rate_detection():
    """Verify flow with packets_per_second >= 100 triggers behavioral observation and indicator."""
    b_engine = BehaviorEngine()
    i_engine = IndicatorEngine()

    feats = make_dummy_features(packets_per_second=260.0, total_packets=500.0)
    profile = b_engine.analyze_flow_behavior(feats)
    assert "HIGH_PACKET_RATE" in profile.observations

    indicators, contribs = i_engine.evaluate_indicators(feats)
    ind_ids = [ind.indicator_id for ind in indicators]
    assert "UNUSUAL_HIGH_PACKET_RATE" in ind_ids
    ind = next(i for i in indicators if i.indicator_id == "UNUSUAL_HIGH_PACKET_RATE")
    assert ind.severity == "MEDIUM"
    rate_contrib = next(c for c in contribs if c.indicator == "UNUSUAL_HIGH_PACKET_RATE")
    assert rate_contrib.points == 20
    assert ind.supporting_features["packets_per_second"] == 260.0


# --------------------------------------------------------------------------
# Requirement 5: High Byte Throughput Detection
# --------------------------------------------------------------------------

def test_05_high_throughput_detection():
    """Verify flow with bytes_per_second >= 500,000 triggers HIGH_BYTE_THROUGHPUT observation."""
    b_engine = BehaviorEngine()
    feats = make_dummy_features(bytes_per_second=750000.0, total_bytes=1500000.0)
    profile = b_engine.analyze_flow_behavior(feats)
    assert "HIGH_BYTE_THROUGHPUT" in profile.observations


# --------------------------------------------------------------------------
# Requirement 6: Directional Asymmetry Detection
# --------------------------------------------------------------------------

def test_06_directional_asymmetry_detection():
    """Verify strong directional ratio triggers asymmetry observations and indicators."""
    b_engine = BehaviorEngine()
    i_engine = IndicatorEngine()

    # Upload asymmetry: forward_bytes >= 85% of total
    feats_upload = make_dummy_features(
        forward_packets=95.0,
        backward_packets=5.0,
        total_packets=100.0,
        forward_bytes=90000.0,
        backward_bytes=2000.0,
        total_bytes=92000.0,
    )
    prof_up = b_engine.analyze_flow_behavior(feats_upload)
    assert "HIGH_DIRECTIONAL_ASYMMETRY" in prof_up.observations
    assert "ASYMMETRIC_UPLOAD_PATTERN" in prof_up.observations

    indicators, contribs = i_engine.evaluate_indicators(feats_upload)
    assert "STRONG_DIRECTIONAL_ASYMMETRY" in [i.indicator_id for i in indicators]

    # Download asymmetry: backward_bytes >= 85% of total
    feats_down = make_dummy_features(
        forward_packets=10.0,
        backward_packets=90.0,
        total_packets=100.0,
        forward_bytes=4000.0,
        backward_bytes=80000.0,
        total_bytes=84000.0,
    )
    prof_down = b_engine.analyze_flow_behavior(feats_down)
    assert "HIGH_DIRECTIONAL_ASYMMETRY" in prof_down.observations
    assert "ASYMMETRIC_DOWNLOAD_PATTERN" in prof_down.observations


# --------------------------------------------------------------------------
# Requirement 7: Periodic Behavior Detection
# --------------------------------------------------------------------------

def test_07_periodic_behavior_detection():
    """Verify low inter-arrival time standard deviation identifies periodic pacing."""
    b_engine = BehaviorEngine()
    i_engine = IndicatorEngine()

    # Low variance IAT + small bytes triggers PERIODIC_LOW_VOLUME_ACTIVITY indicator
    feats = make_dummy_features(
        standard_deviation_inter_arrival_time=0.015,
        mean_inter_arrival_time=0.5,
        total_packets=30.0,
        total_bytes=1500.0,
        flow_duration_seconds=15.0,
    )
    prof = b_engine.analyze_flow_behavior(feats)
    assert "PERIODIC_TRAFFIC_PATTERN" in prof.observations

    indicators, _ = i_engine.evaluate_indicators(feats)
    assert "PERIODIC_LOW_VOLUME_ACTIVITY" in [i.indicator_id for i in indicators]


# --------------------------------------------------------------------------
# Requirement 8: Burst Detection
# --------------------------------------------------------------------------

def test_08_burst_detection():
    """Verify short duration with high packet density triggers burst behavior."""
    b_engine = BehaviorEngine()
    i_engine = IndicatorEngine()

    feats = make_dummy_features(
        flow_duration_seconds=0.8,
        total_packets=80.0,
        packets_per_second=100.0,
        maximum_packets_in_one_second=70.0,
    )
    prof = b_engine.analyze_flow_behavior(feats)
    assert "SHORT_BURSTY_FLOW" in prof.observations
    assert "HIGH_TRAFFIC_BURST" in prof.observations

    indicators, _ = i_engine.evaluate_indicators(feats)
    assert "UNUSUAL_BURST_ACTIVITY" in [i.indicator_id for i in indicators]


# --------------------------------------------------------------------------
# Requirement 9 & 10: Risk Score Bounds and Level Boundaries
# --------------------------------------------------------------------------

def test_09_risk_score_clamping():
    """Verify risk score is strictly clamped between 0 and 100 even if contributions exceed 100."""
    contribs = [
        ScoreContribution("TEST_1", 40, "high"),
        ScoreContribution("TEST_2", 40, "high"),
        ScoreContribution("TEST_3", 35, "high"),
    ]
    # Total sum is 115, must clamp to 100
    res = RiskEngine.calculate_risk_score(contribs)
    assert res.total_score == 100
    assert res.risk_level == "CRITICAL"
    assert len(res.contributions) == 3


def test_10_risk_level_boundaries():
    """Verify boundary thresholds: 0-24 -> LOW, 25-49 -> MEDIUM, 50-74 -> HIGH, 75-100 -> CRITICAL."""
    assert determine_risk_level(0) == RiskLevel.LOW
    assert determine_risk_level(24) == RiskLevel.LOW
    assert determine_risk_level(25) == RiskLevel.MEDIUM
    assert determine_risk_level(49) == RiskLevel.MEDIUM
    assert determine_risk_level(50) == RiskLevel.HIGH
    assert determine_risk_level(74) == RiskLevel.HIGH
    assert determine_risk_level(75) == RiskLevel.CRITICAL
    assert determine_risk_level(100) == RiskLevel.CRITICAL


# --------------------------------------------------------------------------
# Requirement 11: Multiple Indicator Score Aggregation & Traceability
# --------------------------------------------------------------------------

def test_11_multiple_indicator_aggregation():
    """Verify multiple triggered indicators aggregate additively and trace each point contribution."""
    i_engine = IndicatorEngine()
    feats = make_dummy_features(
        packets_per_second=260.0,   # UNUSUAL_HIGH_PACKET_RATE (20 pts)
        forward_bytes=2500000.0,    # UNUSUAL_HIGH_UPLOAD_VOLUME (25 pts)
        total_bytes=2600000.0,
        flow_duration_seconds=1.0,
        total_packets=260.0,
        maximum_packets_in_one_second=200.0,  # UNUSUAL_BURST_ACTIVITY (15 pts)
    )
    indicators, contribs = i_engine.evaluate_indicators(feats)
    score_res = RiskEngine.calculate_risk_score(contribs)

    # 20 + 25 + 15 = 60
    assert score_res.total_score == 60
    assert score_res.risk_level == "HIGH"
    assert len(score_res.contributions) >= 3

    # Ensure contribution dict matches indicators
    for c in score_res.contributions:
        assert c.indicator in [ind.indicator_id for ind in indicators]
        assert c.points > 0


# --------------------------------------------------------------------------
# Requirement 12: No Indicator Baseline Case
# --------------------------------------------------------------------------

def test_12_no_indicator_baseline():
    """Verify completely benign/quiet flow yields 0 risk score, LOW level, and reassuring explanation."""
    flow = make_dummy_flow_result(make_dummy_features())
    pred = make_dummy_prediction(confidence=0.92)

    f_sec = analyze_flow_security(flow, pred)
    assert f_sec.security_assessment["risk_score"] == 0
    assert f_sec.security_assessment["risk_level"] == "LOW"
    assert len(f_sec.security_assessment["indicators"]) == 0
    assert "No elevated behavioral risk indicators" in f_sec.explainability["summary"]


# --------------------------------------------------------------------------
# Requirement 13: Human-Readable Explanation Generation
# --------------------------------------------------------------------------

def test_13_explanation_generation():
    """Verify narrative is grounded in factual features, classification, and triggered indicators."""
    flow = make_dummy_flow_result(
        make_dummy_features(
            packets_per_second=300.0,
            forward_bytes=3000000.0,
            total_bytes=3100000.0,
            total_packets=300.0,
        )
    )
    pred = make_dummy_prediction(predicted_category="video", confidence=0.88)
    f_sec = analyze_flow_security(flow, pred)

    summary = f_sec.explainability["summary"]
    assert "video" in summary
    assert "high confidence" in summary.lower()
    assert "risk" in summary.lower()
    assert "UNUSUAL_HIGH_UPLOAD_VOLUME" in summary or "UNUSUAL_HIGH_PACKET_RATE" in summary


# --------------------------------------------------------------------------
# Requirement 14: Feature Importance Output & Fallback
# --------------------------------------------------------------------------

def test_14_feature_importance_output():
    """Verify feature importances are exposed and sorted by absolute magnitude."""
    importances = {
        "bytes_per_second": 0.12,
        "mean_packet_size": 0.45,
        "backward_packet_ratio": -0.32,
        "flow_duration_seconds": 0.05,
        "total_packets": 0.01,
        "min_packet_size": 0.005,
    }
    flow = make_dummy_flow_result(make_dummy_features())
    pred = make_dummy_prediction(feature_importance=importances)
    f_sec = analyze_flow_security(flow, pred)

    top_feats = f_sec.explainability["important_features"]
    assert len(top_feats) <= 5
    assert top_feats[0]["feature_name"] == "mean_packet_size"
    assert top_feats[1]["feature_name"] == "backward_packet_ratio"


def test_14_feature_importance_fallback():
    """Verify safe fallback when model provides empty feature importances."""
    flow = make_dummy_flow_result(make_dummy_features())
    pred = make_dummy_prediction(feature_importance={})
    f_sec = analyze_flow_security(flow, pred)
    assert f_sec.explainability["important_features"] == []


# --------------------------------------------------------------------------
# Requirement 15: Capture-Level Aggregation & Percentile Blend
# --------------------------------------------------------------------------

def test_15_capture_level_aggregation():
    """Verify capture summary calculates risk distribution, traffic distribution, and blended score."""
    flows = []
    # 9 benign flows (score 0)
    for i in range(9):
        f = make_dummy_flow_result(make_dummy_features(), flow_id=f"benign_{i}")
        p = make_dummy_prediction(predicted_category="web", confidence=0.85)
        flows.append(analyze_flow_security(f, p))

    # 1 critical flow (score >= 75)
    crit_feat = make_dummy_features(
        packets_per_second=300.0,
        forward_bytes=3500000.0,
        total_bytes=3600000.0,
        flow_duration_seconds=120.0,
        total_packets=36000.0,
        maximum_packets_in_one_second=200.0,
    )
    f_crit = make_dummy_flow_result(crit_feat, flow_id="crit_0")
    p_crit = make_dummy_prediction(predicted_category="file_transfer", confidence=0.45)
    flows.append(analyze_flow_security(f_crit, p_crit))

    summary = aggregate_capture_security(flows, None)

    assert summary.total_flows == 10
    assert summary.risk_distribution["LOW"] == 9
    assert summary.traffic_distribution["web"] == 9
    assert summary.traffic_distribution["file_transfer"] == 1
    # Critical flow is preserved by percentile-blend (must not dilute to < 10)
    assert summary.overall_risk_score >= 50
    assert len(summary.top_indicators) > 0


# --------------------------------------------------------------------------
# Requirement 16: Strict JSON Serialization
# --------------------------------------------------------------------------

def test_16_json_serialization(tmp_path: Path):
    """Verify CaptureSecurityResult serializes to valid JSON without NumPy scalar exceptions."""
    flow = make_dummy_flow_result(make_dummy_features())
    pred = make_dummy_prediction()
    f_sec = analyze_flow_security(flow, pred)
    summary = aggregate_capture_security([f_sec], None)

    cap_res = CaptureSecurityResult(
        analysis_metadata={"test": True, "total_packets": 50},
        model_information={"model_id": "test_m"},
        capture_summary=summary,
        flows=[f_sec],
    )

    json_str = cap_res.to_json(indent=2)
    # Parse back with standard library json
    parsed = json.loads(json_str)
    assert parsed["schema_version"] == "1.0"
    assert "capture_summary" in parsed
    assert "flows" in parsed
    assert parsed["capture_summary"]["total_flows"] == 1
    assert parsed["flows"][0]["security_assessment"]["risk_level"] == "LOW"

    # Test file saving
    out_file = tmp_path / "sec_out.json"
    cap_res.to_json_file(out_file)
    assert out_file.is_file()
    assert json.loads(out_file.read_text(encoding="utf-8"))["schema_version"] == "1.0"


# --------------------------------------------------------------------------
# Requirement 17: Full Phase 1 -> Phase 4 End-to-End Integration
# --------------------------------------------------------------------------

def test_17_full_pipeline_integration(valid_basic_pcap: Path, tmp_path: Path):
    """Verify analyze_capture_security executes all 4 phases and produces valid assessment."""
    out_json = tmp_path / "integration_assessment.json"
    sec_res = analyze_capture_security(
        file_path=valid_basic_pcap,
        output_json=out_json,
        allow_unverified_domain=True,
    )

    assert isinstance(sec_res, CaptureSecurityResult)
    assert sec_res.analysis_metadata["analysis_status"] == "SUCCESS"
    assert sec_res.analysis_metadata["total_packets"] == 5
    assert sec_res.capture_summary.total_flows > 0
    assert 0 <= sec_res.capture_summary.overall_risk_score <= 100
    assert sec_res.capture_summary.overall_risk_level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert out_json.is_file()

    with open(out_json, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["capture_summary"]["total_flows"] == sec_res.capture_summary.total_flows


# --------------------------------------------------------------------------
# Requirements 18, 19, 20: Backward Compatibility of Phase 1, 2, 3
# --------------------------------------------------------------------------

def test_18_backward_compatibility_phase1(valid_basic_pcap: Path):
    """Verify Phase 1 analyze_capture interface remains 100% intact and functional."""
    p1 = analyze_capture(valid_basic_pcap)
    assert p1.status.success is True
    assert p1.capture_info.total_packets == 5
    assert hasattr(p1, "ipsec_analysis")
    assert hasattr(p1, "protocol_summary")


def test_19_backward_compatibility_phase2(valid_basic_pcap: Path):
    """Verify Phase 2 analyze_capture_with_features interface remains 100% intact and functional."""
    p2 = analyze_capture_with_features(valid_basic_pcap)
    assert p2.analysis.status.success is True
    assert p2.feature_schema_version == FEATURE_SCHEMA_VERSION
    assert p2.flow_summary.total_flows > 0
    for flow in p2.flows:
        assert len(flow.features) == 25
        assert flow.validation.valid is True


def test_20_backward_compatibility_phase3(valid_basic_pcap: Path):
    """Verify Phase 3 analyze_capture_with_predictions interface remains 100% intact and functional."""
    p3 = analyze_capture_with_predictions(valid_basic_pcap, allow_unverified_domain=True)
    assert p3.capture_features.analysis.status.success is True
    assert p3.prediction_summary.total_flows > 0
    for pred in p3.predictions:
        assert hasattr(pred, "model_status")
        if pred.prediction:
            assert hasattr(pred.prediction, "confidence")
            assert hasattr(pred.prediction, "label")


# --------------------------------------------------------------------------
# Section 10 Tests: Decoupling Model Uncertainty from Behavioral Risk
# --------------------------------------------------------------------------

def test_phase4_correction_test1_low_confidence_alone():
    """Test 1 — Low Confidence Alone: Low confidence without anomalies yields 0 risk points and LOW risk level."""
    flow = make_dummy_flow_result(make_dummy_features())
    pred = make_dummy_prediction(predicted_category="unknown", confidence=0.32)

    f_sec = analyze_flow_security(flow, pred)

    assert f_sec.model_uncertainty["present"] is True
    assert len(f_sec.model_uncertainty["flags"]) == 1
    assert f_sec.model_uncertainty["flags"][0]["code"] == "LOW_CLASSIFICATION_CONFIDENCE"
    assert f_sec.model_uncertainty["flags"][0]["severity"] == "INFO"

    # MUST NOT add risk points
    assert f_sec.security_assessment["risk_score"] == 0
    assert f_sec.security_assessment["risk_level"] == "LOW"


def test_phase4_correction_test2_low_confidence_plus_behavioral_indicator():
    """Test 2 — Low Confidence + Behavioral Indicator: Risk score is calculated ONLY from behavioral indicator."""
    feats = make_dummy_features(packets_per_second=260.0, total_packets=500.0)  # UNUSUAL_HIGH_PACKET_RATE (20 points)
    flow = make_dummy_flow_result(feats)
    pred = make_dummy_prediction(predicted_category="unknown", confidence=0.35)

    f_sec = analyze_flow_security(flow, pred)

    assert f_sec.model_uncertainty["present"] is True
    # Risk score must be exactly 20 (from UNUSUAL_HIGH_PACKET_RATE), 0 from low confidence
    assert f_sec.security_assessment["risk_score"] == 20
    assert f_sec.security_assessment["risk_level"] == "LOW"  # 20 < 25 -> LOW risk tier


def test_phase4_correction_test3_high_confidence_plus_behavioral_indicator():
    """Test 3 — High Confidence + Behavioral Indicator: High confidence does not suppress real behavioral indicators."""
    feats = make_dummy_features(
        forward_bytes=250000.0,
        total_bytes=280000.0,
    )  # UNUSUAL_HIGH_UPLOAD_VOLUME (25 points)
    flow = make_dummy_flow_result(feats)
    pred = make_dummy_prediction(predicted_category="web", confidence=0.92)

    f_sec = analyze_flow_security(flow, pred)

    assert f_sec.model_uncertainty["present"] is False
    assert f_sec.security_assessment["risk_score"] == 25
    assert f_sec.security_assessment["risk_level"] == "MEDIUM"


def test_phase4_correction_test4_json_separation():
    """Test 4 — JSON Separation: Model uncertainty and behavioral risk are exposed in separate keys."""
    flow = make_dummy_flow_result(make_dummy_features())
    pred = make_dummy_prediction(predicted_category="unknown", confidence=0.40)

    f_sec = analyze_flow_security(flow, pred)
    d = f_sec.to_dict()

    assert "model_uncertainty" in d
    assert "security_assessment" in d
    assert d["model_uncertainty"]["present"] is True
    assert d["security_assessment"]["risk_score"] == 0
    assert d["security_assessment"]["risk_level"] == "LOW"


def test_phase4_audit_test_c_risk_engine_isolation():
    """Test C — RiskEngine Isolation: RiskEngine never receives model uncertainty as a behavioral indicator."""
    i_engine = IndicatorEngine()
    feats = make_dummy_features(packets_per_second=260.0, total_packets=500.0)
    indicators, contribs = i_engine.evaluate_indicators(feats)

    # Verify IndicatorEngine produces ONLY behavioral indicators
    ind_ids = [ind.indicator_id for ind in indicators]
    assert "LOW_CLASSIFICATION_CONFIDENCE" not in ind_ids

    # Verify RiskEngine input contains ONLY behavioral contributions
    contrib_ids = [c.indicator for c in contribs]
    assert "LOW_CLASSIFICATION_CONFIDENCE" not in contrib_ids

    score_res = RiskEngine.calculate_risk_score(contribs)
    assert score_res.total_score == 20
    assert all(c.indicator != "LOW_CLASSIFICATION_CONFIDENCE" for c in score_res.contributions)


def test_phase4_audit_test_d_uncertainty_invariance():
    """Test D — Uncertainty Invariance: Changing confidence alone leaves risk_score, risk_level, and score_contributions identical."""
    feats = make_dummy_features(packets_per_second=260.0, total_packets=500.0)
    flow = make_dummy_flow_result(feats)

    pred_low = make_dummy_prediction(predicted_category="unknown", confidence=0.20)
    pred_high = make_dummy_prediction(predicted_category="web", confidence=0.95)

    res_low = analyze_flow_security(flow, pred_low)
    res_high = analyze_flow_security(flow, pred_high)

    # Behavioral risk assessment must be 100% identical
    assert res_low.security_assessment["risk_score"] == res_high.security_assessment["risk_score"] == 20
    assert res_low.security_assessment["risk_level"] == res_high.security_assessment["risk_level"] == "LOW"
    assert res_low.security_assessment["score_contributions"] == res_high.security_assessment["score_contributions"]

    # Model uncertainty differs appropriately in its independent path
    assert res_low.model_uncertainty["present"] is True
    assert res_high.model_uncertainty["present"] is False


