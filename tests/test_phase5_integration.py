"""Comprehensive test suite for Phase 5 End-to-End Integration, Output Contract & Validation.

Covers all requirements:
1. Complete 5-phase pipeline execution
2. Strict JSON serialization
3. Schema version verification (INTEGRATION_SCHEMA_VERSION == "1.0")
4. Feature schema version verification (FEATURE_SCHEMA_VERSION == "1.0")
5. Model uncertainty isolation (zero points, separate path, no contamination)
6. Behavioral risk functionality
7. Empty capture and zero-flow capture handling
8. Invalid file path and error contract
9. Full backward compatibility of Phase 1, 2, 3, and 4
10. Integration validator correctness
11. CLI --complete mode verification
"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import pytest

from person2_engine import (
    FEATURE_SCHEMA_VERSION,
    INTEGRATION_SCHEMA_VERSION,
    UnifiedCaptureResult,
    UnifiedFlowResult,
    analyze_capture,
    analyze_capture_complete,
    analyze_capture_security,
    analyze_capture_with_features,
    analyze_capture_with_predictions,
    validate_integration_result,
)
from person2_engine.src.integration_models import _clean_json_value
from person2_engine.src.integration_validator import IntegrationValidationReport


# --------------------------------------------------------------------------
# Test 1: Complete Pipeline End-to-End Execution
# --------------------------------------------------------------------------

def test_01_complete_pipeline_execution(valid_basic_pcap: Path, tmp_path: Path):
    """Test 1: Verify analyze_capture_complete executes all 5 phases and returns valid UnifiedCaptureResult."""
    out_json = tmp_path / "phase5_out.json"
    result = analyze_capture_complete(
        file_path=valid_basic_pcap,
        output_json=out_json,
        allow_unverified_domain=True,
    )

    assert isinstance(result, UnifiedCaptureResult)
    assert result.integration_schema_version == "1.0"
    assert result.analysis_metadata["file_name"] == valid_basic_pcap.name
    assert result.analysis_metadata["analysis_status"] == "SUCCESS"
    assert result.analysis_metadata["total_packets"] == 5

    assert "total_flows" in result.capture_summary
    assert result.capture_summary["total_flows"] == 5
    assert "ipsec_detected" in result.ipsec_analysis

    assert len(result.flows) == 5
    for f in result.flows:
        assert isinstance(f, UnifiedFlowResult)
        assert f.flow_id.startswith(("TCP_", "UDP_", "ICMP_", "ICMPV6_"))
        assert len(f.features) == 25
        assert "confidence" in f.prediction
        assert "present" in f.model_uncertainty
        assert "risk_score" in f.security_assessment
        assert isinstance(f.summary, str) and len(f.summary) > 0

    assert out_json.is_file()


# --------------------------------------------------------------------------
# Test 2: Strict JSON Serialization
# --------------------------------------------------------------------------

def test_02_json_serialization(valid_basic_pcap: Path):
    """Test 2: Verify json.dumps(result.to_dict()) succeeds without any TypeError."""
    result = analyze_capture_complete(valid_basic_pcap, allow_unverified_domain=True)
    d = result.to_dict()

    # Must serialize without TypeError
    json_str = json.dumps(d, indent=2)
    assert isinstance(json_str, str)

    # Must parse back cleanly into dict
    parsed = json.loads(json_str)
    assert parsed["integration_schema_version"] == "1.0"
    assert len(parsed["flows"]) == 5
    assert parsed["capture_summary"]["total_flows"] == 5


# --------------------------------------------------------------------------
# Test 3 & 4: Schema Version & Feature Version Invariants
# --------------------------------------------------------------------------

def test_03_schema_version_invariant(valid_basic_pcap: Path):
    """Test 3: Verify INTEGRATION_SCHEMA_VERSION == '1.0'."""
    assert INTEGRATION_SCHEMA_VERSION == "1.0"
    result = analyze_capture_complete(valid_basic_pcap, allow_unverified_domain=True)
    assert result.integration_schema_version == "1.0"
    assert result.to_dict()["integration_schema_version"] == "1.0"


def test_04_feature_schema_version_invariant(valid_basic_pcap: Path):
    """Test 4: Verify FEATURE_SCHEMA_VERSION == '1.0' and every flow contains 25 valid features."""
    assert FEATURE_SCHEMA_VERSION == "1.0"
    result = analyze_capture_complete(valid_basic_pcap, allow_unverified_domain=True)
    assert result.analysis_metadata["model_information"]["feature_schema_version"] == "1.0"
    for flow in result.flows:
        assert len(flow.features) == 25
        for feat_name, val in flow.features.items():
            assert isinstance(val, (int, float))
            assert not (val != val)  # not NaN


# --------------------------------------------------------------------------
# Test 5: Model Uncertainty Isolation
# --------------------------------------------------------------------------

def test_05_model_uncertainty_isolation(valid_basic_pcap: Path):
    """Test 5: Verify low classification confidence does not contaminate behavioral risk."""
    result = analyze_capture_complete(valid_basic_pcap, allow_unverified_domain=True)

    disallowed_codes = {"LOW_CLASSIFICATION_CONFIDENCE", "MODEL_UNCERTAINTY"}

    for flow in result.flows:
        # If model uncertainty is present
        if flow.model_uncertainty["present"]:
            # Risk score must be purely behavioral (0 for quiet flows)
            assert flow.security_assessment["risk_score"] == 0
            assert flow.security_assessment["risk_level"] == "LOW"

            # Must NEVER appear in behavioral indicators
            ind_ids = [ind["indicator_id"] for ind in flow.security_assessment["indicators"]]
            for code in disallowed_codes:
                assert code not in ind_ids

            # Must NEVER appear in score contributions
            contrib_ids = [c["indicator"] for c in flow.security_assessment["score_contributions"]]
            for code in disallowed_codes:
                assert code not in contrib_ids


# --------------------------------------------------------------------------
# Test 6: Behavioral Risk Functionality
# --------------------------------------------------------------------------

def test_06_behavioral_risk_still_works():
    """Test 6: Verify a genuine behavioral anomaly triggers risk score normally."""
    from person2_engine.src.behavior_engine import BehaviorEngine
    from person2_engine.src.indicator_engine import IndicatorEngine
    from person2_engine.src.risk_engine import RiskEngine

    i_engine = IndicatorEngine()
    # High packet rate feature trigger
    feats = {
        "total_packets": 500.0,
        "packets_per_second": 260.0,
        "flow_duration_seconds": 2.0,
        "forward_bytes": 1000.0,
        "total_bytes": 2000.0,
        "forward_byte_ratio": 0.5,
        "backward_byte_ratio": 0.5,
        "maximum_packets_in_one_second": 10.0,
        "standard_deviation_inter_arrival_time": 0.1,
        "mean_inter_arrival_time": 0.1,
    }
    indicators, contribs = i_engine.evaluate_indicators(feats)
    score_res = RiskEngine.calculate_risk_score(contribs)

    assert score_res.total_score == 20
    assert any(ind.indicator_id == "UNUSUAL_HIGH_PACKET_RATE" for ind in indicators)


# --------------------------------------------------------------------------
# Test 7: Empty Capture & Zero-Flow Capture Handling
# --------------------------------------------------------------------------

def test_07_empty_capture_handling(tmp_path: Path):
    """Test 7: Verify empty PCAP returns structured valid result without crashing."""
    empty_pcap = tmp_path / "empty.pcap"
    # Create empty 0-byte file
    empty_pcap.touch()

    result = analyze_capture_complete(empty_pcap, allow_unverified_domain=True)
    assert isinstance(result, UnifiedCaptureResult)
    assert result.analysis_metadata["total_packets"] == 0
    assert result.capture_summary["total_flows"] == 0
    assert len(result.flows) == 0

    # JSON serialization still succeeds
    json_str = result.to_json()
    assert '"total_flows": 0' in json_str


# --------------------------------------------------------------------------
# Test 8: Invalid File Error Handling Contract
# --------------------------------------------------------------------------

def test_08_invalid_file_handling():
    """Test 8: Verify non-existent file path raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        analyze_capture_complete("non_existent_file_path_12345.pcap")


# --------------------------------------------------------------------------
# Test 9: Backward Compatibility of Phase 1, 2, 3, 4
# --------------------------------------------------------------------------

def test_09_backward_compatibility(valid_basic_pcap: Path):
    """Test 9: Verify Phase 1, 2, 3, and 4 public APIs remain 100% functional."""
    # Phase 1
    p1 = analyze_capture(valid_basic_pcap)
    assert p1.status.success is True

    # Phase 2
    p2 = analyze_capture_with_features(valid_basic_pcap)
    assert p2.analysis.status.success is True

    # Phase 3
    p3 = analyze_capture_with_predictions(valid_basic_pcap, allow_unverified_domain=True)
    assert p3.capture_features.analysis.status.success is True

    # Phase 4
    p4 = analyze_capture_security(valid_basic_pcap, allow_unverified_domain=True)
    assert p4.analysis_metadata["analysis_status"] == "SUCCESS"


# --------------------------------------------------------------------------
# Test 10: Integration Validator Checks
# --------------------------------------------------------------------------

def test_10_integration_validator(valid_basic_pcap: Path):
    """Test 10: Verify validate_integration_result passes for valid result and catches corruptions."""
    result = analyze_capture_complete(valid_basic_pcap, allow_unverified_domain=True)
    report = validate_integration_result(result)
    assert report.valid is True
    assert len(report.errors) == 0

    # Test error detection on corrupted dictionary
    bad_data = result.to_dict()
    # 1. Invalid schema version
    bad_data["integration_schema_version"] = "99.0"
    rep_bad = validate_integration_result(bad_data)
    assert rep_bad.valid is False
    assert any("Unsupported integration_schema_version" in e for e in rep_bad.errors)

    # 2. Contaminated uncertainty in behavioral indicators
    bad_data2 = result.to_dict()
    bad_data2["flows"][0]["security_assessment"]["indicators"].append(
        {"indicator_id": "LOW_CLASSIFICATION_CONFIDENCE", "severity": "INFO"}
    )
    rep_bad2 = validate_integration_result(bad_data2)
    assert rep_bad2.valid is False
    assert any("CRITICAL ARCHITECTURAL LEAKAGE" in e for e in rep_bad2.errors)


# --------------------------------------------------------------------------
# Test 11: CLI --complete Flag Execution
# --------------------------------------------------------------------------

def test_11_cli_complete_flag(valid_basic_pcap: Path, tmp_path: Path):
    """Test 11: Verify CLI python main.py <pcap> --complete --output <json> succeeds."""
    out_json = tmp_path / "cli_complete_out.json"
    cmd = [
        sys.executable,
        "main.py",
        str(valid_basic_pcap),
        "--complete",
        "--output",
        str(out_json),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 0, f"CLI stderr: {proc.stderr}"
    assert "PHASE 5: UNIFIED NETWORK TRAFFIC ANALYSIS & SECURITY REPORT" in proc.stdout
    assert out_json.is_file()

    with open(out_json, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["integration_schema_version"] == "1.0"
    assert data["capture_summary"]["total_flows"] == 5


# --------------------------------------------------------------------------
# Tests 12 to 18: Mandatory IPsec Domain Policy Verification
# --------------------------------------------------------------------------

def test_12_domain_policy_non_ipsec_inference_works(valid_basic_pcap: Path):
    """Domain Policy Criterion 1: Non-IPsec capture + normal model -> inference works without override."""
    result = analyze_capture_complete(valid_basic_pcap, allow_unverified_domain=False)
    assert result.analysis_metadata["analysis_status"] == "SUCCESS"
    assert len(result.flows) == 5
    for f in result.flows:
        # Standard non-IPsec flow must execute inference
        assert f.prediction["prediction_status"] != "TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED"
        assert f.prediction["traffic_category"] in {"web", "video", "voip", "file_transfer", "interactive"}
        assert 0.0 <= f.prediction["confidence"] <= 1.0


def test_13_domain_policy_ipsec_verified_model_works():
    """Domain Policy Criterion 2: IPsec capture + verified IPsec model -> inference works without override."""
    from person2_engine.src.model_registry import default_registry
    from person2_engine.src.model_adapter import DummyTestModelAdapter
    from person2_engine.src.model_metadata import ModelMetadata
    from person2_engine.src.feature_schema import FEATURE_ORDER

    verified_meta = ModelMetadata(
        model_id="verified_ipsec_test_model",
        model_name="Verified IPsec Model",
        model_version="1.0.0",
        model_type="rule_based_stub",
        prediction_task="application_category",
        input_type="flow_features",
        feature_schema_version="1.0",
        feature_names=list(FEATURE_ORDER),
        feature_count=25,
        preprocessing={"type": "identity"},
        labels={"0": "web", "1": "video", "2": "voip", "3": "file_transfer", "4": "interactive"},
        ipsec_compatibility={"level": "verified_ipsec"},
        artifact_path="in_memory",
        is_test_only=True,
    )
    adapter = DummyTestModelAdapter(verified_meta)
    default_registry.register_adapter(adapter)

    # IPsec PCAP evaluated with verified model should succeed even when allow_unverified_domain=False
    result = analyze_capture_complete(
        "sample_data/ipsec_esp.pcap",
        model_id="verified_ipsec_test_model",
        allow_unverified_domain=False,
        allow_test_models=True,
    )
    assert len(result.flows) == 1
    flow = result.flows[0]
    assert flow.prediction["traffic_category"] in {"web", "video", "voip", "file_transfer", "interactive"}
    assert flow.prediction["prediction_status"] != "TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED"


def test_14_domain_policy_ipsec_unverified_blocked():
    """Domain Policy Criterion 3: IPsec capture + unverified model + opt-in false -> inference blocked/safely represented."""
    result = analyze_capture_complete("sample_data/ipsec_esp.pcap", allow_unverified_domain=False)
    assert len(result.flows) == 1
    flow = result.flows[0]

    # Model inference MUST be blocked
    assert flow.prediction["prediction_status"] == "TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED"
    assert flow.prediction["traffic_category"] == "unclassified"
    assert flow.prediction["confidence"] == 0.0
    assert flow.prediction["probabilities"] == {}

    # Behavioral risk analysis MUST still execute on observable features
    assert flow.security_assessment["risk_score"] > 0
    assert any(ind["indicator_id"] == "UNUSUAL_HIGH_PACKET_RATE" for ind in flow.security_assessment["indicators"])


def test_15_domain_policy_ipsec_unverified_override():
    """Domain Policy Criterion 4: IPsec capture + unverified model + opt-in true -> inference allowed with warning."""
    result = analyze_capture_complete("sample_data/ipsec_esp.pcap", allow_unverified_domain=True)
    assert len(result.flows) == 1
    flow = result.flows[0]

    # Model inference is allowed
    assert flow.prediction["traffic_category"] in {"web", "video", "voip", "file_transfer", "interactive"}
    # Status MUST remain TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED
    assert flow.prediction["prediction_status"] == "TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED"
    assert flow.prediction["domain_status"]["ipsec_validation"] == "unverified"
    assert flow.prediction["domain_status"].get("override_used") is True
    assert any("unverified domain" in w for w in flow.prediction["warnings"])


def test_16_domain_policy_no_false_claim_of_ipsec_validation():
    """Domain Policy Criterion 5: Ensure unverified models never claim IPsec validation."""
    res_default = analyze_capture_complete("sample_data/ipsec_esp.pcap", allow_unverified_domain=False)
    res_override = analyze_capture_complete("sample_data/ipsec_esp.pcap", allow_unverified_domain=True)

    assert res_default.analysis_metadata["model_information"]["domain_status"]["ipsec_validation"] == "unverified"
    assert res_override.analysis_metadata["model_information"]["domain_status"]["ipsec_validation"] == "unverified"


def test_17_domain_policy_no_fabricated_predictions_when_blocked():
    """Domain Policy Criterion 6: No fabricated category predictions when inference is blocked."""
    result = analyze_capture_complete("sample_data/ipsec_esp.pcap", allow_unverified_domain=False)
    flow = result.flows[0]
    assert flow.prediction["traffic_category"] == "unclassified"
    assert flow.prediction["confidence"] == 0.0
    assert flow.prediction["probabilities"] == {}


def test_18_domain_policy_json_valid_both_paths(tmp_path: Path):
    """Domain Policy Criterion 7: JSON remains valid in both blocked and override paths."""
    out_blocked = tmp_path / "blocked.json"
    out_override = tmp_path / "override.json"

    res_b = analyze_capture_complete("sample_data/ipsec_esp.pcap", allow_unverified_domain=False, output_json=out_blocked)
    res_o = analyze_capture_complete("sample_data/ipsec_esp.pcap", allow_unverified_domain=True, output_json=out_override)

    rep_b = validate_integration_result(res_b)
    rep_o = validate_integration_result(res_o)

    assert rep_b.valid is True
    assert rep_o.valid is True
    assert out_blocked.is_file()
    assert out_override.is_file()
