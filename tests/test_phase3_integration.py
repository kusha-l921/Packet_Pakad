"""End-to-end integration tests for Phase 3 Model Integration & Inference Layer."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import pytest

from person2_engine.src.evaluation import ScenarioManifest, evaluate_capture_predictions
from person2_engine.src.feature_schema import FEATURE_SCHEMA_VERSION
from person2_engine.src.packet_analyzer import (
    analyze_capture,
    analyze_capture_with_features,
    analyze_capture_with_predictions,
)
from person2_engine.src.prediction_models import CapturePredictionResult


def test_backward_compatibility_phase1_and_phase2(valid_basic_pcap: Path) -> None:
    """Verify Phase 1 and Phase 2 entry points remain unchanged and functional."""
    # Phase 1
    p1_res = analyze_capture(valid_basic_pcap)
    assert p1_res.status.success
    assert p1_res.capture_info.total_packets == 5

    # Phase 2
    p2_res = analyze_capture_with_features(valid_basic_pcap)
    assert p2_res.analysis.status.success
    assert p2_res.feature_schema_version == FEATURE_SCHEMA_VERSION
    assert p2_res.flow_summary.total_flows > 0


def test_analyze_capture_with_predictions_default_unavailable(esp_pcap: Path) -> None:
    """Verify production behavior defaults to blocking unverified IPsec domain without crashing or faking."""
    p3_res = analyze_capture_with_predictions(esp_pcap)
    assert isinstance(p3_res, CapturePredictionResult)
    assert p3_res.capture_features.analysis.status.success

    # IPsec flows default to TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED without allow_unverified_domain
    assert p3_res.prediction_summary.total_flows > 0
    blocked_flows = p3_res.prediction_summary.model_unavailable + p3_res.prediction_summary.domain_unverified
    assert blocked_flows == p3_res.prediction_summary.total_flows
    assert p3_res.prediction_summary.predictions_successful == 0

    for flow_pred in p3_res.predictions:
        assert flow_pred.model_status in {"MODEL_UNAVAILABLE", "TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED"}
        assert flow_pred.prediction is None
        assert flow_pred.reason is not None


def test_analyze_capture_with_predictions_non_ipsec_succeeds(valid_basic_pcap: Path) -> None:
    """Verify non-IPsec flows run normal inference without requiring domain override."""
    p3_res = analyze_capture_with_predictions(valid_basic_pcap)
    assert isinstance(p3_res, CapturePredictionResult)
    assert p3_res.capture_features.analysis.status.success
    assert p3_res.prediction_summary.total_flows > 0
    assert p3_res.prediction_summary.predictions_successful > 0


def test_analyze_capture_with_predictions_test_mode(esp_pcap: Path) -> None:
    """Verify inference pipeline executes deterministically with allow_test_models=True."""
    p3_res = analyze_capture_with_predictions(
        esp_pcap,
        model_id="dummy_test_model",
        allow_test_models=True,
    )
    assert p3_res.capture_features.analysis.status.success
    assert p3_res.prediction_summary.total_flows == 1
    assert p3_res.prediction_summary.predictions_successful == 1
    assert p3_res.prediction_summary.model_unavailable == 0

    pred = p3_res.predictions[0]
    assert pred.model_status == "READY_FOR_INFERENCE"
    assert pred.prediction is not None
    # For single-packet short flow, dummy model deterministically assigns interactive
    assert pred.prediction.label == "interactive"
    assert any("TEST ONLY" in w for w in pred.warnings)


def test_analyze_capture_with_predictions_json_serialization(
    ikev2_pcap: Path, tmp_path: Path
) -> None:
    """Test serialization of CapturePredictionResult to JSON file and stdout."""
    out_file = tmp_path / "predictions.json"
    p3_res = analyze_capture_with_predictions(ikev2_pcap, output_json=out_file)

    assert out_file.exists()
    content = json.loads(out_file.read_text(encoding="utf-8"))

    assert "capture_info" in content
    assert "protocol_summary" in content
    assert "ipsec_analysis" in content
    assert "feature_schema_version" in content
    assert "flow_summary" in content
    assert "flows" in content
    assert "prediction_summary" in content

    # Flow should have attached prediction record
    flow_0 = content["flows"][0]
    assert "prediction" in flow_0
    assert flow_0["prediction"]["model_status"] in {"MODEL_UNAVAILABLE", "TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED"}


def test_analyze_capture_with_predictions_empty_or_corrupted(
    empty_pcap: Path, corrupted_pcap: Path
) -> None:
    """Test handling of empty or corrupted capture files."""
    p3_res_empty = analyze_capture_with_predictions(empty_pcap)
    assert not p3_res_empty.capture_features.analysis.status.success
    assert p3_res_empty.prediction_summary.total_flows == 0
    assert len(p3_res_empty.predictions) == 0

    p3_res_corr = analyze_capture_with_predictions(corrupted_pcap)
    assert p3_res_corr.prediction_summary.total_flows == 0
    assert len(p3_res_corr.predictions) == 0


def test_evaluation_scaffold_with_scenario_manifest(esp_pcap: Path) -> None:
    """Test evaluation interface for future Person 1 labeled capture evaluation."""
    p3_res = analyze_capture_with_predictions(
        esp_pcap,
        model_id="dummy_test_model",
        allow_test_models=True,
    )

    manifest = ScenarioManifest(
        scenario_id="scenario_esp_tunnel_test",
        ground_truth_label="interactive",
        application_details="iperf3_over_strongswan",
        ipsec_mode="tunnel",
        ipsec_protocol="ESP",
        ike_version="IKEv2",
    )

    eval_res = evaluate_capture_predictions(p3_res, manifest)
    assert eval_res.scenario_id == "scenario_esp_tunnel_test"
    assert eval_res.ground_truth_label == "interactive"
    assert eval_res.evaluated_flows == 1
    assert eval_res.correct_predictions == 1
    assert eval_res.accuracy == 1.0



def test_cli_predict_flag_ipsec_blocked(esp_pcap: Path) -> None:
    """Test running CLI with --predict flag on IPsec capture blocks unverified domain."""
    cmd = [
        sys.executable,
        "main.py",
        str(esp_pcap),
        "--predict",
        "--json-only",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    assert "prediction_summary" in data
    summary = data["prediction_summary"]
    assert (summary.get("model_unavailable", 0) + summary.get("domain_unverified", 0)) > 0


def test_cli_predict_flag_non_ipsec_succeeds(valid_basic_pcap: Path) -> None:
    """Test running CLI with --predict flag on non-IPsec capture succeeds without override."""
    cmd = [
        sys.executable,
        "main.py",
        str(valid_basic_pcap),
        "--predict",
        "--json-only",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    assert "prediction_summary" in data
    summary = data["prediction_summary"]
    assert summary.get("predictions_successful", 0) > 0

