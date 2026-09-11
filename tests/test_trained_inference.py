"""Unit tests for Phase 3 real inference pipeline with trained models.

Tests inference execution on flow vectors and PCAPs, feature importance explainability,
schema mismatch rejection, and IPsec domain limitations.
"""

from pathlib import Path
import pytest

from person2_engine.src.feature_schema import FEATURE_ORDER
from person2_engine.src.inference_engine import predict_flow, predict_flows
from person2_engine.src.model_metadata import ModelStatus
from person2_engine.src.model_registry import get_model_registry
from person2_engine.src.packet_analyzer import (
    analyze_capture,
    analyze_capture_with_features,
    analyze_capture_with_predictions,
)


@pytest.fixture
def sample_pcap_file() -> str:
    """Return path to existing sample PCAP."""
    p = Path("sample_data/basic_traffic.pcap")
    if not p.is_file():
        pytest.skip("sample_data/basic_traffic.pcap not available")
    return str(p)


class TestTrainedInference:
    """Tests for inference using real trained weights."""

    def test_predict_flow_with_trained_random_forest(self, sample_pcap_file):
        """Verify real inference generates valid predictions and feature importance."""
        feat_res = analyze_capture_with_features(sample_pcap_file)
        assert len(feat_res.flows) > 0

        flow = feat_res.flows[0]
        pred_res = predict_flow(
            flow,
            model_id="random_forest_traffic_classifier_v1",
            allow_unverified_domain=True,
        )

        assert pred_res.status == ModelStatus.READY_FOR_INFERENCE.value
        assert pred_res.prediction is not None
        assert pred_res.prediction.label in {"web", "video", "voip", "file_transfer", "interactive"}
        assert 0.0 <= pred_res.prediction.confidence <= 1.0
        assert pred_res.feature_importance is not None
        assert len(pred_res.feature_importance) > 0

    def test_unverified_domain_blocked_without_override(self):
        """Verify model on unverified IPsec domain is blocked by default without allow_unverified_domain."""
        feat_res = analyze_capture_with_features("sample_data/ipsec_esp.pcap")
        flow = feat_res.flows[0]

        pred_res = predict_flow(
            flow,
            model_id="random_forest_traffic_classifier_v1",
            allow_unverified_domain=False,
        )
        assert pred_res.status == ModelStatus.TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED.value
        assert pred_res.prediction is None
        assert any("IPsec" in w or "unverified" in w for w in pred_res.warnings)

    def test_non_ipsec_flow_inference_succeeds_without_override(self, sample_pcap_file):
        """Verify standard non-IPsec flows run inference normally without needing unverified domain override."""
        feat_res = analyze_capture_with_features(sample_pcap_file)
        flow = feat_res.flows[0]

        pred_res = predict_flow(
            flow,
            model_id="random_forest_traffic_classifier_v1",
            allow_unverified_domain=False,
        )
        assert pred_res.status == ModelStatus.READY_FOR_INFERENCE.value
        assert pred_res.prediction is not None
        assert pred_res.prediction.label in {"web", "video", "voip", "file_transfer", "interactive"}

    def test_invalid_vector_rejected_before_inference(self, sample_pcap_file):
        """Verify NaN in features is rejected and halts inference cleanly."""
        feat_res = analyze_capture_with_features(sample_pcap_file)
        flow = feat_res.flows[0]
        # Corrupt feature
        flow.features["total_packets"] = float("nan")

        pred_res = predict_flow(
            flow,
            model_id="random_forest_traffic_classifier_v1",
            allow_unverified_domain=True,
        )
        assert pred_res.status == ModelStatus.INCOMPATIBLE.value
        assert pred_res.prediction is None
        assert any("NaN" in err for err in pred_res.compatibility_errors)

    def test_analyze_capture_with_predictions_end_to_end(self, sample_pcap_file):
        """Test full pipeline from PCAP to predictions and summaries."""
        pred_capture = analyze_capture_with_predictions(
            sample_pcap_file,
            model_id="random_forest_traffic_classifier_v1",
            allow_unverified_domain=True,
        )
        assert pred_capture.capture_features.analysis.status.success is True
        assert len(pred_capture.predictions) == len(pred_capture.capture_features.flows)
        assert pred_capture.summary.total_flows == len(pred_capture.capture_features.flows)
        assert pred_capture.summary.predictions_successful == len(pred_capture.capture_features.flows)

    def test_backward_compatibility_phase1_and_phase2(self, sample_pcap_file):
        """Verify Phase 1 and Phase 2 entry points remain unaffected and fully functional."""
        p1 = analyze_capture(sample_pcap_file)
        assert p1.status.success is True
        assert p1.capture_info.total_packets == 5

        p2 = analyze_capture_with_features(sample_pcap_file)
        assert p2.analysis.status.success is True
        assert p2.flow_summary.total_flows == 5
        assert p2.flow_summary.valid_flows == 5
