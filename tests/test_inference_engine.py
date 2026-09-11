"""Unit tests for Phase 3 Inference Engine and Preprocessing."""

from __future__ import annotations

from pathlib import Path
import pytest

from person2_engine.src.feature_schema import FEATURE_ORDER, FEATURE_SCHEMA_VERSION
from person2_engine.src.flow_models import (
    FlowMetadata,
    FlowResult,
    FlowValidationResult,
    IPsecFlowMetadata,
)
from person2_engine.src.inference_engine import predict_flow, predict_flows
from person2_engine.src.model_adapter import DummyTestModelAdapter
from person2_engine.src.model_metadata import ModelMetadata, ModelStatus
from person2_engine.src.model_preprocessor import ModelPreprocessor
from person2_engine.src.model_registry import ModelRegistry


@pytest.fixture
def sample_valid_flow() -> FlowResult:
    """Create a mock valid FlowResult with typical feature values."""
    features = {name: 10.0 for name in FEATURE_ORDER}
    features["total_packets"] = 2.0
    features["forward_packets"] = 1.0
    features["backward_packets"] = 1.0
    features["total_bytes"] = 100.0
    features["forward_bytes"] = 50.0
    features["backward_bytes"] = 50.0
    features["flow_duration_seconds"] = 1.0
    features["packets_per_second"] = 2.0
    features["bytes_per_second"] = 100.0
    features["forward_packet_ratio"] = 0.5
    features["backward_packet_ratio"] = 0.5
    features["forward_byte_ratio"] = 0.5
    features["backward_byte_ratio"] = 0.5

    meta = FlowMetadata(
        flow_id="TCP_10.0.0.1:1234_10.0.0.2:80",
        ip_version=4,
        protocol="TCP",
        endpoint_a="10.0.0.1:1234",
        endpoint_b="10.0.0.2:80",
        first_timestamp=100.0,
        last_timestamp=101.0,
    )
    ipsec = IPsecFlowMetadata(is_ipsec_related=False)
    val = FlowValidationResult(valid=True, errors=[], warnings=[])

    return FlowResult(
        flow_metadata=meta,
        ipsec_metadata=ipsec,
        features=features,
        validation=val,
    )


@pytest.fixture
def sample_invalid_flow(sample_valid_flow: FlowResult) -> FlowResult:
    """Create a FlowResult marked as invalid by Phase 2 validation."""
    return FlowResult(
        flow_metadata=sample_valid_flow.flow_metadata,
        ipsec_metadata=sample_valid_flow.ipsec_metadata,
        features=sample_valid_flow.features,
        validation=FlowValidationResult(valid=False, errors=["Negative packet count"], warnings=[]),
    )


def test_preprocessing_identity() -> None:
    """Test identity preprocessor preserves vector exactly."""
    preprocessor = ModelPreprocessor({"type": "identity"})
    vec = [1.0, 2.0, 3.0]
    processed = preprocessor.transform(vec)
    assert processed == [1.0, 2.0, 3.0]


def test_preprocessing_standard_scaler() -> None:
    """Test standard scaler Z-score normalization."""
    spec = {
        "type": "standard_scaler",
        "parameters": {
            "mean": [10.0, 20.0],
            "std": [2.0, 5.0],
        },
    }
    preprocessor = ModelPreprocessor(spec)
    vec = [12.0, 30.0]
    processed = preprocessor.transform(vec)
    assert processed[0] == pytest.approx((12.0 - 10.0) / 2.0)
    assert processed[1] == pytest.approx((30.0 - 20.0) / 5.0)


def test_preprocessing_min_max_scaler() -> None:
    """Test min-max scaler range normalization."""
    spec = {
        "type": "min_max_scaler",
        "parameters": {
            "min": [0.0, 100.0],
            "max": [10.0, 200.0],
        },
    }
    preprocessor = ModelPreprocessor(spec)
    vec = [5.0, 150.0]
    processed = preprocessor.transform(vec)
    assert processed[0] == pytest.approx(0.5)
    assert processed[1] == pytest.approx(0.5)


def test_predict_flow_model_unavailable_by_default(sample_valid_flow: FlowResult, tmp_path: Path) -> None:
    """Test that predicting without a registered verified model returns MODEL_UNAVAILABLE cleanly."""
    registry = ModelRegistry(registry_dir=tmp_path)  # Truly empty registry
    res = predict_flow(sample_valid_flow, registry=registry)

    assert res.model_status == "MODEL_UNAVAILABLE"
    assert res.prediction is None
    assert res.reason is not None
    assert "No verified compatible" in res.reason


def test_predict_flow_with_test_dummy_model(sample_valid_flow: FlowResult) -> None:
    """Test deterministic inference using DummyTestModelAdapter when explicitly allowed."""
    registry = ModelRegistry()
    dummy_meta = ModelMetadata(
        model_id="dummy_test_model",
        model_name="Deterministic Test Model",
        model_version="1.0.0",
        model_type="rule_based_test_stub",
        prediction_task="application_category",
        input_type="flow_features",
        feature_schema_version="1.0",
        feature_names=list(FEATURE_ORDER),
        feature_count=25,
        preprocessing={"type": "identity"},
        labels={"0": "web", "1": "video", "2": "voip", "3": "file_transfer", "4": "interactive"},
        ipsec_compatibility={"level": "verified"},
        artifact_path="in_memory_test_stub",
        is_test_only=True,
    )

    dummy_adapter = DummyTestModelAdapter(dummy_meta)
    registry.register_adapter(dummy_adapter)

    # Calling with allow_test_models=False should ignore it and return MODEL_UNAVAILABLE
    res_disallowed = predict_flow(
        sample_valid_flow, registry=registry, model_id="dummy_test_model", allow_test_models=False
    )
    assert res_disallowed.model_status == "MODEL_UNAVAILABLE"

    # Calling with allow_test_models=True should succeed
    res_allowed = predict_flow(
        sample_valid_flow, registry=registry, model_id="dummy_test_model", allow_test_models=True
    )
    assert res_allowed.model_status == "READY_FOR_INFERENCE"
    assert res_allowed.prediction is not None
    assert res_allowed.prediction.label in ["web", "video", "voip", "file_transfer", "interactive"]
    assert 0.0 <= res_allowed.prediction.confidence <= 1.0
    assert any("TEST ONLY" in w for w in res_allowed.warnings)



def test_predict_flow_rejects_invalid_flow(sample_invalid_flow: FlowResult) -> None:
    """Test that flows marked invalid by Phase 2 do not execute model inference."""
    res = predict_flow(sample_invalid_flow)
    assert res.model_status == "INCOMPATIBLE"
    assert res.prediction is None
    assert any("Flow validation failed" in err for err in res.compatibility_errors)


def test_predict_flow_incompatible_model(tmp_path: Path, sample_valid_flow: FlowResult) -> None:
    """Test that an incompatible registered model is cleanly blocked."""
    registry = ModelRegistry()
    incompat_meta = ModelMetadata(
        model_id="incompat_model",
        model_name="Incompatible Model",
        model_version="1.0.0",
        model_type="classifier",
        prediction_task="application_category",
        input_type="flow_features",
        feature_schema_version="1.0",
        feature_names=["f1", "f2"],  # Wrong count and names
        feature_count=2,
        preprocessing={"type": "identity"},
        labels={"0": "c1"},
        artifact_path="/nonexistent/path.bin",
    )
    adapter = DummyTestModelAdapter(incompat_meta)
    registry.register_adapter(adapter)

    res = predict_flow(
        sample_valid_flow, registry=registry, model_id="incompat_model", allow_test_models=True
    )
    assert res.model_status == "INCOMPATIBLE"
    assert res.prediction is None
    assert len(res.compatibility_errors) > 0


def test_predict_flows_batch(sample_valid_flow: FlowResult, tmp_path: Path) -> None:
    """Test batch prediction across multiple flows."""
    flows = [sample_valid_flow, sample_valid_flow]
    registry = ModelRegistry(registry_dir=tmp_path)
    results, summary = predict_flows(flows, registry=registry)
    assert len(results) == 2
    assert summary.total_flows == 2
    for r in results:
        assert r.model_status == "MODEL_UNAVAILABLE"

