"""Unit tests for Phase 3 11-point Model Compatibility Validator."""

from __future__ import annotations

from pathlib import Path
import pytest

from person2_engine.src.feature_schema import FEATURE_ORDER, FEATURE_SCHEMA_VERSION
from person2_engine.src.model_metadata import (
    IPsecCompatibilityLevel,
    InputType,
    ModelMetadata,
    ModelStatus,
    PredictionTask,
)
from person2_engine.src.model_validator import validate_model_compatibility


@pytest.fixture
def valid_model_setup(tmp_path: Path) -> ModelMetadata:
    """Create a physically present dummy artifact and matching valid metadata."""
    artifact = tmp_path / "model.bin"
    artifact.write_bytes(b"dummy_weights")

    return ModelMetadata(
        model_id="valid_model_v1",
        model_name="Valid Flow Classifier",
        model_version="1.0.0",
        model_type="classifier",
        prediction_task=PredictionTask.APPLICATION_CATEGORY.value,
        input_type=InputType.FLOW_FEATURES.value,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        feature_names=list(FEATURE_ORDER),
        feature_count=25,
        preprocessing={"type": "identity"},
        labels={"0": "web", "1": "dns", "2": "voip"},
        training_domain={"traffic": "general"},
        ipsec_compatibility={"level": "verified", "reason": "Evaluated on StrongSwan test suite."},
        artifact_path=str(artifact),
        is_test_only=False,
    )


def test_validator_compatible_model_passes(valid_model_setup: ModelMetadata) -> None:
    """Test that a fully compliant model passes validation."""
    status, errors, warnings = validate_model_compatibility(valid_model_setup)
    assert status == ModelStatus.READY_FOR_INFERENCE
    assert len(errors) == 0
    assert len(warnings) == 0


def test_validator_missing_artifact_fails(valid_model_setup: ModelMetadata) -> None:
    """Test that nonexistent artifact path results in INCOMPATIBLE."""
    valid_model_setup.artifact_path = "/path/does/not/exist/model.bin"
    status, errors, warnings = validate_model_compatibility(valid_model_setup)
    assert status == ModelStatus.INCOMPATIBLE
    assert any("does not exist" in e for e in errors)


def test_validator_wrong_schema_version_fails(valid_model_setup: ModelMetadata) -> None:
    """Test that incompatible feature schema version results in INCOMPATIBLE."""
    valid_model_setup.feature_schema_version = "2.0-beta"
    status, errors, warnings = validate_model_compatibility(valid_model_setup)
    assert status == ModelStatus.INCOMPATIBLE
    assert any("schema version mismatch" in e for e in errors)


def test_validator_wrong_feature_count_fails(valid_model_setup: ModelMetadata) -> None:
    """Test that feature count != 25 results in INCOMPATIBLE."""
    valid_model_setup.feature_count = 20
    status, errors, warnings = validate_model_compatibility(valid_model_setup)
    assert status == ModelStatus.INCOMPATIBLE
    assert any("Feature count mismatch" in e for e in errors)


def test_validator_wrong_feature_names_fails(valid_model_setup: ModelMetadata) -> None:
    """Test that mismatched feature names result in INCOMPATIBLE."""
    altered_names = list(FEATURE_ORDER)
    altered_names[0] = "arbitrary_custom_packet_count"
    valid_model_setup.feature_names = altered_names

    status, errors, warnings = validate_model_compatibility(valid_model_setup)
    assert status == ModelStatus.INCOMPATIBLE
    assert any("Missing expected feature" in e for e in errors)


def test_validator_wrong_feature_order_fails(valid_model_setup: ModelMetadata) -> None:
    """Test that permuted feature ordering is detected and fails validation."""
    shuffled_names = list(FEATURE_ORDER)
    # Swap first two elements
    shuffled_names[0], shuffled_names[1] = shuffled_names[1], shuffled_names[0]
    valid_model_setup.feature_names = shuffled_names

    status, errors, warnings = validate_model_compatibility(valid_model_setup)
    assert status == ModelStatus.INCOMPATIBLE
    assert any("Feature order mismatch at index" in e for e in errors)


def test_validator_missing_labels_fails(valid_model_setup: ModelMetadata) -> None:
    """Test that empty or non-dict labels result in INCOMPATIBLE."""
    valid_model_setup.labels = {}
    status, errors, warnings = validate_model_compatibility(valid_model_setup)
    assert status == ModelStatus.INCOMPATIBLE
    assert any("No output labels defined" in e for e in errors)


def test_validator_unknown_preprocessing_fails(valid_model_setup: ModelMetadata) -> None:
    """Test that unknown preprocessing method is rejected."""
    valid_model_setup.preprocessing = {"type": "unknown_deep_magic"}
    status, errors, warnings = validate_model_compatibility(valid_model_setup)
    assert status == ModelStatus.INCOMPATIBLE
    assert any("Unsupported preprocessing type" in e for e in errors)


def test_validator_standard_scaler_parameter_validation(valid_model_setup: ModelMetadata) -> None:
    """Test standard scaler requires 25 mean and std floats with std > 0."""
    # Missing parameters
    valid_model_setup.preprocessing = {"type": "standard_scaler", "parameters": {}}
    status, errors, warnings = validate_model_compatibility(valid_model_setup)
    assert status == ModelStatus.INCOMPATIBLE

    # Length mismatch
    valid_model_setup.preprocessing = {
        "type": "standard_scaler",
        "parameters": {"mean": [0.0] * 10, "std": [1.0] * 10},
    }
    status, errors, warnings = validate_model_compatibility(valid_model_setup)
    assert status == ModelStatus.INCOMPATIBLE
    assert any("must contain exactly 25" in e for e in errors)

    # Non-positive std
    valid_model_setup.preprocessing = {
        "type": "standard_scaler",
        "parameters": {"mean": [0.0] * 25, "std": [1.0] * 24 + [0.0]},
    }
    status, errors, warnings = validate_model_compatibility(valid_model_setup)
    assert status == ModelStatus.INCOMPATIBLE
    assert any("must be strictly positive" in e for e in errors)


def test_validator_domain_unverified_states(valid_model_setup: ModelMetadata) -> None:
    """Test handling of TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED and override."""
    valid_model_setup.ipsec_compatibility = {
        "level": IPsecCompatibilityLevel.UNVERIFIED.value,
        "reason": "Trained only on public plain TLS data.",
    }

    # Default: Blocked as TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED
    status, errors, warnings = validate_model_compatibility(valid_model_setup, allow_unverified_domain=False)
    assert status == ModelStatus.TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED
    assert len(errors) == 0
    assert len(warnings) > 0
    assert any("IPsec generalization is unverified" in w for w in warnings)

    # Override: Promoted to READY_FOR_INFERENCE with explicit warning
    status, errors, warnings = validate_model_compatibility(valid_model_setup, allow_unverified_domain=True)
    assert status == ModelStatus.READY_FOR_INFERENCE
    assert len(errors) == 0
    assert len(warnings) > 0
    assert any("allowed via configuration" in w for w in warnings)
