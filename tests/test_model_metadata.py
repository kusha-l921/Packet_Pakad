"""Unit tests for Phase 3 Model Metadata and Schema Contract."""

from __future__ import annotations

import json
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


@pytest.fixture
def valid_metadata_dict() -> dict:
    """Return a valid, complete metadata dictionary."""
    return {
        "model_id": "test_classifier_v1",
        "model_name": "Test Application Classifier",
        "model_version": "1.0.0",
        "model_type": "decision_tree",
        "prediction_task": PredictionTask.APPLICATION_CATEGORY.value,
        "input_type": InputType.FLOW_FEATURES.value,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "feature_names": list(FEATURE_ORDER),
        "feature_count": len(FEATURE_ORDER),
        "preprocessing": {
            "type": "identity",
            "parameters": {},
        },
        "labels": {
            "0": "web",
            "1": "video",
            "2": "voip",
        },
        "training_domain": {
            "dataset": "Synthetic Lab 2026",
            "traffic_type": "TCP/UDP",
        },
        "ipsec_compatibility": {
            "level": IPsecCompatibilityLevel.UNVERIFIED.value,
            "reason": "Not yet evaluated on IPsec traffic.",
        },
        "artifact_path": "model.joblib",
        "is_test_only": False,
    }


def test_valid_metadata_from_dict(valid_metadata_dict: dict) -> None:
    """Test instantiating ModelMetadata from a valid dictionary."""
    meta = ModelMetadata.from_dict(valid_metadata_dict)
    assert meta.model_id == "test_classifier_v1"
    assert meta.model_version == "1.0.0"
    assert meta.feature_count == 25
    assert meta.feature_schema_version == "1.0"
    assert len(meta.feature_names) == 25
    assert meta.feature_names == FEATURE_ORDER
    assert meta.labels["0"] == "web"
    assert meta.ipsec_compatibility["level"] == "unverified"
    assert not meta.is_test_only


def test_metadata_roundtrip_json(valid_metadata_dict: dict) -> None:
    """Test serialization to and from JSON."""
    meta = ModelMetadata.from_dict(valid_metadata_dict)
    json_str = meta.to_json()
    assert isinstance(json_str, str)
    parsed = json.loads(json_str)
    assert parsed["model_id"] == "test_classifier_v1"
    assert parsed["feature_count"] == 25

    restored = ModelMetadata.from_dict(parsed)
    assert restored.model_id == meta.model_id
    assert restored.feature_names == meta.feature_names
    assert restored.labels == meta.labels


def test_metadata_missing_fields_error() -> None:
    """Test that missing mandatory fields raise ValueError."""
    incomplete = {"model_id": "test"}
    with pytest.raises(ValueError, match="Missing required metadata field"):
        ModelMetadata.from_dict(incomplete)


def test_metadata_invalid_enums() -> None:
    """Test that invalid enum values raise ValueError."""
    data = {
        "model_id": "bad_task",
        "model_name": "Bad Task",
        "prediction_task": "invalid_unknown_task",
        "input_type": "flow_features",
        "feature_schema_version": "1.0",
        "feature_names": list(FEATURE_ORDER),
        "feature_count": 25,
        "preprocessing": {"type": "identity"},
        "labels": {"0": "class_a"},
        "artifact_path": "model.joblib",
    }
    with pytest.raises(ValueError, match="Invalid prediction_task"):
        ModelMetadata.from_dict(data)

    data["prediction_task"] = "application_category"
    data["input_type"] = "invalid_input"
    with pytest.raises(ValueError, match="Invalid input_type"):
        ModelMetadata.from_dict(data)


def test_metadata_load_from_json_file(tmp_path: Path, valid_metadata_dict: dict) -> None:
    """Test loading ModelMetadata directly from a JSON file."""
    meta_file = tmp_path / "metadata.json"
    meta_file.write_text(json.dumps(valid_metadata_dict), encoding="utf-8")

    meta = ModelMetadata.from_json_file(meta_file)
    assert meta.model_id == "test_classifier_v1"
    assert meta.feature_count == 25


def test_metadata_load_missing_file() -> None:
    """Test loading from non-existent file raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        ModelMetadata.from_json_file(Path("/nonexistent/metadata.json"))
