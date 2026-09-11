"""Model loading and deserialization module for Phase 3."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from person2_engine.src.model_adapter import (
    DummyTestModelAdapter,
    ModelAdapter,
    SklearnModelAdapter,
)
from person2_engine.src.model_metadata import ModelMetadata

logger = logging.getLogger(__name__)


def load_model_from_manifest(manifest_path: str | Path) -> ModelAdapter:
    """Load a model adapter from its metadata JSON manifest file.

    Args:
        manifest_path: Path to the metadata.json or model manifest.

    Returns:
        Instantiated ModelAdapter.

    Raises:
        FileNotFoundError: If manifest file does not exist.
        ValueError: If model type is unrecognized or metadata is malformed.
    """
    path = Path(manifest_path).resolve()
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"Model manifest file not found: {path}")

    content = path.read_text(encoding="utf-8")
    data = json.loads(content)
    metadata = ModelMetadata.from_dict(data)

    if metadata.artifact_path and not Path(metadata.artifact_path).is_absolute():
        metadata.artifact_path = str((path.parent / metadata.artifact_path).resolve())

    if metadata.is_test_only and metadata.model_type in {"test_classifier", "rule_based_test_stub"}:
        return DummyTestModelAdapter(metadata)

    if (
        metadata.model_type in {
            "random_forest",
            "gradient_boosting",
            "extra_trees",
            "logistic_regression",
            "classifier",
        }
        or (metadata.artifact_path and metadata.artifact_path.endswith(".joblib"))
    ):
        if not metadata.artifact_path:
            raise ValueError(f"Model '{metadata.model_id}' specifies no artifact_path for loading.")
        return SklearnModelAdapter(metadata, metadata.artifact_path)

    raise ValueError(
        f"Unsupported model_type '{metadata.model_type}' for model '{metadata.model_id}'."
    )

