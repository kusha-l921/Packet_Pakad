"""Model registry for discovery, registration, and validation of AI/ML models.

Enforces strict compliance checking before exposing any model for inference.
If no verified compatible model exists, cleanly reports MODEL_UNAVAILABLE.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from person2_engine.src.model_adapter import DummyTestModelAdapter, ModelAdapter
from person2_engine.src.model_metadata import ModelMetadata, ModelStatus
from person2_engine.src.model_validator import validate_model_compatibility

logger = logging.getLogger(__name__)

DEFAULT_REGISTRY_DIR = Path(__file__).parent.parent.parent / "models" / "registry"


class ModelRegistry:
    """Central registry tracking available, verified, and test-only models."""

    def __init__(self, registry_dir: Optional[Path] = None) -> None:
        self.registry_dir = registry_dir or DEFAULT_REGISTRY_DIR
        self._adapters: Dict[str, ModelAdapter] = {}
        self._discovered: bool = False

    def register_adapter(self, adapter: ModelAdapter) -> None:
        """Register a ModelAdapter instance in memory."""
        metadata = adapter.get_metadata()
        self._adapters[metadata.model_id] = adapter
        logger.debug("Registered model adapter: %s (%s)", metadata.model_id, metadata.model_name)

    def discover_models(self) -> None:
        """Discover model manifests from registry directory."""
        if not self.registry_dir.exists():
            self._discovered = True
            return

        # Scan for metadata.json files in subdirectories, registry *.json, and models/metadata/*.json
        manifest_files = list(self.registry_dir.glob("*/metadata.json")) + list(
            self.registry_dir.glob("*.json")
        )
        meta_dir = self.registry_dir.parent / "metadata"
        if meta_dir.exists() and meta_dir.is_dir():
            manifest_files.extend(list(meta_dir.glob("*.json")))

        for mf in manifest_files:
            try:
                data = json.loads(mf.read_text(encoding="utf-8"))
                metadata = ModelMetadata.from_dict(data)
                # If metadata points to a relative artifact path, resolve relative to manifest dir
                if metadata.artifact_path and not Path(metadata.artifact_path).is_absolute():
                    resolved_path = str((mf.parent / metadata.artifact_path).resolve())
                    metadata.artifact_path = resolved_path

                # Instantiate adapter if type is recognized
                if metadata.is_test_only and metadata.model_type in {"test_classifier", "rule_based_test_stub"}:
                    adapter = DummyTestModelAdapter(metadata)
                    self.register_adapter(adapter)
                elif (
                    metadata.model_type in {
                        "random_forest",
                        "gradient_boosting",
                        "extra_trees",
                        "logistic_regression",
                        "classifier",
                    }
                    or (metadata.artifact_path and metadata.artifact_path.endswith(".joblib"))
                ):
                    from person2_engine.src.model_adapter import SklearnModelAdapter
                    if metadata.artifact_path and Path(metadata.artifact_path).is_file():
                        adapter = SklearnModelAdapter(metadata, metadata.artifact_path)
                        self.register_adapter(adapter)
            except Exception as e:
                logger.warning("Failed loading model manifest %s: %s", mf, e)

        self._discovered = True
        return self._adapters

    def list_models(self) -> Dict[str, ModelAdapter]:
        """Return dictionary of all registered model adapters, discovering them if needed."""
        if not self._discovered:
            self.discover_models()
        return self._adapters


    def get_model(
        self,
        model_id: Optional[str] = None,
        allow_unverified_domain: bool = False,
        allow_test_models: bool = False,
    ) -> Tuple[Optional[ModelAdapter], ModelStatus, str, List[str]]:
        """Retrieve and validate a model adapter for inference.

        Args:
            model_id: Specific model ID requested. If None, picks the primary verified model.
            allow_unverified_domain: Whether to proceed if model is technically compatible
                                    but IPsec domain is unverified.
            allow_test_models: Whether test-only dummy models may be used.

        Returns:
            Tuple of (adapter or None, ModelStatus, reason_message, warnings_list).
        """
        if not self._discovered:
            self.discover_models()

        if model_id:
            if model_id not in self._adapters:
                reason = (
                    f"Model '{model_id}' is not registered or was not found in registry."
                )
                return None, ModelStatus.MODEL_UNAVAILABLE, reason, []

            adapter = self._adapters[model_id]
            meta = adapter.get_metadata()

            if meta.is_test_only and not allow_test_models:
                reason = f"Model '{model_id}' is flagged as TEST ONLY and cannot be used in production inference."
                return None, ModelStatus.MODEL_UNAVAILABLE, reason, []


            report = validate_model_compatibility(
                metadata=meta,
                allow_unverified_domain=allow_unverified_domain,
            )

            if not report.is_compatible:
                reason = f"Model '{model_id}' is incompatible: {'; '.join(report.errors)}"
                return None, ModelStatus.INCOMPATIBLE, reason, report.errors

            return adapter, report.status, "Model ready.", report.warnings

        # No specific model requested: search for production-ready models
        candidate_adapters = [
            a for a in self._adapters.values()
            if not a.get_metadata().is_test_only or allow_test_models
        ]

        if not candidate_adapters:
            reason = (
                "No verified compatible pretrained model is currently registered for "
                "feature schema 1.0 and the requested prediction task."
            )
            return None, ModelStatus.MODEL_UNAVAILABLE, reason, []

        # Validate candidates
        for adapter in candidate_adapters:
            meta = adapter.get_metadata()
            report = validate_model_compatibility(
                metadata=meta,
                allow_unverified_domain=allow_unverified_domain,
            )
            if report.is_compatible:
                return adapter, report.status, "Model ready.", report.warnings

        # All registered candidates were incompatible
        reason = "Registered models exist but are incompatible with the current feature schema or task."
        return None, ModelStatus.INCOMPATIBLE, reason, []


# Global singleton registry instance
default_registry = ModelRegistry()


def get_model_registry() -> ModelRegistry:
    """Return the global default ModelRegistry singleton instance."""
    return default_registry

