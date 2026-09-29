"""
flow_engine/mlAdapter.py — Machine Learning Traffic Classifier Adapter & Protocol.

Provides a pluggable integration boundary for future ML classifiers (e.g. Scikit-learn,
ONNX, XGBoost) evaluating 25 statistical flow metrics extracted from ESP traffic.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger("flow_engine.mlAdapter")

# Authoritative feature list matching FlowRecord.extract_features()
FEATURE_NAMES: tuple[str, ...] = (
    "total_packets",
    "forward_packets",
    "backward_packets",
    "total_bytes",
    "forward_bytes",
    "backward_bytes",
    "minimum_packet_size",
    "maximum_packet_size",
    "mean_packet_size",
    "standard_deviation_packet_size",
    "median_packet_size",
    "forward_mean_packet_size",
    "backward_mean_packet_size",
    "flow_duration_seconds",
    "packets_per_second",
    "bytes_per_second",
    "mean_inter_arrival_time",
    "minimum_inter_arrival_time",
    "maximum_inter_arrival_time",
    "standard_deviation_inter_arrival_time",
    "forward_packet_ratio",
    "backward_packet_ratio",
    "forward_byte_ratio",
    "backward_byte_ratio",
    "maximum_packets_in_one_second",
)


@runtime_checkable
class TrafficClassifierProtocol(Protocol):
    """Protocol defining the standard interface for traffic classification models."""

    def predict(self, X: list[list[float]]) -> list[Any]:
        """Predict labels for a batch of 25-dimensional feature vectors."""
        ...


class MLModelAdapter:
    """Adapter bridging FlowRecord feature dictionaries with ML classification models."""

    def __init__(
        self,
        model: Any | None = None,
        model_name: str = "unloaded_model",
    ) -> None:
        self.model = model
        self.model_name = model_name

    @property
    def is_loaded(self) -> bool:
        """Indicates whether an operational classification model is available."""
        return self.model is not None

    @classmethod
    def from_file(cls, model_path: str | Path) -> MLModelAdapter:
        """Attempt to load a serialized model file (.joblib or .pkl)."""
        path = Path(model_path)
        if not path.exists():
            raise FileNotFoundError(f"Model file not found: {path}")

        try:
            import pickle
            with open(path, "rb") as f:
                loaded = pickle.load(f)
            return cls(model=loaded, model_name=path.stem)
        except Exception as e:
            logger.error("Failed to load model from %s: %s", path, e)
            raise

    def features_to_vector(self, features: dict[str, float]) -> list[float]:
        """Convert a feature dictionary into an ordered 25-element float vector."""
        return [float(features.get(k, 0.0)) for k in FEATURE_NAMES]

    def predict(self, X: list[list[float]]) -> list[Any]:
        """Delegate predict call directly to the underlying model.

        Matches FlowEngine's expectation: model.predict([list(features.values())])[0]
        """
        if self.model is not None and hasattr(self.model, "predict"):
            return self.model.predict(X)
        return [None for _ in X]

    def classify_flow(self, features: dict[str, float]) -> dict[str, Any]:
        """Classify a single flow window and return a structured verdict dictionary."""
        vector = self.features_to_vector(features)

        if self.model is None:
            return {
                "verdict": None,
                "confidence": None,
                "model_name": None,
                "is_model_loaded": False,
                "feature_count": len(vector),
            }

        try:
            raw_verdict = self.model.predict([vector])[0]
            confidence: float | None = None
            if hasattr(self.model, "predict_proba"):
                try:
                    probs = self.model.predict_proba([vector])[0]
                    confidence = float(max(probs))
                except Exception:
                    pass

            return {
                "verdict": raw_verdict,
                "confidence": confidence,
                "model_name": self.model_name,
                "is_model_loaded": True,
                "feature_count": len(vector),
            }
        except Exception as e:
            logger.warning("Inference failed for flow: %s", e)
            return {
                "verdict": "INFERENCE_ERROR",
                "confidence": 0.0,
                "model_name": self.model_name,
                "is_model_loaded": True,
                "error": str(e),
                "feature_count": len(vector),
            }
