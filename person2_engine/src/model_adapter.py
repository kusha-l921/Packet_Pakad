"""Model adapter abstraction and test-only verification adapter for Phase 3.

Provides a unified interface for model inference architectures and implements
a deterministic DummyTestModelAdapter used strictly for test verification.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import joblib
import numpy as np

from person2_engine.src.feature_schema import FEATURE_ORDER, FEATURE_SCHEMA_VERSION
from person2_engine.src.model_metadata import (
    InputType,
    IPsecCompatibilityLevel,
    ModelMetadata,
    PredictionTask,
)
from person2_engine.src.model_preprocessor import ModelPreprocessor
from person2_engine.src.prediction_models import Prediction


class ModelAdapter(ABC):
    """Abstract base class establishing the contract for all model adapters."""

    def __init__(self, metadata: ModelMetadata) -> None:
        self.metadata = metadata
        self.preprocessor = ModelPreprocessor(metadata.preprocessing)

    def get_metadata(self) -> ModelMetadata:
        """Return declared model metadata."""
        return self.metadata

    def preprocess(self, raw_features: List[float]) -> List[float]:
        """Apply model-specific verified preprocessing to the 25-feature vector."""
        return self.preprocessor.transform(raw_features)

    @abstractmethod
    def predict(self, features: List[float]) -> Prediction:
        """Perform inference on the preprocessed 25-feature vector."""
        raise NotImplementedError

    def get_feature_importances(self) -> Dict[str, float]:
        """Return model feature importances for explainability, if supported."""
        return {}


class DummyTestModelAdapter(ModelAdapter):
    """Deterministic, test-only model adapter for verifying software pipeline behavior."""

    def __init__(self, metadata: Optional[ModelMetadata] = None) -> None:
        if metadata is None:
            metadata = ModelMetadata(
                model_id="dummy_test_classifier",
                model_name="Deterministic Test-Only Model (DUMMY)",
                model_version="1.0-test",
                model_type="test_classifier",
                prediction_task=PredictionTask.APPLICATION_CATEGORY.value,
                input_type=InputType.FLOW_FEATURES.value,
                feature_schema_version=FEATURE_SCHEMA_VERSION,
                feature_names=list(FEATURE_ORDER),
                feature_count=len(FEATURE_ORDER),
                preprocessing={"type": "identity"},
                labels={
                    "0": "web",
                    "1": "video",
                    "2": "voip",
                    "3": "file_transfer",
                    "4": "interactive",
                },
                training_domain={"dataset": "synthetic_test_fixtures", "note": "TEST ONLY"},
                ipsec_compatibility={
                    "level": IPsecCompatibilityLevel.VERIFIED.value,
                    "reason": "Test model certified for CI test fixtures",
                },
                artifact_path=None,
                is_test_only=True,
            )
        super().__init__(metadata)

    def predict(self, features: List[float]) -> Prediction:
        """Rule-based deterministic classification for test assertions."""
        total_pkts = features[0]
        mean_size = features[8]
        duration = features[13]
        bytes_sec = features[15]

        if mean_size > 800.0 or bytes_sec > 50000.0:
            label, idx, conf = "video", 1, 0.92
            probs = {"video": 0.92, "file_transfer": 0.05, "web": 0.02, "voip": 0.01, "interactive": 0.00}
        elif bytes_sec > 10000.0:
            label, idx, conf = "file_transfer", 3, 0.88
            probs = {"file_transfer": 0.88, "video": 0.06, "web": 0.04, "voip": 0.01, "interactive": 0.01}
        elif total_pkts <= 2.0 or duration <= 0.05:
            label, idx, conf = "interactive", 4, 0.95
            probs = {"interactive": 0.95, "web": 0.03, "voip": 0.01, "video": 0.01, "file_transfer": 0.00}
        elif mean_size < 150.0:
            label, idx, conf = "voip", 2, 0.85
            probs = {"voip": 0.85, "interactive": 0.08, "web": 0.05, "video": 0.01, "file_transfer": 0.01}
        else:
            label, idx, conf = "web", 0, 0.89
            probs = {"web": 0.89, "interactive": 0.05, "video": 0.03, "voip": 0.02, "file_transfer": 0.01}

        return Prediction(
            label=label,
            class_index=idx,
            confidence=conf,
            probabilities=probs,
        )


class SklearnModelAdapter(ModelAdapter):
    """Adapter for trained scikit-learn models serialized via joblib."""

    def __init__(
        self,
        metadata: ModelMetadata,
        model_artifact_path: Union[str, Path],
    ) -> None:
        super().__init__(metadata)
        path = Path(model_artifact_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Model artifact file does not exist: {path}")

        payload = joblib.load(path)
        if isinstance(payload, dict):
            self.estimator = payload.get("estimator", payload)
            self.scaler = payload.get("scaler")
            self.classes = list(payload.get("classes", []))
        else:
            self.estimator = payload
            self.scaler = None
            self.classes = []

        if not self.classes and hasattr(self.estimator, "classes_"):
            self.classes = [str(c) for c in self.estimator.classes_]

    def preprocess(self, raw_features: List[float]) -> List[float]:
        """Apply scaler transformation to the raw 25-feature vector."""
        if self.scaler is not None:
            arr = np.array([raw_features], dtype=np.float64)
            scaled = self.scaler.transform(arr)[0]
            return [float(x) for x in scaled]
        return self.preprocessor.transform(raw_features)

    def predict(self, features: List[float]) -> Prediction:
        """Run real inference on preprocessed features using trained weights."""
        arr = np.array([features], dtype=np.float64)
        pred_label_arr = self.estimator.predict(arr)
        pred_label = str(pred_label_arr[0])

        probabilities: Dict[str, float] = {}
        confidence = 1.0

        if hasattr(self.estimator, "predict_proba"):
            probs = self.estimator.predict_proba(arr)[0]
            est_classes = [str(c) for c in self.classes]
            for c_name, prob in zip(est_classes, probs):
                probabilities[c_name] = round(float(prob), 4)

            if pred_label in probabilities:
                confidence = probabilities[pred_label]
            elif len(probs) > 0:
                confidence = float(np.max(probs))

        # Determine class index
        class_idx = 0
        if pred_label in self.classes:
            class_idx = self.classes.index(pred_label)
        else:
            for idx_str, lbl in self.metadata.labels.items():
                if lbl == pred_label:
                    try:
                        class_idx = int(idx_str)
                    except ValueError:
                        pass
                    break

        return Prediction(
            label=pred_label,
            class_index=class_idx,
            confidence=round(confidence, 4),
            probabilities=probabilities,
        )

    def get_feature_importances(self) -> Dict[str, float]:
        """Expose feature importances from the underlying trained model for explainability."""
        from person2_engine.src.model_evaluator import extract_feature_importances
        return extract_feature_importances(self.estimator, self.metadata.feature_names)
