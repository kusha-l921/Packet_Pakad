"""Dataset data models and typed containers for Phase 3 ML training.

Provides typed representations of flow samples, training datasets, dataset metadata,
and train/test partitions adhering strictly to the Phase 2 25-feature schema.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple
import numpy as np

from person2_engine.src.feature_schema import FEATURE_ORDER, FEATURE_SCHEMA_VERSION


@dataclass
class FlowSample:
    """A single flow sample containing the 25 Phase 2 numerical features and a target label."""

    features: List[float]
    label: str
    sample_id: Optional[str] = None
    group: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert sample to dictionary."""
        return {
            "sample_id": self.sample_id,
            "group": self.group,
            "label": self.label,
            "features": dict(zip(FEATURE_ORDER, self.features)),
            "metadata": self.metadata,
        }


@dataclass
class DatasetMetadata:
    """Metadata describing a training dataset's origin, scope, and domain limitations."""

    name: str
    source: str
    traffic_type: str
    sample_count: int
    class_distribution: Dict[str, int]
    ipsec_traffic: bool = False
    description: str = ""
    feature_schema_version: str = FEATURE_SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to dictionary."""
        return asdict(self)


@dataclass
class TrainingDataset:
    """In-memory dataset container for training and evaluating tabular ML models."""

    samples: List[FlowSample]
    metadata: DatasetMetadata
    feature_names: List[str] = field(default_factory=lambda: list(FEATURE_ORDER))
    feature_schema_version: str = FEATURE_SCHEMA_VERSION

    def __len__(self) -> int:
        return len(self.samples)

    def to_arrays(self) -> Tuple[np.ndarray, np.ndarray]:
        """Convert samples into NumPy feature matrix X and label vector y.

        Returns:
            Tuple of (X: float64 array of shape [N, 25], y: string array of shape [N]).
        """
        if not self.samples:
            return np.empty((0, len(self.feature_names)), dtype=np.float64), np.empty((0,), dtype=object)

        X = np.array([s.features for s in self.samples], dtype=np.float64)
        y = np.array([s.label for s in self.samples], dtype=object)
        return X, y

    def get_groups(self) -> np.ndarray:
        """Get array of group identifiers for group-aware train/test splitting."""
        return np.array([s.group or s.sample_id or f"group_{i}" for i, s in enumerate(self.samples)], dtype=object)

    def get_classes(self) -> List[str]:
        """Get sorted list of unique class labels in the dataset."""
        return sorted(list({s.label for s in self.samples}))


@dataclass
class SplitData:
    """Train/test partitions of feature matrices and labels."""

    X_train: np.ndarray
    X_test: np.ndarray
    y_train: np.ndarray
    y_test: np.ndarray
    feature_names: List[str]
    classes: List[str]
    feature_schema_version: str = FEATURE_SCHEMA_VERSION
    X_train_raw: Optional[np.ndarray] = None
    X_test_raw: Optional[np.ndarray] = None
    groups_train: Optional[np.ndarray] = None
    groups_test: Optional[np.ndarray] = None
    split_strategy: str = "stratified"
    evaluation_mode: str = "OVERALL_MIXED_EVALUATION"
    per_class_evaluation_modes: Dict[str, str] = field(default_factory=dict)
    sufficiency_status: Dict[str, str] = field(default_factory=dict)

