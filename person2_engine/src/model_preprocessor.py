"""Feature preprocessor for model inference.

Applies verified, documented scaling and transformations to the Phase 2
25-feature vector without inventing parameters.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List


class ModelPreprocessor:
    """Preprocesses a Phase 2 25-feature vector using metadata-declared transformations."""

    def __init__(self, preprocessing_config: Dict[str, Any]) -> None:
        """Initialize preprocessor from metadata specification.

        Args:
            preprocessing_config: Preprocessing metadata dictionary.
        """
        self.preprocessor_type: str = str(preprocessing_config.get("type", "identity"))
        self.required: bool = bool(
            preprocessing_config.get("required", self.preprocessor_type != "identity")
        )
        self.parameters: Dict[str, Any] = dict(preprocessing_config.get("parameters", {}))


    def transform(self, features: List[float]) -> List[float]:
        """Transform input features according to the declared specification.

        Args:
            features: 25-element float vector in deterministic schema order.

        Returns:
            Preprocessed 25-element float vector.

        Raises:
            ValueError: If preprocessing parameters are invalid, missing, or produce non-finite values.
        """
        if not self.required or self.preprocessor_type == "identity":
            return [float(x) for x in features]

        if self.preprocessor_type == "standard_scaler":
            return self._apply_standard_scaler(features)

        if self.preprocessor_type == "min_max_scaler":
            return self._apply_min_max_scaler(features)

        raise ValueError(
            f"Unsupported or undocumented preprocessing type: '{self.preprocessor_type}'"
        )

    def _apply_standard_scaler(self, features: List[float]) -> List[float]:
        means = self.parameters.get("mean")
        stds = self.parameters.get("std")

        if not means or not stds:
            raise ValueError(
                "Standard scaler preprocessing requires explicit 'mean' and 'std' vectors in parameters."
            )

        if len(means) != len(features) or len(stds) != len(features):
            raise ValueError(
                f"Dimension mismatch in standard scaler parameters: expected {len(features)}, "
                f"got mean={len(means)}, std={len(stds)}."
            )

        transformed: List[float] = []
        for x, mu, s in zip(features, means, stds):
            std_val = float(s) if float(s) > 1e-7 else 1.0
            val = (float(x) - float(mu)) / std_val
            if math.isnan(val) or math.isinf(val):
                raise ValueError(f"Standard scaler produced non-finite value: {val}")
            transformed.append(val)

        return transformed

    def _apply_min_max_scaler(self, features: List[float]) -> List[float]:
        mins = self.parameters.get("min")
        maxs = self.parameters.get("max")

        if not mins or not maxs:
            raise ValueError(
                "MinMax scaler preprocessing requires explicit 'min' and 'max' vectors in parameters."
            )

        if len(mins) != len(features) or len(maxs) != len(features):
            raise ValueError(
                f"Dimension mismatch in MinMax scaler parameters: expected {len(features)}, "
                f"got min={len(mins)}, max={len(maxs)}."
            )

        transformed: List[float] = []
        for x, min_val, max_val in zip(features, mins, maxs):
            denom = float(max_val) - float(min_val)
            scale = denom if denom > 1e-7 else 1.0
            val = (float(x) - float(min_val)) / scale
            if math.isnan(val) or math.isinf(val):
                raise ValueError(f"MinMax scaler produced non-finite value: {val}")
            transformed.append(val)

        return transformed
