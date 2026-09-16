"""Feature adapter guaranteeing Phase 2 25-feature schema consistency across training and inference.

Reuses Phase 2 deterministic feature order and provides conversion helpers for
flow records, dictionary rows, and tabular data matrices.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Sequence

from person2_engine.src.feature_extractor import flow_features_to_vector
from person2_engine.src.feature_schema import FEATURE_ORDER, FEATURE_SCHEMA_VERSION
from person2_engine.src.feature_validator import validate_ml_vector
from person2_engine.src.flow_models import FlowResult


def adapt_flow_to_vector(flow: FlowResult) -> List[float]:
    """Convert a Phase 2 FlowResult directly into the verified 25-feature vector.

    Args:
        flow: FlowResult instance.

    Returns:
        25-element float vector.
    """
    return flow_features_to_vector(flow)


def adapt_dict_to_vector(
    row: Dict[str, Any],
    expected_order: Sequence[str] = FEATURE_ORDER,
) -> List[float]:
    """Extract and validate 25 numerical features from a row dictionary in exact schema order.

    Args:
        row: Row dictionary containing feature keys.
        expected_order: Expected sequence of feature names.

    Returns:
        Deterministic list of 25 float values.

    Raises:
        ValueError: If features are missing, non-numerical, NaN, or infinite.
    """
    vector: List[float] = []
    missing: List[str] = []

    for name in expected_order:
        if name not in row:
            missing.append(name)
            continue

        raw_val = row[name]
        try:
            val = float(raw_val)
            if math.isnan(val) or math.isinf(val):
                raise ValueError(f"Feature '{name}' has invalid non-finite value: {raw_val}")
            vector.append(val)
        except (ValueError, TypeError) as e:
            raise ValueError(f"Feature '{name}' cannot be converted to float: {raw_val} ({e})") from e

    if missing:
        raise ValueError(
            f"Cannot adapt row to Phase 2 feature vector. Missing {len(missing)} feature(s): {missing}"
        )

    # Validate vector bounds
    validation = validate_ml_vector(vector)
    if not validation.valid:
        raise ValueError(f"Feature vector validation failed: {validation.errors}")

    return vector
