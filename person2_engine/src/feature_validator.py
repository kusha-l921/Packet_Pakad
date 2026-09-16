"""Feature validator module ensuring data integrity and ML-readiness.

Validates that feature vectors have no NaNs, no Infs, no negative counts/sizes,
and that ratios fall within [0.0, 1.0].
"""

from __future__ import annotations

import math
from typing import Dict, List, Optional

from person2_engine.src.feature_schema import FEATURE_DEFINITIONS, FEATURE_ORDER
from person2_engine.src.flow_models import FlowValidationResult


def validate_flow_features(features: Dict[str, float]) -> FlowValidationResult:
    """Validate extracted numerical features against the schema contract.

    Args:
        features: Dictionary of feature name to numerical value.

    Returns:
        FlowValidationResult with valid=True if all checks pass, otherwise
        detailed error and warning messages.
    """
    errors: List[str] = []
    warnings: List[str] = []

    # 1. Check all required features are present
    missing_keys = [f for f in FEATURE_ORDER if f not in features]
    if missing_keys:
        errors.append(f"Missing required feature keys: {missing_keys}")

    # 2. Check each feature for NaN, Inf, type, and bounds
    for fd in FEATURE_DEFINITIONS:
        if fd.name not in features:
            continue

        val = features[fd.name]

        # Type check
        if not isinstance(val, (int, float)):
            errors.append(f"Feature '{fd.name}' is not numeric: {type(val).__name__} ({val})")
            continue

        # NaN and Inf check
        if math.isnan(val):
            errors.append(f"Feature '{fd.name}' contains NaN.")
            continue
        if math.isinf(val):
            errors.append(f"Feature '{fd.name}' contains infinite value: {val}.")
            continue

        # Non-negative bound check
        if fd.min_value is not None and val < (fd.min_value - 1e-7):
            errors.append(
                f"Feature '{fd.name}' value {val} is below allowed minimum {fd.min_value}."
            )

        # Maximum bound check (e.g. for ratios)
        if fd.max_value is not None and val > (fd.max_value + 1e-4):
            errors.append(
                f"Feature '{fd.name}' value {val} exceeds allowed maximum {fd.max_value}."
            )

    # 3. Ratio consistency check
    if "forward_packet_ratio" in features and "backward_packet_ratio" in features:
        pkt_ratio_sum = features["forward_packet_ratio"] + features["backward_packet_ratio"]
        total_pkts = features.get("total_packets", 0.0)
        if total_pkts > 0 and abs(pkt_ratio_sum - 1.0) > 0.01:
            warnings.append(
                f"Forward and backward packet ratios do not sum to 1.0: {pkt_ratio_sum:.4f}"
            )

    if "forward_byte_ratio" in features and "backward_byte_ratio" in features:
        byte_ratio_sum = features["forward_byte_ratio"] + features["backward_byte_ratio"]
        total_bytes = features.get("total_bytes", 0.0)
        if total_bytes > 0 and abs(byte_ratio_sum - 1.0) > 0.01:
            warnings.append(
                f"Forward and backward byte ratios do not sum to 1.0: {byte_ratio_sum:.4f}"
            )

    is_valid = len(errors) == 0
    return FlowValidationResult(valid=is_valid, errors=errors, warnings=warnings)


def validate_ml_vector(vector: List[float]) -> FlowValidationResult:
    """Validate an ML-ready numerical feature vector.

    Args:
        vector: List of float values matching FEATURE_ORDER length.

    Returns:
        FlowValidationResult.
    """
    errors: List[str] = []
    warnings: List[str] = []

    if len(vector) != len(FEATURE_ORDER):
        errors.append(
            f"Vector length {len(vector)} does not match schema length {len(FEATURE_ORDER)}."
        )
        return FlowValidationResult(valid=False, errors=errors, warnings=warnings)

    for idx, (val, fd) in enumerate(zip(vector, FEATURE_DEFINITIONS)):
        if not isinstance(val, (int, float)):
            errors.append(f"Vector[{idx}] ({fd.name}) is not float: {val}")
        elif math.isnan(val):
            errors.append(f"Vector[{idx}] ({fd.name}) is NaN.")
        elif math.isinf(val):
            errors.append(f"Vector[{idx}] ({fd.name}) is Inf.")
        elif fd.min_value is not None and val < (fd.min_value - 1e-7):
            errors.append(f"Vector[{idx}] ({fd.name}) is below min: {val} < {fd.min_value}")

    return FlowValidationResult(valid=len(errors) == 0, errors=errors, warnings=warnings)
