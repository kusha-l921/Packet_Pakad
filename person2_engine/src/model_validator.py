"""Model compatibility validator for Phase 3.

Enforces strict verification of model artifacts, feature count, feature ordering,
preprocessing requirements, label mappings, and IPsec domain verification.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import logging
from pathlib import Path
from typing import Dict, List, Optional

from person2_engine.src.feature_schema import FEATURE_ORDER, FEATURE_SCHEMA_VERSION
from person2_engine.src.model_metadata import (
    InputType,
    IPsecCompatibilityLevel,
    ModelMetadata,
    ModelStatus,
    PredictionTask,
)

logger = logging.getLogger(__name__)


@dataclass
class CompatibilityReport:
    """Detailed report on whether a model meets the Phase 3 compatibility contract."""

    is_compatible: bool
    status: ModelStatus
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    checked_criteria: Dict[str, bool] = field(default_factory=dict)

    def __iter__(self):
        return iter((self.status, self.errors, self.warnings))

    def to_dict(self) -> Dict[str, object]:
        """Convert report to dictionary."""
        return {
            "is_compatible": self.is_compatible,
            "status": self.status.value,
            "errors": self.errors,
            "warnings": self.warnings,
            "checked_criteria": self.checked_criteria,
        }


def validate_model_compatibility(
    metadata: ModelMetadata,
    expected_schema_version: str = FEATURE_SCHEMA_VERSION,
    expected_feature_names: Optional[List[str]] = None,
    allow_unverified_domain: bool = False,
    base_dir: Optional[Path] = None,
) -> CompatibilityReport:
    """Validate a model's metadata and artifact against the Phase 2/3 contract."""
    if expected_feature_names is None:
        expected_feature_names = list(FEATURE_ORDER)

    errors: List[str] = []
    warnings: List[str] = []
    criteria: Dict[str, bool] = {}

    # 1. Artifact existence check
    criteria["artifact_exists"] = False
    if metadata.artifact_path:
        artifact_p = Path(metadata.artifact_path)
        if not artifact_p.is_absolute() and base_dir:
            artifact_p = base_dir / artifact_p
        if artifact_p.exists() and artifact_p.is_file():
            criteria["artifact_exists"] = True
        elif metadata.is_test_only:
            criteria["artifact_exists"] = True
        else:
            errors.append(f"Model artifact file does not exist: {artifact_p}")
    elif metadata.is_test_only:
        criteria["artifact_exists"] = True
    else:
        errors.append("Model metadata specifies no artifact_path.")

    # 2. Metadata identification
    criteria["metadata_complete"] = False
    if metadata.model_id and metadata.model_name and metadata.model_version:
        criteria["metadata_complete"] = True
    else:
        errors.append("Model metadata is missing required identification fields (id, name, version).")

    # 3. Known prediction task
    criteria["task_known"] = False
    valid_tasks = {t.value for t in PredictionTask} - {PredictionTask.UNKNOWN.value}
    if metadata.prediction_task in valid_tasks:
        criteria["task_known"] = True
    else:
        errors.append(
            f"Prediction task '{metadata.prediction_task}' is unknown or unsupported. "
            f"Supported tasks: {sorted(valid_tasks)}"
        )

    # 4. Input type compatibility
    criteria["input_type_compatible"] = False
    if metadata.input_type == InputType.FLOW_FEATURES.value:
        criteria["input_type_compatible"] = True
    else:
        errors.append(
            f"Input type '{metadata.input_type}' is incompatible with the flow feature pipeline. "
            f"Expected '{InputType.FLOW_FEATURES.value}'."
        )

    # 5. Feature count
    criteria["feature_count_matches"] = False
    expected_count = len(expected_feature_names)
    if metadata.feature_count == expected_count and len(metadata.feature_names) == expected_count:
        criteria["feature_count_matches"] = True
    else:
        errors.append(
            f"Feature count mismatch: model expects {metadata.feature_count}, "
            f"pipeline provides {expected_count}."
        )

    # 6 & 7. Feature names and exact deterministic order
    criteria["feature_names_match"] = False
    criteria["feature_order_matches"] = False
    if set(metadata.feature_names) == set(expected_feature_names):
        criteria["feature_names_match"] = True
        if metadata.feature_names == expected_feature_names:
            criteria["feature_order_matches"] = True
        else:
            first_mismatch_idx = next(
                (i for i, (a, b) in enumerate(zip(metadata.feature_names, expected_feature_names)) if a != b),
                0,
            )
            errors.append(
                f"Feature order mismatch at index {first_mismatch_idx}: "
                f"expected '{expected_feature_names[first_mismatch_idx]}', "
                f"got '{metadata.feature_names[first_mismatch_idx]}'."
            )
    else:
        missing = set(expected_feature_names) - set(metadata.feature_names)
        unexpected = set(metadata.feature_names) - set(expected_feature_names)
        errors.append(
            f"Missing expected feature(s): {sorted(missing)}. Unexpected: {sorted(unexpected)}"
        )

    # 8. Schema version compatibility
    criteria["schema_version_compatible"] = False
    if metadata.feature_schema_version == expected_schema_version:
        criteria["schema_version_compatible"] = True
    else:
        errors.append(
            f"Feature schema version mismatch: '{metadata.feature_schema_version}' != '{expected_schema_version}'."
        )

    # 9. Preprocessing documentation
    criteria["preprocessing_valid"] = False
    if isinstance(metadata.preprocessing, dict):
        ptype = metadata.preprocessing.get("type", "identity")
        if ptype not in {"identity", "standard_scaler", "min_max_scaler"}:
            errors.append(f"Unsupported preprocessing type: '{ptype}'.")
        elif ptype == "standard_scaler":
            params = metadata.preprocessing.get("parameters", {})
            means = params.get("mean")
            stds = params.get("std")
            if not means or not stds or len(means) != 25 or len(stds) != 25:
                errors.append("Standard scaler parameters 'mean' and 'std' must contain exactly 25 floats each.")
            elif any(float(s) <= 0.0 for s in stds):
                errors.append("Standard scaler 'std' values must be strictly positive.")
            else:
                criteria["preprocessing_valid"] = True
        elif ptype == "min_max_scaler":
            params = metadata.preprocessing.get("parameters", {})
            mins = params.get("min")
            maxs = params.get("max")
            if not mins or not maxs or len(mins) != 25 or len(maxs) != 25:
                errors.append("MinMax scaler parameters 'min' and 'max' must contain exactly 25 floats each.")
            elif any(float(mx) <= float(mn) for mn, mx in zip(mins, maxs)):
                errors.append("MinMax scaler 'max' must be strictly greater than 'min'.")
            else:
                criteria["preprocessing_valid"] = True
        else:
            criteria["preprocessing_valid"] = True
    else:
        errors.append("Preprocessing specification must be a dictionary.")

    # 10. Label mapping
    criteria["labels_valid"] = False
    if not metadata.labels or not isinstance(metadata.labels, dict):
        errors.append("No output labels defined in model metadata.")
    elif len(metadata.labels) < 2:
        errors.append("Model metadata must provide at least 2 output labels.")
    else:
        criteria["labels_valid"] = True

    # 11. IPsec domain verification status
    ipsec_level = str(metadata.ipsec_compatibility.get("level", IPsecCompatibilityLevel.UNKNOWN.value)).lower()
    criteria["ipsec_domain_verified"] = ipsec_level in {
        IPsecCompatibilityLevel.VERIFIED.value,
        IPsecCompatibilityLevel.VERIFIED_IPSEC.value,
        "verified",
        "verified_ipsec",
    }

    if ipsec_level == IPsecCompatibilityLevel.INCOMPATIBLE.value:
        errors.append(
            f"Model is flagged as incompatible with IPsec traffic: "
            f"{metadata.ipsec_compatibility.get('reason', 'Domain incompatibility')}"
        )

    if errors:
        return CompatibilityReport(
            is_compatible=False,
            status=ModelStatus.INCOMPATIBLE,
            errors=errors,
            warnings=warnings,
            checked_criteria=criteria,
        )

    # If technically compatible, check domain verification
    if criteria["ipsec_domain_verified"]:
        return CompatibilityReport(
            is_compatible=True,
            status=ModelStatus.READY_FOR_INFERENCE,
            errors=[],
            warnings=warnings,
            checked_criteria=criteria,
        )

    # Technically compatible, but IPsec domain is unverified
    msg = (
        f"Model '{metadata.model_id}' is technically compatible with Schema {expected_schema_version}, "
        "but has NOT been validated on real IPsec/StrongSwan encrypted traffic. "
        "IPsec generalization is unverified."
    )
    warnings.append(msg)

    if allow_unverified_domain:
        warnings.append("Inference allowed via configuration override for unverified domain.")
        return CompatibilityReport(
            is_compatible=True,
            status=ModelStatus.READY_FOR_INFERENCE,
            errors=[],
            warnings=warnings,
            checked_criteria=criteria,
        )
    else:
        return CompatibilityReport(
            is_compatible=True,
            status=ModelStatus.TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED,
            errors=[],
            warnings=warnings,
            checked_criteria=criteria,
        )

