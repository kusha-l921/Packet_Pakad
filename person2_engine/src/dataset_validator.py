"""Strict dataset schema validator for Phase 3 ML training data.

Enforces verification of all 25 features in exact schema order, absence of NaN/Inf,
presence of valid target labels, and minimum multiclass distribution before training.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

from person2_engine.src.feature_schema import FEATURE_ORDER, FEATURE_SCHEMA_VERSION


@dataclass
class DatasetValidationReport:
    """Outcome of validating a dataset file or table against the Phase 2 contract."""

    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    sample_count: int = 0
    class_distribution: Dict[str, int] = field(default_factory=dict)
    feature_count: int = 0
    feature_schema_version: str = FEATURE_SCHEMA_VERSION

    @property
    def valid(self) -> bool:
        """Alias for is_valid."""
        return self.is_valid

    def __iter__(self):
        return iter((self.is_valid, self.errors, self.warnings))

    def to_dict(self) -> Dict[str, Any]:
        """Convert validation report to dictionary."""
        return {
            "is_valid": self.is_valid,
            "errors": self.errors,
            "warnings": self.warnings,
            "sample_count": self.sample_count,
            "class_distribution": self.class_distribution,
            "feature_count": self.feature_count,
            "feature_schema_version": self.feature_schema_version,
        }


def validate_dataset_records(
    records: Sequence[Dict[str, Any]],
    label_column: str = "label",
    expected_features: Optional[List[str]] = None,
    min_samples: int = 10,
    min_classes: int = 2,
) -> DatasetValidationReport:
    """Validate a list of row dictionaries against the strict Phase 2 feature schema contract.

    Args:
        records: Sequence of dictionaries representing rows.
        label_column: Column name holding class labels.
        expected_features: Ordered list of expected feature names (default FEATURE_ORDER).
        min_samples: Minimum required rows.
        min_classes: Minimum distinct classes required.

    Returns:
        DatasetValidationReport with validation outcome and detailed diagnostic messages.
    """
    if expected_features is None:
        expected_features = list(FEATURE_ORDER)

    errors: List[str] = []
    warnings: List[str] = []
    class_counts: Dict[str, int] = {}

    if not records:
        return DatasetValidationReport(
            is_valid=False,
            errors=["Dataset contains 0 rows/records."],
            sample_count=0,
            feature_count=0,
        )

    # 1. Inspect first row keys for feature existence, extra columns, and ordering
    first_row = records[0]
    keys = list(first_row.keys())

    if label_column not in keys:
        errors.append(f"Missing mandatory target label column: '{label_column}'.")

    known_metadata = {
        label_column,
        "sample_id",
        "capture_group",
        "group",
        "source_dataset",
        "source_capture",
        "original_label",
        "model_eligible",
        "exclusion_reason",
    }
    feature_keys = [k for k in keys if k not in known_metadata and not k.startswith("_")]

    missing_features = [f for f in expected_features if f not in feature_keys]
    if missing_features:
        errors.append(
            f"Dataset is missing {len(missing_features)} required Phase 2 feature(s): {missing_features}"
        )

    unexpected_keys = [k for k in feature_keys if k not in expected_features]
    if unexpected_keys:
        warnings.append(
            f"Dataset contains {len(unexpected_keys)} unexpected extra column(s): {unexpected_keys}"
        )

    # Verify exact sequential ordering if feature count matches
    if len(feature_keys) == len(expected_features):
        for idx, (actual_col, expected_col) in enumerate(zip(feature_keys, expected_features)):
            if actual_col != expected_col:
                errors.append(
                    f"Feature order mismatch at column index {idx}: expected '{expected_col}', got '{actual_col}'."
                )
                break

    # 2. Inspect every row for NaN, Inf, missing label, and type correctness
    nan_count = 0
    inf_count = 0
    missing_label_count = 0

    for row_idx, row in enumerate(records):
        # Validate label
        raw_label = row.get(label_column)
        if raw_label is None or str(raw_label).strip() == "":
            missing_label_count += 1
        else:
            lbl_str = str(raw_label).strip()
            class_counts[lbl_str] = class_counts.get(lbl_str, 0) + 1

        # Validate numerical features
        for f in expected_features:
            if f not in row:
                continue
            val = row[f]
            try:
                f_val = float(val)
                if math.isnan(f_val):
                    nan_count += 1
                elif math.isinf(f_val):
                    inf_count += 1
                elif f in {"forward_packet_ratio", "backward_packet_ratio", "forward_byte_ratio", "backward_byte_ratio"} and (f_val < -1e-5 or f_val > 1.0001):
                    errors.append(
                        f"Row {row_idx}: ratio feature '{f}' value {f_val} is outside valid range [0.0, 1.0]."
                    )
            except (ValueError, TypeError):
                errors.append(
                    f"Row {row_idx}: non-numerical value '{val}' for feature '{f}'."
                )

    if missing_label_count > 0:
        errors.append(f"Dataset contains {missing_label_count} row(s) with missing or empty labels.")

    if nan_count > 0:
        errors.append(f"Dataset contains {nan_count} NaN feature value(s).")

    if inf_count > 0:
        errors.append(f"Dataset contains {inf_count} Infinite (Inf/-Inf) feature value(s).")

    # 3. Verify sample size and class balance
    total_samples = len(records)
    if total_samples < min_samples:
        errors.append(
            f"Dataset sample count {total_samples} is below the minimum required threshold of {min_samples}."
        )

    if len(class_counts) < min_classes:
        errors.append(
            f"Dataset contains only {len(class_counts)} class(es): {list(class_counts.keys())}. "
            f"At least {min_classes} distinct classes are required for classification."
        )

    # Check for severely under-represented classes (< 3 samples)
    for c_name, count in class_counts.items():
        if count < 3:
            warnings.append(
                f"Class '{c_name}' has only {count} sample(s), which may impair stratified train/test splitting."
            )

    is_valid = len(errors) == 0

    return DatasetValidationReport(
        is_valid=is_valid,
        errors=errors,
        warnings=warnings,
        sample_count=total_samples,
        class_distribution=class_counts,
        feature_count=len(expected_features),
    )


def validate_csv_dataset(
    file_path: Union[str, Path],
    label_column: str = "label",
    expected_features: Optional[List[str]] = None,
    min_samples: int = 10,
) -> DatasetValidationReport:
    """Validate a CSV file directly from disk against the Phase 2 feature schema contract.

    Args:
        file_path: Path to the CSV file.
        label_column: Column name containing the target class.
        expected_features: Expected feature ordering.
        min_samples: Minimum required samples.

    Returns:
        DatasetValidationReport.
    """
    path = Path(file_path).resolve()
    if not path.is_file():
        return DatasetValidationReport(
            is_valid=False,
            errors=[f"Dataset file does not exist: {path}"],
        )

    try:
        with open(path, mode="r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            if reader.fieldnames is None:
                return DatasetValidationReport(
                    is_valid=False,
                    errors=["CSV file is empty or missing header line."],
                )
            rows = list(reader)

        return validate_dataset_records(
            records=rows,
            label_column=label_column,
            expected_features=expected_features,
            min_samples=min_samples,
        )
    except Exception as e:
        return DatasetValidationReport(
            is_valid=False,
            errors=[f"Failed to read or parse CSV dataset '{path}': {e}"],
        )
