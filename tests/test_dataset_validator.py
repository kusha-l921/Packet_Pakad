"""Unit tests for Phase 3 dataset validator module.

Validates schema adherence, feature completeness, NaN/Inf checks, label detection,
and error reporting on synthetic and file-based flow datasets.
"""

from pathlib import Path
import pytest

from person2_engine.src.dataset_validator import (
    DatasetValidationReport,
    validate_csv_dataset,
    validate_dataset_records,
)
from person2_engine.src.feature_schema import FEATURE_ORDER, FEATURE_SCHEMA_VERSION


def _make_valid_record(label: str = "web", offset: float = 0.0) -> dict:
    """Helper to generate a valid single flow record matching the 25-feature schema."""
    rec = {feat: float(i + 1) + offset for i, feat in enumerate(FEATURE_ORDER)}
    # Set realistic non-conflicting ratios
    rec["forward_packet_ratio"] = 0.6
    rec["backward_packet_ratio"] = 0.4
    rec["forward_byte_ratio"] = 0.7
    rec["backward_byte_ratio"] = 0.3
    rec["label"] = label
    return rec


class TestDatasetValidator:
    """Tests for dataset schema validation against Phase 2 contracts."""

    def test_valid_dataset_records_pass(self):
        """Test that fully compliant records pass validation."""
        records = [
            _make_valid_record("web", offset=float(i))
            for i in range(10)
        ] + [
            _make_valid_record("video", offset=float(i + 10))
            for i in range(10)
        ]
        report = validate_dataset_records(records)
        assert report.valid is True
        assert report.is_valid is True
        assert report.sample_count == 20
        assert len(report.errors) == 0
        assert report.feature_count == 25
        assert report.feature_schema_version == FEATURE_SCHEMA_VERSION

    def test_missing_feature_column_fails(self):
        """Test that omitting a required Phase 2 feature causes validation failure."""
        rec = _make_valid_record("web")
        del rec["bytes_per_second"]
        report = validate_dataset_records([rec], min_samples=1)
        assert report.valid is False
        assert any("bytes_per_second" in err for err in report.errors)

    def test_nan_value_detected(self):
        """Test that NaN values in numerical features are flagged as invalid."""
        rec = _make_valid_record("web")
        rec["mean_packet_size"] = float("nan")
        report = validate_dataset_records([rec], min_samples=1)
        assert report.valid is False
        assert any("NaN" in err for err in report.errors)

    def test_infinite_value_detected(self):
        """Test that infinite values are flagged as invalid."""
        rec = _make_valid_record("web")
        rec["packets_per_second"] = float("inf")
        report = validate_dataset_records([rec], min_samples=1)
        assert report.valid is False
        assert any("infinite" in err.lower() for err in report.errors)

    def test_missing_label_column_fails(self):
        """Test that missing target label is detected and rejected."""
        rec = _make_valid_record("web")
        del rec["label"]
        report = validate_dataset_records([rec], min_samples=1)
        assert report.valid is False
        assert any("label" in err.lower() for err in report.errors)

    def test_empty_or_whitespace_label_fails(self):
        """Test that empty or blank string labels are rejected."""
        rec = _make_valid_record("   ")
        report = validate_dataset_records([rec], min_samples=1)
        assert report.valid is False
        assert any("missing or empty label" in err.lower() for err in report.errors)

    def test_non_numerical_feature_value_fails(self):
        """Test that string or non-numerical values in numerical columns fail."""
        rec = _make_valid_record("web")
        rec["flow_duration_seconds"] = "not_a_number"
        report = validate_dataset_records([rec], min_samples=1)
        assert report.valid is False
        assert any("non-numerical" in err for err in report.errors)

    def test_ratio_bounds_enforced(self):
        """Test that ratio bounds exceeding [0.0, 1.0] trigger validation errors."""
        rec = _make_valid_record("web")
        rec["forward_packet_ratio"] = 1.5
        report = validate_dataset_records([rec], min_samples=1)
        assert report.valid is False
        assert any("forward_packet_ratio" in err for err in report.errors)

    def test_validate_csv_file_on_disk(self, tmp_path: Path):
        """Test loading and validating an actual CSV file."""
        csv_file = tmp_path / "valid_flows.csv"
        headers = list(FEATURE_ORDER) + ["label"]
        rows = [
            [str(float(i + 1)) for i in range(len(FEATURE_ORDER))] + ["web"]
            for _ in range(6)
        ] + [
            [str(float(i + 2)) for i in range(len(FEATURE_ORDER))] + ["video"]
            for _ in range(6)
        ]
        # Fix ratios
        fwd_idx = FEATURE_ORDER.index("forward_packet_ratio")
        bwd_idx = FEATURE_ORDER.index("backward_packet_ratio")
        fwd_b_idx = FEATURE_ORDER.index("forward_byte_ratio")
        bwd_b_idx = FEATURE_ORDER.index("backward_byte_ratio")
        for r in rows:
            r[fwd_idx] = "0.5"
            r[bwd_idx] = "0.5"
            r[fwd_b_idx] = "0.5"
            r[bwd_b_idx] = "0.5"

        with open(csv_file, "w", encoding="utf-8") as f:
            f.write(",".join(headers) + "\n")
            for r in rows:
                f.write(",".join(r) + "\n")

        report = validate_csv_dataset(csv_file)
        assert report.valid is True
        assert report.sample_count == 12
        assert "web" in report.class_distribution
        assert "video" in report.class_distribution

    def test_validate_nonexistent_file_returns_error(self, tmp_path: Path):
        """Test validation on non-existent CSV file returns structured error."""
        nonexistent = tmp_path / "does_not_exist.csv"
        report = validate_csv_dataset(nonexistent)
        assert report.valid is False
        assert any("does not exist" in err for err in report.errors)
