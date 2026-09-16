"""Unit tests for the central feature schema specification in feature_schema.py."""

from person2_engine.src.feature_schema import (
    FEATURE_DEFINITIONS,
    FEATURE_MAP,
    FEATURE_ORDER,
    FEATURE_SCHEMA_VERSION,
)


def test_schema_version():
    """Verify feature schema version is 1.0."""
    assert FEATURE_SCHEMA_VERSION == "1.0"


def test_feature_count():
    """Verify schema defines exactly 25 core features."""
    assert len(FEATURE_ORDER) == 25
    assert len(FEATURE_DEFINITIONS) == 25


def test_deterministic_ordering():
    """Verify feature order is fixed and deterministic."""
    expected_first_5 = [
        "total_packets",
        "forward_packets",
        "backward_packets",
        "total_bytes",
        "forward_bytes",
    ]
    assert FEATURE_ORDER[:5] == expected_first_5
    assert FEATURE_ORDER[-1] == "maximum_packets_in_one_second"


def test_feature_metadata_completeness():
    """Verify every feature has valid metadata, description, and default value."""
    for fd in FEATURE_DEFINITIONS:
        assert fd.name in FEATURE_ORDER
        assert isinstance(fd.description, str) and len(fd.description) > 5
        assert fd.dtype == float
        assert isinstance(fd.default_value, float)
        assert fd.min_value is not None and fd.min_value >= 0.0


def test_feature_map_lookup():
    """Verify quick dictionary lookup matches definitions."""
    assert len(FEATURE_MAP) == 25
    for name in FEATURE_ORDER:
        assert name in FEATURE_MAP
        assert FEATURE_MAP[name].name == name
