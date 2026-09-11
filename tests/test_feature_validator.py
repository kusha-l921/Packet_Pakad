"""Unit tests for feature validation in feature_validator.py."""

from person2_engine.src.feature_schema import FEATURE_MAP, FEATURE_ORDER
from person2_engine.src.feature_validator import validate_flow_features, validate_ml_vector


def get_dummy_valid_features() -> dict[str, float]:
    """Return a fully valid dictionary of features using schema defaults."""
    return {name: FEATURE_MAP[name].default_value for name in FEATURE_ORDER}


def test_valid_features_pass():
    """Verify that a compliant feature dictionary passes validation."""
    feats = get_dummy_valid_features()
    res = validate_flow_features(feats)
    assert res.valid is True
    assert len(res.errors) == 0


def test_missing_feature_fails():
    """Verify that omitting a required feature key causes validation failure."""
    feats = get_dummy_valid_features()
    del feats["mean_packet_size"]

    res = validate_flow_features(feats)
    assert res.valid is False
    assert any("Missing required feature keys" in err for err in res.errors)


def test_nan_fails():
    """Verify that NaN values are caught and flagged."""
    feats = get_dummy_valid_features()
    feats["flow_duration_seconds"] = float("nan")

    res = validate_flow_features(feats)
    assert res.valid is False
    assert any("contains NaN" in err for err in res.errors)


def test_inf_fails():
    """Verify that infinite values are caught and flagged."""
    feats = get_dummy_valid_features()
    feats["packets_per_second"] = float("inf")

    res = validate_flow_features(feats)
    assert res.valid is False
    assert any("infinite value" in err for err in res.errors)


def test_negative_values_fail():
    """Verify that negative packet/byte/size values fail validation."""
    feats = get_dummy_valid_features()
    feats["total_packets"] = -5.0

    res = validate_flow_features(feats)
    assert res.valid is False
    assert any("below allowed minimum" in err for err in res.errors)


def test_ratio_bounds():
    """Verify that ratios exceeding 1.0 fail validation."""
    feats = get_dummy_valid_features()
    feats["forward_packet_ratio"] = 1.5

    res = validate_flow_features(feats)
    assert res.valid is False
    assert any("exceeds allowed maximum" in err for err in res.errors)


def test_ml_vector_validator():
    """Verify ML vector validation against lengths and non-finite values."""
    # Valid vector
    valid_vec = [1.0] * 25
    assert validate_ml_vector(valid_vec).valid is True

    # Too short
    short_vec = [1.0] * 24
    assert validate_ml_vector(short_vec).valid is False

    # Contains NaN
    nan_vec = [1.0] * 24 + [float("nan")]
    assert validate_ml_vector(nan_vec).valid is False
