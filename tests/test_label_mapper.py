"""Unit tests for Phase 3 label mapper module.

Tests explicit mapping of dataset-specific class names to canonical project categories
and enforces that no silent arbitrary label merging occurs.
"""

import pytest

from person2_engine.src.label_mapper import (
    CANONICAL_CATEGORIES,
    DEFAULT_LABEL_MAPPING,
    LabelMapper,
)


class TestLabelMapper:
    """Tests for label normalization and canonical classification mapping."""

    def test_canonical_categories_present(self):
        """Verify the 5 canonical categories exist."""
        assert "web" in CANONICAL_CATEGORIES
        assert "video" in CANONICAL_CATEGORIES
        assert "voip" in CANONICAL_CATEGORIES
        assert "file_transfer" in CANONICAL_CATEGORIES
        assert "interactive" in CANONICAL_CATEGORIES

    def test_default_label_mappings(self):
        """Test default mappings for standard internet application labels."""
        mapper = LabelMapper()
        assert mapper.map_label("HTTPS") == "web"
        assert mapper.map_label("HTTP") == "web"
        assert mapper.map_label("YouTube") == "video"
        assert mapper.map_label("Netflix") == "video"
        assert mapper.map_label("Skype") == "voip"
        assert mapper.map_label("Discord") == "voip"
        assert mapper.map_label("FTP") == "file_transfer"
        assert mapper.map_label("BitTorrent") == "file_transfer"
        assert mapper.map_label("SSH") == "interactive"
        assert mapper.map_label("Telnet") == "interactive"

    def test_identity_mapping_for_canonical_labels(self):
        """Verify canonical categories map directly to themselves."""
        mapper = LabelMapper()
        for cat in CANONICAL_CATEGORIES:
            assert mapper.map_label(cat) == cat

    def test_strict_mode_rejects_unknown_label(self):
        """Test that unknown labels raise ValueError by default without fallback."""
        mapper = LabelMapper()
        with pytest.raises(ValueError, match="Unmapped dataset label: 'custom_unknown_protocol'"):
            mapper.map_label("custom_unknown_protocol")

    def test_non_strict_mode_falls_back_or_passes_through(self):
        """Test fallback behavior when fallback_label is configured."""
        mapper = LabelMapper(fallback_label="web")
        assert mapper.map_label("unrecognized_traffic") == "web"

    def test_custom_label_mapping(self):
        """Test user-defined custom mapping dictionary."""
        custom = {
            "StrongSwan-ESP": "interactive",
            "WireGuard-Tunnel": "file_transfer",
        }
        mapper = LabelMapper(custom_mapping=custom)
        assert mapper.map_label("StrongSwan-ESP") == "interactive"
        assert mapper.map_label("WireGuard-Tunnel") == "file_transfer"

    def test_invalid_canonical_target_rejected(self):
        """Test that mapping to a non-canonical target raises ValueError."""
        with pytest.raises(ValueError, match="not in canonical categories"):
            LabelMapper(custom_mapping={"test": "invalid_target_category"})
