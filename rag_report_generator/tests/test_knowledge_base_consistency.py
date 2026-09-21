"""Regression tests verifying factual consistency between RAG knowledge base and authoritative specifications."""

import re
import unittest
from pathlib import Path

KB_DIR = Path(__file__).resolve().parent.parent / "knowledge_base"


class TestKnowledgeBaseConsistency(unittest.TestCase):
    """Enforces strict consistency between curated knowledge documents and project contracts."""

    # Authoritative Phase 4 Behavioral Risk Indicators and point contributions
    PHASE4_AUTHORITATIVE_INDICATORS = {
        "UNUSUAL_HIGH_UPLOAD_VOLUME": 25,
        "UNUSUAL_HIGH_PACKET_RATE": 20,
        "UNUSUAL_BURST_ACTIVITY": 15,
        "LONG_LIVED_HIGH_VOLUME_FLOW": 15,
        "PERIODIC_LOW_VOLUME_ACTIVITY": 10,
        "STRONG_DIRECTIONAL_ASYMMETRY": 10,
    }

    # Authoritative Phase 2 25 Flow Features
    PHASE2_AUTHORITATIVE_FEATURES = [
        "total_packets",
        "forward_packets",
        "backward_packets",
        "total_bytes",
        "forward_bytes",
        "backward_bytes",
        "minimum_packet_size",
        "maximum_packet_size",
        "mean_packet_size",
        "standard_deviation_packet_size",
        "median_packet_size",
        "forward_mean_packet_size",
        "backward_mean_packet_size",
        "flow_duration_seconds",
        "packets_per_second",
        "bytes_per_second",
        "mean_inter_arrival_time",
        "minimum_inter_arrival_time",
        "maximum_inter_arrival_time",
        "standard_deviation_inter_arrival_time",
        "forward_packet_ratio",
        "backward_packet_ratio",
        "forward_byte_ratio",
        "backward_byte_ratio",
        "maximum_packets_in_one_second",
    ]

    # Authoritative IPsec Domain Policy Statuses
    AUTHORITATIVE_DOMAIN_STATUSES = [
        "VERIFIED IPSEC",
        "TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED",
        "allow_unverified_domain",
    ]

    # Authoritative Evaluation Modes
    AUTHORITATIVE_EVALUATION_MODES = [
        "GROUP_ISOLATED",
        "WITHIN_CAPTURE_HOLDOUT",
        "OVERALL_MIXED_EVALUATION",
    ]

    # Authoritative Traffic Resemblance Categories
    AUTHORITATIVE_TRAFFIC_CATEGORIES = [
        "web",
        "video",
        "voip",
        "file_transfer",
        "interactive",
    ]

    def test_behavioral_indicators_and_point_values_match_authoritative_spec(self):
        """Verify each Phase 4 indicator is documented exactly once with bit-exact risk points."""
        indicators_file = KB_DIR / "behavioral" / "risk_indicators.md"
        self.assertTrue(indicators_file.exists(), f"Missing file: {indicators_file}")

        content = indicators_file.read_text(encoding="utf-8")

        for indicator_name, expected_points in self.PHASE4_AUTHORITATIVE_INDICATORS.items():
            # Check heading exists exactly once
            heading_matches = re.findall(rf"^##\s+{re.escape(indicator_name)}\s*$", content, flags=re.MULTILINE)
            self.assertEqual(
                len(heading_matches),
                1,
                f"Indicator '{indicator_name}' must appear as a section heading exactly once. Found: {len(heading_matches)}",
            )

            # Extract section text
            pattern = rf"^##\s+{re.escape(indicator_name)}\b(.*?)(?=^##\s+|\Z)"
            sec_match = re.search(pattern, content, flags=re.MULTILINE | re.DOTALL)
            self.assertIsNotNone(sec_match, f"Could not find section body for '{indicator_name}'")

            sec_text = sec_match.group(1)

            # Extract risk contribution points
            pts_match = re.search(r"Risk Contribution:\s*(\d+)\s*points", sec_text, flags=re.IGNORECASE)
            self.assertIsNotNone(
                pts_match,
                f"Section for '{indicator_name}' missing 'Risk Contribution: X points' statement.",
            )

            documented_points = int(pts_match.group(1))
            self.assertEqual(
                documented_points,
                expected_points,
                f"Mismatch in risk contribution for '{indicator_name}': "
                f"Documented {documented_points} pts != Authoritative {expected_points} pts",
            )

    def test_phase2_feature_schema_contains_exact_25_features(self):
        """Verify all 25 Phase 2 flow features are documented in the catalog exactly once."""
        catalog_file = KB_DIR / "features" / "phase2_feature_catalog.md"
        self.assertTrue(catalog_file.exists(), f"Missing file: {catalog_file}")

        content = catalog_file.read_text(encoding="utf-8")
        self.assertEqual(len(self.PHASE2_AUTHORITATIVE_FEATURES), 25)

        for feat in self.PHASE2_AUTHORITATIVE_FEATURES:
            matches = re.findall(rf"^##\s+{re.escape(feat)}\s*$", content, flags=re.MULTILINE)
            self.assertEqual(
                len(matches),
                1,
                f"Feature '{feat}' must be documented as a section heading exactly once. Found: {len(matches)}",
            )

    def test_domain_validation_statuses_documented(self):
        """Verify all supported IPsec domain statuses are documented."""
        domain_file = KB_DIR / "integration" / "ipsec_domain_validation.md"
        self.assertTrue(domain_file.exists(), f"Missing file: {domain_file}")

        content = domain_file.read_text(encoding="utf-8")
        for status in self.AUTHORITATIVE_DOMAIN_STATUSES:
            self.assertIn(
                status,
                content,
                f"Domain status '{status}' must be documented in ipsec_domain_validation.md",
            )

    def test_evaluation_modes_documented(self):
        """Verify all evaluation modes are documented with the unseen-capture limitation."""
        eval_file = KB_DIR / "evaluation" / "evaluation_modes.md"
        self.assertTrue(eval_file.exists(), f"Missing file: {eval_file}")

        content = eval_file.read_text(encoding="utf-8")
        for mode in self.AUTHORITATIVE_EVALUATION_MODES:
            self.assertIn(mode, content, f"Evaluation mode '{mode}' must be documented in evaluation_modes.md")

        # Verify WITHIN_CAPTURE_HOLDOUT is not unseen-capture validation
        clean_text = re.sub(r"[*_`]", "", content.lower())
        self.assertIn("not equivalent to unseen-capture validation", clean_text)

    def test_traffic_categories_documented(self):
        """Verify all 5 traffic categories are documented as resemblance."""
        cat_file = KB_DIR / "classification" / "traffic_category_resemblance.md"
        self.assertTrue(cat_file.exists(), f"Missing file: {cat_file}")

        content = cat_file.read_text(encoding="utf-8")
        for cat in self.AUTHORITATIVE_TRAFFIC_CATEGORIES:
            self.assertIn(cat, content, f"Traffic category '{cat}' must be documented in traffic_category_resemblance.md")

        self.assertIn("not guaranteed application identification", content.lower())

    def test_risk_scoring_model_tiers_and_uncertainty_separation(self):
        """Verify risk tiers and the strict separation of model uncertainty from risk."""
        risk_file = KB_DIR / "behavioral" / "risk_scoring_model.md"
        content = risk_file.read_text(encoding="utf-8")

        self.assertIn("LOW (0–24", content)
        self.assertIn("MEDIUM (25–49", content)
        self.assertIn("HIGH (50–74", content)
        self.assertIn("CRITICAL (75–100", content)

        # Check model uncertainty contributes 0 points
        self.assertIn("0 risk points", content.lower())


if __name__ == "__main__":
    unittest.main()
