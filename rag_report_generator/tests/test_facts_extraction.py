"""Unit tests for Phase 5 fact extraction and preservation."""

import json
from pathlib import Path
import unittest

from rag_report_generator.src.context.facts import extract_analysis_facts

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestFactExtraction(unittest.TestCase):
    """Test extraction of authoritative facts from Phase 5 JSON fixtures."""

    def test_extract_low_risk_facts(self):
        with open(FIXTURES_DIR / "low_risk.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        facts = extract_analysis_facts(data)
        self.assertEqual(facts.capture.packet_count, 512)
        self.assertEqual(facts.capture.flow_count, 4)
        self.assertEqual(facts.capture.duration_seconds, 12.5)
        self.assertEqual(facts.capture.total_bytes, 245000)

        self.assertFalse(facts.ipsec.detected)
        self.assertFalse(facts.ipsec.esp_detected)
        self.assertEqual(facts.classification.predicted_category, "web")
        self.assertEqual(facts.classification.confidence, 0.92)
        self.assertEqual(facts.classification.confidence_tier, "HIGH")

        self.assertEqual(facts.behavioral.risk_score, 0)
        self.assertEqual(facts.behavioral.risk_level, "LOW")
        self.assertEqual(facts.behavioral.triggered_indicators, [])

        self.assertEqual(facts.model_uncertainty.level, "LOW")
        self.assertEqual(facts.model_uncertainty.entropy, 0.12)
        self.assertEqual(facts.model_uncertainty.margin, 0.88)

    def test_extract_high_risk_facts(self):
        with open(FIXTURES_DIR / "high_risk.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        facts = extract_analysis_facts(data)
        self.assertEqual(facts.capture.packet_count, 45000)
        self.assertEqual(facts.capture.flow_count, 18)
        self.assertEqual(facts.capture.duration_seconds, 120.0)
        self.assertEqual(facts.capture.total_bytes, 48000000)

        self.assertTrue(facts.ipsec.detected)
        self.assertTrue(facts.ipsec.esp_detected)
        self.assertEqual(facts.ipsec.domain_validation_status, "TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED")

        self.assertEqual(facts.behavioral.risk_score, 60)
        self.assertEqual(facts.behavioral.risk_level, "HIGH")
        self.assertEqual(
            facts.behavioral.triggered_indicators,
            ["UNUSUAL_HIGH_UPLOAD_VOLUME", "UNUSUAL_HIGH_PACKET_RATE", "UNUSUAL_BURST_ACTIVITY"],
        )

    def test_extract_ipsec_unverified_preserves_floats(self):
        with open(FIXTURES_DIR / "ipsec_unverified.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        facts = extract_analysis_facts(data)
        # Verify confidence is exact float 0.812 without rounding to 81%
        self.assertEqual(facts.classification.confidence, 0.812)
        self.assertEqual(facts.capture.duration_seconds, 35.7)
        self.assertTrue(facts.ipsec.ike_detected)
        self.assertFalse(facts.ipsec.ah_detected)
        self.assertEqual(facts.ipsec.domain_validation_status, "TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED")

    def test_invalid_input_raises(self):
        with self.assertRaises(ValueError):
            extract_analysis_facts("not a dictionary")  # type: ignore


if __name__ == "__main__":
    unittest.main()
