"""Integration tests validating Part 2 consumption of REAL Phase 5 Unified JSON from Person 2 engine."""

import json
from pathlib import Path
import unittest

from rag_report_generator import (
    ReportConfig,
    generate_report,
    generate_report_from_phase5,
    retrieve,
)
from rag_report_generator.src.context.facts import extract_analysis_facts
from rag_report_generator.src.context.query_plan import QueryPlanner

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestRealPhase5Integration(unittest.TestCase):
    """Verifies end-to-end integration using actual Phase 5 outputs produced by the Person 2 engine."""

    def test_real_non_ipsec_basic_traffic(self):
        """Test consuming actual Phase 5 JSON from: main.py sample_data/basic_traffic.pcap --complete."""
        fixture_p = FIXTURES_DIR / "real_basic_traffic.json"
        with open(fixture_p, "r", encoding="utf-8") as f:
            data = json.load(f)

        # 1. Fact extraction from real Phase 5 structure
        facts = extract_analysis_facts(data)
        self.assertEqual(facts.capture.packet_count, 5)
        self.assertEqual(facts.capture.flow_count, 5)
        self.assertEqual(facts.capture.total_bytes, 283)
        self.assertFalse(facts.ipsec.detected)
        self.assertFalse(facts.ipsec.esp_detected)
        self.assertEqual(facts.classification.predicted_category, "interactive")
        self.assertAlmostEqual(facts.classification.confidence, 0.9049, places=4)
        self.assertEqual(facts.behavioral.risk_score, 0)
        self.assertEqual(facts.behavioral.risk_level, "LOW")
        self.assertEqual(facts.behavioral.triggered_indicators, [])

        # 2. End-to-end report generation
        res = generate_report_from_phase5(
            analysis_result=data,
            config=ReportConfig(llm_provider="mock"),
        )

        self.assertEqual(res.status, "SUCCESS")
        self.assertTrue(res.validation["is_valid"])
        self.assertIn("# Network Traffic Analysis Report", res.markdown)
        self.assertIn("5", res.markdown)
        self.assertIn("interactive", res.markdown)
        self.assertIn("0 / 100", res.markdown)

    def test_real_ipsec_esp_default_safe_mode(self):
        """Test consuming actual Phase 5 JSON from: main.py sample_data/ipsec_esp.pcap --complete.
        
        Verifies safe default policy: unverified IPsec domain blocks inference (unclassified / 0.0 confidence).
        """
        fixture_p = FIXTURES_DIR / "real_ipsec_esp_default.json"
        with open(fixture_p, "r", encoding="utf-8") as f:
            data = json.load(f)

        facts = extract_analysis_facts(data)
        self.assertEqual(facts.capture.packet_count, 2)
        self.assertEqual(facts.capture.flow_count, 1)
        self.assertTrue(facts.ipsec.detected)
        self.assertTrue(facts.ipsec.esp_detected)
        self.assertFalse(facts.ipsec.allow_unverified_domain)
        self.assertEqual(facts.ipsec.domain_validation_status, "TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED")
        self.assertEqual(facts.classification.predicted_category, "unclassified")
        self.assertEqual(facts.classification.confidence, 0.0)
        self.assertEqual(facts.behavioral.risk_score, 20)
        self.assertEqual(facts.behavioral.risk_level, "LOW")
        self.assertEqual(facts.behavioral.triggered_indicators, ["UNUSUAL_HIGH_PACKET_RATE"])

        res = generate_report_from_phase5(
            analysis_result=data,
            config=ReportConfig(llm_provider="mock"),
        )

        self.assertEqual(res.status, "SUCCESS")
        self.assertTrue(res.validation["is_valid"])
        self.assertIn("unclassified", res.markdown)
        self.assertIn("20 / 100", res.markdown)
        self.assertIn("TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED", res.markdown)
        self.assertNotIn("IPsec-validated", res.markdown)

    def test_real_ipsec_esp_explicit_override_mode(self):
        """Test consuming actual Phase 5 JSON from: main.py sample_data/ipsec_esp.pcap --complete --allow-unverified-domain.
        
        Verifies override policy: inference executed (web, 81.2%), but domain status remains UNVERIFIED.
        """
        fixture_p = FIXTURES_DIR / "real_ipsec_esp_override.json"
        with open(fixture_p, "r", encoding="utf-8") as f:
            data = json.load(f)

        facts = extract_analysis_facts(data)
        self.assertEqual(facts.capture.packet_count, 2)
        self.assertEqual(facts.capture.flow_count, 1)
        self.assertTrue(facts.ipsec.detected)
        self.assertTrue(facts.ipsec.esp_detected)
        self.assertTrue(facts.ipsec.allow_unverified_domain)
        self.assertEqual(facts.ipsec.domain_validation_status, "TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED")
        self.assertEqual(facts.classification.predicted_category, "web")
        self.assertAlmostEqual(facts.classification.confidence, 0.8117, places=4)
        self.assertEqual(facts.behavioral.risk_score, 20)
        self.assertEqual(facts.behavioral.risk_level, "LOW")
        self.assertEqual(facts.behavioral.triggered_indicators, ["UNUSUAL_HIGH_PACKET_RATE"])

        res = generate_report_from_phase5(
            analysis_result=data,
            config=ReportConfig(llm_provider="mock"),
        )

        self.assertEqual(res.status, "SUCCESS")
        self.assertTrue(res.validation["is_valid"])
        self.assertIn("web", res.markdown)
        self.assertIn("0.8117", res.markdown)
        self.assertIn("TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED", res.markdown)
        self.assertNotIn("IPsec-validated", res.markdown)


if __name__ == "__main__":
    unittest.main()
