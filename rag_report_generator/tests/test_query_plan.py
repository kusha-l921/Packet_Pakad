"""Unit tests for deterministic QueryPlanner."""

import json
from pathlib import Path
import unittest

from rag_report_generator.src.context.facts import extract_analysis_facts
from rag_report_generator.src.context.query_plan import QueryPlanner

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestQueryPlanner(unittest.TestCase):
    """Test deterministic retrieval query generation."""

    def test_queries_for_high_risk_fixture(self):
        with open(FIXTURES_DIR / "high_risk.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        facts = extract_analysis_facts(data)
        plan = QueryPlanner.build_plan(facts)

        # Indicator queries must only be generated for active indicators
        all_q = plan.all_queries()
        self.assertTrue(any("UNUSUAL_HIGH_UPLOAD_VOLUME" in q for q in all_q))
        self.assertTrue(any("UNUSUAL_HIGH_PACKET_RATE" in q for q in all_q))
        self.assertTrue(any("UNUSUAL_BURST_ACTIVITY" in q for q in all_q))

        # Inactive indicators must NOT have queries
        self.assertFalse(any("PERIODIC_LOW_VOLUME_ACTIVITY" in q for q in all_q))

        # ESP was detected, so ESP query must be present
        self.assertTrue(any("ESP" in q for q in plan.ipsec_queries))

        # Domain is unverified, so TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED query must be present
        self.assertTrue(any("TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED" in q for q in plan.limitation_queries))

    def test_queries_for_low_risk_no_ipsec(self):
        with open(FIXTURES_DIR / "low_risk.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        facts = extract_analysis_facts(data)
        plan = QueryPlanner.build_plan(facts)

        # No IPsec detected -> ipsec_queries empty
        self.assertEqual(len(plan.ipsec_queries), 0)
        # No indicators -> no indicator-specific queries
        for q in plan.behavioral_queries:
            self.assertNotIn("meaning", q.split()[0])


if __name__ == "__main__":
    unittest.main()
