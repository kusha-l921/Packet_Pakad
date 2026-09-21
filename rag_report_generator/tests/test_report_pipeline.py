"""End-to-end integration test: Phase 5 fixture -> Part 1 Retrieval -> Context Builder -> Mock LLM -> Validator -> Markdown."""

import json
from pathlib import Path
import unittest

from rag_report_generator import (
    RAGConfig,
    ReportConfig,
    generate_report,
    generate_report_from_phase5,
    retrieve,
)
from rag_report_generator.src.context.facts import extract_analysis_facts
from rag_report_generator.src.context.query_plan import QueryPlanner

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestReportPipeline(unittest.TestCase):
    """Integration test verifying Part 1 retrieval -> Part 2 report pipeline contract."""

    def test_full_pipeline_with_low_risk_fixture(self):
        fixture_path = FIXTURES_DIR / "low_risk.json"
        with open(fixture_path, "r", encoding="utf-8") as f:
            phase5_data = json.load(f)

        # 1. Fact extraction
        facts = extract_analysis_facts(phase5_data)
        self.assertEqual(facts.capture.packet_count, 512)

        # 2. Query planning
        plan = QueryPlanner.build_plan(facts)
        queries = plan.all_queries()
        self.assertGreater(len(queries), 0)

        # 3. Part 1 retrieval
        retrieved_evidence = []
        for q in queries[:3]:
            res = retrieve(q, top_k=2)
            retrieved_evidence.extend(res.retrieved_evidence)

        # 4. Generate report
        report_res = generate_report(
            analysis_result=phase5_data,
            retrieved_evidence=retrieved_evidence,
            config=ReportConfig(llm_provider="mock"),
        )

        self.assertEqual(report_res.status, "SUCCESS")
        self.assertIsNotNone(report_res.report_json)
        self.assertIsNotNone(report_res.markdown)
        self.assertEqual(report_res.validation["is_valid"], True)

        # Verify Markdown content
        self.assertIn("# Network Traffic Analysis Report", report_res.markdown)
        self.assertIn("512", report_res.markdown)
        self.assertIn("web", report_res.markdown)

    def test_generate_report_from_phase5_convenience_api(self):
        fixture_path = FIXTURES_DIR / "ipsec_unverified.json"
        with open(fixture_path, "r", encoding="utf-8") as f:
            phase5_data = json.load(f)

        report_res = generate_report_from_phase5(
            analysis_result=phase5_data,
            config=ReportConfig(llm_provider="mock"),
        )

        self.assertEqual(report_res.status, "SUCCESS")
        self.assertIn("TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED", report_res.markdown)
        self.assertIn("1,024", report_res.markdown)
        self.assertEqual(report_res.validation["is_valid"], True)

    def test_all_seven_fixtures_succeed(self):
        fixtures = [
            "low_risk.json",
            "high_risk.json",
            "medium_risk.json",
            "ipsec_unverified.json",
            "ipsec_verified.json",
            "high_uncertainty.json",
            "mixed_indicators.json",
        ]
        for fix_name in fixtures:
            with open(FIXTURES_DIR / fix_name, "r", encoding="utf-8") as f:
                data = json.load(f)
            res = generate_report_from_phase5(
                analysis_result=data,
                config=ReportConfig(llm_provider="mock"),
            )
            self.assertEqual(res.status, "SUCCESS", f"Fixture {fix_name} failed: {res.validation.get('errors')}")
            self.assertIsNotNone(res.markdown)
            self.assertIsNotNone(res.report_json)


if __name__ == "__main__":
    unittest.main()
