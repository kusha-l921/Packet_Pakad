"""Unit tests for public retrieval API and output contracts."""

import unittest

from rag_report_generator import (
    retrieve,
    retrieve_for_indicator,
    retrieve_for_feature,
    retrieve_for_domain_status,
    retrieve_for_evaluation_mode,
    retrieve_for_uncertainty,
    build_index,
    RAGConfig,
)


class TestRetrievalAPI(unittest.TestCase):
    """Test retrieval responses, deterministic evidence IDs, and helper functions."""

    @classmethod
    def setUpClass(cls):
        # Ensure knowledge base is indexed
        build_index()

    def test_retrieve_returns_structured_evidence(self):
        res = retrieve("What is UNUSUAL_HIGH_PACKET_RATE?", top_k=3)
        self.assertEqual(res.status, "SUCCESS")
        self.assertEqual(res.knowledge_base_version, "1.0")
        self.assertLessEqual(len(res.retrieved_evidence), 3)

        # Check deterministic evidence ID sequence
        for i, ev in enumerate(res.retrieved_evidence, start=1):
            self.assertEqual(ev.evidence_id, f"E{i:03d}")
            self.assertIsInstance(ev.score, float)
            self.assertTrue(0.0 <= ev.score <= 1.0)
            self.assertTrue(ev.document_id)
            self.assertTrue(ev.source)

    def test_helper_retrieve_for_indicator(self):
        res = retrieve_for_indicator("UNUSUAL_BURST_ACTIVITY", top_k=2)
        self.assertEqual(res.status, "SUCCESS")
        self.assertGreater(len(res.retrieved_evidence), 0)
        top = res.retrieved_evidence[0]
        self.assertEqual(top.category, "behavioral_indicator")
        self.assertIn("UNUSUAL_BURST_ACTIVITY", top.section)

    def test_helper_retrieve_for_feature(self):
        res = retrieve_for_feature("forward_byte_ratio", top_k=2)
        self.assertEqual(res.status, "SUCCESS")
        self.assertGreater(len(res.retrieved_evidence), 0)
        top = res.retrieved_evidence[0]
        self.assertEqual(top.category, "feature")
        self.assertEqual(top.section, "forward_byte_ratio")

    def test_helper_retrieve_for_domain_status(self):
        res = retrieve_for_domain_status("TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED", top_k=2)
        self.assertEqual(res.status, "SUCCESS")
        self.assertGreater(len(res.retrieved_evidence), 0)
        top = res.retrieved_evidence[0]
        self.assertEqual(top.category, "integration")
        self.assertIn("TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED", top.section)

    def test_empty_or_whitespace_query_returns_no_evidence(self):
        res = retrieve("    ")
        self.assertEqual(res.status, "NO_RELEVANT_EVIDENCE")
        self.assertEqual(res.retrieved_evidence, [])

    def test_serialization_to_dict(self):
        res = retrieve("ESP", top_k=2)
        d = res.to_dict()
        self.assertIn("query", d)
        self.assertIn("retrieved_evidence", d)
        self.assertIn("status", d)
        self.assertIn("knowledge_base_version", d)
        if d["retrieved_evidence"]:
            ev = d["retrieved_evidence"][0]
            self.assertIn("evidence_id", ev)
            self.assertIn("score", ev)
            self.assertIn("source", ev)


if __name__ == "__main__":
    unittest.main()
