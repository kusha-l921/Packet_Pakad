"""Unit tests for deterministic QueryBuilder."""

import unittest

from rag_report_generator.src.retrieval.query_builder import QueryBuilder


class TestQueryBuilder(unittest.TestCase):
    """Test deterministic query templates for all core project concepts."""

    def test_indicator_query_construction(self):
        q = QueryBuilder.build_indicator_query("UNUSUAL_HIGH_PACKET_RATE")
        self.assertIn("UNUSUAL_HIGH_PACKET_RATE", q)
        self.assertIn("behavioral risk indicator", q)

    def test_feature_query_construction(self):
        q = QueryBuilder.build_feature_query("forward_byte_ratio")
        self.assertIn("forward_byte_ratio", q)
        self.assertIn("traffic flow feature", q)

    def test_domain_query_construction(self):
        q = QueryBuilder.build_domain_query("TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED")
        self.assertIn("IPsec domain validation", q)
        self.assertIn("technically compatible unverified", q)

    def test_protocol_query_construction(self):
        q_esp = QueryBuilder.build_protocol_query("ESP")
        self.assertIn("ESP", q_esp)
        self.assertIn("Protocol 50", q_esp)

        q_ike = QueryBuilder.build_protocol_query("IKE")
        self.assertIn("IKE", q_ike)
        self.assertIn("UDP 500", q_ike)

    def test_evaluation_query_construction(self):
        q_group = QueryBuilder.build_evaluation_query("GROUP_ISOLATED")
        self.assertIn("GROUP_ISOLATED", q_group)
        self.assertIn("unseen validation", q_group)

        q_holdout = QueryBuilder.build_evaluation_query("WITHIN_CAPTURE_HOLDOUT")
        self.assertIn("WITHIN_CAPTURE_HOLDOUT", q_holdout)
        self.assertIn("holdout", q_holdout)

    def test_uncertainty_query_construction(self):
        q = QueryBuilder.build_uncertainty_query("LOW_CLASSIFICATION_CONFIDENCE")
        self.assertIn("LOW_CLASSIFICATION_CONFIDENCE", q)
        self.assertIn("model uncertainty", q)
        self.assertIn("behavioral risk separation", q)


if __name__ == "__main__":
    unittest.main()
