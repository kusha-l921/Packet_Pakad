"""Negative retrieval tests to ensure distinct cross-domain queries do not return irrelevant top results."""

import unittest

from rag_report_generator import retrieve, build_index


class TestNegativeRetrieval(unittest.TestCase):
    """Negative tests to ensure false positive cross-domain ranking does not occur."""

    @classmethod
    def setUpClass(cls):
        build_index()

    def test_burst_activity_does_not_rank_esp_first(self):
        res = retrieve("UNUSUAL_BURST_ACTIVITY", top_k=3)
        self.assertEqual(res.status, "SUCCESS")
        self.assertGreater(len(res.retrieved_evidence), 0)

        top_evidence = res.retrieved_evidence[0]
        self.assertNotEqual(
            top_evidence.section,
            "ESP",
            "UNUSUAL_BURST_ACTIVITY incorrectly returned ESP as top result.",
        )
        self.assertEqual(
            top_evidence.category,
            "behavioral_indicator",
            "Top result for UNUSUAL_BURST_ACTIVITY should be a behavioral indicator.",
        )

    def test_forward_byte_ratio_does_not_rank_ike_first(self):
        res = retrieve("forward_byte_ratio", top_k=3)
        self.assertEqual(res.status, "SUCCESS")
        self.assertGreater(len(res.retrieved_evidence), 0)

        top_evidence = res.retrieved_evidence[0]
        self.assertNotIn(
            "IKE",
            top_evidence.section,
            "forward_byte_ratio query incorrectly returned IKE as top result.",
        )
        self.assertEqual(
            top_evidence.category,
            "feature",
            "Top result for forward_byte_ratio should be a feature.",
        )

    def test_domain_unverified_does_not_rank_flow_features_first(self):
        res = retrieve("TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED", top_k=3)
        self.assertEqual(res.status, "SUCCESS")
        self.assertGreater(len(res.retrieved_evidence), 0)

        top_evidence = res.retrieved_evidence[0]
        self.assertEqual(
            top_evidence.category,
            "integration",
            "Top result for TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED should be integration domain policy.",
        )


if __name__ == "__main__":
    unittest.main()
