"""Retrieval quality benchmark tests across all key project domains."""

import unittest

from rag_report_generator import retrieve, build_index


class TestRetrievalBenchmarks(unittest.TestCase):
    """Retrieval benchmark verifying top-K relevance for project-specific concepts."""

    @classmethod
    def setUpClass(cls):
        build_index()

    def _assert_top_k_contains_category_or_topic(
        self, query: str, expected_categories: list[str], expected_token: str, top_k: int = 3
    ):
        res = retrieve(query, top_k=top_k)
        self.assertEqual(res.status, "SUCCESS", f"Query failed: '{query}'")
        self.assertGreater(len(res.retrieved_evidence), 0, f"No results for: '{query}'")

        found = False
        for ev in res.retrieved_evidence:
            cat_match = ev.category in expected_categories
            token_match = (
                expected_token.lower() in ev.section.lower()
                or expected_token.lower() in ev.text.lower()
                or expected_token.lower() in ev.title.lower()
            )
            if cat_match and token_match:
                found = True
                break

        self.assertTrue(
            found,
            f"Query '{query}' did not return evidence matching categories {expected_categories} "
            f"and token '{expected_token}'. Retrieved: {[e.section for e in res.retrieved_evidence]}",
        )

    # 1. Behavioral indicators (all 6 indicators)
    def test_benchmark_unusual_high_packet_rate(self):
        self._assert_top_k_contains_category_or_topic(
            query="UNUSUAL_HIGH_PACKET_RATE",
            expected_categories=["behavioral_indicator"],
            expected_token="UNUSUAL_HIGH_PACKET_RATE",
            top_k=2,
        )

    def test_benchmark_unusual_high_upload_volume(self):
        self._assert_top_k_contains_category_or_topic(
            query="UNUSUAL_HIGH_UPLOAD_VOLUME",
            expected_categories=["behavioral_indicator"],
            expected_token="UNUSUAL_HIGH_UPLOAD_VOLUME",
            top_k=2,
        )

    def test_benchmark_unusual_burst_activity(self):
        self._assert_top_k_contains_category_or_topic(
            query="UNUSUAL_BURST_ACTIVITY",
            expected_categories=["behavioral_indicator"],
            expected_token="UNUSUAL_BURST_ACTIVITY",
            top_k=2,
        )

    def test_benchmark_long_lived_high_volume_flow(self):
        self._assert_top_k_contains_category_or_topic(
            query="LONG_LIVED_HIGH_VOLUME_FLOW",
            expected_categories=["behavioral_indicator"],
            expected_token="LONG_LIVED_HIGH_VOLUME_FLOW",
            top_k=2,
        )

    def test_benchmark_periodic_low_volume_activity(self):
        self._assert_top_k_contains_category_or_topic(
            query="PERIODIC_LOW_VOLUME_ACTIVITY",
            expected_categories=["behavioral_indicator"],
            expected_token="PERIODIC_LOW_VOLUME_ACTIVITY",
            top_k=2,
        )

    def test_benchmark_strong_directional_asymmetry(self):
        self._assert_top_k_contains_category_or_topic(
            query="STRONG_DIRECTIONAL_ASYMMETRY",
            expected_categories=["behavioral_indicator"],
            expected_token="STRONG_DIRECTIONAL_ASYMMETRY",
            top_k=2,
        )

    # 2. Features
    def test_benchmark_forward_byte_ratio(self):
        self._assert_top_k_contains_category_or_topic(
            query="forward_byte_ratio",
            expected_categories=["feature"],
            expected_token="forward_byte_ratio",
            top_k=2,
        )

    # 3. Protocols
    def test_benchmark_esp(self):
        self._assert_top_k_contains_category_or_topic(
            query="ESP",
            expected_categories=["ipsec"],
            expected_token="ESP",
            top_k=3,
        )

    def test_benchmark_ike(self):
        self._assert_top_k_contains_category_or_topic(
            query="IKE",
            expected_categories=["ipsec"],
            expected_token="IKE",
            top_k=3,
        )

    # 4. Risk model
    def test_benchmark_high_risk(self):
        self._assert_top_k_contains_category_or_topic(
            query="HIGH risk score severity tier",
            expected_categories=["risk"],
            expected_token="HIGH",
            top_k=3,
        )

    # 5. Uncertainty
    def test_benchmark_low_classification_confidence(self):
        self._assert_top_k_contains_category_or_topic(
            query="LOW_CLASSIFICATION_CONFIDENCE",
            expected_categories=["classification"],
            expected_token="confidence",
            top_k=3,
        )

    # 6. Domain validation
    def test_benchmark_technically_compatible_domain_unverified(self):
        self._assert_top_k_contains_category_or_topic(
            query="TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED",
            expected_categories=["integration"],
            expected_token="TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED",
            top_k=2,
        )

    # 7. Evaluation modes
    def test_benchmark_group_isolated(self):
        self._assert_top_k_contains_category_or_topic(
            query="GROUP_ISOLATED",
            expected_categories=["evaluation"],
            expected_token="GROUP_ISOLATED",
            top_k=2,
        )

    def test_benchmark_within_capture_holdout(self):
        self._assert_top_k_contains_category_or_topic(
            query="WITHIN_CAPTURE_HOLDOUT",
            expected_categories=["evaluation", "limitations"],
            expected_token="WITHIN_CAPTURE_HOLDOUT",
            top_k=2,
        )


if __name__ == "__main__":
    unittest.main()
