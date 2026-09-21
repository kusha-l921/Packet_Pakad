"""Unit tests for embedding providers."""

import math
import unittest

from rag_report_generator.src.embeddings.local_provider import DeterministicLocalEmbeddingProvider


class TestDeterministicLocalEmbeddingProvider(unittest.TestCase):
    """Test embedding dimensionality, determinism, and normalization."""

    def setUp(self):
        self.provider = DeterministicLocalEmbeddingProvider(dimension=384)

    def test_embedding_dimensionality(self):
        text = "UNUSUAL_HIGH_PACKET_RATE meaning behavioral risk indicator"
        vec = self.provider.embed_query(text)
        self.assertEqual(len(vec), 384)
        self.assertEqual(self.provider.dimension, 384)

    def test_deterministic_embedding_generation(self):
        text = "Exact 25 Phase 2 flow features: forward_byte_ratio and packets_per_second."
        vec1 = self.provider.embed_query(text)
        vec2 = self.provider.embed_query(text)
        self.assertEqual(vec1, vec2)

    def test_unit_length_l2_normalization(self):
        text = "IPsec ESP protocol 50 encryption and integrity verification."
        vec = self.provider.embed_query(text)
        norm = math.sqrt(sum(x * x for x in vec))
        self.assertAlmostEqual(norm, 1.0, places=5)

    def test_semantic_differentiation(self):
        vec_network = self.provider.embed_query("IPsec ESP tunnel mode encryption security association")
        vec_unrelated = self.provider.embed_query("culinary recipes for baking bread with yeast")

        # Dot product
        dot = sum(a * b for a, b in zip(vec_network, vec_unrelated))
        # Dissimilar texts should have low dot product compared to self-similarity (1.0)
        self.assertLess(dot, 0.4)

    def test_batch_embed_texts(self):
        texts = [
            "UNUSUAL_HIGH_PACKET_RATE",
            "forward_byte_ratio",
            "TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED",
        ]
        vectors = self.provider.embed_texts(texts)
        self.assertEqual(len(vectors), 3)
        for v in vectors:
            self.assertEqual(len(v), 384)

    def test_empty_string_handling(self):
        vec = self.provider.embed_query("")
        self.assertEqual(len(vec), 384)
        self.assertEqual(vec, [0.0] * 384)


if __name__ == "__main__":
    unittest.main()
