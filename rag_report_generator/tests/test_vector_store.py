"""Unit tests for FlatCosineVectorStore."""

import tempfile
import unittest
from pathlib import Path

from rag_report_generator.src.models.chunk import DocumentChunk
from rag_report_generator.src.retrieval.vector_store import FlatCosineVectorStore


class TestFlatCosineVectorStore(unittest.TestCase):
    """Test vector store insertion, cosine similarity search, disk persistence, and filtering."""

    def setUp(self):
        self.dim = 8
        self.store = FlatCosineVectorStore(dimension=self.dim, version="1.0")

        self.chunk1 = DocumentChunk(
            chunk_id="chunk_001",
            document_id="doc1",
            title="Doc 1",
            category="behavioral_indicator",
            section="Sec 1",
            text="High packet rate indicator.",
            source="src/doc1.md",
            version="1.0",
        )
        self.chunk2 = DocumentChunk(
            chunk_id="chunk_002",
            document_id="doc2",
            title="Doc 2",
            category="ipsec",
            section="Sec 2",
            text="ESP tunnel mode encryption.",
            source="src/doc2.md",
            version="1.0",
        )

        # Normalized test vectors
        self.vec1 = [1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
        self.vec2 = [0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

    def test_add_and_search(self):
        self.store.add_documents([self.chunk1, self.chunk2], [self.vec1, self.vec2])

        # Search with vector identical to vec1
        results = self.store.search(query_embedding=self.vec1, top_k=2)
        self.assertEqual(len(results), 2)
        top_chunk, top_score = results[0]
        self.assertEqual(top_chunk.chunk_id, "chunk_001")
        self.assertAlmostEqual(top_score, 1.0, places=4)

    def test_metadata_filtering(self):
        self.store.add_documents([self.chunk1, self.chunk2], [self.vec1, self.vec2])

        # Filter by category = ipsec
        results = self.store.search(
            query_embedding=self.vec1,
            top_k=2,
            filters={"category": "ipsec"},
        )
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0].chunk_id, "chunk_002")

    def test_save_and_reload(self):
        self.store.add_documents([self.chunk1, self.chunk2], [self.vec1, self.vec2])

        with tempfile.TemporaryDirectory() as tmp_dir:
            save_path = Path(tmp_dir) / "index"
            self.store.save(save_path)

            # Create fresh store and load
            reloaded_store = FlatCosineVectorStore(dimension=self.dim, version="1.0")
            reloaded_store.load(save_path)

            self.assertEqual(len(reloaded_store.chunks), 2)
            results = reloaded_store.search(query_embedding=self.vec2, top_k=1)
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0][0].chunk_id, "chunk_002")
            self.assertAlmostEqual(results[0][1], 1.0, places=4)

    def test_dimension_mismatch_raises_error(self):
        with self.assertRaises(ValueError):
            self.store.add_documents([self.chunk1], [[1.0, 0.0]])


if __name__ == "__main__":
    unittest.main()
