"""Unit tests for semantic chunking and metadata preservation."""

import unittest

from rag_report_generator.src.ingestion.chunker import SemanticChunker
from rag_report_generator.src.models.document import Document


class TestSemanticChunker(unittest.TestCase):
    """Test semantic heading splitting, metadata inheritance, and atomic definition preservation."""

    def setUp(self):
        self.chunker = SemanticChunker(max_chunk_chars=2000)

    def test_chunking_preserves_headings_and_atomic_definitions(self):
        doc = Document(
            document_id="test_indicators",
            title="Test Indicators",
            category="behavioral_indicator",
            section="Behavioral Indicators",
            source="test/indicators.md",
            text="""# Test Indicators Overview

Introductory text about indicators.

## UNUSUAL_HIGH_PACKET_RATE

Meaning:
Observed packet rate exceeds configured rate threshold.

Risk contribution:
20 points.

## UNUSUAL_HIGH_UPLOAD_VOLUME

Meaning:
Observed forward byte volume exceeds configured upload ceiling.

Risk contribution:
20 points.
""",
            version="1.0",
            metadata={"authority": "project_spec", "project_specific": True},
        )

        chunks = self.chunker.chunk_document(doc)

        # Should produce at least 2 chunks (or 3 including preamble)
        sections = [c.section for c in chunks]
        self.assertIn("UNUSUAL_HIGH_PACKET_RATE", sections)
        self.assertIn("UNUSUAL_HIGH_UPLOAD_VOLUME", sections)

        # Find UNUSUAL_HIGH_PACKET_RATE chunk
        target_chunk = next(c for c in chunks if c.section == "UNUSUAL_HIGH_PACKET_RATE")
        self.assertEqual(target_chunk.document_id, "test_indicators")
        self.assertEqual(target_chunk.category, "behavioral_indicator")
        self.assertEqual(target_chunk.source, "test/indicators.md")
        self.assertEqual(target_chunk.version, "1.0")
        self.assertIn("20 points.", target_chunk.text)
        self.assertIn("UNUSUAL_HIGH_PACKET_RATE", target_chunk.metadata.get("keywords", []))

    def test_metadata_copied_to_chunks(self):
        doc = Document(
            document_id="meta_test",
            title="Metadata Test Doc",
            category="ipsec",
            section="IPsec Overview",
            source="ipsec/test.md",
            text="""## ESP Protocol

Details about ESP protocol 50.
""",
            version="1.2",
            metadata={"custom_flag": True, "authority": "project_spec"},
        )

        chunks = self.chunker.chunk_document(doc)
        self.assertEqual(len(chunks), 1)
        chunk = chunks[0]

        self.assertEqual(chunk.document_id, "meta_test")
        self.assertEqual(chunk.category, "ipsec")
        self.assertEqual(chunk.version, "1.2")
        self.assertTrue(chunk.metadata.get("custom_flag"))
        self.assertEqual(chunk.metadata.get("authority"), "project_spec")

    def test_empty_document_produces_empty_chunks(self):
        doc = Document(
            document_id="empty",
            title="Empty",
            category="none",
            section="None",
            source="empty.md",
            text="",
            version="1.0",
        )
        chunks = self.chunker.chunk_document(doc)
        self.assertEqual(chunks, [])

    def test_empty_intermediate_headings_handled(self):
        doc = Document(
            document_id="hierarchy",
            title="Hierarchy Test",
            category="ipsec",
            section="Hierarchy",
            source="hierarchy.md",
            text="""# Main Title

## Section A

### Subsection A1

Content inside subsection A1.

### Subsection A2

Content inside subsection A2.
""",
        )

        chunks = self.chunker.chunk_document(doc)
        sections = [c.section for c in chunks]
        self.assertIn("Subsection A1", sections)
        self.assertIn("Subsection A2", sections)


if __name__ == "__main__":
    unittest.main()
