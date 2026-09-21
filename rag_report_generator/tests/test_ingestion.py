"""Unit tests for document loading and normalization."""

import tempfile
import unittest
from pathlib import Path

from rag_report_generator.src.ingestion.loader import DocumentLoader
from rag_report_generator.src.ingestion.normalizer import DocumentNormalizer


class TestDocumentNormalizer(unittest.TestCase):
    """Test text normalization rules."""

    def test_normalize_empty_text(self):
        self.assertEqual(DocumentNormalizer.normalize(""), "")
        self.assertEqual(DocumentNormalizer.normalize("   \n\n  "), "")

    def test_normalize_newlines_and_spaces(self):
        raw = "Line 1  \r\nLine 2 \r\n\r\n\r\n\r\nLine 3"
        normalized = DocumentNormalizer.normalize(raw)
        self.assertIn("Line 1\nLine 2", normalized)
        # Should collapse 4 blank lines to 2
        self.assertNotIn("\n\n\n", normalized)
        self.assertTrue(normalized.endswith("Line 3"))

    def test_strip_bom(self):
        raw = "\ufeff# Title\nContent"
        normalized = DocumentNormalizer.normalize(raw)
        self.assertFalse(normalized.startswith("\ufeff"))
        self.assertTrue(normalized.startswith("# Title"))


class TestDocumentLoader(unittest.TestCase):
    """Test document discovery, parsing, and error handling."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)
        self.loader = DocumentLoader(base_path=self.base_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_load_valid_markdown_with_frontmatter(self):
        md_file = self.base_path / "doc1.md"
        content = """---
document_id: custom_doc_01
title: Custom Document Title
category: behavioral_indicator
section: Section One
version: "1.0"
---

# Custom Document Title

This is the document body text.
"""
        md_file.write_text(content, encoding="utf-8")
        doc = self.loader.load_file(md_file)

        self.assertIsNotNone(doc)
        self.assertEqual(doc.document_id, "custom_doc_01")
        self.assertEqual(doc.title, "Custom Document Title")
        self.assertEqual(doc.category, "behavioral_indicator")
        self.assertEqual(doc.section, "Section One")
        self.assertEqual(doc.version, "1.0")
        self.assertEqual(doc.source, "doc1.md")
        self.assertIn("This is the document body text.", doc.text)

    def test_load_valid_plaintext(self):
        txt_file = self.base_path / "notes.txt"
        txt_file.write_text("Plain text title\nBody content of plain text.", encoding="utf-8")
        doc = self.loader.load_file(txt_file)

        self.assertIsNotNone(doc)
        self.assertEqual(doc.document_id, "notes")
        self.assertEqual(doc.title, "Plain text title")
        self.assertIn("Body content", doc.text)

    def test_load_valid_json_document(self):
        json_file = self.base_path / "spec.json"
        content = {
            "document_id": "json_spec_01",
            "title": "JSON Specification",
            "category": "integration",
            "text": "Specifications content in JSON format.",
            "version": "1.0",
        }
        import json
        json_file.write_text(json.dumps(content), encoding="utf-8")
        doc = self.loader.load_file(json_file)

        self.assertIsNotNone(doc)
        self.assertEqual(doc.document_id, "json_spec_01")
        self.assertEqual(doc.title, "JSON Specification")
        self.assertEqual(doc.category, "integration")
        self.assertIn("Specifications content", doc.text)

    def test_load_malformed_frontmatter_graceful_recovery(self):
        bad_md = self.base_path / "bad.md"
        bad_md.write_text("---\n: invalid : yaml : [unclosed\n---\n# Real Title\nContent here.", encoding="utf-8")
        doc = self.loader.load_file(bad_md)

        self.assertIsNotNone(doc)
        self.assertEqual(doc.title, "Real Title")
        self.assertIn("Content here.", doc.text)

    def test_load_empty_document_ignored(self):
        empty_file = self.base_path / "empty.md"
        empty_file.write_text("   \n\n   ", encoding="utf-8")
        doc = self.loader.load_file(empty_file)
        self.assertIsNone(doc)

    def test_load_nonexistent_file(self):
        missing = self.base_path / "missing.md"
        doc = self.loader.load_file(missing)
        self.assertIsNone(doc)


if __name__ == "__main__":
    unittest.main()
