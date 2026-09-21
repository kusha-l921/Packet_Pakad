"""Unit tests for ContextBuilder and evidence deduplication."""

import json
from pathlib import Path
import unittest

from rag_report_generator.src.context.context_builder import ContextBuilder
from rag_report_generator.src.context.facts import extract_analysis_facts
from rag_report_generator.src.models.evidence import RetrievedEvidence
from rag_report_generator.src.models.report_metadata import ReportConfig

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestContextBuilder(unittest.TestCase):
    """Test context construction, deduplication, and size bounds."""

    def test_deduplication_keeps_highest_score(self):
        ev1 = RetrievedEvidence(
            evidence_id="E001",
            document_id="doc_ipsec",
            title="IPsec Protocols",
            category="ipsec",
            section="ESP",
            text="Passage 1",
            score=0.85,
            source="kb/ipsec.md",
        )
        ev2 = RetrievedEvidence(
            evidence_id="E002",
            document_id="doc_ipsec",
            title="IPsec Protocols",
            category="ipsec",
            section="ESP",  # Same doc + section
            text="Passage 2 duplicate",
            score=0.92,  # Higher score
            source="kb/ipsec.md",
        )
        ev3 = RetrievedEvidence(
            evidence_id="E003",
            document_id="doc_indicators",
            title="Indicators",
            category="behavioral",
            section="Upload Volume",
            text="Passage 3",
            score=0.75,
            source="kb/ind.md",
        )

        deduped = ContextBuilder.deduplicate_evidence([ev1, ev2, ev3], max_evidence=5)
        self.assertEqual(len(deduped), 2)
        # Higher score chunk for (doc_ipsec, ESP) should be kept
        ipsec_chunks = [e for e in deduped if e.document_id == "doc_ipsec"]
        self.assertEqual(len(ipsec_chunks), 1)
        self.assertEqual(ipsec_chunks[0].evidence_id, "E002")
        self.assertEqual(ipsec_chunks[0].score, 0.92)

    def test_context_respects_character_limit(self):
        with open(FIXTURES_DIR / "low_risk.json", "r", encoding="utf-8") as f:
            facts = extract_analysis_facts(json.load(f))

        long_evidence = [
            RetrievedEvidence(
                evidence_id=f"E{i:03d}",
                document_id=f"doc_{i}",
                title=f"Doc {i}",
                category="test",
                section="Sec",
                text="X" * 3000,
                score=0.9 - (i * 0.01),
                source="test.md",
            )
            for i in range(10)
        ]

        cfg = ReportConfig(max_context_characters=4000, max_evidence=5)
        ctx = ContextBuilder.build_context(facts, long_evidence, cfg)
        self.assertLessEqual(len(ctx.full_prompt_text), 4500)


if __name__ == "__main__":
    unittest.main()
