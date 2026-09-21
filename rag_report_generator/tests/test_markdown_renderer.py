"""Unit tests for MarkdownRenderer."""

import json
from pathlib import Path
import unittest

from rag_report_generator.src.context.facts import extract_analysis_facts
from rag_report_generator.src.generation.llm_provider import MockLLMProvider
from rag_report_generator.src.generation.json_repair import JSONRepair
from rag_report_generator.src.generation.markdown_renderer import MarkdownRenderer
from rag_report_generator.src.models.evidence import RetrievedEvidence
from rag_report_generator.src.models.report import Report

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestMarkdownRenderer(unittest.TestCase):
    """Test deterministic Markdown rendering."""

    def test_render_contains_all_sections(self):
        with open(FIXTURES_DIR / "high_risk.json", "r", encoding="utf-8") as f:
            facts = extract_analysis_facts(json.load(f))

        evidence = [
            RetrievedEvidence(
                evidence_id="E001",
                document_id="doc_esp",
                title="ESP Protocol",
                category="ipsec",
                section="ESP",
                text="ESP encrypts payload data.",
                score=0.90,
                source="kb/esp.md",
            )
        ]

        mock = MockLLMProvider(facts=facts, evidence=evidence)
        rep_dict = JSONRepair.clean_and_parse(mock.generate("prompt"))
        report = Report.from_dict(rep_dict)

        md = MarkdownRenderer.render(report)

        self.assertIn("# Network Traffic Analysis Report", md)
        self.assertIn("## 1. Executive Summary", md)
        self.assertIn("## 2. Capture Overview", md)
        self.assertIn("## 3. IPsec / Encryption Analysis", md)
        self.assertIn("## 4. Traffic Classification", md)
        self.assertIn("## 5. Behavioral Risk Analysis", md)
        self.assertIn("## 6. Notable Flow Findings", md)
        self.assertIn("## 7. Model Uncertainty Assessment", md)
        self.assertIn("## 8. Technical & Domain Limitations", md)
        self.assertIn("## 9. Technical Evidence References", md)
        self.assertIn("## 10. Recommended Review Areas", md)
        self.assertIn("## 11. Conclusion", md)

        # Numbers preserved in markdown
        self.assertIn("45,000", md)  # packet count
        self.assertIn("60 / 100", md)  # risk score
        self.assertIn("HIGH", md)  # severity tier
        self.assertIn("Important Disclaimer", md)


if __name__ == "__main__":
    unittest.main()
