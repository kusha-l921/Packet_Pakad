"""Unit tests for MockLLMProvider and OllamaProvider."""

import json
from pathlib import Path
import unittest

from rag_report_generator.src.context.facts import extract_analysis_facts
from rag_report_generator.src.generation.json_repair import JSONRepair
from rag_report_generator.src.generation.llm_provider import MockLLMProvider
from rag_report_generator.src.generation.ollama_provider import OllamaProvider
from rag_report_generator.src.models.evidence import RetrievedEvidence
from rag_report_generator.src.models.report_metadata import ReportConfig

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestLLMProviders(unittest.TestCase):
    """Test MockLLMProvider behavior modes and Ollama error handling."""

    def setUp(self):
        with open(FIXTURES_DIR / "low_risk.json", "r", encoding="utf-8") as f:
            self.facts = extract_analysis_facts(json.load(f))
        self.evidence = [
            RetrievedEvidence(
                evidence_id="E001",
                document_id="doc1",
                title="Web Traffic Classification",
                category="classification",
                section="Overview",
                text="Web traffic resembles standard HTTP/HTTPS flows.",
                score=0.95,
                source="kb/web.md",
            )
        ]

    def test_mock_valid_generation(self):
        mock = MockLLMProvider(facts=self.facts, evidence=self.evidence)
        output = mock.generate("Prompt")
        parsed = JSONRepair.clean_and_parse(output)
        self.assertIn("report_metadata", parsed)
        self.assertEqual(parsed["capture_overview"]["packet_count"], 512)
        self.assertEqual(parsed["behavioral_analysis"]["risk_score"], 0)

    def test_mock_mutation_modes(self):
        # Altered risk score
        mock_risk = MockLLMProvider(mode="altered_risk_score", facts=self.facts, evidence=self.evidence)
        parsed = JSONRepair.clean_and_parse(mock_risk.generate("Prompt"))
        self.assertEqual(parsed["behavioral_analysis"]["risk_score"], 50)

        # Invented indicator
        mock_ind = MockLLMProvider(mode="invented_indicator", facts=self.facts, evidence=self.evidence)
        parsed = JSONRepair.clean_and_parse(mock_ind.generate("Prompt"))
        self.assertIn("UNSUPPORTED_PORT_SCAN_INDICATOR", parsed["behavioral_analysis"]["triggered_indicators"])

        # Malformed JSON
        mock_malformed = MockLLMProvider(mode="malformed_json", facts=self.facts, evidence=self.evidence)
        with self.assertRaises(ValueError):
            JSONRepair.clean_and_parse(mock_malformed.generate("Prompt"))

    def test_ollama_unavailable_graceful_handling(self):
        # Using a dummy unreachable port
        ollama = OllamaProvider(base_url="http://127.0.0.1:59999", timeout=1.0)
        self.assertFalse(ollama.is_available())
        with self.assertRaises(ConnectionError):
            ollama.generate("Test prompt", ReportConfig(timeout_seconds=1.0))


if __name__ == "__main__":
    unittest.main()
