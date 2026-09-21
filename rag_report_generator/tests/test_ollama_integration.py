"""Optional integration test for real local Ollama instance (skipped if unavailable)."""

import json
from pathlib import Path
import unittest

from rag_report_generator.src.generation.ollama_provider import OllamaProvider
from rag_report_generator.src.generation.report_generator import ReportGenerator
from rag_report_generator.src.models.evidence import RetrievedEvidence
from rag_report_generator.src.models.report_metadata import ReportConfig

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestOllamaIntegration(unittest.TestCase):
    """Real Ollama generation test if local Ollama daemon is running."""

    def setUp(self):
        self.provider = OllamaProvider()
        if not self.provider.is_available():
            self.skipTest("Local Ollama daemon is not running or unreachable at http://localhost:11434.")

    def test_real_ollama_report_generation(self):
        with open(FIXTURES_DIR / "low_risk.json", "r", encoding="utf-8") as f:
            phase5_data = json.load(f)

        evidence = [
            RetrievedEvidence(
                evidence_id="E001",
                document_id="doc_web",
                title="Web Traffic Classification",
                category="classification",
                section="HTTP/HTTPS Profile",
                text="Web traffic exhibits standard bidirectional request/response patterns.",
                score=0.90,
                source="kb/classification.md",
            )
        ]

        cfg = ReportConfig(
            llm_provider="ollama",
            llm_model="llama3.2",
            temperature=0.1,
            timeout_seconds=30.0,
        )
        generator = ReportGenerator(config=cfg, provider=self.provider)
        res = generator.generate(phase5_data, evidence)

        # Verify generation response
        self.assertIn(res.status, ("SUCCESS", "VALIDATION_FAILED"))
        if res.status == "SUCCESS":
            self.assertIsNotNone(res.markdown)
            self.assertIsNotNone(res.report_json)


if __name__ == "__main__":
    unittest.main()
