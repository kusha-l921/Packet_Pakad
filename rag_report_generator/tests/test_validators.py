"""Unit tests for ReportValidator, FactChecker, EvidenceChecker, and TerminologyChecker."""

import json
from pathlib import Path
import unittest

from rag_report_generator.src.context.facts import extract_analysis_facts
from rag_report_generator.src.generation.llm_provider import MockLLMProvider
from rag_report_generator.src.generation.json_repair import JSONRepair
from rag_report_generator.src.models.evidence import RetrievedEvidence
from rag_report_generator.src.models.report import Report
from rag_report_generator.src.validation.report_validator import ReportValidator

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestValidators(unittest.TestCase):
    """Test deterministic validation gates preventing hallucinated or altered reports."""

    def setUp(self):
        with open(FIXTURES_DIR / "high_risk.json", "r", encoding="utf-8") as f:
            self.facts = extract_analysis_facts(json.load(f))

        self.evidence = [
            RetrievedEvidence(
                evidence_id="E001",
                document_id="doc_esp",
                title="ESP Protocol",
                category="ipsec",
                section="ESP",
                text="ESP encrypts payload data.",
                score=0.90,
                source="kb/esp.md",
            ),
            RetrievedEvidence(
                evidence_id="E002",
                document_id="doc_ind",
                title="Risk Indicators",
                category="behavioral",
                section="Upload Volume",
                text="High upload volume points.",
                score=0.85,
                source="kb/ind.md",
            ),
        ]

    def test_valid_report_passes(self):
        mock = MockLLMProvider(facts=self.facts, evidence=self.evidence)
        report_dict = JSONRepair.clean_and_parse(mock.generate("prompt"))
        report = Report.from_dict(report_dict)

        val = ReportValidator.validate(report, self.facts, self.evidence)
        self.assertTrue(val.is_valid, f"Validation failed unexpectedly: {val.errors}")
        self.assertEqual(len(val.errors), 0)

    def test_altered_risk_score_fails(self):
        mock = MockLLMProvider(mode="altered_risk_score", facts=self.facts, evidence=self.evidence)
        report_dict = JSONRepair.clean_and_parse(mock.generate("prompt"))
        report = Report.from_dict(report_dict)

        val = ReportValidator.validate(report, self.facts, self.evidence)
        self.assertFalse(val.is_valid)
        self.assertTrue(any("Risk score altered" in err for err in val.errors))

    def test_altered_packet_count_fails(self):
        mock = MockLLMProvider(mode="altered_packet_count", facts=self.facts, evidence=self.evidence)
        report_dict = JSONRepair.clean_and_parse(mock.generate("prompt"))
        report = Report.from_dict(report_dict)

        val = ReportValidator.validate(report, self.facts, self.evidence)
        self.assertFalse(val.is_valid)
        self.assertTrue(any("Packet count mismatch" in err for err in val.errors))

    def test_invented_indicator_fails(self):
        mock = MockLLMProvider(mode="invented_indicator", facts=self.facts, evidence=self.evidence)
        report_dict = JSONRepair.clean_and_parse(mock.generate("prompt"))
        report = Report.from_dict(report_dict)

        val = ReportValidator.validate(report, self.facts, self.evidence)
        self.assertFalse(val.is_valid)
        self.assertTrue(any("Invented behavioral indicator" in err for err in val.errors))

    def test_wrong_ipsec_status_fails(self):
        mock = MockLLMProvider(mode="wrong_ipsec_status", facts=self.facts, evidence=self.evidence)
        report_dict = JSONRepair.clean_and_parse(mock.generate("prompt"))
        report = Report.from_dict(report_dict)

        val = ReportValidator.validate(report, self.facts, self.evidence)
        self.assertFalse(val.is_valid)
        self.assertTrue(any("ESP detected mismatch" in err for err in val.errors))

    def test_unsupported_sensationalist_claim_fails(self):
        mock = MockLLMProvider(mode="unsupported_claim", facts=self.facts, evidence=self.evidence)
        report_dict = JSONRepair.clean_and_parse(mock.generate("prompt"))
        report = Report.from_dict(report_dict)

        val = ReportValidator.validate(report, self.facts, self.evidence)
        self.assertFalse(val.is_valid)
        self.assertTrue(any("Prohibited definitive or sensationalist phrase" in err for err in val.errors))

    def test_unsupported_ipsec_validation_claim_fails(self):
        mock = MockLLMProvider(mode="unsupported_ipsec_validation", facts=self.facts, evidence=self.evidence)
        report_dict = JSONRepair.clean_and_parse(mock.generate("prompt"))
        report = Report.from_dict(report_dict)

        val = ReportValidator.validate(report, self.facts, self.evidence)
        self.assertFalse(val.is_valid)
        self.assertTrue(any("claims IPsec verification" in err for err in val.errors))

    def test_model_uncertainty_as_risk_fails(self):
        mock = MockLLMProvider(mode="model_uncertainty_as_risk", facts=self.facts, evidence=self.evidence)
        report_dict = JSONRepair.clean_and_parse(mock.generate("prompt"))
        report = Report.from_dict(report_dict)

        val = ReportValidator.validate(report, self.facts, self.evidence)
        self.assertFalse(val.is_valid)
        self.assertTrue(any("Model uncertainty conflated with behavioral risk" in err for err in val.errors))

    def test_invalid_evidence_id_fails(self):
        mock = MockLLMProvider(mode="invalid_evidence_id", facts=self.facts, evidence=self.evidence)
        report_dict = JSONRepair.clean_and_parse(mock.generate("prompt"))
        report = Report.from_dict(report_dict)

        val = ReportValidator.validate(report, self.facts, self.evidence)
        self.assertFalse(val.is_valid)
        self.assertTrue(any("Report cites unretrieved or hallucinated evidence ID" in err for err in val.errors))


if __name__ == "__main__":
    unittest.main()
