"""Root report validator orchestrating structural, fact, evidence, and terminology checks."""

from typing import Any
from ..models.evidence import RetrievedEvidence
from ..models.facts import AnalysisFacts
from ..models.report import Report
from ..models.report_metadata import ValidationSummary
from .evidence_checker import EvidenceChecker
from .fact_checker import FactChecker
from .terminology_checker import TerminologyChecker


class ReportValidator:
    """Multi-layer deterministic report validator."""

    @classmethod
    def check_structure(cls, report: Report, summary: ValidationSummary) -> None:
        """Verify that all mandatory sections are present and non-empty."""
        summary.add_rule("SCHEMA_CHECKER: Required Sections and Non-Empty Content")

        if not report.executive_summary or not report.executive_summary.strip():
            summary.add_error("Executive summary is missing or empty.")

        if not report.capture_overview.summary_text or not report.capture_overview.summary_text.strip():
            summary.add_error("Capture overview summary text is missing or empty.")

        if not report.ipsec_analysis.explanation or not report.ipsec_analysis.explanation.strip():
            summary.add_error("IPsec analysis explanation is missing or empty.")

        if not report.traffic_classification.resemblance_explanation or not report.traffic_classification.resemblance_explanation.strip():
            summary.add_error("Traffic classification resemblance explanation is missing or empty.")

        if not report.behavioral_analysis.explanation or not report.behavioral_analysis.explanation.strip():
            summary.add_error("Behavioral analysis explanation is missing or empty.")

        if not report.behavioral_analysis.non_malice_disclaimer or not report.behavioral_analysis.non_malice_disclaimer.strip():
            summary.add_error("Behavioral analysis non-malice disclaimer is missing or empty.")

        if not report.model_uncertainty.explanation or not report.model_uncertainty.explanation.strip():
            summary.add_error("Model uncertainty explanation is missing or empty.")

        if not report.model_uncertainty.risk_separation_statement or not report.model_uncertainty.risk_separation_statement.strip():
            summary.add_error("Model uncertainty risk separation statement is missing or empty.")

        if not report.conclusion or not report.conclusion.strip():
            summary.add_error("Conclusion section is missing or empty.")

    @classmethod
    def validate(
        cls,
        report: Report,
        facts: AnalysisFacts,
        retrieved_evidence: list[RetrievedEvidence],
    ) -> ValidationSummary:
        """Run complete validation suite across structure, facts, evidence, and terminology."""
        summary = ValidationSummary(is_valid=True)

        # 1. Structural schema completeness
        cls.check_structure(report, summary)

        # 2. Fact consistency against AnalysisFacts
        FactChecker.check(report, facts, summary)

        # 3. Evidence citation grounding
        EvidenceChecker.check(report, retrieved_evidence, summary)

        # 4. Terminology, domain policy, and risk separation
        TerminologyChecker.check(report, facts, summary)

        return summary
