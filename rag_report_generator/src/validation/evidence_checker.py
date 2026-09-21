"""Evidence citation checker verifying that cited evidence IDs exist in retrieved evidence."""

from ..models.evidence import RetrievedEvidence
from ..models.report import Report
from ..models.report_metadata import ValidationSummary


class EvidenceChecker:
    """Verifies that all evidence citations in the report match retrieved evidence."""

    @classmethod
    def check(
        cls,
        report: Report,
        retrieved_evidence: list[RetrievedEvidence],
        summary: ValidationSummary,
    ) -> None:
        summary.add_rule("EVIDENCE_CHECKER: Citation Grounding and Auditability")

        valid_ids = {e.evidence_id for e in retrieved_evidence}

        # Collect all citations across sections
        all_cited_ids: set[str] = set()

        all_cited_ids.update(report.ipsec_analysis.evidence_ids)
        all_cited_ids.update(report.traffic_classification.evidence_ids)
        all_cited_ids.update(report.behavioral_analysis.evidence_ids)
        all_cited_ids.update(report.model_uncertainty.evidence_ids)

        for lim in report.limitations:
            all_cited_ids.update(lim.evidence_ids)

        for tech_ev in report.technical_evidence:
            all_cited_ids.add(tech_ev.evidence_id)

        # Check for ungrounded citations (invented evidence IDs)
        ungrounded_ids = all_cited_ids - valid_ids
        if ungrounded_ids:
            summary.add_error(
                f"Report cites unretrieved or hallucinated evidence ID(s): {sorted(ungrounded_ids)}. "
                f"Valid retrieved IDs: {sorted(valid_ids)}."
            )

        # Evidence sufficiency check
        if not retrieved_evidence:
            if all_cited_ids:
                summary.add_error(
                    "No evidence was retrieved, but report cited evidence IDs: "
                    f"{sorted(all_cited_ids)}."
                )
            else:
                summary.add_warning("No retrieved evidence provided for explanatory grounding.")
