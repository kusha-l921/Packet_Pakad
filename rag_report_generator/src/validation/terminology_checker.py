"""Terminology, domain policy, and tone validator."""

import re
from ..models.facts import AnalysisFacts
from ..models.report import Report
from ..models.report_metadata import ValidationSummary


class TerminologyChecker:
    """Verifies strict adherence to project terminology, tone, and domain constraints."""

    # Prohibited sensationalist or definitive attack phrasing
    PROHIBITED_PHRASES = [
        "attack detected",
        "confirmed attack",
        "malware confirmed",
        "definitely malicious",
        "intrusion identified",
        "guaranteed application",
        "guaranteed identity",
    ]

    @classmethod
    def check(cls, report: Report, facts: AnalysisFacts, summary: ValidationSummary) -> None:
        summary.add_rule("TERMINOLOGY_CHECKER: Tone, Domain Policy, and Risk Separation")

        # Collect all textual content for phrase scanning
        text_corpus = " ".join([
            report.executive_summary,
            report.capture_overview.summary_text,
            report.ipsec_analysis.explanation,
            report.traffic_classification.resemblance_explanation,
            report.behavioral_analysis.explanation,
            report.behavioral_analysis.non_malice_disclaimer,
            report.model_uncertainty.explanation,
            report.model_uncertainty.risk_separation_statement,
            report.conclusion,
            " ".join(report.review_areas),
            " ".join(f.description for f in report.flow_findings),
            " ".join(l.statement for l in report.limitations),
        ]).lower()

        # 1. Check for prohibited sensationalist phrases
        for phrase in cls.PROHIBITED_PHRASES:
            if phrase in text_corpus:
                summary.add_error(
                    f"Prohibited definitive or sensationalist phrase detected: '{phrase}'. "
                    "Phase 4 system is an indicator engine, not an autonomous attack confirmation tool."
                )

        # 2. Check for domain validation policy compliance
        is_unverified = "UNVERIFIED" in facts.ipsec.domain_validation_status or "UNVERIFIED" in facts.classification.prediction_status
        if is_unverified:
            # Check for forbidden claims of verified IPsec
            forbidden_domain_patterns = [
                r"ipsec[- ]validated",
                r"validated web traffic",
                r"validated classification",
                r"verified ipsec classification",
            ]
            for pat in forbidden_domain_patterns:
                if re.search(pat, text_corpus):
                    summary.add_error(
                        f"Report claims IPsec verification ({pat}) despite domain status "
                        f"'{facts.ipsec.domain_validation_status}'. "
                        "High confidence does not confer domain verification."
                    )

        # 3. Model Uncertainty vs Behavioral Risk Separation
        # Must not claim risk score is caused by model uncertainty
        unc_as_risk_patterns = [
            r"risk (?:score|level) (?:is|was) \d+ because the model is uncertain",
            r"risk (?:score|level) is due to model uncertainty",
            r"uncertainty caused the high risk",
            r"risk score resulted from model uncertainty",
        ]
        for pat in unc_as_risk_patterns:
            if re.search(pat, text_corpus):
                summary.add_error(
                    "Model uncertainty conflated with behavioral risk: "
                    "risk score must not be attributed to model uncertainty."
                )

        # 4. Check for arbitrary new AI scores
        if re.search(r"ai risk (?:score)?\s*[:=]\s*\d+", text_corpus):
            summary.add_error(
                "Unsupported scoring system detected: LLM must not invent arbitrary AI risk scores."
            )

        # 5. Check recommendation tone overreach
        if re.search(r"immediately block this ip because it is malicious", text_corpus):
            summary.add_error(
                "Recommendation overreach: definitive accusation and blocking order unsupported by indicators."
            )
