"""Fact consistency checker comparing Report against authoritative AnalysisFacts."""

import math
from ..models.facts import AnalysisFacts
from ..models.report import Report
from ..models.report_metadata import ValidationSummary


class FactChecker:
    """Verifies that structured Report contains zero invented or altered facts."""

    @classmethod
    def check(cls, report: Report, facts: AnalysisFacts, summary: ValidationSummary) -> None:
        summary.add_rule("FACT_CHECKER: Numerical and Enumeration Integrity")

        # 1. Packet & Flow Counts
        if report.capture_overview.packet_count != facts.capture.packet_count:
            summary.add_error(
                f"Packet count mismatch: report states {report.capture_overview.packet_count}, "
                f"authoritative facts state {facts.capture.packet_count}."
            )

        if report.capture_overview.flow_count != facts.capture.flow_count:
            summary.add_error(
                f"Flow count mismatch: report states {report.capture_overview.flow_count}, "
                f"authoritative facts state {facts.capture.flow_count}."
            )

        if not math.isclose(report.capture_overview.duration_seconds, facts.capture.duration_seconds, rel_tol=1e-3, abs_tol=1e-3):
            summary.add_error(
                f"Duration mismatch: report states {report.capture_overview.duration_seconds}, "
                f"authoritative facts state {facts.capture.duration_seconds}."
            )

        if report.capture_overview.total_bytes != facts.capture.total_bytes:
            summary.add_error(
                f"Total bytes mismatch: report states {report.capture_overview.total_bytes}, "
                f"authoritative facts state {facts.capture.total_bytes}."
            )

        # 2. Risk Score & Risk Level
        if report.behavioral_analysis.risk_score != facts.behavioral.risk_score:
            summary.add_error(
                f"Risk score altered: report states {report.behavioral_analysis.risk_score}, "
                f"authoritative facts state {facts.behavioral.risk_score}."
            )

        if report.behavioral_analysis.risk_level.upper() != facts.behavioral.risk_level.upper():
            summary.add_error(
                f"Risk level mismatch: report states '{report.behavioral_analysis.risk_level}', "
                f"authoritative facts state '{facts.behavioral.risk_level}'."
            )

        # 3. Behavioral Indicators (Zero Hallucination / No Invented Indicators)
        fact_inds = set(facts.behavioral.triggered_indicators)
        report_inds = set(report.behavioral_analysis.triggered_indicators)
        invented_inds = report_inds - fact_inds
        if invented_inds:
            summary.add_error(
                f"Invented behavioral indicator(s) detected: {sorted(invented_inds)}. "
                f"Authoritative indicators: {sorted(fact_inds)}."
            )

        # 4. Traffic Classification
        if report.traffic_classification.predicted_category.lower() != facts.classification.predicted_category.lower():
            summary.add_error(
                f"Predicted category mismatch: report states '{report.traffic_classification.predicted_category}', "
                f"authoritative facts state '{facts.classification.predicted_category}'."
            )

        if not math.isclose(report.traffic_classification.confidence, facts.classification.confidence, rel_tol=1e-3, abs_tol=1e-3):
            summary.add_error(
                f"Confidence altered: report states {report.traffic_classification.confidence}, "
                f"authoritative facts state {facts.classification.confidence}."
            )

        # 5. IPsec Protocol Observations
        if report.ipsec_analysis.detected != facts.ipsec.detected:
            summary.add_error(
                f"IPsec detected mismatch: report states {report.ipsec_analysis.detected}, "
                f"authoritative facts state {facts.ipsec.detected}."
            )

        if report.ipsec_analysis.esp_detected != facts.ipsec.esp_detected:
            summary.add_error(
                f"ESP detected mismatch: report states {report.ipsec_analysis.esp_detected}, "
                f"authoritative facts state {facts.ipsec.esp_detected}."
            )

        if report.ipsec_analysis.ah_detected != facts.ipsec.ah_detected:
            summary.add_error(
                f"AH detected mismatch: report states {report.ipsec_analysis.ah_detected}, "
                f"authoritative facts state {facts.ipsec.ah_detected}."
            )

        if report.ipsec_analysis.ike_detected != facts.ipsec.ike_detected:
            summary.add_error(
                f"IKE detected mismatch: report states {report.ipsec_analysis.ike_detected}, "
                f"authoritative facts state {facts.ipsec.ike_detected}."
            )

        if report.ipsec_analysis.nat_t_detected != facts.ipsec.nat_t_detected:
            summary.add_error(
                f"NAT-T detected mismatch: report states {report.ipsec_analysis.nat_t_detected}, "
                f"authoritative facts state {facts.ipsec.nat_t_detected}."
            )

        if report.ipsec_analysis.domain_validation_status != facts.ipsec.domain_validation_status:
            summary.add_error(
                f"Domain validation status mismatch: report states '{report.ipsec_analysis.domain_validation_status}', "
                f"authoritative facts state '{facts.ipsec.domain_validation_status}'."
            )

        # 6. Model Uncertainty Level
        if report.model_uncertainty.uncertainty_level.upper() != facts.model_uncertainty.level.upper():
            summary.add_error(
                f"Model uncertainty level mismatch: report states '{report.model_uncertainty.uncertainty_level}', "
                f"authoritative facts state '{facts.model_uncertainty.level}'."
            )
