"""Deterministic Markdown renderer converting structured Report objects to GitHub-flavored Markdown."""

from ..models.report import Report


class MarkdownRenderer:
    """Renders a validated Report object deterministically into Markdown."""

    @classmethod
    def render(cls, report: Report) -> str:
        lines: list[str] = []

        # 1. Header & Metadata
        lines.append("# Network Traffic Analysis Report")
        lines.append("")
        lines.append(f"> **Report ID:** `{report.report_metadata.report_id}`  ")
        lines.append(f"> **Generated:** {report.report_metadata.generated_at}  ")
        lines.append(f"> **Schema Version:** `{report.report_metadata.report_schema_version}` | **LLM Provider:** `{report.report_metadata.llm_provider}` ({report.report_metadata.llm_model})  ")
        lines.append("")

        # 2. Executive Summary
        lines.append("## 1. Executive Summary")
        lines.append("")
        lines.append(report.executive_summary.strip())
        lines.append("")

        # 3. Capture Overview
        lines.append("## 2. Capture Overview")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("| :--- | :--- |")
        lines.append(f"| **Packet Count** | {report.capture_overview.packet_count:,} |")
        lines.append(f"| **Flow Count** | {report.capture_overview.flow_count:,} |")
        lines.append(f"| **Duration** | {report.capture_overview.duration_seconds:.2f} seconds |")
        lines.append(f"| **Total Volume** | {report.capture_overview.total_bytes:,} bytes |")
        lines.append("")
        if report.capture_overview.summary_text:
            lines.append(report.capture_overview.summary_text.strip())
            lines.append("")

        # 4. IPsec / Encryption Analysis
        lines.append("## 3. IPsec / Encryption Analysis")
        lines.append("")
        lines.append(f"- **Overall IPsec Detected:** `{'Yes' if report.ipsec_analysis.detected else 'No'}`")
        lines.append(f"- **ESP (Protocol 50):** `{'Detected' if report.ipsec_analysis.esp_detected else 'Not Detected'}`")
        lines.append(f"- **AH (Protocol 51):** `{'Detected' if report.ipsec_analysis.ah_detected else 'Not Detected'}`")
        lines.append(f"- **IKE (UDP 500):** `{'Detected' if report.ipsec_analysis.ike_detected else 'Not Detected'}`")
        lines.append(f"- **NAT-T (UDP 4500):** `{'Detected' if report.ipsec_analysis.nat_t_detected else 'Not Detected'}`")
        lines.append(f"- **Domain Validation Status:** `{report.ipsec_analysis.domain_validation_status}`")
        lines.append("")
        lines.append(report.ipsec_analysis.explanation.strip())
        if report.ipsec_analysis.evidence_ids:
            cites = ", ".join(f"`[{eid}]`" for eid in report.ipsec_analysis.evidence_ids)
            lines.append(f"\n*Evidence Grounding:* {cites}")
        lines.append("")

        # 5. Traffic Classification
        lines.append("## 4. Traffic Classification (Category Resemblance)")
        lines.append("")
        lines.append(f"- **Predicted Resemblance Category:** `{report.traffic_classification.predicted_category}`")
        lines.append(f"- **Model Confidence:** `{report.traffic_classification.confidence:.4f}`")
        lines.append("")
        if report.traffic_classification.probabilities:
            lines.append("| Category | Resemblance Probability |")
            lines.append("| :--- | :--- |")
            for cat, prob in sorted(report.traffic_classification.probabilities.items(), key=lambda x: x[1], reverse=True):
                lines.append(f"| `{cat}` | {prob:.4f} |")
            lines.append("")
        lines.append(report.traffic_classification.resemblance_explanation.strip())
        if report.traffic_classification.evidence_ids:
            cites = ", ".join(f"`[{eid}]`" for eid in report.traffic_classification.evidence_ids)
            lines.append(f"\n*Evidence Grounding:* {cites}")
        lines.append("")

        # 6. Behavioral Risk Analysis
        lines.append("## 5. Behavioral Risk Analysis")
        lines.append("")
        lines.append(f"- **Phase 4 Risk Score:** `{report.behavioral_analysis.risk_score} / 100`")
        lines.append(f"- **Severity Tier:** `{report.behavioral_analysis.risk_level}`")
        lines.append("")
        if report.behavioral_analysis.triggered_indicators:
            lines.append("### Triggered Indicators")
            for ind in report.behavioral_analysis.triggered_indicators:
                lines.append(f"- `{ind}`")
            lines.append("")
        else:
            lines.append("*No elevated behavioral risk indicators were triggered.*")
            lines.append("")
        lines.append(report.behavioral_analysis.explanation.strip())
        lines.append("")
        lines.append(f"> **Important Disclaimer:** {report.behavioral_analysis.non_malice_disclaimer.strip()}")
        if report.behavioral_analysis.evidence_ids:
            cites = ", ".join(f"`[{eid}]`" for eid in report.behavioral_analysis.evidence_ids)
            lines.append(f"\n*Evidence Grounding:* {cites}")
        lines.append("")

        # 7. Flow-Level Findings
        if report.flow_findings:
            lines.append("## 6. Notable Flow Findings")
            lines.append("")
            for flow in report.flow_findings:
                lines.append(f"### Flow `{flow.flow_id}`")
                lines.append(f"- **Risk Score:** `{flow.risk_score}`")
                if flow.indicators:
                    lines.append(f"- **Indicators:** {', '.join(f'`{i}`' for i in flow.indicators)}")
                lines.append(f"- **Description:** {flow.description.strip()}")
                lines.append("")

        # 8. Model Uncertainty
        lines.append("## 7. Model Uncertainty Assessment")
        lines.append("")
        lines.append(f"- **Uncertainty Level:** `{report.model_uncertainty.uncertainty_level}`")
        lines.append("")
        lines.append(report.model_uncertainty.explanation.strip())
        lines.append("")
        lines.append(f"> **Separation of Concerns:** {report.model_uncertainty.risk_separation_statement.strip()}")
        if report.model_uncertainty.evidence_ids:
            cites = ", ".join(f"`[{eid}]`" for eid in report.model_uncertainty.evidence_ids)
            lines.append(f"\n*Evidence Grounding:* {cites}")
        lines.append("")

        # 9. Technical & Domain Limitations
        if report.limitations:
            lines.append("## 8. Technical & Domain Limitations")
            lines.append("")
            for lim in report.limitations:
                cites_str = f" ({', '.join(f'`[{eid}]`' for eid in lim.evidence_ids)})" if lim.evidence_ids else ""
                lines.append(f"- **{lim.topic}:** {lim.statement.strip()}{cites_str}")
            lines.append("")

        # 10. Technical Evidence Citations
        if report.technical_evidence:
            lines.append("## 9. Technical Evidence References")
            lines.append("")
            lines.append("| Evidence ID | Document / Title | Source | Section |")
            lines.append("| :--- | :--- | :--- | :--- |")
            for ev in report.technical_evidence:
                lines.append(f"| `[{ev.evidence_id}]` | {ev.title} | `{ev.source}` | {ev.section} |")
            lines.append("")

        # 11. Review Areas
        if report.review_areas:
            lines.append("## 10. Recommended Review Areas")
            lines.append("")
            for item in report.review_areas:
                lines.append(f"- {item.strip()}")
            lines.append("")

        # 12. Conclusion
        lines.append("## 11. Conclusion")
        lines.append("")
        lines.append(report.conclusion.strip())
        lines.append("")

        return "\n".join(lines)
