"""Context builder creating structured, deduplicated LLM context from facts and evidence."""

from dataclasses import dataclass, field
from typing import Any
from ..models.evidence import RetrievedEvidence
from ..models.facts import AnalysisFacts
from ..models.report_metadata import ReportConfig


@dataclass
class AssembledContext:
    """Structured assembled context ready for prompt templating."""
    facts_block: str
    evidence_block: str
    rules_block: str
    full_prompt_text: str
    deduplicated_evidence: list[RetrievedEvidence] = field(default_factory=list)
    evidence_id_map: dict[str, RetrievedEvidence] = field(default_factory=dict)


class ContextBuilder:
    """Deduplicates retrieved evidence and builds a controlled context string."""

    @classmethod
    def deduplicate_evidence(
        cls,
        evidence_list: list[RetrievedEvidence],
        max_evidence: int = 8,
    ) -> list[RetrievedEvidence]:
        """Deduplicate evidence by (document_id, section), retaining highest score."""
        best_by_key: dict[tuple[str, str], RetrievedEvidence] = {}

        for ev in evidence_list:
            key = (ev.document_id, ev.section)
            if key not in best_by_key:
                best_by_key[key] = ev
            else:
                if ev.score > best_by_key[key].score:
                    best_by_key[key] = ev

        # Sort by score descending
        sorted_ev = sorted(best_by_key.values(), key=lambda e: e.score, reverse=True)
        return sorted_ev[:max_evidence]

    @classmethod
    def format_facts_block(cls, facts: AnalysisFacts) -> str:
        """Format authoritative AnalysisFacts into clean structured text."""
        cap = facts.capture
        ip = facts.ipsec
        cls_f = facts.classification
        beh = facts.behavioral
        unc = facts.model_uncertainty
        ev = facts.evaluation

        lines = [
            "==================================================",
            "SOURCE OF TRUTH #1: AUTHORITATIVE ANALYSIS FACTS",
            "==================================================",
            "[CAPTURE OVERVIEW]",
            f"- Packet Count: {cap.packet_count}",
            f"- Flow Count: {cap.flow_count}",
            f"- Duration (seconds): {cap.duration_seconds}",
            f"- Total Bytes: {cap.total_bytes}",
            f"- Observed Protocols: {cap.protocols}",
            "",
            "[IPSEC / ENCRYPTION ANALYSIS]",
            f"- IPsec Detected: {ip.detected}",
            f"- ESP Detected: {ip.esp_detected}",
            f"- AH Detected: {ip.ah_detected}",
            f"- IKE Detected: {ip.ike_detected}",
            f"- NAT-T Detected: {ip.nat_t_detected}",
            f"- Domain Validation Status: {ip.domain_validation_status}",
            f"- Allow Unverified Domain: {ip.allow_unverified_domain}",
            "",
            "[TRAFFIC CLASSIFICATION (CATEGORY RESEMBLANCE)]",
            f"- Predicted Category: {cls_f.predicted_category}",
            f"- Confidence: {cls_f.confidence}",
            f"- Confidence Tier: {cls_f.confidence_tier}",
            f"- Prediction Status: {cls_f.prediction_status}",
            f"- Category Probabilities: {cls_f.category_probabilities}",
            "",
            "[BEHAVIORAL RISK ASSESSMENT]",
            f"- Risk Score: {beh.risk_score}",
            f"- Risk Level: {beh.risk_level}",
            f"- Triggered Indicators: {beh.triggered_indicators}",
            f"- Indicator Points: {beh.indicator_points}",
            "",
            "[MODEL UNCERTAINTY]",
            f"- Uncertainty Level: {unc.level}",
            f"- Entropy: {unc.entropy}",
            f"- Margin: {unc.margin}",
            f"- Reason: {unc.reason}",
            "",
            "[DATASET EVALUATION PROVENANCE]",
            f"- Evaluation Mode: {ev.evaluation_mode}",
            f"- Dataset Provenance: {ev.dataset_provenance}",
        ]

        if facts.selected_flows:
            lines.append("")
            lines.append("[NOTABLE FLOWS]")
            for idx, flow in enumerate(facts.selected_flows, 1):
                lines.append(
                    f"Flow #{idx} ({flow.flow_id}): "
                    f"5-tuple={flow.five_tuple}, packets={flow.packets}, bytes={flow.bytes}, "
                    f"duration={flow.duration_seconds}s, risk_score={flow.risk_score}, "
                    f"indicators={flow.indicators}, is_ipsec={flow.is_ipsec}"
                )

        return "\n".join(lines)

    @classmethod
    def format_evidence_block(cls, evidence_list: list[RetrievedEvidence]) -> str:
        """Format retrieved explanatory knowledge with clear evidence IDs."""
        if not evidence_list:
            return (
                "==================================================\n"
                "SOURCE OF TRUTH #2: RETRIEVED EXPLANATORY KNOWLEDGE\n"
                "==================================================\n"
                "NO_RELEVANT_EVIDENCE: No trusted explanatory evidence was retrieved.\n"
                "Do not hallucinate project knowledge. Explicitly note absence of source."
            )

        lines = [
            "==================================================",
            "SOURCE OF TRUTH #2: RETRIEVED EXPLANATORY KNOWLEDGE",
            "==================================================",
        ]

        for ev in evidence_list:
            lines.append(f"[{ev.evidence_id}]")
            lines.append(f"Title: {ev.title}")
            lines.append(f"Source: {ev.source}")
            lines.append(f"Section: {ev.section}")
            lines.append(f"Category: {ev.category}")
            lines.append(f"Content: {ev.text}")
            lines.append("-" * 40)

        return "\n".join(lines)

    @classmethod
    def format_rules_block(cls) -> str:
        """Core strict rules governing report generation."""
        return (
            "==================================================\n"
            "MANDATORY REPORT RULES (ZERO-HALLUCINATION POLICY)\n"
            "==================================================\n"
            "1. AnalysisFacts are strictly authoritative for all observed facts.\n"
            "2. NEVER alter numbers: packet_count, flow_count, duration, bytes, confidence, risk_score, probabilities.\n"
            "3. NEVER invent behavioral indicators. Only use triggered_indicators from AnalysisFacts.\n"
            "4. NEVER recalculate or invent a risk score or AI score. Use the exact risk_score given.\n"
            "5. Traffic category is RESEMBLANCE, NOT guaranteed application identity.\n"
            "6. If domain_validation_status contains 'UNVERIFIED', you MUST NOT claim IPsec-validated classification.\n"
            "7. Model uncertainty is separate from behavioral risk. Do NOT explain risk score as being caused by uncertainty.\n"
            "8. DO NOT use sensationalist language: 'attack detected', 'malware confirmed', 'definitely malicious'.\n"
            "   Use neutral phrasing: 'behavioral risk indicator', 'suspicious behavior', 'requires review'.\n"
            "9. Retain evidence IDs (e.g. ['E001']) for explanatory definitions cited from retrieved knowledge.\n"
            "10. If evidence is absent, state that project-specific explanatory documentation was unavailable.\n"
            "11. Output MUST be a valid JSON object strictly matching the Report schema."
        )

    @classmethod
    def build_context(
        cls,
        facts: AnalysisFacts,
        evidence_list: list[RetrievedEvidence],
        config: ReportConfig | None = None,
    ) -> AssembledContext:
        """Assemble full context with deduplicated evidence and character limits."""
        cfg = config or ReportConfig()

        deduped = cls.deduplicate_evidence(evidence_list, max_evidence=cfg.max_evidence)
        ev_id_map = {e.evidence_id: e for e in deduped}

        facts_block = cls.format_facts_block(facts)
        evidence_block = cls.format_evidence_block(deduped)
        rules_block = cls.format_rules_block()

        # Enforce max context character limits if needed
        total_len = len(facts_block) + len(evidence_block) + len(rules_block)
        if total_len > cfg.max_context_characters:
            # Trim evidence passages if oversized, keeping facts and rules intact
            allowed_ev_len = max(500, cfg.max_context_characters - len(facts_block) - len(rules_block) - 200)
            if len(evidence_block) > allowed_ev_len:
                evidence_block = evidence_block[:allowed_ev_len] + "\n... [Context truncated to size limit]"

        full_prompt = f"{rules_block}\n\n{facts_block}\n\n{evidence_block}"

        return AssembledContext(
            facts_block=facts_block,
            evidence_block=evidence_block,
            rules_block=rules_block,
            full_prompt_text=full_prompt,
            deduplicated_evidence=deduped,
            evidence_id_map=ev_id_map,
        )
