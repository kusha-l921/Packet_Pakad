"""LLM Provider abstraction and MockLLMProvider for deterministic offline testing."""

import abc
import json
import time
from typing import Any
from ..models.evidence import RetrievedEvidence
from ..models.facts import AnalysisFacts
from ..models.report_metadata import ReportConfig


class LLMProvider(abc.ABC):
    """Abstract base class for LLM providers."""

    @abc.abstractmethod
    def generate(self, prompt: str, config: ReportConfig | None = None) -> str:
        """Generate a response for the given prompt."""
        raise NotImplementedError


class MockLLMProvider(LLMProvider):
    """Mock LLM provider returning deterministic, structured JSON for tests.
    
    Can operate in standard 'valid' mode or simulate specific failure modes.
    """

    def __init__(
        self,
        mode: str = "valid",
        facts: AnalysisFacts | None = None,
        evidence: list[RetrievedEvidence] | None = None,
        custom_response: str | None = None,
    ):
        self.mode = mode
        self.facts = facts
        self.evidence = evidence or []
        self.custom_response = custom_response

    def set_facts_and_evidence(
        self,
        facts: AnalysisFacts,
        evidence: list[RetrievedEvidence],
    ) -> None:
        self.facts = facts
        self.evidence = evidence

    def build_valid_report_dict(
        self,
        facts: AnalysisFacts,
        evidence: list[RetrievedEvidence],
    ) -> dict[str, Any]:
        """Build a strictly valid report dictionary conforming to facts and evidence."""
        ev_ids = [e.evidence_id for e in evidence]
        
        # Determine evidence references
        ipsec_ev = [e.evidence_id for e in evidence if e.category in ("ipsec", "protocols")]
        cls_ev = [e.evidence_id for e in evidence if e.category in ("classification", "features")]
        beh_ev = [e.evidence_id for e in evidence if e.category in ("behavioral", "indicators")]
        unc_ev = [e.evidence_id for e in evidence if e.category in ("uncertainty", "evaluation")]
        lim_ev = [e.evidence_id for e in evidence if e.category in ("limitations", "evaluation", "integration")]

        # Ensure citations list is populated
        citations = [
            {
                "evidence_id": e.evidence_id,
                "title": e.title,
                "source": e.source,
                "section": e.section,
            }
            for e in evidence
        ]

        # Flow findings
        flow_findings = []
        for f in facts.selected_flows:
            flow_findings.append({
                "flow_id": f.flow_id,
                "description": (
                    f"Flow between {f.five_tuple.get('src_ip')}:{f.five_tuple.get('src_port')} "
                    f"and {f.five_tuple.get('dst_ip')}:{f.five_tuple.get('dst_port')} "
                    f"exhibiting {f.packets} packets and {f.bytes} bytes over {f.duration_seconds}s."
                ),
                "risk_score": f.risk_score,
                "indicators": list(f.indicators),
            })

        # Limitations
        limitations = []
        if "UNVERIFIED" in facts.ipsec.domain_validation_status:
            limitations.append({
                "topic": "Domain Validation",
                "statement": (
                    "The traffic was evaluated under TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED. "
                    "The model has not been validated against verified IPsec datasets."
                ),
                "evidence_ids": lim_ev[:2],
            })
        limitations.append({
            "topic": "Category Resemblance",
            "statement": (
                "Traffic classification reflects statistical feature resemblance, not cryptographic "
                "or deep-packet-inspected application identity verification."
            ),
            "evidence_ids": cls_ev[:1] if cls_ev else [],
        })
        limitations.append({
            "topic": "Behavioral Indicators",
            "statement": (
                "Behavioral risk indicators highlight statistical and protocol anomalies; they do not "
                "constitute confirmed malice or autonomous security compromise."
            ),
            "evidence_ids": beh_ev[:1] if beh_ev else [],
        })

        review_areas = []
        if facts.behavioral.triggered_indicators:
            for ind in facts.behavioral.triggered_indicators:
                review_areas.append(f"Investigate activity triggering indicator {ind}.")
        else:
            review_areas.append("Routine traffic observation; no elevated risk indicators triggered.")

        report_dict = {
            "report_metadata": {
                "report_id": "rep_mock_001",
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "report_schema_version": "1.0",
                "input_schema_version": "1.0",
                "rag_knowledge_base_version": "1.0",
                "llm_provider": "mock",
                "llm_model": "mock-deterministic",
            },
            "executive_summary": (
                f"Automated traffic evaluation processed {facts.capture.packet_count} packets "
                f"across {facts.capture.flow_count} flows with a duration of {facts.capture.duration_seconds} seconds. "
                f"The traffic exhibited behavioral characteristics resembling the '{facts.classification.predicted_category}' "
                f"category with a confidence of {facts.classification.confidence}. "
                f"The deterministic Phase 4 risk score is {facts.behavioral.risk_score} ({facts.behavioral.risk_level} risk), "
                f"with domain validation status {facts.ipsec.domain_validation_status}."
            ),
            "capture_overview": {
                "packet_count": facts.capture.packet_count,
                "flow_count": facts.capture.flow_count,
                "duration_seconds": facts.capture.duration_seconds,
                "total_bytes": facts.capture.total_bytes,
                "summary_text": (
                    f"Observed {facts.capture.packet_count} packets totaling {facts.capture.total_bytes} bytes "
                    f"over {facts.capture.duration_seconds} seconds."
                ),
            },
            "ipsec_analysis": {
                "detected": facts.ipsec.detected,
                "esp_detected": facts.ipsec.esp_detected,
                "ah_detected": facts.ipsec.ah_detected,
                "ike_detected": facts.ipsec.ike_detected,
                "nat_t_detected": facts.ipsec.nat_t_detected,
                "domain_validation_status": facts.ipsec.domain_validation_status,
                "explanation": (
                    f"IPsec protocol observation: detected={facts.ipsec.detected}, "
                    f"ESP={facts.ipsec.esp_detected}, AH={facts.ipsec.ah_detected}, "
                    f"IKE={facts.ipsec.ike_detected}, NAT-T={facts.ipsec.nat_t_detected}. "
                    f"Operating under domain status {facts.ipsec.domain_validation_status}."
                ),
                "evidence_ids": ipsec_ev,
            },
            "traffic_classification": {
                "predicted_category": facts.classification.predicted_category,
                "confidence": facts.classification.confidence,
                "probabilities": dict(facts.classification.category_probabilities),
                "resemblance_explanation": (
                    f"Traffic features statistically resemble '{facts.classification.predicted_category}' "
                    f"with model confidence {facts.classification.confidence} ({facts.classification.confidence_tier} tier)."
                ),
                "evidence_ids": cls_ev,
            },
            "behavioral_analysis": {
                "risk_score": facts.behavioral.risk_score,
                "risk_level": facts.behavioral.risk_level,
                "triggered_indicators": list(facts.behavioral.triggered_indicators),
                "explanation": (
                    f"Calculated behavioral risk score of {facts.behavioral.risk_score} ({facts.behavioral.risk_level} risk) "
                    f"based on observed indicators: {facts.behavioral.triggered_indicators}."
                ),
                "non_malice_disclaimer": (
                    "Behavioral risk indicators highlight statistical traffic deviations and potential anomalies; "
                    "they do not confirm an attack or malicious compromise."
                ),
                "evidence_ids": beh_ev,
            },
            "flow_findings": flow_findings,
            "model_uncertainty": {
                "uncertainty_level": facts.model_uncertainty.level,
                "explanation": (
                    f"Model uncertainty is assessed at {facts.model_uncertainty.level} level "
                    f"(entropy: {facts.model_uncertainty.entropy}, margin: {facts.model_uncertainty.margin})."
                ),
                "risk_separation_statement": (
                    "Model uncertainty measures classification confidence dispersion and is strictly decoupled "
                    "from Phase 4 behavioral risk scoring."
                ),
                "evidence_ids": unc_ev,
            },
            "limitations": limitations,
            "technical_evidence": citations,
            "review_areas": review_areas,
            "conclusion": (
                f"Analysis completed with risk tier {facts.behavioral.risk_level} and classification "
                f"resemblance '{facts.classification.predicted_category}'. Technical review advised for flagged areas."
            ),
        }

        return report_dict

    def generate(self, prompt: str, config: ReportConfig | None = None) -> str:
        """Generate response based on configured mode."""
        if self.custom_response is not None:
            return self.custom_response

        if self.mode == "malformed_json":
            return "```json\n{\ninvalid_json: 123,\n```"

        if not self.facts:
            # Return minimal dummy JSON if no facts set
            return json.dumps({"status": "no_facts_provided"})

        rep = self.build_valid_report_dict(self.facts, self.evidence)

        # Apply specific failure mutations if requested
        if self.mode == "altered_risk_score":
            rep["behavioral_analysis"]["risk_score"] = rep["behavioral_analysis"]["risk_score"] + 50
        elif self.mode == "altered_packet_count":
            rep["capture_overview"]["packet_count"] = rep["capture_overview"]["packet_count"] + 99999
        elif self.mode == "altered_duration":
            rep["capture_overview"]["duration_seconds"] = rep["capture_overview"]["duration_seconds"] + 500.0
        elif self.mode == "altered_confidence":
            rep["traffic_classification"]["confidence"] = 0.999
        elif self.mode == "altered_category":
            rep["traffic_classification"]["predicted_category"] = "unsupported_category_xyz"
        elif self.mode == "invented_indicator":
            rep["behavioral_analysis"]["triggered_indicators"].append("UNSUPPORTED_PORT_SCAN_INDICATOR")
        elif self.mode == "wrong_ipsec_status":
            rep["ipsec_analysis"]["esp_detected"] = not rep["ipsec_analysis"]["esp_detected"]
        elif self.mode == "unsupported_claim":
            rep["executive_summary"] += " A confirmed attack was detected with definitely malicious intrusion."
        elif self.mode == "unsupported_ipsec_validation":
            rep["executive_summary"] += " This is an IPsec-validated classification and validated web traffic."
        elif self.mode == "model_uncertainty_as_risk":
            rep["behavioral_analysis"]["explanation"] = (
                f"The risk score is {rep['behavioral_analysis']['risk_score']} because the model is uncertain."
            )
        elif self.mode == "missing_section":
            del rep["executive_summary"]
        elif self.mode == "invalid_evidence_id":
            rep["behavioral_analysis"]["evidence_ids"].append("E999_NON_EXISTENT")

        return f"```json\n{json.dumps(rep, indent=2)}\n```"
