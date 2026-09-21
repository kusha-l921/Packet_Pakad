"""Prompt template construction for structured report generation."""

from ..context.context_builder import AssembledContext


class PromptTemplate:
    """Constructs explicit prompt requiring structured JSON matching the Report schema."""

    REPORT_JSON_SCHEMA_DESCRIPTION = """
You MUST output a single JSON object with EXACTLY the following structure:
{
  "report_metadata": {
    "report_id": "string (e.g. rep_20260921_001)",
    "generated_at": "string (ISO8601 timestamp)",
    "report_schema_version": "1.0",
    "input_schema_version": "1.0",
    "rag_knowledge_base_version": "1.0",
    "llm_provider": "string",
    "llm_model": "string"
  },
  "executive_summary": "string (concise neutral overview citing facts, resemblance, risk tier, and domain status)",
  "capture_overview": {
    "packet_count": integer (MUST match AnalysisFacts),
    "flow_count": integer (MUST match AnalysisFacts),
    "duration_seconds": float (MUST match AnalysisFacts),
    "total_bytes": integer (MUST match AnalysisFacts),
    "summary_text": "string"
  },
  "ipsec_analysis": {
    "detected": boolean (MUST match AnalysisFacts),
    "esp_detected": boolean (MUST match AnalysisFacts),
    "ah_detected": boolean (MUST match AnalysisFacts),
    "ike_detected": boolean (MUST match AnalysisFacts),
    "nat_t_detected": boolean (MUST match AnalysisFacts),
    "domain_validation_status": "string (MUST match AnalysisFacts)",
    "explanation": "string (explanation grounded in retrieved knowledge)",
    "evidence_ids": ["string (e.g. E001)"]
  },
  "traffic_classification": {
    "predicted_category": "string (MUST match AnalysisFacts)",
    "confidence": float (MUST match AnalysisFacts),
    "probabilities": { "category_name": float },
    "resemblance_explanation": "string (explains category resemblance; NOT application identity)",
    "evidence_ids": ["string"]
  },
  "behavioral_analysis": {
    "risk_score": integer (MUST match AnalysisFacts),
    "risk_level": "string (LOW|MEDIUM|HIGH|CRITICAL - MUST match AnalysisFacts)",
    "triggered_indicators": ["string (ONLY indicators present in AnalysisFacts)"],
    "explanation": "string (factual explanation of indicators triggering risk score)",
    "non_malice_disclaimer": "string (explicit statement that indicators do NOT confirm attack or malice)",
    "evidence_ids": ["string"]
  },
  "flow_findings": [
    {
      "flow_id": "string",
      "description": "string",
      "risk_score": integer,
      "indicators": ["string"]
    }
  ],
  "model_uncertainty": {
    "uncertainty_level": "string (LOW|MEDIUM|HIGH - MUST match AnalysisFacts)",
    "explanation": "string",
    "risk_separation_statement": "string (explicit statement that uncertainty is separate from risk score)",
    "evidence_ids": ["string"]
  },
  "limitations": [
    {
      "topic": "string",
      "statement": "string",
      "evidence_ids": ["string"]
    }
  ],
  "technical_evidence": [
    {
      "evidence_id": "string",
      "title": "string",
      "source": "string",
      "section": "string"
    }
  ],
  "review_areas": ["string (factual investigation recommendations without definitive accusation)"],
  "conclusion": "string (balanced concluding summary)"
}
"""

    @classmethod
    def render(cls, context: AssembledContext, model_name: str = "llama3.2") -> str:
        """Render the complete prompt text for the LLM."""
        return (
            "You are an expert network security analysis report generator. "
            "Your role is to produce a strictly factual, professional, and neutral technical analysis report.\n\n"
            f"{context.full_prompt_text}\n\n"
            "==================================================\n"
            "OUTPUT FORMAT SPECIFICATION\n"
            "==================================================\n"
            f"{cls.REPORT_JSON_SCHEMA_DESCRIPTION}\n\n"
            "Respond ONLY with the JSON object. Do not include introductory text or trailing thoughts."
        )
