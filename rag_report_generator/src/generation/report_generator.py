import logging
import time
from typing import Any
from ..context.context_builder import ContextBuilder

logger = logging.getLogger(__name__)
from ..context.facts import extract_analysis_facts
from ..models.evidence import RetrievedEvidence
from ..models.report import Report
from ..models.report_metadata import GeneratedReport, ReportConfig, ValidationSummary
from ..validation.report_validator import ReportValidator
from .json_repair import JSONRepair
from .llm_provider import LLMProvider, MockLLMProvider
from .markdown_renderer import MarkdownRenderer
from .ollama_provider import OllamaProvider
from .prompt_template import PromptTemplate


class ReportGenerator:
    """Orchestrates the Phase 5 + Evidence -> Controlled LLM Context -> Structured Report -> Validation -> Markdown pipeline."""

    def __init__(
        self,
        config: ReportConfig | None = None,
        provider: LLMProvider | None = None,
    ):
        self.config = config or ReportConfig()
        self.provider = provider or self._init_provider(self.config)

    @classmethod
    def _init_provider(cls, config: ReportConfig) -> LLMProvider:
        """Initialize provider according to configuration."""
        if config.llm_provider.lower() == "ollama":
            return OllamaProvider(
                base_url=config.ollama_base_url,
                default_model=config.llm_model,
                timeout=config.timeout_seconds,
            )
        return MockLLMProvider()

    def generate(
        self,
        analysis_result: dict[str, Any],
        retrieved_evidence: list[RetrievedEvidence],
    ) -> GeneratedReport:
        """Execute full report generation pipeline."""
        start_time = time.time()
        metadata: dict[str, Any] = {
            "report_schema_version": self.config.report_schema_version,
            "input_schema_version": self.config.input_schema_version,
            "rag_knowledge_base_version": self.config.rag_knowledge_base_version,
            "llm_provider": self.config.llm_provider,
            "llm_model": self.config.llm_model,
            "evidence_count": len(retrieved_evidence),
        }

        # 1. Validate input structure
        if not isinstance(analysis_result, dict):
            return GeneratedReport(
                status="INVALID_INPUT",
                metadata=metadata,
                validation={"errors": ["Phase 5 analysis result must be a JSON dictionary."]},
            )

        # 2. Extract authoritative facts
        try:
            facts = extract_analysis_facts(analysis_result, max_flows=self.config.max_flows)
        except Exception as e:
            return GeneratedReport(
                status="INVALID_INPUT",
                metadata=metadata,
                validation={"errors": [f"Failed to extract analysis facts: {e}"]},
            )

        # 3. Build controlled context and prompt
        context = ContextBuilder.build_context(
            facts=facts,
            evidence_list=retrieved_evidence,
            config=self.config,
        )
        metadata["evidence_ids"] = [e.evidence_id for e in context.deduplicated_evidence]

        prompt = PromptTemplate.render(context, model_name=self.config.llm_model)

        # 4. Invoke LLM provider
        # If using MockLLMProvider, update its facts and evidence for deterministic responses
        if isinstance(self.provider, MockLLMProvider):
            self.provider.set_facts_and_evidence(facts, context.deduplicated_evidence)

        logger.info(
            "LLM started using provider: %s (model: %s)",
            self.config.llm_provider,
            self.config.llm_model,
        )
        try:
            raw_output = self.provider.generate(prompt, config=self.config)
        except Exception as e:
            logger.error("LLM generation failed: %s", e)
            return GeneratedReport(
                status="GENERATION_FAILED",
                metadata=metadata,
                validation={"errors": [f"LLM generation failed: {e}"]},
            )
        logger.info("LLM completed generation (%d characters)", len(raw_output))

        # 5. Safe structural JSON extraction and repair
        try:
            parsed_dict = JSONRepair.clean_and_parse(raw_output)
        except Exception as e:
            logger.error("Failed to parse structured JSON from LLM output: %s", e)
            return GeneratedReport(
                status="GENERATION_FAILED",
                metadata=metadata,
                validation={"errors": [f"Failed to parse structured JSON from LLM: {e}"]},
            )

        # 6. Parse structured Report schema
        try:
            report = Report.from_dict(parsed_dict)
        except Exception as e:
            logger.error("Report schema compliance error: %s", e)
            return GeneratedReport(
                status="VALIDATION_FAILED",
                report_json=parsed_dict,
                metadata=metadata,
                validation={"errors": [f"Schema compliance error: {e}"]},
            )

        # 7. Run full multi-layer validation
        val_summary = ReportValidator.validate(
            report=report,
            facts=facts,
            retrieved_evidence=context.deduplicated_evidence,
        )

        metadata["validation_status"] = "PASSED" if val_summary.is_valid else "FAILED"
        metadata["duration_seconds"] = round(time.time() - start_time, 3)
        logger.info(
            "Report validation completed: status=%s (valid=%s, %d errors, %d warnings)",
            metadata["validation_status"],
            val_summary.is_valid,
            len(val_summary.errors),
            len(val_summary.warnings),
        )

        if not val_summary.is_valid:
            return GeneratedReport(
                status="VALIDATION_FAILED",
                report_json=parsed_dict,
                metadata=metadata,
                validation=val_summary.to_dict(),
            )

        # 8. Render deterministic Markdown report
        markdown_text = MarkdownRenderer.render(report)

        return GeneratedReport(
            status="SUCCESS",
            report_json=parsed_dict,
            markdown=markdown_text,
            metadata=metadata,
            validation=val_summary.to_dict(),
        )
