"""Configuration, validation summary, and generated report result models."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ReportConfig:
    """Configuration options for report generation."""
    llm_provider: str = "mock"  # "mock" | "ollama"
    llm_model: str = "llama3.2"
    temperature: float = 0.1
    max_output_tokens: int = 4096
    timeout_seconds: float = 60.0
    ollama_base_url: str = "http://localhost:11434"
    max_flows: int = 5
    max_evidence: int = 8
    max_context_characters: int = 12000
    report_schema_version: str = "1.0"
    rag_knowledge_base_version: str = "1.0"
    input_schema_version: str = "1.0"

    def to_dict(self) -> dict[str, Any]:
        return {
            "llm_provider": self.llm_provider,
            "llm_model": self.llm_model,
            "temperature": self.temperature,
            "max_output_tokens": self.max_output_tokens,
            "timeout_seconds": self.timeout_seconds,
            "ollama_base_url": self.ollama_base_url,
            "max_flows": self.max_flows,
            "max_evidence": self.max_evidence,
            "max_context_characters": self.max_context_characters,
            "report_schema_version": self.report_schema_version,
            "rag_knowledge_base_version": self.rag_knowledge_base_version,
            "input_schema_version": self.input_schema_version,
        }


@dataclass
class ValidationSummary:
    """Outcome of multi-layer report validation."""
    is_valid: bool = True
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    checked_rules: list[str] = field(default_factory=list)

    def add_error(self, message: str) -> None:
        self.errors.append(message)
        self.is_valid = False

    def add_warning(self, message: str) -> None:
        self.warnings.append(message)

    def add_rule(self, rule_name: str) -> None:
        self.checked_rules.append(rule_name)

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "checked_rules": list(self.checked_rules),
        }


@dataclass
class GeneratedReport:
    """Unified result container returned by Part 2 report generation API."""
    status: str  # "SUCCESS" | "VALIDATION_FAILED" | "GENERATION_FAILED" | "INVALID_INPUT" | "NO_EVIDENCE"
    report_json: dict[str, Any] | None = None
    markdown: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    validation: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "report_json": self.report_json,
            "markdown": self.markdown,
            "metadata": self.metadata,
            "validation": self.validation,
        }
