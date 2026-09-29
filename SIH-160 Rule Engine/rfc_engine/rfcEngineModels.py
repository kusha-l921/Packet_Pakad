"""
rfcEngineModels.py — Data Models, Enums, and Result Containers for RFC Health and Compliance Engine.

Defines the internal rule schema, evaluation outcomes, severity tiers, requirement levels,
and comprehensive structured report objects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RuleStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_VERIFIABLE = "NOT_VERIFIABLE"


class RequirementLevel(str, Enum):
    MUST = "MUST"
    MUST_NOT = "MUST NOT"
    SHOULD = "SHOULD"
    SHOULD_NOT = "SHOULD NOT"
    MAY = "MAY"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class ApplicableContext(str, Enum):
    HANDSHAKE = "HANDSHAKE"
    RUNTIME = "RUNTIME"
    COMMON = "COMMON"


class RuleCategory(str, Enum):
    CAT1_IKEV2_PROTOCOL = "IKEv2 Protocol Compliance"
    CAT2_CRYPTO_TRANSFORMS = "IKEv2 Cryptographic Transforms"
    CAT3_ENCRYPTION = "Encryption Rules"
    CAT4_PRF = "PRF Rules"
    CAT5_INTEGRITY = "Integrity Rules"
    CAT6_DH_KEY_EXCHANGE = "Diffie-Hellman / Key Exchange"
    CAT7_AUTHENTICATION = "Identity & Authentication"
    CAT8_ESP_IPSEC = "ESP / IPsec Rules"
    CAT9_SA_LIFECYCLE = "Security Association Lifecycle"
    CAT10_ANTI_REPLAY = "Anti-Replay / ESN"
    CAT11_NAT_TRAVERSAL = "NAT Traversal"
    CAT12_SPD_POLICY = "IPsec Security Policy (SPD)"


class SecurityPosture(str, Enum):
    STRONG = "STRONG"
    ACCEPTABLE = "ACCEPTABLE"
    WEAK = "WEAK"
    BROKEN = "BROKEN"
    UNKNOWN = "UNKNOWN"


class PqcClassification(str, Enum):
    NONE = "NONE"
    PQC_KEM = "PQC_KEM"
    PPK = "PPK"
    PQC_SIG = "PQC_SIG"
    COMPOSITE = "COMPOSITE"
    UNKNOWN = "UNKNOWN"


class HybridClassification(str, Enum):
    HYBRID = "HYBRID"
    NOT_HYBRID = "NOT_HYBRID"
    NOT_VERIFIABLE = "NOT_VERIFIABLE"


class SpecSourceType(str, Enum):
    PUBLISHED_RFC = "PUBLISHED RFC"
    INTERNET_DRAFT = "INTERNET-DRAFT"
    IANA_REGISTRY = "IANA REGISTRY"
    FIPS_STANDARD = "FIPS STANDARD"


@dataclass
class RuleDefinition:
    """Internal rule definition schema."""
    rule_id: str
    rfc: str
    section: str
    category: RuleCategory
    condition: str
    requirement_level: RequirementLevel
    applicable_context: ApplicableContext
    pass_condition: str
    fail_condition: str
    severity: Severity
    spec_source: SpecSourceType = SpecSourceType.PUBLISHED_RFC


@dataclass
class RuleEvaluationResult:
    """Evaluation result for an individual RFC rule."""
    rule_id: str
    rfc: str
    section: str
    category: str
    condition: str
    requirement_level: str
    applicable_context: str
    status: RuleStatus
    severity: Severity
    reason: str
    observed_value: Any = None
    expected_requirement: str = ""
    spec_source: str = SpecSourceType.PUBLISHED_RFC.value

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rfc": self.rfc,
            "section": self.section,
            "category": self.category,
            "condition": self.condition,
            "requirement_level": self.requirement_level,
            "applicable_context": self.applicable_context,
            "status": self.status.value,
            "severity": self.severity.value,
            "reason": self.reason,
            "observed_value": str(self.observed_value) if self.observed_value is not None else None,
            "expected_requirement": self.expected_requirement,
            "spec_source": self.spec_source,
        }

    def format_finding(self) -> str:
        """Format individual finding matching the requested output format."""
        return (
            f"{self.status.value}\n"
            f"Rule:        {self.rule_id}\n"
            f"Observed:    {self.observed_value}\n"
            f"Requirement: {self.expected_requirement or self.requirement_level}\n"
            f"RFC:         {self.rfc}\n"
            f"Section:     {self.section}\n"
            f"Reason:      {self.reason}\n"
            f"Severity:    {self.severity.value}"
        )


@dataclass
class CategoryComplianceSummary:
    category: str
    status: RuleStatus
    passed_count: int = 0
    failed_count: int = 0
    warning_count: int = 0
    not_verifiable_count: int = 0
    not_applicable_count: int = 0


@dataclass
class EngineReport:
    """Comprehensive structured report returning all decoupled compliance dimensions."""
    overall_rfc_status: RuleStatus
    protocol_compliance: RuleStatus
    cryptographic_compliance: RuleStatus
    ipsec_esp_compliance: RuleStatus
    authentication_compliance: RuleStatus
    pqc_classification: PqcClassification
    hybrid_classification: HybridClassification
    cryptographic_posture: SecurityPosture
    ipsec_mode: str = "TUNNEL"

    critical_failures: list[RuleEvaluationResult] = field(default_factory=list)
    warnings: list[RuleEvaluationResult] = field(default_factory=list)
    passed_rules: list[RuleEvaluationResult] = field(default_factory=list)
    not_verifiable_rules: list[RuleEvaluationResult] = field(default_factory=list)
    not_applicable_rules: list[RuleEvaluationResult] = field(default_factory=list)
    all_results: list[RuleEvaluationResult] = field(default_factory=list)
    category_summaries: dict[str, CategoryComplianceSummary] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_rfc_status": self.overall_rfc_status.value,
            "ipsec_mode": self.ipsec_mode,
            "protocol_compliance": self.protocol_compliance.value,
            "cryptographic_compliance": self.cryptographic_compliance.value,
            "ipsec_esp_compliance": self.ipsec_esp_compliance.value,
            "authentication_compliance": self.authentication_compliance.value,
            "pqc_classification": self.pqc_classification.value,
            "hybrid_classification": self.hybrid_classification.value,
            "cryptographic_posture": self.cryptographic_posture.value,
            "counts": {
                "critical_failures": len(self.critical_failures),
                "warnings": len(self.warnings),
                "passed_rules": len(self.passed_rules),
                "not_verifiable_rules": len(self.not_verifiable_rules),
                "not_applicable_rules": len(self.not_applicable_rules),
                "total_evaluated": len(self.all_results),
            },
            "category_summaries": {
                k: {
                    "status": v.status.value,
                    "passed": v.passed_count,
                    "failed": v.failed_count,
                    "warnings": v.warning_count,
                    "not_verifiable": v.not_verifiable_count,
                }
                for k, v in self.category_summaries.items()
            },
            "critical_failures": [r.to_dict() for r in self.critical_failures],
            "warnings": [r.to_dict() for r in self.warnings],
            "passed_rules": [r.to_dict() for r in self.passed_rules],
            "not_verifiable_rules": [r.to_dict() for r in self.not_verifiable_rules],
        }

    def to_text_report(self) -> str:
        """Generate human-readable structured text report."""
        lines = []
        lines.append("=" * 80)
        lines.append("IPSEC / IKEV2 RFC HEALTH & COMPLIANCE REPORT")
        lines.append("=" * 80)
        lines.append(f"Overall RFC Status:             {self.overall_rfc_status.value}")
        lines.append("")
        lines.append(f"Protocol Compliance:            {self.protocol_compliance.value}")
        lines.append(f"Cryptographic Compliance:       {self.cryptographic_compliance.value}")
        lines.append(f"IPsec/ESP Compliance:           {self.ipsec_esp_compliance.value}")
        lines.append(f"Authentication Compliance:      {self.authentication_compliance.value}")
        lines.append(f"PQC Classification:             {self.pqc_classification.value}")
        lines.append(f"Hybrid Classification:          {self.hybrid_classification.value}")
        lines.append(f"Cryptographic Posture:          {self.cryptographic_posture.value}")
        lines.append("")
        lines.append(f"Critical Failures:              {len(self.critical_failures)}")
        lines.append(f"Warnings:                       {len(self.warnings)}")
        lines.append(f"Passed Rules:                   {len(self.passed_rules)}")
        lines.append(f"Not Verifiable Rules:           {len(self.not_verifiable_rules)}")
        lines.append("-" * 80)

        if self.critical_failures:
            lines.append("CRITICAL FAILURES:")
            lines.append("-" * 80)
            for f in self.critical_failures:
                lines.append(f.format_finding())
                lines.append("-" * 40)

        if self.warnings:
            lines.append("WARNINGS:")
            lines.append("-" * 80)
            for w in self.warnings:
                lines.append(w.format_finding())
                lines.append("-" * 40)

        if not self.critical_failures and not self.warnings:
            lines.append("No failures or warnings observed.")
            lines.append("-" * 80)

        return "\n".join(lines)
