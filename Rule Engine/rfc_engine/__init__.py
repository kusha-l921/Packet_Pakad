"""
rfc_engine — RFC Compliance & Health Rule Engine Package.

Provides handshake control-plane auditing (Categories 1-12), runtime ESP
anti-replay sliding window (RFC 4303), 64-bit sequence rollover detection,
and unified compliance reporting.
"""

from __future__ import annotations

from .rfcEngineModels import (
    EngineReport,
    PqcClassification,
    RequirementLevel,
    RuleEvaluationResult,
    RuleStatus,
    SecurityPosture,
    Severity,
    SpecSourceType,
)
from .rfcRegistries import (
    AEAD_ENCR_IDS,
    CERT_KEY_TYPE_OIDS,
    CERT_SIG_ALGO_OIDS,
    ESP_ENCR_REGISTRY,
    ESP_INTEG_REGISTRY,
    IKEV2_AUTH_METHODS_REGISTRY,
    IKEV2_DH_REGISTRY,
    IKEV2_ENCR_REGISTRY,
    IKEV2_INTEG_REGISTRY,
    IKEV2_PRF_REGISTRY,
    PQC_SIG_ALGO_REGISTRY,
)
from .rfcControlPlane import RfcControlPlaneEngine
from .rfcRuntimeTelemetry import RfcRuntimeTelemetryEngine
from .rfcRuleEngine import RfcRuleEngine

__all__ = [
    "RfcRuleEngine",
    "RfcControlPlaneEngine",
    "RfcRuntimeTelemetryEngine",
    "EngineReport",
    "RuleEvaluationResult",
    "SecurityPosture",
    "PqcClassification",
    "RuleStatus",
    "Severity",
    "RequirementLevel",
    "SpecSourceType",
    "AEAD_ENCR_IDS",
    "CERT_KEY_TYPE_OIDS",
    "CERT_SIG_ALGO_OIDS",
    "ESP_ENCR_REGISTRY",
    "ESP_INTEG_REGISTRY",
    "IKEV2_AUTH_METHODS_REGISTRY",
    "IKEV2_DH_REGISTRY",
    "IKEV2_ENCR_REGISTRY",
    "IKEV2_INTEG_REGISTRY",
    "IKEV2_PRF_REGISTRY",
    "PQC_SIG_ALGO_REGISTRY",
]
