"""
rfcRuleEngine.py — Standalone RFC Health and Compliance Rule Engine for IPsec / IKEv2.

Orchestrates:
- Part 1: Post-Handshake Control-Plane Engine (Categories 1–7, 9, 11, static SA)
- Part 2: Runtime Telemetry Engine (Categories 8, 10, 12)
"""

from __future__ import annotations

from typing import Any

from .rfcControlPlane import RfcControlPlaneEngine
from .rfcEngineModels import (
    CategoryComplianceSummary,
    EngineReport,
    RuleCategory,
    RuleEvaluationResult,
    RuleStatus,
)
from .rfcRuntimeTelemetry import RfcRuntimeTelemetryEngine


class RfcRuleEngine:
    """RFC Health and Compliance Rule Engine for IPsec and IKEv2."""

    def __init__(self, replay_window_size: int = 64) -> None:
        self.control_plane_engine = RfcControlPlaneEngine()
        self.telemetry_engine = RfcRuntimeTelemetryEngine(default_window_size=replay_window_size)

    def evaluate(
        self,
        session_dict: dict[str, Any],
        telemetry_dict: dict[str, Any] | None = None,
    ) -> EngineReport:
        """Evaluate an IKEv2 session and optional ESP runtime telemetry against RFC rules."""
        all_results: list[RuleEvaluationResult] = []

        cp_results = self.control_plane_engine.evaluate_session(session_dict)
        all_results.extend(cp_results)

        dp_data = telemetry_dict if telemetry_dict is not None else session_dict.get("data_plane")
        child_sa_ctx = session_dict.get("IKE_AUTH", {}).get("child_sa")

        telemetry_results = self.telemetry_engine.evaluate_telemetry(
            dp_data, child_sa_context=child_sa_ctx
        )
        all_results.extend(telemetry_results)

        critical_failures: list[RuleEvaluationResult] = []
        warnings: list[RuleEvaluationResult] = []
        passed_rules: list[RuleEvaluationResult] = []
        not_verifiable_rules: list[RuleEvaluationResult] = []
        not_applicable_rules: list[RuleEvaluationResult] = []

        for r in all_results:
            if r.status == RuleStatus.FAIL:
                critical_failures.append(r)
            elif r.status == RuleStatus.WARNING:
                warnings.append(r)
            elif r.status == RuleStatus.PASS:
                passed_rules.append(r)
            elif r.status == RuleStatus.NOT_VERIFIABLE:
                not_verifiable_rules.append(r)
            elif r.status == RuleStatus.NOT_APPLICABLE:
                not_applicable_rules.append(r)

        category_summaries = self._compute_category_summaries(all_results)
        overall_status = self._aggregate_overall_status(all_results)

        proto_comp = self._category_group_status(
            all_results, [RuleCategory.CAT1_IKEV2_PROTOCOL.value]
        )
        crypto_comp = self._category_group_status(
            all_results,
            [
                RuleCategory.CAT2_CRYPTO_TRANSFORMS.value,
                RuleCategory.CAT3_ENCRYPTION.value,
                RuleCategory.CAT4_PRF.value,
                RuleCategory.CAT5_INTEGRITY.value,
                RuleCategory.CAT6_DH_KEY_EXCHANGE.value,
            ],
        )
        esp_comp = self._category_group_status(
            all_results,
            [
                RuleCategory.CAT8_ESP_IPSEC.value,
                RuleCategory.CAT10_ANTI_REPLAY.value,
                RuleCategory.CAT12_SPD_POLICY.value,
            ],
        )
        auth_comp = self._category_group_status(
            all_results, [RuleCategory.CAT7_AUTHENTICATION.value]
        )

        security_posture = self.control_plane_engine.evaluate_security_posture(session_dict)
        pqc_classification = self.control_plane_engine.evaluate_pqc_status(session_dict)
        hybrid_classification = self.control_plane_engine.evaluate_hybrid_status(session_dict)

        # Determine IPsec encapsulation mode (RFC 7296 §1.3.1 & §3.10.1)
        raw_notif = session_dict.get("notify", {})
        notify_types = raw_notif.get("notify_types", []) if isinstance(raw_notif, dict) else []
        if not isinstance(notify_types, (list, set, tuple)):
            notify_types = []
        is_transport = 16391 in notify_types or session_dict.get("ipsec_mode") == "TRANSPORT"
        ipsec_mode = "TRANSPORT" if is_transport else "TUNNEL"

        return EngineReport(
            overall_rfc_status=overall_status,
            protocol_compliance=proto_comp,
            cryptographic_compliance=crypto_comp,
            ipsec_esp_compliance=esp_comp,
            authentication_compliance=auth_comp,
            pqc_classification=pqc_classification,
            hybrid_classification=hybrid_classification,
            cryptographic_posture=security_posture,
            ipsec_mode=ipsec_mode,
            critical_failures=critical_failures,
            warnings=warnings,
            passed_rules=passed_rules,
            not_verifiable_rules=not_verifiable_rules,
            not_applicable_rules=not_applicable_rules,
            all_results=all_results,
            category_summaries=category_summaries,
        )

    def process_esp_packet(
        self,
        packet_dict: dict[str, Any],
        session_dict: dict[str, Any] | None = None,
    ) -> list[RuleEvaluationResult]:
        """Process a single ESP packet in real time, updating the sliding window."""
        child_sa_ctx = (session_dict or {}).get("IKE_AUTH", {}).get("child_sa")
        return self.telemetry_engine.process_esp_packet(
            packet_dict, child_sa_context=child_sa_ctx
        )

    def reset_telemetry_windows(self, spi: str | None = None) -> None:
        """Reset anti-replay sliding window state for a specific SPI or all SPIs."""
        self.telemetry_engine.reset_window(spi)

    def _aggregate_overall_status(self, results: list[RuleEvaluationResult]) -> RuleStatus:
        if any(r.status == RuleStatus.FAIL for r in results):
            return RuleStatus.FAIL
        if any(r.status == RuleStatus.WARNING for r in results):
            return RuleStatus.WARNING
        if any(r.status == RuleStatus.PASS for r in results):
            return RuleStatus.PASS
        return RuleStatus.NOT_VERIFIABLE

    def _category_group_status(
        self, results: list[RuleEvaluationResult], target_categories: list[str]
    ) -> RuleStatus:
        filtered = [r for r in results if r.category in target_categories]
        if not filtered:
            return RuleStatus.NOT_VERIFIABLE
        if any(r.status == RuleStatus.FAIL for r in filtered):
            return RuleStatus.FAIL
        if any(r.status == RuleStatus.WARNING for r in filtered):
            return RuleStatus.WARNING
        if any(r.status == RuleStatus.PASS for r in filtered):
            return RuleStatus.PASS
        return RuleStatus.NOT_VERIFIABLE

    def _compute_category_summaries(
        self, results: list[RuleEvaluationResult]
    ) -> dict[str, CategoryComplianceSummary]:
        summaries: dict[str, CategoryComplianceSummary] = {}

        for cat in RuleCategory:
            summaries[cat.value] = CategoryComplianceSummary(
                category=cat.value, status=RuleStatus.NOT_VERIFIABLE
            )

        for r in results:
            cat_name = r.category
            if cat_name not in summaries:
                summaries[cat_name] = CategoryComplianceSummary(
                    category=cat_name, status=RuleStatus.NOT_VERIFIABLE
                )

            entry = summaries[cat_name]
            if r.status == RuleStatus.PASS:
                entry.passed_count += 1
            elif r.status == RuleStatus.FAIL:
                entry.failed_count += 1
            elif r.status == RuleStatus.WARNING:
                entry.warning_count += 1
            elif r.status == RuleStatus.NOT_VERIFIABLE:
                entry.not_verifiable_count += 1
            elif r.status == RuleStatus.NOT_APPLICABLE:
                entry.not_applicable_count += 1

        for entry in summaries.values():
            if entry.failed_count > 0:
                entry.status = RuleStatus.FAIL
            elif entry.warning_count > 0:
                entry.status = RuleStatus.WARNING
            elif entry.passed_count > 0:
                entry.status = RuleStatus.PASS
            else:
                entry.status = RuleStatus.NOT_VERIFIABLE

        return summaries
