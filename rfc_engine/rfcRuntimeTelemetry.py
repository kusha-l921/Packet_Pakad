"""
rfcRuntimeTelemetry.py — Part 2: Runtime Telemetry Engine for ESP & Anti-Replay.

Evaluates periodic sliding windows or streams of data-plane ESP records against RFC requirements:
- Category 8: ESP Runtime Compliance (RFC 4301, RFC 4303, RFC 8221)
- Category 10: Anti-Replay & Extended Sequence Numbers (RFC 4303 §3.3.3, §3.4.3, RFC 4304)
- Category 12: Security Policy Database (SPD) Enforcement (RFC 4301 §4.4.1)
"""

from __future__ import annotations

from typing import Any
import ipaddress

from .rfcEngineModels import (
    ApplicableContext,
    RequirementLevel,
    RuleCategory,
    RuleEvaluationResult,
    RuleStatus,
    Severity,
    SpecSourceType,
)


class SlidingWindowReplayDetector:
    """RFC 4303 Section 3.4.3 Anti-Replay Sliding Window Simulator."""

    def __init__(self, window_size: int = 64) -> None:
        self.window_size = window_size
        self.highest_seq = 0
        self.received_window: set[int] = set()
        self.duplicate_count = 0
        self.trailing_drop_count = 0
        self.valid_count = 0

    def check_and_update(self, seq_num: int) -> tuple[bool, str]:
        """Check sequence number against the sliding window."""
        if seq_num <= 0:
            return False, f"Invalid non-positive sequence number {seq_num}."

        if self.highest_seq == 0:
            self.highest_seq = seq_num
            self.received_window.add(seq_num)
            self.valid_count += 1
            return True, "Initial packet accepted."

        if seq_num > self.highest_seq:
            self.highest_seq = seq_num
            self.received_window.add(seq_num)
            min_valid = self.highest_seq - self.window_size + 1
            self.received_window = {s for s in self.received_window if s >= min_valid}
            self.valid_count += 1
            return True, "Window advanced."

        min_valid = self.highest_seq - self.window_size + 1
        if seq_num < min_valid:
            self.trailing_drop_count += 1
            return (
                False,
                f"Packet seq {seq_num} fell behind trailing edge {min_valid} "
                f"(window=[{min_valid}, {self.highest_seq}]).",
            )

        if seq_num in self.received_window:
            self.duplicate_count += 1
            return False, f"Duplicate sequence number {seq_num} detected (replay attack)."

        self.received_window.add(seq_num)
        self.valid_count += 1
        return True, "Out-of-order packet accepted within sliding window."


class RfcRuntimeTelemetryEngine:
    """Evaluates data-plane ESP runtime telemetry records against RFC 4301, 4303, 4304."""

    def __init__(self, default_window_size: int = 64) -> None:
        self.default_window_size = default_window_size
        self.windows: dict[str, SlidingWindowReplayDetector] = {}

    def get_or_create_window(self, spi: str) -> SlidingWindowReplayDetector:
        """Retrieve or initialize the sliding window for a given SPI."""
        if spi not in self.windows:
            self.windows[spi] = SlidingWindowReplayDetector(window_size=self.default_window_size)
        return self.windows[spi]

    def reset_window(self, spi: str | None = None) -> None:
        """Reset sliding window state for a specific SPI or all SPIs."""
        if spi is not None:
            self.windows.pop(spi, None)
        else:
            self.windows.clear()

    def process_esp_packet(
        self,
        packet_dict: dict[str, Any],
        child_sa_context: dict[str, Any] | None = None,
    ) -> list[RuleEvaluationResult]:
        """Evaluate a single ESP packet in real time against anti-replay, rollover, and encapsulation."""
        results: list[RuleEvaluationResult] = []

        seq_num = packet_dict.get("seq_num")
        if seq_num is None:
            results.append(RuleEvaluationResult(
                rule_id="ESP-SEQ-PRESENT-001",
                rfc="RFC 4303",
                section="§3.3.3",
                category=RuleCategory.CAT10_ANTI_REPLAY.value,
                condition="ESP sequence number presence",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.RUNTIME.value,
                status=RuleStatus.FAIL,
                severity=Severity.CRITICAL,
                reason="ESP packet is missing mandatory Sequence Number field.",
                observed_value="None",
                expected_requirement="Sequence number MUST be present",
                spec_source=SpecSourceType.PUBLISHED_RFC.value,
            ))
            return results

        spi = str(packet_dict.get("spi", "default"))
        window = self.get_or_create_window(spi)
        esn_enabled = self._resolve_esn_status(packet_dict, child_sa_context)

        max_32_bit = 0xFFFFFFFF
        if not esn_enabled:
            if seq_num >= max_32_bit:
                results.append(RuleEvaluationResult(
                    rule_id="ESP-SEQ-ROLLOVER-001",
                    rfc="RFC 4303",
                    section="§3.3.3",
                    category=RuleCategory.CAT10_ANTI_REPLAY.value,
                    condition="32-bit sequence number counter rollover check",
                    requirement_level=RequirementLevel.MUST_NOT.value,
                    applicable_context=ApplicableContext.RUNTIME.value,
                    status=RuleStatus.FAIL,
                    severity=Severity.CRITICAL,
                    reason=(
                        f"Sequence number {seq_num} reached or exceeded 32-bit maximum ({max_32_bit}) "
                        "without rekeying. Rollover through zero is strictly prohibited!"
                    ),
                    observed_value=f"seq={seq_num}",
                    expected_requirement="MUST NOT wrap past 2^32 - 1 without rekeying",
                    spec_source=SpecSourceType.PUBLISHED_RFC.value,
                ))
            elif seq_num >= max_32_bit - 100000:
                results.append(RuleEvaluationResult(
                    rule_id="ESP-SEQ-ROLLOVER-001",
                    rfc="RFC 4303",
                    section="§3.3.3",
                    category=RuleCategory.CAT10_ANTI_REPLAY.value,
                    condition="32-bit sequence number counter exhaustion warning",
                    requirement_level=RequirementLevel.SHOULD.value,
                    applicable_context=ApplicableContext.RUNTIME.value,
                    status=RuleStatus.WARNING,
                    severity=Severity.HIGH,
                    reason=(
                        f"Sequence number {seq_num} is within 100,000 packets of 32-bit exhaustion. "
                        "Immediate SA rekeying is required."
                    ),
                    observed_value=f"seq={seq_num}",
                    expected_requirement="Rekey before 2^32 - 1 is reached",
                    spec_source=SpecSourceType.PUBLISHED_RFC.value,
                ))
            else:
                results.append(RuleEvaluationResult(
                    rule_id="ESP-SEQ-ROLLOVER-001",
                    rfc="RFC 4303",
                    section="§3.3.3",
                    category=RuleCategory.CAT10_ANTI_REPLAY.value,
                    condition="32-bit sequence number counter rollover check",
                    requirement_level=RequirementLevel.MUST.value,
                    applicable_context=ApplicableContext.RUNTIME.value,
                    status=RuleStatus.PASS,
                    severity=Severity.INFORMATIONAL,
                    reason="Sequence number is within 32-bit bounds.",
                    observed_value=f"seq={seq_num}",
                    expected_requirement="seq < 2^32 - 1",
                    spec_source=SpecSourceType.PUBLISHED_RFC.value,
                ))
        else:
            results.append(RuleEvaluationResult(
                rule_id="ESP-SEQ-ROLLOVER-001",
                rfc="RFC 4304",
                section="§2",
                category=RuleCategory.CAT10_ANTI_REPLAY.value,
                condition="64-bit Extended Sequence Number (ESN) active",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.RUNTIME.value,
                status=RuleStatus.PASS,
                severity=Severity.INFORMATIONAL,
                reason="ESN is enabled; 64-bit sequence space prevents 32-bit rollover.",
                observed_value=f"ESN active, seq={seq_num}",
                expected_requirement="64-bit sequence space",
                spec_source=SpecSourceType.PUBLISHED_RFC.value,
            ))

        valid, reason = window.check_and_update(seq_num)
        if not valid:
            if "Duplicate" in reason:
                results.append(RuleEvaluationResult(
                    rule_id="ESP-REPLAY-DUP-001",
                    rfc="RFC 4303",
                    section="§3.4.3",
                    category=RuleCategory.CAT10_ANTI_REPLAY.value,
                    condition="Anti-replay sliding window duplicate detection",
                    requirement_level=RequirementLevel.MUST_NOT.value,
                    applicable_context=ApplicableContext.RUNTIME.value,
                    status=RuleStatus.FAIL,
                    severity=Severity.CRITICAL,
                    reason=reason,
                    observed_value=f"Duplicate seq={seq_num}",
                    expected_requirement="Duplicate sequence numbers MUST be rejected",
                    spec_source=SpecSourceType.PUBLISHED_RFC.value,
                ))
            elif "trailing edge" in reason:
                results.append(RuleEvaluationResult(
                    rule_id="ESP-REPLAY-WINDOW-001",
                    rfc="RFC 4303",
                    section="§3.4.3",
                    category=RuleCategory.CAT10_ANTI_REPLAY.value,
                    condition="Anti-replay sliding window trailing edge check",
                    requirement_level=RequirementLevel.MUST.value,
                    applicable_context=ApplicableContext.RUNTIME.value,
                    status=RuleStatus.FAIL,
                    severity=Severity.HIGH,
                    reason=reason,
                    observed_value=f"Trailing drop seq={seq_num}",
                    expected_requirement="Packets behind trailing edge MUST be discarded",
                    spec_source=SpecSourceType.PUBLISHED_RFC.value,
                ))
        else:
            results.append(RuleEvaluationResult(
                rule_id="ESP-REPLAY-WINDOW-001",
                rfc="RFC 4303",
                section="§3.4.3",
                category=RuleCategory.CAT10_ANTI_REPLAY.value,
                condition="Anti-replay sliding window check",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.RUNTIME.value,
                status=RuleStatus.PASS,
                severity=Severity.INFORMATIONAL,
                reason=reason,
                observed_value=f"seq={seq_num} (window=[{max(1, window.highest_seq - window.window_size + 1)}, {window.highest_seq}])",
                expected_requirement="Valid sequence number within window",
                spec_source=SpecSourceType.PUBLISHED_RFC.value,
            ))

        is_natt = packet_dict.get("is_natt", False)
        src_port = packet_dict.get("src_port")
        dst_port = packet_dict.get("dst_port")
        if is_natt:
            if src_port == 4500 or dst_port == 4500:
                results.append(RuleEvaluationResult(
                    rule_id="ESP-NATT-PORT-001",
                    rfc="RFC 3948",
                    section="§2.1",
                    category=RuleCategory.CAT8_ESP_IPSEC.value,
                    condition="NAT-T UDP encapsulation port mapping",
                    requirement_level=RequirementLevel.MUST.value,
                    applicable_context=ApplicableContext.RUNTIME.value,
                    status=RuleStatus.PASS,
                    severity=Severity.INFORMATIONAL,
                    reason="NAT-T encapsulated ESP utilizes port 4500.",
                    observed_value=f"UDP 4500 (src={src_port}, dst={dst_port})",
                    expected_requirement="UDP port 4500",
                ))
            else:
                results.append(RuleEvaluationResult(
                    rule_id="ESP-NATT-PORT-001",
                    rfc="RFC 3948",
                    section="§2.1",
                    category=RuleCategory.CAT8_ESP_IPSEC.value,
                    condition="NAT-T UDP encapsulation port mapping",
                    requirement_level=RequirementLevel.SHOULD.value,
                    applicable_context=ApplicableContext.RUNTIME.value,
                    status=RuleStatus.WARNING,
                    severity=Severity.MEDIUM,
                    reason="NAT-T indicated but neither source nor destination port is 4500.",
                    observed_value=f"src={src_port}, dst={dst_port}",
                    expected_requirement="UDP port 4500",
                ))

        inner_src = packet_dict.get("inner_src_ip")
        inner_dst = packet_dict.get("inner_dst_ip")
        if inner_src and inner_dst:
            ts_data = (child_sa_context or {}).get("traffic_selectors", {})
            tsi = ts_data.get("initiator", [])
            tsr = ts_data.get("responder", [])
            if tsi or tsr:
                if not self._match_traffic_selectors(inner_src, inner_dst, tsi, tsr):
                    results.append(RuleEvaluationResult(
                        rule_id="SPD-POLICY-TS-MAPPING-001",
                        rfc="RFC 4301",
                        section="§4.4.1",
                        category=RuleCategory.CAT12_SPD_POLICY.value,
                        condition="Traffic Selector matching against cleartext inner headers",
                        requirement_level=RequirementLevel.MUST.value,
                        applicable_context=ApplicableContext.RUNTIME.value,
                        status=RuleStatus.FAIL,
                        severity=Severity.CRITICAL,
                        reason=f"Packet ({inner_src} -> {inner_dst}) violates negotiated TS bounds.",
                        observed_value=f"{inner_src} -> {inner_dst}",
                        expected_requirement="Traffic matching TS",
                    ))
                else:
                    results.append(RuleEvaluationResult(
                        rule_id="SPD-POLICY-TS-MAPPING-001",
                        rfc="RFC 4301",
                        section="§4.4.1",
                        category=RuleCategory.CAT12_SPD_POLICY.value,
                        condition="Traffic Selector matching against cleartext inner headers",
                        requirement_level=RequirementLevel.MUST.value,
                        applicable_context=ApplicableContext.RUNTIME.value,
                        status=RuleStatus.PASS,
                        severity=Severity.INFORMATIONAL,
                        reason="Packet matches negotiated Traffic Selector bounds.",
                        observed_value=f"{inner_src} -> {inner_dst}",
                        expected_requirement="Traffic matching TS",
                    ))

        return results

    def evaluate_telemetry(
        self,
        telemetry_dict: dict[str, Any] | None,
        child_sa_context: dict[str, Any] | None = None,
    ) -> list[RuleEvaluationResult]:
        """Evaluate ESP data-plane packets and anti-replay state."""
        results: list[RuleEvaluationResult] = []

        if telemetry_dict is None:
            return self._not_verifiable_boundary("No runtime telemetry data supplied.")

        dp = telemetry_dict.get("data_plane", telemetry_dict)
        packets = (
            dp.get("packets")
            or dp.get("observed_packets")
            or telemetry_dict.get("observed_packets")
            or []
        )

        if not isinstance(packets, list) or len(packets) == 0:
            return self._not_verifiable_boundary(
                "Data plane container contains zero observed packets."
            )

        esn_enabled = self._resolve_esn_status(dp, child_sa_context)
        results.extend(self._eval_seq_rollover(packets, esn_enabled))
        results.extend(self._eval_anti_replay_window(packets, esn_enabled))
        results.extend(self._eval_esp_encapsulation(dp, packets))
        results.extend(self._eval_spd_policy(dp, packets, child_sa_context))

        return results

    def _eval_anti_replay_window(
        self, packets: list[dict[str, Any]], esn_enabled: bool
    ) -> list[RuleEvaluationResult]:
        results = []
        window = SlidingWindowReplayDetector(window_size=self.default_window_size)

        duplicates = []
        trailing_drops = []

        for p in packets:
            seq = p.get("seq_num")
            if seq is None:
                continue

            valid, reason = window.check_and_update(seq)
            if not valid:
                if "Duplicate" in reason:
                    duplicates.append(seq)
                elif "trailing edge" in reason:
                    trailing_drops.append(seq)

        if duplicates:
            results.append(RuleEvaluationResult(
                rule_id="ESP-REPLAY-DUP-001",
                rfc="RFC 4303",
                section="§3.4.3",
                category=RuleCategory.CAT10_ANTI_REPLAY.value,
                condition="Anti-replay sliding window duplicate detection",
                requirement_level=RequirementLevel.MUST_NOT.value,
                applicable_context=ApplicableContext.RUNTIME.value,
                status=RuleStatus.FAIL,
                severity=Severity.CRITICAL,
                reason=f"Detected {len(duplicates)} duplicate sequence number(s): {duplicates[:5]}... Replay violation!",
                observed_value=f"{len(duplicates)} duplicates",
                expected_requirement="Duplicate sequence numbers MUST be rejected",
                spec_source=SpecSourceType.PUBLISHED_RFC.value,
            ))
        else:
            results.append(RuleEvaluationResult(
                rule_id="ESP-REPLAY-DUP-001",
                rfc="RFC 4303",
                section="§3.4.3",
                category=RuleCategory.CAT10_ANTI_REPLAY.value,
                condition="Anti-replay sliding window duplicate detection",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.RUNTIME.value,
                status=RuleStatus.PASS,
                severity=Severity.INFORMATIONAL,
                reason="No duplicate sequence numbers observed across the telemetry window.",
                observed_value=f"0 duplicates in {len(packets)} packets",
                expected_requirement="No duplicate sequence numbers",
                spec_source=SpecSourceType.PUBLISHED_RFC.value,
            ))

        if trailing_drops:
            results.append(RuleEvaluationResult(
                rule_id="ESP-REPLAY-WINDOW-001",
                rfc="RFC 4303",
                section="§3.4.3",
                category=RuleCategory.CAT10_ANTI_REPLAY.value,
                condition="Anti-replay sliding window trailing edge check",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.RUNTIME.value,
                status=RuleStatus.FAIL,
                severity=Severity.HIGH,
                reason=(
                    f"Detected {len(trailing_drops)} packet(s) falling behind the sliding window "
                    f"trailing edge (window_size={self.default_window_size}): {trailing_drops[:5]}..."
                ),
                observed_value=f"{len(trailing_drops)} trailing drops",
                expected_requirement="Packets behind trailing edge MUST be discarded",
                spec_source=SpecSourceType.PUBLISHED_RFC.value,
            ))
        else:
            results.append(RuleEvaluationResult(
                rule_id="ESP-REPLAY-WINDOW-001",
                rfc="RFC 4303",
                section="§3.4.3",
                category=RuleCategory.CAT10_ANTI_REPLAY.value,
                condition="Anti-replay sliding window trailing edge check",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.RUNTIME.value,
                status=RuleStatus.PASS,
                severity=Severity.INFORMATIONAL,
                reason="All packets fell within the valid sliding window bounds.",
                observed_value=f"Window size {self.default_window_size}",
                expected_requirement="Packets within valid sliding window",
                spec_source=SpecSourceType.PUBLISHED_RFC.value,
            ))

        return results

    def _eval_seq_rollover(
        self, packets: list[dict[str, Any]], esn_enabled: bool
    ) -> list[RuleEvaluationResult]:
        results = []
        max_32_bit = 0xFFFFFFFF
        warning_threshold = max_32_bit - 100000

        seqs = [p.get("seq_num") for p in packets if p.get("seq_num") is not None]
        if not seqs:
            return results

        max_seq = max(seqs)

        if not esn_enabled:
            if max_seq >= max_32_bit:
                results.append(RuleEvaluationResult(
                    rule_id="ESP-SEQ-ROLLOVER-001",
                    rfc="RFC 4303",
                    section="§3.3.3",
                    category=RuleCategory.CAT10_ANTI_REPLAY.value,
                    condition="32-bit sequence number counter rollover check",
                    requirement_level=RequirementLevel.MUST_NOT.value,
                    applicable_context=ApplicableContext.RUNTIME.value,
                    status=RuleStatus.FAIL,
                    severity=Severity.CRITICAL,
                    reason=(
                        f"Sequence number reached or exceeded 32-bit maximum (seq={max_seq} >= {max_32_bit}) "
                        "without rekeying. Rollover through zero is strictly prohibited!"
                    ),
                    observed_value=f"seq={max_seq}",
                    expected_requirement="MUST NOT wrap past 2^32 - 1 without rekeying",
                    spec_source=SpecSourceType.PUBLISHED_RFC.value,
                ))
            elif max_seq >= warning_threshold:
                results.append(RuleEvaluationResult(
                    rule_id="ESP-SEQ-ROLLOVER-001",
                    rfc="RFC 4303",
                    section="§3.3.3",
                    category=RuleCategory.CAT10_ANTI_REPLAY.value,
                    condition="32-bit sequence number counter exhaustion warning",
                    requirement_level=RequirementLevel.SHOULD.value,
                    applicable_context=ApplicableContext.RUNTIME.value,
                    status=RuleStatus.WARNING,
                    severity=Severity.HIGH,
                    reason=(
                        f"Sequence number {max_seq} is within 100,000 packets of 32-bit exhaustion. "
                        "Immediate SA rekeying is required."
                    ),
                    observed_value=f"seq={max_seq}",
                    expected_requirement="Rekey before 2^32 - 1 is reached",
                    spec_source=SpecSourceType.PUBLISHED_RFC.value,
                ))
            else:
                results.append(RuleEvaluationResult(
                    rule_id="ESP-SEQ-ROLLOVER-001",
                    rfc="RFC 4303",
                    section="§3.3.3",
                    category=RuleCategory.CAT10_ANTI_REPLAY.value,
                    condition="32-bit sequence number counter rollover check",
                    requirement_level=RequirementLevel.MUST.value,
                    applicable_context=ApplicableContext.RUNTIME.value,
                    status=RuleStatus.PASS,
                    severity=Severity.INFORMATIONAL,
                    reason="Sequence number is well within 32-bit bounds without rollover.",
                    observed_value=f"Max seq={max_seq}",
                    expected_requirement="seq < 2^32 - 1",
                    spec_source=SpecSourceType.PUBLISHED_RFC.value,
                ))
        else:
            results.append(RuleEvaluationResult(
                rule_id="ESP-SEQ-ROLLOVER-001",
                rfc="RFC 4304",
                section="§2",
                category=RuleCategory.CAT10_ANTI_REPLAY.value,
                condition="64-bit Extended Sequence Number (ESN) active",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.RUNTIME.value,
                status=RuleStatus.PASS,
                severity=Severity.INFORMATIONAL,
                reason="ESN is enabled; 64-bit sequence space prevents 32-bit rollover.",
                observed_value=f"ESN active, max wire seq={max_seq}",
                expected_requirement="64-bit sequence space",
                spec_source=SpecSourceType.PUBLISHED_RFC.value,
            ))

        return results

    def _eval_esp_encapsulation(
        self, dp: dict[str, Any], packets: list[dict[str, Any]]
    ) -> list[RuleEvaluationResult]:
        results = []
        is_natt = dp.get("is_natt", False)
        src_port = dp.get("src_port")
        dst_port = dp.get("dst_port")

        if is_natt:
            if src_port == 4500 or dst_port == 4500:
                results.append(RuleEvaluationResult(
                    rule_id="ESP-NATT-PORT-001",
                    rfc="RFC 3948",
                    section="§2.1",
                    category=RuleCategory.CAT8_ESP_IPSEC.value,
                    condition="NAT-T UDP encapsulation port mapping",
                    requirement_level=RequirementLevel.MUST.value,
                    applicable_context=ApplicableContext.RUNTIME.value,
                    status=RuleStatus.PASS,
                    severity=Severity.INFORMATIONAL,
                    reason="NAT-T encapsulated ESP utilizes port 4500.",
                    observed_value=f"UDP 4500 (src={src_port}, dst={dst_port})",
                    expected_requirement="UDP port 4500",
                ))
            else:
                results.append(RuleEvaluationResult(
                    rule_id="ESP-NATT-PORT-001",
                    rfc="RFC 3948",
                    section="§2.1",
                    category=RuleCategory.CAT8_ESP_IPSEC.value,
                    condition="NAT-T UDP encapsulation port mapping",
                    requirement_level=RequirementLevel.SHOULD.value,
                    applicable_context=ApplicableContext.RUNTIME.value,
                    status=RuleStatus.WARNING,
                    severity=Severity.MEDIUM,
                    reason="NAT-T indicated but neither source nor destination port is 4500.",
                    observed_value=f"src={src_port}, dst={dst_port}",
                    expected_requirement="UDP port 4500",
                ))
        else:
            results.append(RuleEvaluationResult(
                rule_id="ESP-NATIVE-PROTO-001",
                rfc="RFC 4303",
                section="§2",
                category=RuleCategory.CAT8_ESP_IPSEC.value,
                condition="Native ESP protocol encapsulation",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.RUNTIME.value,
                status=RuleStatus.PASS,
                severity=Severity.INFORMATIONAL,
                reason="Native ESP (IP protocol 50) encapsulation verified.",
                observed_value="Native ESP (Protocol 50)",
                expected_requirement="IP Protocol 50",
            ))

        return results

    def _eval_spd_policy(
        self,
        dp: dict[str, Any],
        packets: list[dict[str, Any]],
        child_sa_context: dict[str, Any] | None,
    ) -> list[RuleEvaluationResult]:
        results = []

        has_inner_headers = any("inner_src_ip" in p or "inner_dst_ip" in p for p in packets)

        if not has_inner_headers:
            results.append(RuleEvaluationResult(
                rule_id="SPD-POLICY-TS-MAPPING-001",
                rfc="RFC 4301",
                section="§4.4.1",
                category=RuleCategory.CAT12_SPD_POLICY.value,
                condition="Traffic Selector matching against cleartext inner packet headers",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.RUNTIME.value,
                status=RuleStatus.NOT_VERIFIABLE,
                severity=Severity.LOW,
                reason=(
                    "Encrypted ESP inner payload headers cannot be inspected from passive telemetry "
                    "without SA key material. SPD selector mapping is NOT_VERIFIABLE."
                ),
                observed_value="Encrypted payload (inner headers unavailable)",
                expected_requirement="Inner header inspection against negotiated TS",
            ))
            return results

        ts_data = (child_sa_context or {}).get("traffic_selectors", {})
        tsi = ts_data.get("initiator", [])
        tsr = ts_data.get("responder", [])

        if not tsi and not tsr:
            results.append(RuleEvaluationResult(
                rule_id="SPD-POLICY-TS-MAPPING-001",
                rfc="RFC 4301",
                section="§4.4.1",
                category=RuleCategory.CAT12_SPD_POLICY.value,
                condition="Traffic Selector bounds verification",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.RUNTIME.value,
                status=RuleStatus.NOT_VERIFIABLE,
                severity=Severity.LOW,
                reason="Inner headers present but negotiated Traffic Selectors were not supplied.",
                observed_value="TS missing in context",
                expected_requirement="Negotiated TS",
            ))
            return results

        violations = []
        for p in packets:
            inner_src = p.get("inner_src_ip")
            inner_dst = p.get("inner_dst_ip")
            if inner_src and inner_dst:
                if not self._match_traffic_selectors(inner_src, inner_dst, tsi, tsr):
                    violations.append((inner_src, inner_dst))

        if violations:
            results.append(RuleEvaluationResult(
                rule_id="SPD-POLICY-TS-MAPPING-001",
                rfc="RFC 4301",
                section="§4.4.1",
                category=RuleCategory.CAT12_SPD_POLICY.value,
                condition="Traffic Selector matching against cleartext inner headers",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.RUNTIME.value,
                status=RuleStatus.FAIL,
                severity=Severity.CRITICAL,
                reason=f"Observed {len(violations)} inner packet(s) violating negotiated TS bounds: {violations[:3]}...",
                observed_value=f"{len(violations)} violations",
                expected_requirement="All traffic MUST match negotiated TS",
            ))
        else:
            results.append(RuleEvaluationResult(
                rule_id="SPD-POLICY-TS-MAPPING-001",
                rfc="RFC 4301",
                section="§4.4.1",
                category=RuleCategory.CAT12_SPD_POLICY.value,
                condition="Traffic Selector matching against cleartext inner headers",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.RUNTIME.value,
                status=RuleStatus.PASS,
                severity=Severity.INFORMATIONAL,
                reason="All inspected inner packets match negotiated Traffic Selector bounds.",
                observed_value="All packets within TS",
                expected_requirement="Traffic matching TS",
            ))

        return results

    def _not_verifiable_boundary(self, reason: str) -> list[RuleEvaluationResult]:
        return [
            RuleEvaluationResult(
                rule_id="ESP-RUNTIME-TELEMETRY-001",
                rfc="RFC 4303",
                section="§3.3",
                category=RuleCategory.CAT8_ESP_IPSEC.value,
                condition="ESP runtime telemetry ingestion",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.RUNTIME.value,
                status=RuleStatus.NOT_VERIFIABLE,
                severity=Severity.LOW,
                reason=reason,
                observed_value="None",
                expected_requirement="Observed data-plane ESP packets",
            ),
            RuleEvaluationResult(
                rule_id="ESP-ANTI-REPLAY-001",
                rfc="RFC 4303",
                section="§3.4.3",
                category=RuleCategory.CAT10_ANTI_REPLAY.value,
                condition="Anti-replay sliding window simulation",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.RUNTIME.value,
                status=RuleStatus.NOT_VERIFIABLE,
                severity=Severity.LOW,
                reason=reason,
                observed_value="None",
                expected_requirement="Observed sequence numbers",
            ),
            RuleEvaluationResult(
                rule_id="SPD-POLICY-TS-MAPPING-001",
                rfc="RFC 4301",
                section="§4.4.1",
                category=RuleCategory.CAT12_SPD_POLICY.value,
                condition="Security Policy Database (SPD) verification",
                requirement_level=RequirementLevel.MUST.value,
                applicable_context=ApplicableContext.RUNTIME.value,
                status=RuleStatus.NOT_VERIFIABLE,
                severity=Severity.LOW,
                reason=reason,
                observed_value="None",
                expected_requirement="Observed traffic vs negotiated SPD/TS",
            ),
        ]

    def _resolve_esn_status(
        self, dp: dict[str, Any], child_sa_context: dict[str, Any] | None
    ) -> bool:
        if "esn" in dp:
            return bool(dp["esn"])

        if child_sa_context:
            proposals = child_sa_context.get("proposals", [])
            for p in proposals:
                esn_tx = p.get("transforms", {}).get("extended_sequence_numbers", [])
                for e in esn_tx:
                    if e.get("id") == 1:
                        return True

        return False

    def _match_traffic_selectors(
        self, inner_src: str, inner_dst: str, tsi: list[dict], tsr: list[dict]
    ) -> bool:
        try:
            src_ip = ipaddress.ip_address(inner_src)
            dst_ip = ipaddress.ip_address(inner_dst)
        except ValueError:
            return False

        src_matched = not tsi
        for sel in tsi:
            start_addr = sel.get("start_address")
            end_addr = sel.get("end_address")
            if start_addr and end_addr:
                if (
                    ipaddress.ip_address(start_addr)
                    <= src_ip
                    <= ipaddress.ip_address(end_addr)
                ):
                    src_matched = True
                    break

        dst_matched = not tsr
        for sel in tsr:
            start_addr = sel.get("start_address")
            end_addr = sel.get("end_address")
            if start_addr and end_addr:
                if (
                    ipaddress.ip_address(start_addr)
                    <= dst_ip
                    <= ipaddress.ip_address(end_addr)
                ):
                    dst_matched = True
                    break

        return src_matched and dst_matched
