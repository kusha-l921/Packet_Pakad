from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from FlowRecord import FlowRecord


@dataclass
class FlowVerdict:
    """Encapsulates ML prediction verdict and extracted traffic metrics for a flow window."""

    flow_key: tuple[str, str]
    verdict: Any
    trigger_type: str  # "WINDOW_STRIDE" | "IDLE_TIMEOUT"
    features: dict[str, float]
    packet_count: int
    duration_seconds: float


class FlowEngine:
    """Real-time statistical flow engine for encrypted traffic ML classification.

    Maintains per-flow sliding windows of ESP packets, extracts 25 statistical traffic features,
    and runs ML model inference when windows advance by stride or upon flow idle timeout.
    """

    def __init__(
        self,
        window_size: int = 200,
        stride: int = 25,
        idle_timeout: float = 5.0,
        min_packets: int = 10,
        verbose: bool = False,
    ) -> None:
        self.window_size = window_size
        self.stride = stride
        self.idle_timeout = idle_timeout
        self.min_packets = min_packets
        self.verbose = verbose
        self.active_flows: dict[tuple[str, str], FlowRecord] = {}

    def process_packet(
        self,
        esp_meta: dict[str, Any] | None,
        model: Any | None = None,
    ) -> list[FlowVerdict]:
        """Process a single ESP packet metadata dictionary.

        Updates the corresponding flow's sliding window and triggers ML inference
        if the window reaches stride or if any existing flows timed out.

        Returns a list of FlowVerdict instances triggered during this call.
        """
        if not esp_meta:
            return []

        src_ip = esp_meta.get("src_ip")
        dst_ip = esp_meta.get("dst_ip")
        if not src_ip or not dst_ip:
            return []

        current_time = float(esp_meta.get("timestamp", 0.0))
        flow_key = tuple(sorted([str(src_ip), str(dst_ip)]))

        if flow_key not in self.active_flows:
            self.active_flows[flow_key] = FlowRecord(
                initiator_ip=str(src_ip),
                window_size=self.window_size,
                stride=self.stride,
            )

        flow = self.active_flows[flow_key]
        verdicts: list[FlowVerdict] = []

        # 1. Check window stride trigger
        if flow.update(esp_meta):
            features = flow.extract_features()
            if features:
                pred = model.predict([list(features.values())])[0] if model is not None else None
                if self.verbose:
                    print(f"[FLOW {flow_key}] Verdict: {pred}")
                verdicts.append(
                    FlowVerdict(
                        flow_key=flow_key,
                        verdict=pred,
                        trigger_type="WINDOW_STRIDE",
                        features=features,
                        packet_count=flow.packet_count,
                        duration_seconds=features.get("flow_duration_seconds", 0.0),
                    )
                )

        # 2. Check idle timeout triggers
        expired: list[tuple[str, str]] = []
        for key, record in self.active_flows.items():
            if record.is_idle(current_time, timeout_seconds=self.idle_timeout):
                if record.packet_count >= self.min_packets:
                    features = record.extract_features()
                    if features:
                        pred = model.predict([list(features.values())])[0] if model is not None else None
                        if self.verbose:
                            print(f"[TIMEOUT TRIGGER] Inactive Flow {key} -> {pred}")
                        verdicts.append(
                            FlowVerdict(
                                flow_key=key,
                                verdict=pred,
                                trigger_type="IDLE_TIMEOUT",
                                features=features,
                                packet_count=record.packet_count,
                                duration_seconds=features.get("flow_duration_seconds", 0.0),
                            )
                        )
                record.packets_since_last_predict = 0
                expired.append(key)

        for key in expired:
            del self.active_flows[key]

        return verdicts

    def get_flow(self, flow_key: tuple[str, str]) -> FlowRecord | None:
        """Retrieve the FlowRecord for a given flow key."""
        return self.active_flows.get(flow_key)

    def reset(self, flow_key: tuple[str, str] | None = None) -> None:
        """Reset flow state for a specific flow key or all active flows."""
        if flow_key is not None:
            self.active_flows.pop(flow_key, None)
        else:
            self.active_flows.clear()


# ═══════════════════════════════════════════════════════════════════════════
#  Backward-compatible module-level API & global default instance
# ═══════════════════════════════════════════════════════════════════════════

IDLE_TIMEOUT: float = 5.0
MIN_PACKETS: int = 10
_default_engine = FlowEngine(idle_timeout=IDLE_TIMEOUT, min_packets=MIN_PACKETS, verbose=True)
active_flows = _default_engine.active_flows


def process_packet(
    model: Any,
    esp_meta: dict[str, Any] | None,
    window_size: int = 200,
    stride: int = 25,
) -> list[FlowVerdict]:
    """Backward-compatible function matching the original FlowEngine.process_packet signature."""
    _default_engine.window_size = window_size
    _default_engine.stride = stride
    return _default_engine.process_packet(esp_meta, model=model)


# ═══════════════════════════════════════════════════════════════════════════
#  Unified Live Packet Dispatcher (Optional Orchestrator)
# ═══════════════════════════════════════════════════════════════════════════

class RealtimePacketDispatcher:
    """Coordinates both RFC compliance evaluation and ML flow classification on incoming packets.

    Keeps the two internal sliding window engines cleanly separated while providing
    a single entry point for live packet captures.
    """

    def __init__(
        self,
        rfc_engine: Any | None = None,
        flow_engine: FlowEngine | None = None,
        ml_model: Any | None = None,
    ) -> None:
        from rfcRuleEngine import RfcRuleEngine

        self.rfc_engine = rfc_engine or RfcRuleEngine()
        self.flow_engine = flow_engine or FlowEngine()
        self.ml_model = ml_model

    def dispatch(
        self,
        esp_meta: dict[str, Any],
        session_dict: dict[str, Any] | None = None,
    ) -> tuple[list[Any], list[FlowVerdict]]:
        """Dispatch an ESP packet to both the RFC compliance engine and the Flow ML engine."""
        rfc_results = self.rfc_engine.process_esp_packet(esp_meta, session_dict=session_dict)
        flow_verdicts = self.flow_engine.process_packet(esp_meta, model=self.ml_model)
        return rfc_results, flow_verdicts