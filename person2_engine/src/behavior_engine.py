"""Behavioral analysis engine operating on canonical 25 Phase 2 flow features.

Evaluates deterministic statistical properties of encrypted flows to generate
transparent, explainable behavioral observations without inspecting packet payloads
or requiring deep learning models.
"""

from __future__ import annotations

from typing import Any, Dict, List

from person2_engine.src.security_models import BehaviorProfile

# Configurable Behavioral Thresholds
THRESH_HIGH_PACKET_RATE: float = 100.0  # packets/second
THRESH_HIGH_BYTE_THROUGHPUT: float = 250_000.0  # bytes/second (~250 KB/s)
THRESH_DIRECTIONAL_ASYMMETRY: float = 0.90  # ratio in either direction
THRESH_ASYMMETRIC_VOLUME: float = 50_000.0  # bytes total for volume-backed asymmetry
THRESH_ASYMMETRIC_RATIO: float = 0.85  # ratio threshold for upload/download categorization
THRESH_HIGH_PACKET_SIZE_VARIANCE: float = 400.0  # bytes std dev
THRESH_LOW_PACKET_SIZE_VARIANCE: float = 30.0  # bytes std dev (fixed-length framing)
THRESH_MIN_PACKETS_FOR_VARIANCE: int = 10
THRESH_PERIODIC_IAT_STD: float = 0.05  # seconds std dev
THRESH_LONG_DURATION: float = 300.0  # seconds (5 minutes)
THRESH_BURSTY_MAX_DURATION: float = 2.0  # seconds
THRESH_BURSTY_MIN_RATE: float = 50.0  # packets/second
THRESH_HIGH_BURST_COUNT: int = 50  # packets in 1 second
THRESH_HIGH_BURST_FRACTION: float = 0.50  # fraction of total packets in 1 second


class BehaviorEngine:
    """Evaluates flow statistics to determine behavioral patterns and observations."""

    def __init__(
        self,
        high_packet_rate: float = THRESH_HIGH_PACKET_RATE,
        high_byte_throughput: float = THRESH_HIGH_BYTE_THROUGHPUT,
        directional_asymmetry: float = THRESH_DIRECTIONAL_ASYMMETRY,
        high_burst_count: int = THRESH_HIGH_BURST_COUNT,
        long_duration: float = THRESH_LONG_DURATION,
    ) -> None:
        self.high_packet_rate = high_packet_rate
        self.high_byte_throughput = high_byte_throughput
        self.directional_asymmetry = directional_asymmetry
        self.high_burst_count = high_burst_count
        self.long_duration = long_duration

    def analyze_flow_behavior(self, features: Dict[str, float]) -> BehaviorProfile:
        """Analyze a flow's 25 numerical features to produce a structured behavior profile.

        Args:
            features: Dictionary containing the 25 canonical Phase 2 numerical features.

        Returns:
            BehaviorProfile with traffic pattern, observations list, and metrics summary.
        """
        observations: List[str] = []

        total_packets = int(features.get("total_packets", 0))
        total_bytes = int(features.get("total_bytes", 0))
        duration = float(features.get("flow_duration_seconds", 0.0))
        pps = float(features.get("packets_per_second", 0.0))
        bps = float(features.get("bytes_per_second", 0.0))

        fwd_byte_ratio = float(features.get("forward_byte_ratio", 0.5))
        bwd_byte_ratio = float(features.get("backward_byte_ratio", 0.5))
        std_pkt_size = float(features.get("standard_deviation_packet_size", 0.0))
        mean_iat = float(features.get("mean_inter_arrival_time", 0.0))
        std_iat = float(features.get("standard_deviation_inter_arrival_time", 0.0))
        max_pkts_1s = int(features.get("maximum_packets_in_one_second", 0))

        # 1. Packet and Byte Throughput
        if pps >= self.high_packet_rate:
            observations.append("HIGH_PACKET_RATE")

        if bps >= self.high_byte_throughput:
            observations.append("HIGH_BYTE_THROUGHPUT")

        # 2. Directional Asymmetry
        if fwd_byte_ratio >= self.directional_asymmetry or bwd_byte_ratio >= self.directional_asymmetry:
            observations.append("HIGH_DIRECTIONAL_ASYMMETRY")

        if fwd_byte_ratio >= THRESH_ASYMMETRIC_RATIO and total_bytes >= THRESH_ASYMMETRIC_VOLUME:
            observations.append("ASYMMETRIC_UPLOAD_PATTERN")
        elif bwd_byte_ratio >= THRESH_ASYMMETRIC_RATIO and total_bytes >= THRESH_ASYMMETRIC_VOLUME:
            observations.append("ASYMMETRIC_DOWNLOAD_PATTERN")

        # 3. Packet Size Uniformity vs Variance
        if total_packets >= THRESH_MIN_PACKETS_FOR_VARIANCE:
            if std_pkt_size >= THRESH_HIGH_PACKET_SIZE_VARIANCE:
                observations.append("HIGH_PACKET_SIZE_VARIANCE")
            elif std_pkt_size <= THRESH_LOW_PACKET_SIZE_VARIANCE:
                observations.append("LOW_PACKET_SIZE_VARIANCE")

        # 4. Temporal and Periodicity Observations
        if total_packets >= THRESH_MIN_PACKETS_FOR_VARIANCE and mean_iat > 0.01:
            if std_iat <= THRESH_PERIODIC_IAT_STD:
                observations.append("PERIODIC_TRAFFIC_PATTERN")

        if duration >= self.long_duration:
            observations.append("LONG_DURATION_FLOW")
        elif duration <= THRESH_BURSTY_MAX_DURATION and pps >= THRESH_BURSTY_MIN_RATE and total_packets >= 6:
            observations.append("SHORT_BURSTY_FLOW")

        # 5. Burst Activity
        if max_pkts_1s >= self.high_burst_count:
            observations.append("HIGH_TRAFFIC_BURST")
        elif total_packets >= 20 and (max_pkts_1s / total_packets) >= THRESH_HIGH_BURST_FRACTION:
            observations.append("HIGH_TRAFFIC_BURST")

        # 6. Synthesize Primary Traffic Pattern Summary
        pattern = self._determine_primary_pattern(observations, total_bytes, fwd_byte_ratio, bwd_byte_ratio)

        metrics_summary = {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "duration_seconds": round(duration, 4),
            "packets_per_second": round(pps, 2),
            "bytes_per_second": round(bps, 2),
            "forward_byte_ratio": round(fwd_byte_ratio, 4),
            "backward_byte_ratio": round(bwd_byte_ratio, 4),
            "max_packets_one_second": max_pkts_1s,
        }

        return BehaviorProfile(
            traffic_pattern=pattern,
            observations=observations,
            metrics_summary=metrics_summary,
        )

    def _determine_primary_pattern(
        self,
        observations: List[str],
        total_bytes: int,
        fwd_ratio: float,
        bwd_ratio: float,
    ) -> str:
        """Classify high-level behavioral archetype from active observations."""
        if "ASYMMETRIC_UPLOAD_PATTERN" in observations:
            return "Asymmetric Outbound Transfer"
        elif "ASYMMETRIC_DOWNLOAD_PATTERN" in observations:
            return "Asymmetric Inbound Transfer"
        elif "HIGH_BYTE_THROUGHPUT" in observations and "HIGH_PACKET_RATE" in observations:
            return "High-Throughput Streaming / Bulk Transfer"
        elif "SHORT_BURSTY_FLOW" in observations or "HIGH_TRAFFIC_BURST" in observations:
            return "Short Bursty Exchange"
        elif "PERIODIC_TRAFFIC_PATTERN" in observations:
            return "Periodic Synchronized Timing"
        elif "LONG_DURATION_FLOW" in observations:
            return "Persistent Long-Lived Session"
        elif total_bytes < 2000 and ("HIGH_DIRECTIONAL_ASYMMETRY" in observations or abs(fwd_ratio - bwd_ratio) < 0.2):
            return "Low-Volume Interactive Exchange"
        else:
            return "Standard Bidirectional Traffic"
