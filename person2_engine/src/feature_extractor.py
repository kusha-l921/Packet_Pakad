"""Feature extraction engine computing flow-level statistical metrics.

Calculates the 25 fixed core features defined in feature_schema.py from
bidirectional flow packets and serializes validated ML-ready feature vectors.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Union

from person2_engine.src.feature_schema import FEATURE_ORDER
from person2_engine.src.feature_validator import validate_ml_vector
from person2_engine.src.flow_models import Flow, FlowResult


def extract_flow_features(flow: Flow) -> Dict[str, float]:
    """Extract all 25 statistical, temporal, and directional features from a Flow.

    Guarantees:
    - Never divides by zero.
    - Produces finite float values (no NaN, no Inf).
    - Conforms to schema defaults when flows have 0 or 1 packet.

    Args:
        flow: Flow instance with accumulated FlowPacketRecords.

    Returns:
        Dictionary mapping each feature name in FEATURE_ORDER to its float value.
    """
    total_pkts = float(len(flow.packets))
    fwd_pkts = float(flow.forward_packets)
    bwd_pkts = float(flow.backward_packets)

    total_bytes = float(flow.total_bytes)
    fwd_bytes = float(flow.forward_bytes)
    bwd_bytes = float(flow.backward_bytes)

    # Packet sizes
    all_sizes = [p.length for p in flow.packets]
    fwd_sizes = [p.length for p in flow.packets if p.direction == "FORWARD"]
    bwd_sizes = [p.length for p in flow.packets if p.direction == "BACKWARD"]

    if all_sizes:
        min_size = float(min(all_sizes))
        max_size = float(max(all_sizes))
        mean_size = float(sum(all_sizes) / len(all_sizes))
        if len(all_sizes) >= 2:
            variance = sum((x - mean_size) ** 2 for x in all_sizes) / (len(all_sizes) - 1)
            std_size = float(math.sqrt(variance))
        else:
            std_size = 0.0

        sorted_sizes = sorted(all_sizes)
        mid = len(sorted_sizes) // 2
        if len(sorted_sizes) % 2 == 1:
            med_size = float(sorted_sizes[mid])
        else:
            med_size = float((sorted_sizes[mid - 1] + sorted_sizes[mid]) / 2.0)
    else:
        min_size = 0.0
        max_size = 0.0
        mean_size = 0.0
        std_size = 0.0
        med_size = 0.0

    fwd_mean_size = float(sum(fwd_sizes) / len(fwd_sizes)) if fwd_sizes else 0.0
    bwd_mean_size = float(sum(bwd_sizes) / len(bwd_sizes)) if bwd_sizes else 0.0

    # Timestamps & flow duration
    timestamps = sorted([p.timestamp for p in flow.packets])
    if len(timestamps) >= 1:
        first_ts = timestamps[0]
        last_ts = timestamps[-1]
        duration = max(0.0, float(last_ts - first_ts))
    else:
        duration = 0.0

    # Rates
    if duration > 0.0:
        pkts_per_sec = float(total_pkts / duration)
        bytes_per_sec = float(total_bytes / duration)
    else:
        pkts_per_sec = 0.0
        bytes_per_sec = 0.0

    # Inter-arrival times (IAT)
    if len(timestamps) >= 2:
        iats = [t2 - t1 for t1, t2 in zip(timestamps[:-1], timestamps[1:])]
        mean_iat = float(sum(iats) / len(iats))
        min_iat = float(min(iats))
        max_iat = float(max(iats))
        if len(iats) >= 2:
            iat_variance = sum((x - mean_iat) ** 2 for x in iats) / (len(iats) - 1)
            std_iat = float(math.sqrt(iat_variance))
        else:
            std_iat = 0.0
    else:
        mean_iat = 0.0
        min_iat = 0.0
        max_iat = 0.0
        std_iat = 0.0

    # Directional ratios
    if total_pkts > 0.0:
        fwd_pkt_ratio = float(fwd_pkts / total_pkts)
        bwd_pkt_ratio = float(bwd_pkts / total_pkts)
    else:
        fwd_pkt_ratio = 1.0
        bwd_pkt_ratio = 0.0

    if total_bytes > 0.0:
        fwd_byte_ratio = float(fwd_bytes / total_bytes)
        bwd_byte_ratio = float(bwd_bytes / total_bytes)
    else:
        fwd_byte_ratio = 1.0
        bwd_byte_ratio = 0.0

    # Maximum packets in any 1-second sliding window
    if len(timestamps) <= 1:
        max_pkts_1s = float(len(timestamps))
    else:
        max_count = 1
        left = 0
        for right in range(len(timestamps)):
            while timestamps[right] - timestamps[left] > 1.0:
                left += 1
            cur_count = right - left + 1
            if cur_count > max_count:
                max_count = cur_count
        max_pkts_1s = float(max_count)

    return {
        "total_packets": total_pkts,
        "forward_packets": fwd_pkts,
        "backward_packets": bwd_pkts,
        "total_bytes": total_bytes,
        "forward_bytes": fwd_bytes,
        "backward_bytes": bwd_bytes,
        "minimum_packet_size": min_size,
        "maximum_packet_size": max_size,
        "mean_packet_size": round(mean_size, 4),
        "standard_deviation_packet_size": round(std_size, 4),
        "median_packet_size": med_size,
        "forward_mean_packet_size": round(fwd_mean_size, 4),
        "backward_mean_packet_size": round(bwd_mean_size, 4),
        "flow_duration_seconds": round(duration, 6),
        "packets_per_second": round(pkts_per_sec, 4),
        "bytes_per_second": round(bytes_per_sec, 4),
        "mean_inter_arrival_time": round(mean_iat, 6),
        "minimum_inter_arrival_time": round(min_iat, 6),
        "maximum_inter_arrival_time": round(max_iat, 6),
        "standard_deviation_inter_arrival_time": round(std_iat, 6),
        "forward_packet_ratio": round(fwd_pkt_ratio, 4),
        "backward_packet_ratio": round(bwd_pkt_ratio, 4),
        "forward_byte_ratio": round(fwd_byte_ratio, 4),
        "backward_byte_ratio": round(bwd_byte_ratio, 4),
        "maximum_packets_in_one_second": max_pkts_1s,
    }


def flow_features_to_vector(flow_result: Union[FlowResult, Dict[str, Any]]) -> List[float]:
    """Convert a flow's features to a deterministic, schema-ordered ML-ready float vector.

    Args:
        flow_result: Either a FlowResult instance or its dictionary representation.

    Returns:
        List of 25 float feature values in exact FEATURE_ORDER.

    Raises:
        ValueError: If vector validation fails (e.g. missing keys or non-finite values).
    """
    if isinstance(flow_result, FlowResult):
        features_dict = flow_result.features
    elif isinstance(flow_result, dict):
        features_dict = flow_result.get("features", {})
    else:
        raise TypeError(f"Expected FlowResult or dict, got {type(flow_result).__name__}")

    vector: List[float] = []
    for feat_name in FEATURE_ORDER:
        val = features_dict.get(feat_name, 0.0)
        vector.append(float(val))

    validation = validate_ml_vector(vector)
    if not validation.valid:
        raise ValueError(f"ML feature vector validation failed: {validation.errors}")

    return vector
