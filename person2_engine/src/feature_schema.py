"""Central, versioned feature schema definition for Phase 2.

Defines the stable contract for flow-level numerical features required by
future machine learning training and inference pipelines.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

FEATURE_SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class FeatureDefinition:
    """Definition and metadata for an individual flow feature."""

    name: str
    dtype: type
    default_value: float
    description: str
    min_value: Optional[float] = 0.0
    max_value: Optional[float] = None


FEATURE_DEFINITIONS: List[FeatureDefinition] = [
    # 1. Flow Size Features
    FeatureDefinition(
        name="total_packets",
        dtype=float,
        default_value=0.0,
        min_value=0.0,
        description="Total number of packets observed in the bidirectional flow.",
    ),
    FeatureDefinition(
        name="forward_packets",
        dtype=float,
        default_value=0.0,
        min_value=0.0,
        description="Number of packets traveling in the initial (forward) direction.",
    ),
    FeatureDefinition(
        name="backward_packets",
        dtype=float,
        default_value=0.0,
        min_value=0.0,
        description="Number of packets traveling in the reverse (backward) direction.",
    ),
    FeatureDefinition(
        name="total_bytes",
        dtype=float,
        default_value=0.0,
        min_value=0.0,
        description="Total wire bytes transferred across both directions in the flow.",
    ),
    FeatureDefinition(
        name="forward_bytes",
        dtype=float,
        default_value=0.0,
        min_value=0.0,
        description="Total wire bytes transferred in the forward direction.",
    ),
    FeatureDefinition(
        name="backward_bytes",
        dtype=float,
        default_value=0.0,
        min_value=0.0,
        description="Total wire bytes transferred in the backward direction.",
    ),
    # 2. Packet Size Features
    FeatureDefinition(
        name="minimum_packet_size",
        dtype=float,
        default_value=0.0,
        min_value=0.0,
        description="Smallest packet size (in bytes) observed in the flow.",
    ),
    FeatureDefinition(
        name="maximum_packet_size",
        dtype=float,
        default_value=0.0,
        min_value=0.0,
        description="Largest packet size (in bytes) observed in the flow.",
    ),
    FeatureDefinition(
        name="mean_packet_size",
        dtype=float,
        default_value=0.0,
        min_value=0.0,
        description="Arithmetic mean of packet sizes across the flow.",
    ),
    FeatureDefinition(
        name="standard_deviation_packet_size",
        dtype=float,
        default_value=0.0,
        min_value=0.0,
        description="Sample standard deviation of packet sizes (0.0 if fewer than 2 packets).",
    ),
    FeatureDefinition(
        name="median_packet_size",
        dtype=float,
        default_value=0.0,
        min_value=0.0,
        description="Median packet size across the flow.",
    ),
    # 3. Directional Packet Size Features
    FeatureDefinition(
        name="forward_mean_packet_size",
        dtype=float,
        default_value=0.0,
        min_value=0.0,
        description="Arithmetic mean of packet sizes in the forward direction.",
    ),
    FeatureDefinition(
        name="backward_mean_packet_size",
        dtype=float,
        default_value=0.0,
        min_value=0.0,
        description="Arithmetic mean of packet sizes in the backward direction (0.0 if no backward packets).",
    ),
    # 4. Flow Time Features
    FeatureDefinition(
        name="flow_duration_seconds",
        dtype=float,
        default_value=0.0,
        min_value=0.0,
        description="Elapsed duration between first and last packet in seconds (0.0 for 1-packet flows).",
    ),
    FeatureDefinition(
        name="packets_per_second",
        dtype=float,
        default_value=0.0,
        min_value=0.0,
        description="Average packet rate in packets/sec (0.0 if duration is 0).",
    ),
    FeatureDefinition(
        name="bytes_per_second",
        dtype=float,
        default_value=0.0,
        min_value=0.0,
        description="Average byte rate in bytes/sec (0.0 if duration is 0).",
    ),
    # 5. Inter-Arrival Time Features
    FeatureDefinition(
        name="mean_inter_arrival_time",
        dtype=float,
        default_value=0.0,
        min_value=0.0,
        description="Arithmetic mean of consecutive packet inter-arrival times in seconds.",
    ),
    FeatureDefinition(
        name="minimum_inter_arrival_time",
        dtype=float,
        default_value=0.0,
        min_value=0.0,
        description="Minimum consecutive packet inter-arrival time in seconds.",
    ),
    FeatureDefinition(
        name="maximum_inter_arrival_time",
        dtype=float,
        default_value=0.0,
        min_value=0.0,
        description="Maximum consecutive packet inter-arrival time in seconds.",
    ),
    FeatureDefinition(
        name="standard_deviation_inter_arrival_time",
        dtype=float,
        default_value=0.0,
        min_value=0.0,
        description="Sample standard deviation of inter-arrival times (0.0 if fewer than 3 packets).",
    ),
    # 6. Directional Ratio Features
    FeatureDefinition(
        name="forward_packet_ratio",
        dtype=float,
        default_value=1.0,
        min_value=0.0,
        max_value=1.0,
        description="Ratio of forward packets to total packets (forward_packets / total_packets).",
    ),
    FeatureDefinition(
        name="backward_packet_ratio",
        dtype=float,
        default_value=0.0,
        min_value=0.0,
        max_value=1.0,
        description="Ratio of backward packets to total packets (backward_packets / total_packets).",
    ),
    FeatureDefinition(
        name="forward_byte_ratio",
        dtype=float,
        default_value=1.0,
        min_value=0.0,
        max_value=1.0,
        description="Ratio of forward bytes to total bytes (forward_bytes / total_bytes).",
    ),
    FeatureDefinition(
        name="backward_byte_ratio",
        dtype=float,
        default_value=0.0,
        min_value=0.0,
        max_value=1.0,
        description="Ratio of backward bytes to total bytes (backward_bytes / total_bytes).",
    ),
    # 7. Burst / Temporal Features
    FeatureDefinition(
        name="maximum_packets_in_one_second",
        dtype=float,
        default_value=1.0,
        min_value=0.0,
        description="Maximum number of packets arriving within any 1.0-second sliding window.",
    ),
]

# Exact deterministic feature order
FEATURE_ORDER: List[str] = [fd.name for fd in FEATURE_DEFINITIONS]

# Quick lookup map
FEATURE_MAP: Dict[str, FeatureDefinition] = {fd.name: fd for fd in FEATURE_DEFINITIONS}
