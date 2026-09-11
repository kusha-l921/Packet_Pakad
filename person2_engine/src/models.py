"""Data models for Phase 1 PCAP packet analysis.

Defines typed data structures for packet-level metadata, capture statistics,
protocol counts, IPsec detection flags, and final structured analysis output.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from typing import Any, List, Optional


@dataclass
class PacketMetadata:
    """Internal per-packet metadata extracted during layer inspection."""

    packet_index: int
    timestamp: float
    length: int
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ip_version: Optional[int] = None
    transport_protocol: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocols: List[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert packet metadata to dictionary."""
        return asdict(self)


@dataclass
class CaptureInfo:
    """Metadata regarding the PCAP/PCAPNG input file."""

    file_name: str
    file_type: str
    total_packets: int = 0
    readable: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert capture info to dictionary."""
        return asdict(self)


@dataclass
class ProtocolSummary:
    """Aggregate protocol counts across the packet capture."""

    ethernet: int = 0
    ipv4: int = 0
    ipv6: int = 0
    tcp: int = 0
    udp: int = 0
    icmp: int = 0
    icmpv6: int = 0
    other: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert protocol summary to dictionary."""
        return asdict(self)


@dataclass
class IPsecAnalysis:
    """IPsec and IKE protocol detection flags and metadata."""

    ipsec_detected: bool = False
    esp_detected: bool = False
    ah_detected: bool = False
    ike_related_traffic_detected: bool = False
    nat_traversal_related_traffic_detected: bool = False
    ike_version: Optional[str] = None  # "IKEv1", "IKEv2", "Unknown", or None

    def to_dict(self) -> dict[str, Any]:
        """Convert IPsec analysis to dictionary."""
        return asdict(self)


@dataclass
class PacketStatistics:
    """Statistical summary of packet sizes within the capture."""

    minimum_packet_size: int = 0
    maximum_packet_size: int = 0
    average_packet_size: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert packet statistics to dictionary."""
        return asdict(self)


@dataclass
class ExecutionStatus:
    """Status indicators, errors, and warnings for the analysis run."""

    success: bool = True
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert execution status to dictionary."""
        return asdict(self)


@dataclass
class AnalysisResult:
    """Top-level structured machine-readable result of the capture analysis."""

    capture_info: CaptureInfo
    protocol_summary: ProtocolSummary
    ipsec_analysis: IPsecAnalysis
    packet_statistics: PacketStatistics
    status: ExecutionStatus
    # packets list kept internally for downstream flow/feature phases
    packets: List[PacketMetadata] = field(default_factory=list, repr=False)

    def to_dict(self, include_packets: bool = False) -> dict[str, Any]:
        """Serializes the result to a dict adhering to the stable schema contract."""
        data: dict[str, Any] = {
            "capture_info": self.capture_info.to_dict(),
            "protocol_summary": self.protocol_summary.to_dict(),
            "ipsec_analysis": self.ipsec_analysis.to_dict(),
            "packet_statistics": self.packet_statistics.to_dict(),
            "status": self.status.to_dict(),
        }
        if include_packets:
            data["packets"] = [p.to_dict() for p in self.packets]
        return data

    def to_json(self, indent: int = 2, include_packets: bool = False) -> str:
        """Serializes the result to a JSON formatted string."""
        return json.dumps(self.to_dict(include_packets=include_packets), indent=indent)
