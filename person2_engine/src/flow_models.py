"""Flow-level data models and representations for Phase 2.

Defines canonical bidirectional flow keys, flow metadata, IPsec flow metadata,
feature containers, validation containers, and capture-level feature summaries.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from typing import Any, Dict, List, Optional, Tuple

from person2_engine.src.models import AnalysisResult


@dataclass(frozen=True)
class FlowKey:
    """Canonical bidirectional flow key.

    Endpoints are canonicalized so that packets in forward and backward
    directions map to the identical key.
    """

    ip_version: Optional[int]
    endpoint_a_ip: Optional[str]
    endpoint_a_port: Optional[int]
    endpoint_b_ip: Optional[str]
    endpoint_b_port: Optional[int]
    transport_protocol: str

    @classmethod
    def create(
        cls,
        ip_version: Optional[int],
        src_ip: Optional[str],
        dst_ip: Optional[str],
        src_port: Optional[int],
        dst_port: Optional[int],
        transport_protocol: Optional[str],
    ) -> FlowKey:
        """Create a canonicalized bidirectional FlowKey."""
        proto = (transport_protocol or "UNKNOWN").upper()

        # Non-port protocols (ESP, AH, ICMP, ICMPv6, etc.) have None ports
        p1 = src_port if proto in {"TCP", "UDP"} else None
        p2 = dst_port if proto in {"TCP", "UDP"} else None

        ep1 = (src_ip or "", p1 if p1 is not None else -1)
        ep2 = (dst_ip or "", p2 if p2 is not None else -1)

        if ep1 <= ep2:
            a_ip, a_port = src_ip, p1
            b_ip, b_port = dst_ip, p2
        else:
            a_ip, a_port = dst_ip, p2
            b_ip, b_port = src_ip, p1

        return cls(
            ip_version=ip_version,
            endpoint_a_ip=a_ip,
            endpoint_a_port=a_port,
            endpoint_b_ip=b_ip,
            endpoint_b_port=b_port,
            transport_protocol=proto,
        )

    def to_flow_id(self) -> str:
        """Generate a stable, human-readable flow ID string."""
        port_a_str = f":{self.endpoint_a_port}" if self.endpoint_a_port is not None else ""
        port_b_str = f":{self.endpoint_b_port}" if self.endpoint_b_port is not None else ""
        return (
            f"{self.transport_protocol}_{self.endpoint_a_ip or 'any'}{port_a_str}"
            f"_{self.endpoint_b_ip or 'any'}{port_b_str}"
        )


@dataclass
class FlowPacketRecord:
    """Lightweight representation of a packet stored in a flow."""

    packet_index: int
    timestamp: float
    length: int
    direction: str  # "FORWARD" or "BACKWARD"
    protocols: List[str] = field(default_factory=list)


@dataclass
class FlowMetadata:
    """Descriptive identification metadata for a network flow."""

    flow_id: str
    ip_version: Optional[int]
    protocol: str
    endpoint_a: str
    endpoint_b: str
    first_timestamp: float
    last_timestamp: float

    def to_dict(self) -> Dict[str, Any]:
        """Convert flow metadata to dictionary."""
        return asdict(self)


@dataclass
class IPsecFlowMetadata:
    """IPsec and VPN-related indicators for a flow."""

    is_ipsec_related: bool = False
    esp_detected: bool = False
    ah_detected: bool = False
    ike_related: bool = False
    nat_t_related: bool = False
    spi: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert IPsec flow metadata to dictionary."""
        return asdict(self)


@dataclass
class FlowValidationResult:
    """Validation report for a flow's extracted features."""

    valid: bool = True
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert validation result to dictionary."""
        return asdict(self)


@dataclass
class FlowResult:
    """Complete structured output for an individual flow."""

    flow_metadata: FlowMetadata
    ipsec_metadata: IPsecFlowMetadata
    features: Dict[str, float]
    validation: FlowValidationResult

    def to_dict(self) -> Dict[str, Any]:
        """Convert flow result to dictionary."""
        return {
            "flow_metadata": self.flow_metadata.to_dict(),
            "ipsec_metadata": self.ipsec_metadata.to_dict(),
            "features": self.features,
            "validation": self.validation.to_dict(),
        }


@dataclass
class FlowSummary:
    """Aggregate counts of flows identified in a capture."""

    total_flows: int = 0
    valid_flows: int = 0
    invalid_flows: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert flow summary to dictionary."""
        return asdict(self)


@dataclass
class Flow:
    """Internal active accumulator representing a bidirectional flow during processing."""

    flow_id: str
    flow_key: FlowKey
    forward_src_ip: Optional[str]
    forward_dst_ip: Optional[str]
    forward_src_port: Optional[int]
    forward_dst_port: Optional[int]
    packets: List[FlowPacketRecord] = field(default_factory=list)
    forward_packets: int = 0
    backward_packets: int = 0
    total_bytes: int = 0
    forward_bytes: int = 0
    backward_bytes: int = 0
    ipsec_metadata: IPsecFlowMetadata = field(default_factory=IPsecFlowMetadata)

    def add_packet(
        self,
        packet_index: int,
        timestamp: float,
        length: int,
        src_ip: Optional[str],
        dst_ip: Optional[str],
        src_port: Optional[int],
        dst_port: Optional[int],
        protocols: List[str],
    ) -> str:
        """Add a packet to this flow and determine its direction.

        The first observed packet established the forward direction.
        Subsequent packets with matching src_ip and src_port are FORWARD;
        opposite packets are BACKWARD.

        Returns:
            The assigned direction ("FORWARD" or "BACKWARD").
        """
        is_forward = False
        if (
            self.forward_src_ip == src_ip
            and self.forward_dst_ip == dst_ip
            and (self.forward_src_port is None or self.forward_src_port == src_port)
        ):
            is_forward = True

        direction = "FORWARD" if is_forward else "BACKWARD"

        if direction == "FORWARD":
            self.forward_packets += 1
            self.forward_bytes += length
        else:
            self.backward_packets += 1
            self.backward_bytes += length

        self.total_bytes += length

        self.packets.append(
            FlowPacketRecord(
                packet_index=packet_index,
                timestamp=timestamp,
                length=length,
                direction=direction,
                protocols=protocols,
            )
        )
        return direction


@dataclass
class CaptureFeaturesResult:
    """Capture-level result combining Phase 1 analysis and Phase 2 flow features."""

    analysis: AnalysisResult
    feature_schema_version: str
    flow_summary: FlowSummary
    flows: List[FlowResult]

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the result to a dict adhering to the Phase 2 contract."""
        base_dict = self.analysis.to_dict(include_packets=False)
        base_dict["feature_schema_version"] = self.feature_schema_version
        base_dict["flow_summary"] = self.flow_summary.to_dict()
        base_dict["flows"] = [f.to_dict() for f in self.flows]
        return base_dict

    def to_json(self, indent: int = 2) -> str:
        """Serialize result to formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)
