"""Bidirectional flow builder grouping packets into flows and extracting features.

Groups packets into canonical flows based on endpoints and transport protocols,
tracks forward/backward packet directions, and produces validated FlowResults.
"""

from __future__ import annotations

import logging
from typing import Dict, Iterable, List, Optional, Tuple

from person2_engine.src.feature_extractor import extract_flow_features
from person2_engine.src.feature_validator import validate_flow_features
from person2_engine.src.flow_models import (
    Flow,
    FlowKey,
    FlowMetadata,
    FlowResult,
    FlowSummary,
    IPsecFlowMetadata,
)
from person2_engine.src.models import PacketMetadata

logger = logging.getLogger(__name__)

PORT_IKE = 500
PORT_NAT_T = 4500


class FlowBuilder:
    """Aggregates packet records into bidirectional flows and coordinates feature extraction."""

    def __init__(self) -> None:
        self._flows: Dict[FlowKey, Flow] = {}

    def process_packet(self, packet: PacketMetadata) -> None:
        """Process a single PacketMetadata record into its canonical bidirectional flow.

        Args:
            packet: PacketMetadata record from Phase 1.
        """
        # Determine canonical flow key
        key = FlowKey.create(
            ip_version=packet.ip_version,
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            src_port=packet.src_port,
            dst_port=packet.dst_port,
            transport_protocol=packet.transport_protocol,
        )

        # Detect IPsec indicators on this packet
        proto = (packet.transport_protocol or "").upper()
        protocols_set = set(packet.protocols)

        is_esp = proto == "ESP" or "ESP" in protocols_set
        is_ah = proto == "AH" or "AH" in protocols_set
        is_ike = (
            packet.src_port == PORT_IKE
            or packet.dst_port == PORT_IKE
            or "ISAKMP" in protocols_set
        )
        is_natt = packet.src_port == PORT_NAT_T or packet.dst_port == PORT_NAT_T
        is_ipsec = is_esp or is_ah or is_ike or is_natt

        if key not in self._flows:
            flow = Flow(
                flow_id=key.to_flow_id(),
                flow_key=key,
                forward_src_ip=packet.src_ip,
                forward_dst_ip=packet.dst_ip,
                forward_src_port=packet.src_port,
                forward_dst_port=packet.dst_port,
                ipsec_metadata=IPsecFlowMetadata(
                    is_ipsec_related=is_ipsec,
                    esp_detected=is_esp,
                    ah_detected=is_ah,
                    ike_related=is_ike,
                    nat_t_related=is_natt,
                ),
            )
            self._flows[key] = flow
        else:
            flow = self._flows[key]
            # Accumulate IPsec flags across packets in the flow
            if is_ipsec:
                flow.ipsec_metadata.is_ipsec_related = True
            if is_esp:
                flow.ipsec_metadata.esp_detected = True
            if is_ah:
                flow.ipsec_metadata.ah_detected = True
            if is_ike:
                flow.ipsec_metadata.ike_related = True
            if is_natt:
                flow.ipsec_metadata.nat_t_related = True

        flow.add_packet(
            packet_index=packet.packet_index,
            timestamp=packet.timestamp,
            length=packet.length,
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            src_port=packet.src_port,
            dst_port=packet.dst_port,
            protocols=packet.protocols,
        )

    def process_packets(self, packets: Iterable[PacketMetadata]) -> None:
        """Process an iterable of PacketMetadata records.

        Args:
            packets: Iterable of PacketMetadata records.
        """
        for pkt in packets:
            self.process_packet(pkt)

    def build_flow_results(self) -> Tuple[List[FlowResult], FlowSummary]:
        """Extract features, validate, and assemble final FlowResults.

        Returns:
            Tuple of (sorted List of FlowResults, FlowSummary).
        """
        flow_results: List[FlowResult] = []
        valid_count = 0
        invalid_count = 0

        # Sort flows deterministically by first packet timestamp, then flow_id
        sorted_flows = sorted(
            self._flows.values(),
            key=lambda f: (
                f.packets[0].timestamp if f.packets else 0.0,
                f.flow_id,
            ),
        )

        for flow in sorted_flows:
            if not flow.packets:
                continue

            timestamps = [p.timestamp for p in flow.packets]
            first_ts = min(timestamps) if timestamps else 0.0
            last_ts = max(timestamps) if timestamps else 0.0

            endpoint_a = (
                f"{flow.flow_key.endpoint_a_ip}:{flow.flow_key.endpoint_a_port}"
                if flow.flow_key.endpoint_a_port is not None
                else str(flow.flow_key.endpoint_a_ip or "unknown")
            )
            endpoint_b = (
                f"{flow.flow_key.endpoint_b_ip}:{flow.flow_key.endpoint_b_port}"
                if flow.flow_key.endpoint_b_port is not None
                else str(flow.flow_key.endpoint_b_ip or "unknown")
            )

            metadata = FlowMetadata(
                flow_id=flow.flow_id,
                ip_version=flow.flow_key.ip_version,
                protocol=flow.flow_key.transport_protocol,
                endpoint_a=endpoint_a,
                endpoint_b=endpoint_b,
                first_timestamp=first_ts,
                last_timestamp=last_ts,
            )

            features = extract_flow_features(flow)
            validation = validate_flow_features(features)

            if validation.valid:
                valid_count += 1
            else:
                invalid_count += 1

            flow_results.append(
                FlowResult(
                    flow_metadata=metadata,
                    ipsec_metadata=flow.ipsec_metadata,
                    features=features,
                    validation=validation,
                )
            )

        summary = FlowSummary(
            total_flows=len(flow_results),
            valid_flows=valid_count,
            invalid_flows=invalid_count,
        )

        return flow_results, summary
