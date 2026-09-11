"""IPsec and IKE protocol detection module.

Inspects packet layers for:
- ESP (IP proto 50 or Scapy ESP layer, and UDP 4500 encapsulated ESP)
- AH (IP proto 51 or Scapy AH layer)
- IKE traffic on UDP port 500
- NAT-Traversal traffic on UDP port 4500 (both encapsulated IKE and encapsulated ESP)
- Strictly decoded IKE version (IKEv1 vs IKEv2), avoiding guessing when indeterminable.
"""

from __future__ import annotations

import logging
from typing import Optional, Set

from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.ipsec import AH, ESP
from scapy.layers.isakmp import ISAKMP
from scapy.packet import Packet

from person2_engine.src.models import IPsecAnalysis

logger = logging.getLogger(__name__)

IP_PROTO_ESP = 50
IP_PROTO_AH = 51
PORT_IKE = 500
PORT_NAT_T = 4500
NON_ESP_MARKER = b"\x00\x00\x00\x00"
MIN_ISAKMP_HEADER_LEN = 28


def inspect_ike_version(isakmp_layer: ISAKMP) -> Optional[str]:
    """Extract IKE version from decoded ISAKMP layer.

    RFC 2408 / RFC 7296 define the ISAKMP version byte:
    - High 4 bits: Major version
    - Low 4 bits: Minor version

    Args:
        isakmp_layer: Decoded Scapy ISAKMP layer.

    Returns:
        "IKEv1" if major version is 1,
        "IKEv2" if major version is 2,
        "Unknown" if version cannot be cleanly mapped,
        None if no version field present.
    """
    try:
        ver = getattr(isakmp_layer, "version", None)
        if ver is None:
            return "Unknown"
        major = (int(ver) >> 4) & 0x0F
        if major == 1:
            return "IKEv1"
        elif major == 2:
            return "IKEv2"
        return "Unknown"
    except Exception as e:
        logger.debug("Failed to extract IKE version from ISAKMP layer: %s", e)
        return "Unknown"


class IPsecDetector:
    """Accumulator and detector for IPsec-related traffic across packet streams."""

    def __init__(self) -> None:
        self.esp_detected: bool = False
        self.ah_detected: bool = False
        self.ike_related_traffic_detected: bool = False
        self.nat_traversal_related_traffic_detected: bool = False
        self._observed_ike_versions: Set[str] = set()
        self._had_undecodable_ike: bool = False

    def process_packet(self, packet: Packet) -> None:
        """Inspect a single packet for ESP, AH, IKE, and NAT-T signatures.

        Args:
            packet: Scapy Packet instance.
        """
        # 1. Inspect Layer 3 protocol numbers
        proto_num = None
        if packet.haslayer(IP):
            proto_num = getattr(packet[IP], "proto", None)
        elif packet.haslayer(IPv6):
            proto_num = getattr(packet[IPv6], "nh", None)

        # 2. Check ESP (Native IP proto 50 or Scapy ESP layer)
        if proto_num == IP_PROTO_ESP or packet.haslayer(ESP):
            self.esp_detected = True

        # 3. Check AH (Native IP proto 51 or Scapy AH layer)
        if proto_num == IP_PROTO_AH or packet.haslayer(AH):
            self.ah_detected = True

        # 4. Check UDP transport for IKE (500) and NAT-T (4500)
        if packet.haslayer(UDP):
            udp_layer = packet[UDP]
            sport = int(getattr(udp_layer, "sport", 0))
            dport = int(getattr(udp_layer, "dport", 0))

            # UDP Port 500 (Standard IKE)
            if sport == PORT_IKE or dport == PORT_IKE:
                self.ike_related_traffic_detected = True
                self._inspect_udp_ike(packet, udp_layer)

            # UDP Port 4500 (IPsec NAT-Traversal)
            if sport == PORT_NAT_T or dport == PORT_NAT_T:
                self.nat_traversal_related_traffic_detected = True
                self._inspect_nat_t(packet, udp_layer)

    def _inspect_udp_ike(self, packet: Packet, udp_layer: UDP) -> None:
        """Inspect UDP 500 payload to determine if IKE version is decodable."""
        if packet.haslayer(ISAKMP):
            version_str = inspect_ike_version(packet[ISAKMP])
            if version_str in {"IKEv1", "IKEv2"}:
                self._observed_ike_versions.add(version_str)
            else:
                self._had_undecodable_ike = True
        else:
            # Attempt to decode raw payload as ISAKMP
            payload = bytes(udp_layer.payload)
            if len(payload) >= MIN_ISAKMP_HEADER_LEN:
                try:
                    decoded = ISAKMP(payload)
                    version_str = inspect_ike_version(decoded)
                    if version_str in {"IKEv1", "IKEv2"}:
                        self._observed_ike_versions.add(version_str)
                    else:
                        self._had_undecodable_ike = True
                except Exception:
                    self._had_undecodable_ike = True
            else:
                self._had_undecodable_ike = True

    def _inspect_nat_t(self, packet: Packet, udp_layer: UDP) -> None:
        """Inspect UDP 4500 payload for Non-ESP Marker (IKE) or ESP SPI."""
        payload = bytes(udp_layer.payload)
        if len(payload) >= 4:
            marker = payload[:4]
            if marker == NON_ESP_MARKER:
                # Followed by ISAKMP header (RFC 3948)
                self.ike_related_traffic_detected = True
                ike_payload = payload[4:]
                if len(ike_payload) >= MIN_ISAKMP_HEADER_LEN:
                    try:
                        decoded = ISAKMP(ike_payload)
                        version_str = inspect_ike_version(decoded)
                        if version_str in {"IKEv1", "IKEv2"}:
                            self._observed_ike_versions.add(version_str)
                        else:
                            self._had_undecodable_ike = True
                    except Exception:
                        self._had_undecodable_ike = True
                else:
                    self._had_undecodable_ike = True
            else:
                # Non-zero 4-byte marker is the SPI of encapsulated ESP
                self.esp_detected = True

    def get_analysis(self) -> IPsecAnalysis:
        """Derive aggregate IPsec analysis metrics.

        Returns:
            Populated IPsecAnalysis model.
        """
        ipsec_detected = (
            self.esp_detected
            or self.ah_detected
            or self.ike_related_traffic_detected
            or self.nat_traversal_related_traffic_detected
        )

        resolved_ike_version: Optional[str] = None
        if "IKEv1" in self._observed_ike_versions and "IKEv2" in self._observed_ike_versions:
            resolved_ike_version = "Unknown"  # Mixed/inconclusive single version
        elif "IKEv1" in self._observed_ike_versions:
            resolved_ike_version = "IKEv1"
        elif "IKEv2" in self._observed_ike_versions:
            resolved_ike_version = "IKEv2"
        elif self.ike_related_traffic_detected or self.nat_traversal_related_traffic_detected:
            # IKE or NAT-T was detected, but no valid IKEv1/IKEv2 header could be decoded
            resolved_ike_version = "Unknown"
        else:
            resolved_ike_version = None

        return IPsecAnalysis(
            ipsec_detected=ipsec_detected,
            esp_detected=self.esp_detected,
            ah_detected=self.ah_detected,
            ike_related_traffic_detected=self.ike_related_traffic_detected,
            nat_traversal_related_traffic_detected=self.nat_traversal_related_traffic_detected,
            ike_version=resolved_ike_version,
        )
