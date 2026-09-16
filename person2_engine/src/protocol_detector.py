"""Protocol detection module.

Identifies network layers (Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, Other)
per packet and computes cumulative protocol metrics for the capture.
"""

from __future__ import annotations

import logging
from typing import List, Set

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, _ICMPv6
from scapy.layers.l2 import Ether
from scapy.packet import Packet

from person2_engine.src.models import ProtocolSummary

logger = logging.getLogger(__name__)

KNOWN_L4_IP_PROTOS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    58: "ICMPv6",
}


def detect_protocols_in_packet(packet: Packet) -> Set[str]:
    """Inspect packet layers and return a set of detected protocol identifiers.

    Args:
        packet: Scapy Packet instance.

    Returns:
        Set of string protocol names, e.g. {"Ethernet", "IPv4", "TCP"}.
    """
    detected: Set[str] = set()

    if packet.haslayer(Ether):
        detected.add("Ethernet")

    is_ip = False
    proto_num = None

    if packet.haslayer(IP):
        detected.add("IPv4")
        is_ip = True
        proto_num = getattr(packet[IP], "proto", None)
    elif packet.haslayer(IPv6):
        detected.add("IPv6")
        is_ip = True
        proto_num = getattr(packet[IPv6], "nh", None)

    has_l4 = False

    if packet.haslayer(TCP):
        detected.add("TCP")
        has_l4 = True
    if packet.haslayer(UDP):
        detected.add("UDP")
        has_l4 = True
    if packet.haslayer(ICMP) or proto_num == 1:
        detected.add("ICMP")
        has_l4 = True
    if packet.haslayer(_ICMPv6) or proto_num == 58 or "ICMPv6" in packet.summary():
        detected.add("ICMPv6")
        has_l4 = True

    # Check for other protocols (e.g. ESP, AH, ARP, GRE, SCTP, etc.)
    if is_ip:
        if not has_l4 or (proto_num is not None and proto_num not in KNOWN_L4_IP_PROTOS):
            detected.add("Other")
    else:
        # Non-IP packet (e.g. pure Ethernet, ARP, STP)
        if not detected.intersection({"IPv4", "IPv6"}):
            detected.add("Other")

    return detected


class ProtocolDetector:
    """Accumulates protocol metrics across all packets in a capture."""

    def __init__(self) -> None:
        self._ethernet_count = 0
        self._ipv4_count = 0
        self._ipv6_count = 0
        self._tcp_count = 0
        self._udp_count = 0
        self._icmp_count = 0
        self._icmpv6_count = 0
        self._other_count = 0

    def process_packet(self, packet: Packet) -> List[str]:
        """Analyze a single packet and update aggregate protocol counts.

        Args:
            packet: Scapy Packet instance.

        Returns:
            Sorted list of protocol names detected in this packet.
        """
        detected = detect_protocols_in_packet(packet)

        if "Ethernet" in detected:
            self._ethernet_count += 1
        if "IPv4" in detected:
            self._ipv4_count += 1
        if "IPv6" in detected:
            self._ipv6_count += 1
        if "TCP" in detected:
            self._tcp_count += 1
        if "UDP" in detected:
            self._udp_count += 1
        if "ICMP" in detected:
            self._icmp_count += 1
        if "ICMPv6" in detected:
            self._icmpv6_count += 1
        if "Other" in detected:
            self._other_count += 1

        return sorted(list(detected))

    def get_summary(self) -> ProtocolSummary:
        """Return the cumulative ProtocolSummary object."""
        return ProtocolSummary(
            ethernet=self._ethernet_count,
            ipv4=self._ipv4_count,
            ipv6=self._ipv6_count,
            tcp=self._tcp_count,
            udp=self._udp_count,
            icmp=self._icmp_count,
            icmpv6=self._icmpv6_count,
            other=self._other_count,
        )
