"""Unit tests for protocol detection in person2_engine.src.protocol_detector."""

from pathlib import Path
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.layers.ipsec import ESP
from scapy.layers.l2 import Ether

from person2_engine.src.protocol_detector import (
    ProtocolDetector,
    detect_protocols_in_packet,
)


def test_detect_ipv4_tcp_packet():
    """Verify protocol identification on IPv4 TCP packet."""
    pkt = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1000, dport=80)
    protos = detect_protocols_in_packet(pkt)
    assert protos == {"Ethernet", "IPv4", "TCP"}


def test_detect_ipv4_udp_packet():
    """Verify protocol identification on IPv4 UDP packet."""
    pkt = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / UDP(sport=1000, dport=53)
    protos = detect_protocols_in_packet(pkt)
    assert protos == {"Ethernet", "IPv4", "UDP"}


def test_detect_ipv4_icmp_packet():
    """Verify protocol identification on IPv4 ICMP packet."""
    pkt = Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / ICMP()
    protos = detect_protocols_in_packet(pkt)
    assert protos == {"Ethernet", "IPv4", "ICMP"}


def test_detect_ipv6_icmpv6_packet():
    """Verify protocol identification on IPv6 ICMPv6 packet."""
    pkt = Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / ICMPv6EchoRequest()
    protos = detect_protocols_in_packet(pkt)
    assert "Ethernet" in protos
    assert "IPv6" in protos
    assert "ICMPv6" in protos


def test_detect_other_protocol_esp():
    """Verify that ESP packets are detected under 'Other' protocols in basic protocol detector."""
    pkt = Ether() / IP(src="1.1.1.1", dst="2.2.2.2", proto=50) / ESP(spi=0x1234)
    protos = detect_protocols_in_packet(pkt)
    assert "IPv4" in protos
    assert "Other" in protos


def test_protocol_detector_accumulator():
    """Verify cumulative counts in ProtocolSummary."""
    detector = ProtocolDetector()

    detector.process_packet(Ether() / IP() / TCP())
    detector.process_packet(Ether() / IP() / UDP())
    detector.process_packet(Ether() / IP() / ICMP())
    detector.process_packet(Ether() / IPv6() / TCP())
    detector.process_packet(Ether() / IPv6() / ICMPv6EchoRequest())
    detector.process_packet(Ether() / IP(proto=50) / ESP())

    summary = detector.get_summary()

    assert summary.ethernet == 6
    assert summary.ipv4 == 4
    assert summary.ipv6 == 2
    assert summary.tcp == 2
    assert summary.udp == 1
    assert summary.icmp == 1
    assert summary.icmpv6 == 1
    assert summary.other == 1
