"""Unit tests for PCAP and PCAPNG reading in person2_engine.src.pcap_reader."""

from pathlib import Path
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from person2_engine.src.pcap_reader import extract_packet_metadata, safe_read_packets


def test_safe_read_valid_pcap(valid_basic_pcap: Path):
    """Verify safe streaming read on a valid PCAP file."""
    packets = list(safe_read_packets(valid_basic_pcap))
    assert len(packets) == 5
    # Indexes are 1-based
    assert packets[0][0] == 1
    assert packets[4][0] == 5


def test_safe_read_valid_pcapng(valid_pcapng: Path):
    """Verify safe streaming read on a valid PCAPNG file."""
    packets = list(safe_read_packets(valid_pcapng))
    assert len(packets) == 2
    assert packets[0][0] == 1
    assert packets[1][0] == 2


def test_safe_read_corrupted_file(corrupted_pcap: Path):
    """Verify that reading a corrupted file does not raise an unhandled exception."""
    packets = list(safe_read_packets(corrupted_pcap))
    # May return empty list or fail cleanly without crashing
    assert isinstance(packets, list)


def test_extract_metadata_ipv4_tcp():
    """Verify packet metadata extraction on IPv4 TCP packet."""
    pkt = Ether() / IP(src="192.168.1.100", dst="10.0.0.1") / TCP(sport=50000, dport=443)
    meta = extract_packet_metadata(pkt, 1)

    assert meta.packet_index == 1
    assert meta.src_ip == "192.168.1.100"
    assert meta.dst_ip == "10.0.0.1"
    assert meta.ip_version == 4
    assert meta.transport_protocol == "TCP"
    assert meta.src_port == 50000
    assert meta.dst_port == 443
    assert "Ethernet" in meta.protocols
    assert "IPv4" in meta.protocols
    assert "TCP" in meta.protocols


def test_extract_metadata_non_ip():
    """Verify safe metadata extraction on non-IP frame (pure Ethernet)."""
    pkt = Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff")
    meta = extract_packet_metadata(pkt, 2)

    assert meta.packet_index == 2
    assert meta.src_ip is None
    assert meta.dst_ip is None
    assert meta.ip_version is None
    assert meta.src_port is None
    assert meta.dst_port is None
    assert "Ethernet" in meta.protocols
