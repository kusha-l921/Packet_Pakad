"""Unit tests for IPsec and IKE detection in person2_engine.src.ipsec_detector."""

from pathlib import Path
from scapy.layers.inet import IP, UDP
from scapy.layers.ipsec import AH, ESP
from scapy.layers.isakmp import ISAKMP
from scapy.layers.l2 import Ether

from person2_engine.src.ipsec_detector import IPsecDetector
from person2_engine.src.packet_analyzer import analyze_capture


def test_esp_detection():
    """Verify native ESP packet detection."""
    detector = IPsecDetector()
    pkt = Ether() / IP(proto=50) / ESP(spi=0x12345678, seq=1)
    detector.process_packet(pkt)

    analysis = detector.get_analysis()
    assert analysis.ipsec_detected is True
    assert analysis.esp_detected is True
    assert analysis.ah_detected is False
    assert analysis.ike_related_traffic_detected is False
    assert analysis.nat_traversal_related_traffic_detected is False
    assert analysis.ike_version is None


def test_ah_detection():
    """Verify native AH packet detection."""
    detector = IPsecDetector()
    pkt = Ether() / IP(proto=51) / AH(spi=0x87654321, seq=1)
    detector.process_packet(pkt)

    analysis = detector.get_analysis()
    assert analysis.ipsec_detected is True
    assert analysis.esp_detected is False
    assert analysis.ah_detected is True
    assert analysis.ike_related_traffic_detected is False
    assert analysis.ike_version is None


def test_ikev1_detection():
    """Verify IKEv1 detection on UDP port 500 with ISAKMP header."""
    detector = IPsecDetector()
    pkt = Ether() / IP() / UDP(sport=500, dport=500) / ISAKMP(version=0x10, init_cookie=b"12345678")
    detector.process_packet(pkt)

    analysis = detector.get_analysis()
    assert analysis.ipsec_detected is True
    assert analysis.ike_related_traffic_detected is True
    assert analysis.ike_version == "IKEv1"
    assert analysis.esp_detected is False


def test_ikev2_detection():
    """Verify IKEv2 detection on UDP port 500 with ISAKMP header."""
    detector = IPsecDetector()
    pkt = Ether() / IP() / UDP(sport=500, dport=500) / ISAKMP(version=0x20, init_cookie=b"AAAABBBB")
    detector.process_packet(pkt)

    analysis = detector.get_analysis()
    assert analysis.ipsec_detected is True
    assert analysis.ike_related_traffic_detected is True
    assert analysis.ike_version == "IKEv2"
    assert analysis.esp_detected is False


def test_udp500_unknown_payload():
    """Verify that UDP 500 with unparseable payload is NOT guessed as a specific IKE version."""
    detector = IPsecDetector()
    pkt = Ether() / IP() / UDP(sport=500, dport=500) / b"CORRUPTED_NON_ISAKMP_PAYLOAD"
    detector.process_packet(pkt)

    analysis = detector.get_analysis()
    assert analysis.ipsec_detected is True
    assert analysis.ike_related_traffic_detected is True
    assert analysis.ike_version == "Unknown"


def test_natt_ike_detection():
    """Verify NAT-Traversal IKE detection with Non-ESP marker on UDP 4500."""
    detector = IPsecDetector()
    non_esp = b"\x00\x00\x00\x00"
    ike2_raw = bytes(ISAKMP(version=0x20, init_cookie=b"12345678"))
    pkt = Ether() / IP() / UDP(sport=4500, dport=4500) / (non_esp + ike2_raw)
    detector.process_packet(pkt)

    analysis = detector.get_analysis()
    assert analysis.ipsec_detected is True
    assert analysis.nat_traversal_related_traffic_detected is True
    assert analysis.ike_related_traffic_detected is True
    assert analysis.ike_version == "IKEv2"


def test_natt_esp_detection():
    """Verify NAT-Traversal encapsulated ESP (non-zero SPI) on UDP 4500."""
    detector = IPsecDetector()
    esp_data = b"\x12\x34\x56\x78\x00\x00\x00\x01PAYLOAD"
    pkt = Ether() / IP() / UDP(sport=4500, dport=4500) / esp_data
    detector.process_packet(pkt)

    analysis = detector.get_analysis()
    assert analysis.ipsec_detected is True
    assert analysis.nat_traversal_related_traffic_detected is True
    assert analysis.esp_detected is True


def test_non_ipsec_traffic():
    """Verify that regular non-IPsec traffic results in all False flags and null ike_version."""
    detector = IPsecDetector()
    pkt = Ether() / IP() / UDP(sport=53, dport=53) / b"DNS"
    detector.process_packet(pkt)

    analysis = detector.get_analysis()
    assert analysis.ipsec_detected is False
    assert analysis.esp_detected is False
    assert analysis.ah_detected is False
    assert analysis.ike_related_traffic_detected is False
    assert analysis.nat_traversal_related_traffic_detected is False
    assert analysis.ike_version is None


def test_analyze_capture_e2e_ipsec(esp_pcap: Path, ikev2_pcap: Path, tmp_path: Path):
    """End-to-end integration test of analyze_capture on IPsec fixtures."""
    res_esp = analyze_capture(esp_pcap)
    assert res_esp.status.success is True
    assert res_esp.ipsec_analysis.esp_detected is True
    assert res_esp.ipsec_analysis.ipsec_detected is True

    json_out = tmp_path / "out_ikev2.json"
    res_ike = analyze_capture(ikev2_pcap, output_json=json_out)
    assert res_ike.status.success is True
    assert res_ike.ipsec_analysis.ike_related_traffic_detected is True
    assert res_ike.ipsec_analysis.ike_version == "IKEv2"
    assert json_out.exists()
