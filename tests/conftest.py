"""Pytest configuration and programmatic packet fixtures for Phase 1 testing."""

from pathlib import Path
import pytest
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.layers.ipsec import AH, ESP
from scapy.layers.isakmp import ISAKMP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap, wrpcapng


@pytest.fixture
def sample_data_dir() -> Path:
    """Return path to persistent sample_data directory."""
    return Path(__file__).parent.parent / "sample_data"


@pytest.fixture
def empty_pcap(tmp_path: Path) -> Path:
    """Create a 0-byte empty file with .pcap extension."""
    path = tmp_path / "empty.pcap"
    path.touch()
    return path


@pytest.fixture
def empty_pcapng(tmp_path: Path) -> Path:
    """Create a 0-byte empty file with .pcapng extension."""
    path = tmp_path / "empty.pcapng"
    path.touch()
    return path


@pytest.fixture
def corrupted_pcap(tmp_path: Path) -> Path:
    """Create a corrupted file with invalid binary header."""
    path = tmp_path / "corrupted.pcap"
    path.write_bytes(b"\x00\x01\x02\x03\x04\x05GARBAGE_PAYLOAD_NOT_A_PCAP")
    return path


@pytest.fixture
def unsupported_ext_file(tmp_path: Path) -> Path:
    """Create a file with unsupported extension."""
    path = tmp_path / "test.txt"
    path.write_text("not a capture file")
    return path


@pytest.fixture
def valid_basic_pcap(tmp_path: Path) -> Path:
    """Create a valid PCAP containing IPv4, IPv6, TCP, UDP, ICMP packets."""
    path = tmp_path / "basic.pcap"
    pkts = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80),
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=53000, dport=53) / b"dns",
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(),
        Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=44300, dport=443),
        Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / ICMPv6EchoRequest(),
    ]
    wrpcap(str(path), pkts)
    return path


@pytest.fixture
def valid_pcapng(tmp_path: Path) -> Path:
    """Create a valid PCAPNG file."""
    path = tmp_path / "test.pcapng"
    pkts = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=8080, dport=80),
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=9000, dport=9001),
    ]
    wrpcapng(str(path), pkts)
    return path


@pytest.fixture
def esp_pcap(tmp_path: Path) -> Path:
    """Create a PCAP containing ESP packets."""
    path = tmp_path / "esp.pcap"
    pkts = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2", proto=50) / ESP(spi=0x11112222, seq=1, data=b"secret"),
    ]
    wrpcap(str(path), pkts)
    return path


@pytest.fixture
def ah_pcap(tmp_path: Path) -> Path:
    """Create a PCAP containing AH packets."""
    path = tmp_path / "ah.pcap"
    pkts = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2", proto=51) / AH(spi=0x33334444, seq=1),
    ]
    wrpcap(str(path), pkts)
    return path


@pytest.fixture
def ikev1_pcap(tmp_path: Path) -> Path:
    """Create a PCAP containing UDP 500 IKEv1 packets."""
    path = tmp_path / "ikev1.pcap"
    pkts = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=500, dport=500) / ISAKMP(
            version=0x10, init_cookie=b"11112222", resp_cookie=b"33334444"
        ),
    ]
    wrpcap(str(path), pkts)
    return path


@pytest.fixture
def ikev2_pcap(tmp_path: Path) -> Path:
    """Create a PCAP containing UDP 500 IKEv2 packets."""
    path = tmp_path / "ikev2.pcap"
    pkts = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=500, dport=500) / ISAKMP(
            version=0x20, init_cookie=b"AAAABBBB", resp_cookie=b"CCCCDDDD"
        ),
    ]
    wrpcap(str(path), pkts)
    return path


@pytest.fixture
def natt_pcap(tmp_path: Path) -> Path:
    """Create a PCAP containing UDP 4500 NAT-T IKE and ESP packets."""
    path = tmp_path / "natt.pcap"
    non_esp = b"\x00\x00\x00\x00"
    ike_body = bytes(ISAKMP(version=0x20, init_cookie=b"99998888"))
    esp_spi = b"\x12\x34\x56\x78"

    pkts = [
        # Packet 1: NAT-T IKE
        Ether() / IP(src="192.168.0.2", dst="10.1.1.1") / UDP(sport=4500, dport=4500) / (non_esp + ike_body),
        # Packet 2: NAT-T ESP
        Ether() / IP(src="192.168.0.2", dst="10.1.1.1") / UDP(sport=4500, dport=4500) / (esp_spi + b"\x00\x00\x00\x01data"),
    ]
    wrpcap(str(path), pkts)
    return path


@pytest.fixture
def unknown_ike_payload_pcap(tmp_path: Path) -> Path:
    """Create a PCAP with UDP 500 traffic but non-ISAKMP undecodable payload."""
    path = tmp_path / "udp500_unknown.pcap"
    pkts = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=500, dport=500) / b"UNPARSEABLE_JUNK_PAYLOAD",
    ]
    wrpcap(str(path), pkts)
    return path
