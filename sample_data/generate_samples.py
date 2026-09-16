"""Utility script to generate synthetic test PCAP and PCAPNG files in sample_data/."""

from pathlib import Path
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.layers.ipsec import AH, ESP
from scapy.layers.isakmp import ISAKMP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap, wrpcapng

SAMPLE_DIR = Path(__file__).parent


def generate_all_samples():
    # 1. Basic network traffic (Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6)
    pkts_basic = [
        Ether() / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=54321, dport=80, flags="S"),
        Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=53210, dport=53) / b"DNS_QUERY",
        Ether() / IP(src="192.168.1.10", dst="1.1.1.1") / ICMP(type=8, code=0),
        Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / TCP(sport=54322, dport=443, flags="S"),
        Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2") / ICMPv6EchoRequest(),
    ]
    wrpcap(str(SAMPLE_DIR / "basic_traffic.pcap"), pkts_basic)

    # 2. IPsec IKEv1
    # Major version 1 -> 0x10
    pkts_ikev1 = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=500, dport=500) / ISAKMP(
            init_cookie=b"12345678", resp_cookie=b"\x00" * 8, next_payload=1, version=0x10, exch_type=2, flags=0
        )
    ]
    wrpcap(str(SAMPLE_DIR / "ipsec_ikev1.pcap"), pkts_ikev1)

    # 3. IPsec IKEv2
    # Major version 2 -> 0x20
    pkts_ikev2 = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=500, dport=500) / ISAKMP(
            init_cookie=b"AABBCCDD", resp_cookie=b"\x00" * 8, next_payload=33, version=0x20, exch_type=34, flags=0x08
        )
    ]
    wrpcap(str(SAMPLE_DIR / "ipsec_ikev2.pcap"), pkts_ikev2)

    # 4. Native ESP traffic (proto 50)
    pkts_esp = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2", proto=50) / ESP(spi=0x12345678, seq=1, data=b"ENCRYPTED_PAYLOAD_ESP"),
        Ether() / IP(src="10.0.0.2", dst="10.0.0.1", proto=50) / ESP(spi=0x87654321, seq=1, data=b"ENCRYPTED_PAYLOAD_ESP_RESP"),
    ]
    wrpcap(str(SAMPLE_DIR / "ipsec_esp.pcap"), pkts_esp)

    # 5. Native AH traffic (proto 51)
    pkts_ah = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2", proto=51) / AH(spi=0x12345678, seq=1),
    ]
    wrpcap(str(SAMPLE_DIR / "ipsec_ah.pcap"), pkts_ah)

    # 6. NAT-Traversal (UDP 4500)
    # Packet A: Non-ESP Marker + IKEv2 header
    # Packet B: Encapsulated ESP (non-zero SPI)
    non_esp_marker = b"\x00\x00\x00\x00"
    ikev2_header = bytes(ISAKMP(version=0x20, init_cookie=b"11223344", resp_cookie=b"55667788"))
    esp_spi = b"\xde\xad\xbe\xef"

    pkts_natt = [
        Ether() / IP(src="192.168.1.50", dst="203.0.113.1") / UDP(sport=4500, dport=4500) / (non_esp_marker + ikev2_header),
        Ether() / IP(src="192.168.1.50", dst="203.0.113.1") / UDP(sport=4500, dport=4500) / (esp_spi + b"\x00\x00\x00\x01CIPHERTEXT"),
    ]
    wrpcap(str(SAMPLE_DIR / "ipsec_natt.pcap"), pkts_natt)

    # 7. PCAPNG format
    wrpcapng(str(SAMPLE_DIR / "sample.pcapng"), pkts_basic + pkts_ikev2 + pkts_esp)

    print(f"Generated {len(list(SAMPLE_DIR.glob('*')))} sample captures in {SAMPLE_DIR}")


if __name__ == "__main__":
    generate_all_samples()
