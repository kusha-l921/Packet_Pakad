"""PCAP and PCAPNG reader module.

Safely reads packets from .pcap and .pcapng files using Scapy, extracting
standard layer metadata while preventing crashes on corrupted frames.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Generator, List, Optional, Tuple

from scapy.error import Scapy_Exception
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.ipsec import AH, ESP
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from scapy.utils import PcapNgReader, PcapReader

from person2_engine.src.models import PacketMetadata

logger = logging.getLogger(__name__)

# Standard IP protocol numbers
IP_PROTO_ICMP = 1
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17
IP_PROTO_ESP = 50
IP_PROTO_AH = 51
IP_PROTO_ICMPV6 = 58


def get_packet_reader(file_path: str | Path):
    """Instantiate the appropriate Scapy packet reader for the given capture file.

    Selects PcapNgReader for .pcapng files or Section Header Block magic bytes,
    otherwise falls back to PcapReader.

    Args:
        file_path: Absolute or relative path to the capture file.

    Returns:
        A Scapy PcapNgReader or PcapReader instance.
    """
    path = Path(file_path)
    is_pcapng = path.suffix.lower() == ".pcapng"

    # Fallback to inspecting magic number
    if not is_pcapng and path.exists() and path.stat().st_size >= 4:
        try:
            with open(path, "rb") as f:
                header = f.read(4)
                if header == b"\x0a\x0d\x0d\x0a":
                    is_pcapng = True
        except OSError:
            pass

    if is_pcapng:
        return PcapNgReader(str(path))
    return PcapReader(str(path))


def safe_read_packets(
    file_path: str | Path,
) -> Generator[Tuple[int, Packet], None, List[str]]:
    """Yield packets from a capture file safely, catching parsing errors.

    Args:
        file_path: Path to the capture file.

    Yields:
        Tuples of (packet_index: int, packet: scapy.packet.Packet), 1-indexed.

    Returns:
        List of warning/error strings encountered during stream iteration.
    """
    issues: List[str] = []
    index = 0

    try:
        reader = get_packet_reader(file_path)
    except Exception as e:
        msg = f"Failed to initialize packet reader for '{file_path}': {e}"
        logger.error(msg)
        issues.append(msg)
        return issues

    try:
        with reader as pcap_stream:
            while True:
                try:
                    pkt = pcap_stream.read_packet()
                    if pkt is None:
                        break
                    index += 1
                    yield (index, pkt)
                except EOFError:
                    break
                except (Scapy_Exception, OSError, ValueError, struct_error_types()) as e:
                    msg = f"Packet #{index + 1} read warning/corruption: {e}"
                    logger.warning(msg)
                    issues.append(msg)
                    continue
                except Exception as e:
                    msg = f"Unexpected error reading packet #{index + 1}: {e}"
                    logger.error(msg)
                    issues.append(msg)
                    break
    except Exception as e:
        msg = f"Stream error reading capture '{file_path}': {e}"
        logger.error(msg)
        issues.append(msg)

    return issues


def struct_error_types() -> tuple:
    """Return tuple of struct error types."""
    import struct
    return (struct.error,)


def extract_packet_metadata(packet: Packet, packet_index: int) -> PacketMetadata:
    """Extract standard metadata fields from a parsed Scapy packet.

    Extracts:
    - packet_index: 1-indexed count
    - timestamp: float unix timestamp
    - length: packet size in bytes
    - src_ip / dst_ip: IPv4 or IPv6 addresses
    - ip_version: 4 or 6
    - transport_protocol: "TCP", "UDP", "ICMP", "ICMPv6", "ESP", "AH", or other
    - src_port / dst_port: where transport layer is TCP/UDP

    Args:
        packet: Scapy Packet instance.
        packet_index: 1-indexed sequential packet number.

    Returns:
        Populated PacketMetadata object.
    """
    raw_time = getattr(packet, "time", None)
    timestamp = float(raw_time) if raw_time is not None else 0.0

    wirelen = getattr(packet, "wirelen", None)
    length = int(wirelen) if wirelen is not None else len(packet)

    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ip_version: Optional[int] = None
    transport_protocol: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocols: List[str] = []

    # Layer 2
    if packet.haslayer(Ether):
        protocols.append("Ethernet")

    # Layer 3
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)
        ip_version = 4
        protocols.append("IPv4")
        proto_num = getattr(ip_layer, "proto", None)
    elif packet.haslayer(IPv6):
        ip6_layer = packet[IPv6]
        src_ip = str(ip6_layer.src)
        dst_ip = str(ip6_layer.dst)
        ip_version = 6
        protocols.append("IPv6")
        proto_num = getattr(ip6_layer, "nh", None)
    else:
        proto_num = None

    # Layer 4 / Transport & Network Security
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        transport_protocol = "TCP"
        src_port = int(tcp_layer.sport)
        dst_port = int(tcp_layer.dport)
        protocols.append("TCP")
    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        transport_protocol = "UDP"
        src_port = int(udp_layer.sport)
        dst_port = int(udp_layer.dport)
        protocols.append("UDP")
    elif packet.haslayer(ICMP):
        transport_protocol = "ICMP"
        protocols.append("ICMP")
    elif packet.haslayer("ICMPv6EchoRequest") or packet.haslayer("ICMPv6EchoReply") or "ICMPv6" in packet.summary():
        transport_protocol = "ICMPv6"
        protocols.append("ICMPv6")
    elif packet.haslayer(ESP) or proto_num == IP_PROTO_ESP:
        transport_protocol = "ESP"
        protocols.append("ESP")
    elif packet.haslayer(AH) or proto_num == IP_PROTO_AH:
        transport_protocol = "AH"
        protocols.append("AH")
    elif proto_num is not None:
        if proto_num == IP_PROTO_ICMP:
            transport_protocol = "ICMP"
            protocols.append("ICMP")
        elif proto_num == IP_PROTO_ICMPV6:
            transport_protocol = "ICMPv6"
            protocols.append("ICMPv6")
        else:
            transport_protocol = f"IP_PROTO_{proto_num}"
            protocols.append(transport_protocol)

    return PacketMetadata(
        packet_index=packet_index,
        timestamp=timestamp,
        length=length,
        src_ip=src_ip,
        dst_ip=dst_ip,
        ip_version=ip_version,
        transport_protocol=transport_protocol,
        src_port=src_port,
        dst_port=dst_port,
        protocols=protocols,
    )
