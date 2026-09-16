"""Unit tests for bidirectional flow building in person2_engine.src.flow_builder."""

from person2_engine.src.flow_builder import FlowBuilder
from person2_engine.src.flow_models import FlowKey
from person2_engine.src.models import PacketMetadata


def test_tcp_forward_and_reverse_same_flow():
    """Verify forward and reverse TCP packets between two endpoints map to one flow."""
    builder = FlowBuilder()

    p1 = PacketMetadata(
        packet_index=1,
        timestamp=100.0,
        length=64,
        src_ip="192.168.1.10",
        dst_ip="10.0.0.1",
        src_port=54321,
        dst_port=80,
        ip_version=4,
        transport_protocol="TCP",
        protocols=["Ethernet", "IPv4", "TCP"],
    )
    p2 = PacketMetadata(
        packet_index=2,
        timestamp=100.1,
        length=128,
        src_ip="10.0.0.1",
        dst_ip="192.168.1.10",
        src_port=80,
        dst_port=54321,
        ip_version=4,
        transport_protocol="TCP",
        protocols=["Ethernet", "IPv4", "TCP"],
    )

    builder.process_packets([p1, p2])
    flows, summary = builder.build_flow_results()

    assert len(flows) == 1
    assert summary.total_flows == 1
    assert summary.valid_flows == 1

    flow = flows[0]
    assert flow.features["total_packets"] == 2.0
    assert flow.features["forward_packets"] == 1.0
    assert flow.features["backward_packets"] == 1.0
    assert flow.features["total_bytes"] == 192.0
    assert flow.features["forward_bytes"] == 64.0
    assert flow.features["backward_bytes"] == 128.0


def test_different_ports_create_different_flows():
    """Verify packets with different ports map to distinct flows."""
    builder = FlowBuilder()

    p1 = PacketMetadata(
        packet_index=1,
        timestamp=10.0,
        length=60,
        src_ip="192.168.1.5",
        dst_ip="8.8.8.8",
        src_port=10001,
        dst_port=53,
        ip_version=4,
        transport_protocol="UDP",
        protocols=["Ethernet", "IPv4", "UDP"],
    )
    p2 = PacketMetadata(
        packet_index=2,
        timestamp=10.1,
        length=60,
        src_ip="192.168.1.5",
        dst_ip="8.8.8.8",
        src_port=10002,  # Different source port
        dst_port=53,
        ip_version=4,
        transport_protocol="UDP",
        protocols=["Ethernet", "IPv4", "UDP"],
    )

    builder.process_packets([p1, p2])
    flows, summary = builder.build_flow_results()

    assert len(flows) == 2
    assert summary.total_flows == 2


def test_different_protocols_create_different_flows():
    """Verify packets with identical IPs/ports but different protocols create different flows."""
    builder = FlowBuilder()

    p_tcp = PacketMetadata(
        packet_index=1,
        timestamp=1.0,
        length=50,
        src_ip="1.1.1.1",
        dst_ip="2.2.2.2",
        src_port=80,
        dst_port=80,
        ip_version=4,
        transport_protocol="TCP",
        protocols=["Ethernet", "IPv4", "TCP"],
    )
    p_udp = PacketMetadata(
        packet_index=2,
        timestamp=1.1,
        length=50,
        src_ip="1.1.1.1",
        dst_ip="2.2.2.2",
        src_port=80,
        dst_port=80,
        ip_version=4,
        transport_protocol="UDP",
        protocols=["Ethernet", "IPv4", "UDP"],
    )

    builder.process_packets([p_tcp, p_udp])
    flows, summary = builder.build_flow_results()

    assert len(flows) == 2
    protocols = {f.flow_metadata.protocol for f in flows}
    assert protocols == {"TCP", "UDP"}


def test_ipv6_flows():
    """Verify IPv6 traffic builds flows properly."""
    builder = FlowBuilder()

    p1 = PacketMetadata(
        packet_index=1,
        timestamp=5.0,
        length=100,
        src_ip="2001:db8::1",
        dst_ip="2001:db8::2",
        src_port=44300,
        dst_port=443,
        ip_version=6,
        transport_protocol="TCP",
        protocols=["Ethernet", "IPv6", "TCP"],
    )
    p2 = PacketMetadata(
        packet_index=2,
        timestamp=5.2,
        length=200,
        src_ip="2001:db8::2",
        dst_ip="2001:db8::1",
        src_port=443,
        dst_port=44300,
        ip_version=6,
        transport_protocol="TCP",
        protocols=["Ethernet", "IPv6", "TCP"],
    )

    builder.process_packets([p1, p2])
    flows, summary = builder.build_flow_results()

    assert len(flows) == 1
    assert flows[0].flow_metadata.ip_version == 6
    assert flows[0].features["total_packets"] == 2.0


def test_esp_flows_without_ports():
    """Verify ESP flows group by IP endpoints without requiring transport ports."""
    builder = FlowBuilder()

    p1 = PacketMetadata(
        packet_index=1,
        timestamp=100.0,
        length=140,
        src_ip="10.10.10.1",
        dst_ip="10.10.10.2",
        src_port=None,
        dst_port=None,
        ip_version=4,
        transport_protocol="ESP",
        protocols=["Ethernet", "IPv4", "ESP"],
    )
    p2 = PacketMetadata(
        packet_index=2,
        timestamp=100.5,
        length=140,
        src_ip="10.10.10.2",
        dst_ip="10.10.10.1",
        src_port=None,
        dst_port=None,
        ip_version=4,
        transport_protocol="ESP",
        protocols=["Ethernet", "IPv4", "ESP"],
    )

    builder.process_packets([p1, p2])
    flows, summary = builder.build_flow_results()

    assert len(flows) == 1
    flow = flows[0]
    assert flow.flow_metadata.protocol == "ESP"
    assert flow.ipsec_metadata.is_ipsec_related is True
    assert flow.ipsec_metadata.esp_detected is True
    assert flow.features["total_packets"] == 2.0
    assert flow.features["forward_packets"] == 1.0
    assert flow.features["backward_packets"] == 1.0


def test_ah_flows():
    """Verify AH flows group by IP endpoints."""
    builder = FlowBuilder()

    p1 = PacketMetadata(
        packet_index=1,
        timestamp=20.0,
        length=90,
        src_ip="172.16.0.1",
        dst_ip="172.16.0.2",
        src_port=None,
        dst_port=None,
        ip_version=4,
        transport_protocol="AH",
        protocols=["Ethernet", "IPv4", "AH"],
    )

    builder.process_packet(p1)
    flows, summary = builder.build_flow_results()

    assert len(flows) == 1
    assert flows[0].ipsec_metadata.ah_detected is True
    assert flows[0].ipsec_metadata.is_ipsec_related is True


def test_single_packet_flow():
    """Verify single-packet flow construction."""
    builder = FlowBuilder()

    p = PacketMetadata(
        packet_index=1,
        timestamp=10.0,
        length=50,
        src_ip="192.168.0.1",
        dst_ip="192.168.0.2",
        src_port=1234,
        dst_port=80,
        ip_version=4,
        transport_protocol="TCP",
        protocols=["Ethernet", "IPv4", "TCP"],
    )
    builder.process_packet(p)
    flows, summary = builder.build_flow_results()

    assert len(flows) == 1
    assert flows[0].features["total_packets"] == 1.0
    assert flows[0].features["forward_packets"] == 1.0
    assert flows[0].features["backward_packets"] == 0.0
    assert flows[0].features["flow_duration_seconds"] == 0.0


def test_packets_without_ip_handled_safely():
    """Verify packets without IP addresses (e.g. pure Ethernet/ARP) do not crash."""
    builder = FlowBuilder()

    p = PacketMetadata(
        packet_index=1,
        timestamp=10.0,
        length=42,
        src_ip=None,
        dst_ip=None,
        src_port=None,
        dst_port=None,
        ip_version=None,
        transport_protocol=None,
        protocols=["Ethernet"],
    )
    builder.process_packet(p)
    flows, summary = builder.build_flow_results()

    assert len(flows) == 1
    assert flows[0].validation.valid is True
