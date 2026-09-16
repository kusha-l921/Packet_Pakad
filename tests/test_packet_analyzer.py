"""Integration and schema contract tests for person2_engine.src.packet_analyzer and CLI."""

import json
from pathlib import Path
import subprocess
import sys

from person2_engine.src.packet_analyzer import analyze_capture


def test_schema_conformance(sample_data_dir: Path, tmp_path: Path):
    """Verify that output dictionary matches the exact Phase 1 schema contract."""
    target_pcap = sample_data_dir / "basic_traffic.pcap"
    out_json = tmp_path / "result.json"

    result = analyze_capture(target_pcap, output_json=out_json)
    data = result.to_dict()

    # Verify top-level sections
    expected_top_keys = {"capture_info", "protocol_summary", "ipsec_analysis", "packet_statistics", "status"}
    assert set(data.keys()) == expected_top_keys

    # Verify capture_info keys
    assert set(data["capture_info"].keys()) == {"file_name", "file_type", "total_packets", "readable"}
    assert data["capture_info"]["file_name"] == "basic_traffic.pcap"
    assert data["capture_info"]["file_type"] == "pcap"
    assert data["capture_info"]["total_packets"] == 5
    assert data["capture_info"]["readable"] is True

    # Verify protocol_summary keys
    assert set(data["protocol_summary"].keys()) == {
        "ethernet", "ipv4", "ipv6", "tcp", "udp", "icmp", "icmpv6", "other"
    }
    assert data["protocol_summary"]["ethernet"] == 5
    assert data["protocol_summary"]["ipv4"] == 3
    assert data["protocol_summary"]["ipv6"] == 2
    assert data["protocol_summary"]["tcp"] == 2
    assert data["protocol_summary"]["udp"] == 1
    assert data["protocol_summary"]["icmp"] == 1
    assert data["protocol_summary"]["icmpv6"] == 1

    # Verify ipsec_analysis keys
    assert set(data["ipsec_analysis"].keys()) == {
        "ipsec_detected",
        "esp_detected",
        "ah_detected",
        "ike_related_traffic_detected",
        "nat_traversal_related_traffic_detected",
        "ike_version",
    }
    assert data["ipsec_analysis"]["ipsec_detected"] is False
    assert data["ipsec_analysis"]["ike_version"] is None

    # Verify packet_statistics keys
    assert set(data["packet_statistics"].keys()) == {
        "minimum_packet_size", "maximum_packet_size", "average_packet_size"
    }
    assert data["packet_statistics"]["minimum_packet_size"] > 0
    assert data["packet_statistics"]["maximum_packet_size"] >= data["packet_statistics"]["minimum_packet_size"]

    # Verify status keys
    assert set(data["status"].keys()) == {"success", "errors", "warnings"}
    assert data["status"]["success"] is True
    assert data["status"]["errors"] == []

    # Verify written JSON file matches
    loaded = json.loads(out_json.read_text(encoding="utf-8"))
    assert loaded == data


def test_analyze_sample_ikev1(sample_data_dir: Path):
    """Verify analysis of sample IKEv1 capture."""
    pcap = sample_data_dir / "ipsec_ikev1.pcap"
    res = analyze_capture(pcap)
    assert res.status.success is True
    assert res.ipsec_analysis.ipsec_detected is True
    assert res.ipsec_analysis.ike_related_traffic_detected is True
    assert res.ipsec_analysis.ike_version == "IKEv1"
    assert res.protocol_summary.udp == 1


def test_analyze_sample_ikev2(sample_data_dir: Path):
    """Verify analysis of sample IKEv2 capture."""
    pcap = sample_data_dir / "ipsec_ikev2.pcap"
    res = analyze_capture(pcap)
    assert res.status.success is True
    assert res.ipsec_analysis.ipsec_detected is True
    assert res.ipsec_analysis.ike_related_traffic_detected is True
    assert res.ipsec_analysis.ike_version == "IKEv2"
    assert res.protocol_summary.udp == 1


def test_analyze_sample_esp(sample_data_dir: Path):
    """Verify analysis of sample ESP capture."""
    pcap = sample_data_dir / "ipsec_esp.pcap"
    res = analyze_capture(pcap)
    assert res.status.success is True
    assert res.ipsec_analysis.ipsec_detected is True
    assert res.ipsec_analysis.esp_detected is True
    assert res.protocol_summary.other == 2


def test_analyze_sample_ah(sample_data_dir: Path):
    """Verify analysis of sample AH capture."""
    pcap = sample_data_dir / "ipsec_ah.pcap"
    res = analyze_capture(pcap)
    assert res.status.success is True
    assert res.ipsec_analysis.ipsec_detected is True
    assert res.ipsec_analysis.ah_detected is True
    assert res.protocol_summary.other == 1


def test_analyze_sample_natt(sample_data_dir: Path):
    """Verify analysis of sample NAT-T capture."""
    pcap = sample_data_dir / "ipsec_natt.pcap"
    res = analyze_capture(pcap)
    assert res.status.success is True
    assert res.ipsec_analysis.ipsec_detected is True
    assert res.ipsec_analysis.nat_traversal_related_traffic_detected is True
    assert res.ipsec_analysis.ike_related_traffic_detected is True
    assert res.ipsec_analysis.esp_detected is True
    assert res.ipsec_analysis.ike_version == "IKEv2"


def test_analyze_sample_pcapng(sample_data_dir: Path):
    """Verify analysis of sample PCAPNG capture."""
    pcapng = sample_data_dir / "sample.pcapng"
    res = analyze_capture(pcapng)
    assert res.status.success is True
    assert res.capture_info.file_type == "pcapng"
    assert res.capture_info.total_packets == 8
    assert res.ipsec_analysis.ipsec_detected is True


def test_analyze_missing_file():
    """Verify analyze_capture handles missing file without raising exceptions."""
    res = analyze_capture("/tmp/non_existent_file_12345.pcap")
    assert res.status.success is False
    assert res.capture_info.readable is False
    assert len(res.status.errors) > 0
    assert "does not exist" in res.status.errors[0]


def test_analyze_empty_file(empty_pcap: Path):
    """Verify analyze_capture handles empty file without raising exceptions."""
    res = analyze_capture(empty_pcap)
    assert res.status.success is False
    assert res.capture_info.readable is False
    assert len(res.status.errors) > 0
    assert "empty" in res.status.errors[0]


def test_analyze_unsupported_file(unsupported_ext_file: Path):
    """Verify analyze_capture handles unsupported file extension without raising exceptions."""
    res = analyze_capture(unsupported_ext_file)
    assert res.status.success is False
    assert res.capture_info.readable is False
    assert len(res.status.errors) > 0
    assert "Unsupported file extension" in res.status.errors[0]


def test_cli_execution_valid(sample_data_dir: Path, tmp_path: Path):
    """Verify running main.py CLI with output flag."""
    pcap = sample_data_dir / "basic_traffic.pcap"
    out_file = tmp_path / "cli_out.json"

    proc = subprocess.run(
        [sys.executable, "main.py", str(pcap), "--output", str(out_file)],
        cwd=str(Path(__file__).parent.parent),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    assert "PHASE 1: PCAP & PACKET ANALYSIS REPORT" in proc.stdout
    assert out_file.exists()


def test_cli_execution_json_only(sample_data_dir: Path):
    """Verify running main.py with --json-only output."""
    pcap = sample_data_dir / "ipsec_ikev2.pcap"
    proc = subprocess.run(
        [sys.executable, "main.py", str(pcap), "--json-only"],
        cwd=str(Path(__file__).parent.parent),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    assert data["ipsec_analysis"]["ike_version"] == "IKEv2"


def test_cli_execution_missing_file():
    """Verify running main.py on missing file exits with non-zero code and error info."""
    proc = subprocess.run(
        [sys.executable, "main.py", "does_not_exist.pcap"],
        cwd=str(Path(__file__).parent.parent),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1
    assert "STATUS:           FAILED" in proc.stdout


def test_real_world_ikev1_certs(sample_data_dir: Path):
    """Verify analyze_capture against real-world Wireshark IKEv1 capture."""
    pcap = sample_data_dir / "real_ikev1-certs.pcap"
    if pcap.exists():
        res = analyze_capture(pcap)
        assert res.status.success is True
        assert res.capture_info.total_packets == 10
        assert res.capture_info.readable is True
        assert res.ipsec_analysis.ipsec_detected is True
        assert res.ipsec_analysis.ike_related_traffic_detected is True
        assert res.ipsec_analysis.ike_version == "IKEv1"
        assert res.protocol_summary.udp == 10
        # Check metadata extraction
        assert len(res.packets) == 10
        assert res.packets[0].src_port == 500
        assert res.packets[0].dst_port == 500


def test_real_world_ikev2_captures(sample_data_dir: Path):
    """Verify analyze_capture against real-world Wireshark IKEv2 captures."""
    pcap = sample_data_dir / "real_ikev2-decrypt-aes128ccm12.pcap"
    if pcap.exists():
        res = analyze_capture(pcap)
        assert res.status.success is True
        assert res.capture_info.total_packets == 6
        assert res.ipsec_analysis.ipsec_detected is True
        assert res.ipsec_analysis.ike_related_traffic_detected is True
        assert res.ipsec_analysis.ike_version == "IKEv2"


def test_real_world_esp_pcapng(sample_data_dir: Path):
    """Verify analyze_capture against real-world Wireshark ESP PCAPNG capture."""
    pcapng = sample_data_dir / "real_esp-bug-12671.pcapng"
    if pcapng.exists():
        res = analyze_capture(pcapng)
        assert res.status.success is True
        assert res.capture_info.file_type == "pcapng"
        assert res.capture_info.total_packets == 6
        assert res.ipsec_analysis.ipsec_detected is True
        assert res.ipsec_analysis.esp_detected is True
        assert res.ipsec_analysis.ike_version is None


def test_real_world_dns_mdns(sample_data_dir: Path):
    """Verify analyze_capture against real-world Wireshark large multi-protocol capture."""
    pcap = sample_data_dir / "real_dns-mdns.pcap"
    if pcap.exists():
        res = analyze_capture(pcap)
        assert res.status.success is True
        assert res.capture_info.total_packets == 587
        assert res.protocol_summary.ipv4 == 242
        assert res.protocol_summary.ipv6 == 335
        assert res.protocol_summary.tcp == 28
        assert res.protocol_summary.udp == 190
        assert res.ipsec_analysis.ipsec_detected is False
        assert res.ipsec_analysis.ike_version is None
