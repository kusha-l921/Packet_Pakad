"""End-to-end integration tests for Phase 2 capture-level flow feature extraction."""

import json
from pathlib import Path
import subprocess
import sys

from person2_engine import (
    analyze_capture,
    analyze_capture_with_features,
    flow_features_to_vector,
)
from person2_engine.src.feature_schema import FEATURE_ORDER


def test_phase1_backward_compatibility(sample_data_dir: Path):
    """Verify analyze_capture() still works and produces identical Phase 1 schema."""
    pcap = sample_data_dir / "basic_traffic.pcap"
    res = analyze_capture(pcap)

    assert res.status.success is True
    assert res.capture_info.total_packets == 5
    data = res.to_dict()
    assert set(data.keys()) == {
        "capture_info",
        "protocol_summary",
        "ipsec_analysis",
        "packet_statistics",
        "status",
    }


def test_analyze_capture_with_features_schema(sample_data_dir: Path, tmp_path: Path):
    """Verify analyze_capture_with_features output dictionary matches required Phase 2 contract."""
    pcap = sample_data_dir / "basic_traffic.pcap"
    out_json = tmp_path / "flow_out.json"

    res = analyze_capture_with_features(pcap, output_json=out_json)
    data = res.to_dict()

    # Verify Phase 1 keys are intact
    assert "capture_info" in data
    assert "protocol_summary" in data
    assert "ipsec_analysis" in data
    assert "packet_statistics" in data
    assert "status" in data

    # Verify Phase 2 additions
    assert data["feature_schema_version"] == "1.0"
    assert "flow_summary" in data
    assert "flows" in data

    assert data["flow_summary"]["total_flows"] > 0
    assert data["flow_summary"]["valid_flows"] == data["flow_summary"]["total_flows"]

    # Verify flow structure
    for flow in data["flows"]:
        assert set(flow.keys()) == {"flow_metadata", "ipsec_metadata", "features", "validation"}
        assert len(flow["features"]) == 25
        assert set(flow["features"].keys()) == set(FEATURE_ORDER)
        assert flow["validation"]["valid"] is True

        # Test vector extraction
        vec = flow_features_to_vector(flow)
        assert len(vec) == 25
        assert all(isinstance(x, float) for x in vec)

    # Check written file matches
    loaded = json.loads(out_json.read_text(encoding="utf-8"))
    assert loaded == data


def test_real_world_ikev1_features(sample_data_dir: Path):
    """Verify flow feature extraction on real-world Wireshark IKEv1 capture."""
    pcap = sample_data_dir / "real_ikev1-certs.pcap"
    if pcap.exists():
        res = analyze_capture_with_features(pcap)
        assert res.analysis.status.success is True
        assert res.flow_summary.total_flows == 1
        flow = res.flows[0]
        assert flow.ipsec_metadata.is_ipsec_related is True
        assert flow.ipsec_metadata.ike_related is True
        assert flow.validation.valid is True
        assert flow.features["total_packets"] == 10.0


def test_real_world_esp_features(sample_data_dir: Path):
    """Verify flow feature extraction on real-world Wireshark ESP PCAPNG capture."""
    pcapng = sample_data_dir / "real_esp-bug-12671.pcapng"
    if pcapng.exists():
        res = analyze_capture_with_features(pcapng)
        assert res.analysis.status.success is True
        assert res.flow_summary.total_flows == 1
        flow = res.flows[0]
        assert flow.flow_metadata.protocol == "ESP"
        assert flow.ipsec_metadata.esp_detected is True
        assert flow.validation.valid is True
        assert flow.features["total_packets"] == 6.0


def test_real_world_dns_mdns_features(sample_data_dir: Path):
    """Verify flow feature extraction on multi-flow real-world capture."""
    pcap = sample_data_dir / "real_dns-mdns.pcap"
    if pcap.exists():
        res = analyze_capture_with_features(pcap)
        assert res.analysis.status.success is True
        assert res.flow_summary.total_flows > 10
        assert res.flow_summary.valid_flows == res.flow_summary.total_flows
        for flow in res.flows:
            assert flow.validation.valid is True


def test_cli_features_flag(sample_data_dir: Path, tmp_path: Path):
    """Verify running main.py with --features produces flow summaries and JSON."""
    pcap = sample_data_dir / "ipsec_ikev2.pcap"
    out_file = tmp_path / "cli_features.json"

    proc = subprocess.run(
        [sys.executable, "main.py", str(pcap), "--features", "--output", str(out_file)],
        cwd=str(Path(__file__).parent.parent),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    assert "PHASE 2: BIDIRECTIONAL FLOWS & FEATURE SUMMARY" in proc.stdout
    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert "flows" in data
    assert data["feature_schema_version"] == "1.0"
