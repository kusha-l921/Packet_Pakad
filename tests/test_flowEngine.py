"""
test_flowEngine.py — Comprehensive Test Suite for FlowEngine & FlowRecord.

Validates sliding window buffering, 25-feature extraction, stride prediction triggers,
inactivity timeouts, bidirectional IP grouping, and RealtimePacketDispatcher integration.

Run:
    python test_flowEngine.py
"""

from __future__ import annotations

import sys
from pathlib import Path
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
from typing import Any
from flow_engine.FlowEngine import FlowEngine, FlowVerdict, RealtimePacketDispatcher, process_packet
from flow_engine.FlowRecord import FlowRecord
from rfc_engine.rfcEngineModels import RuleStatus


class MockMLModel:
    """Mock ML model for testing inference verdicts."""

    def __init__(self, label: str = "IPSEC_TUNNEL_TRAFFIC") -> None:
        self.label = label
        self.call_count = 0

    def predict(self, feature_rows: list[list[float]]) -> list[str]:
        self.call_count += 1
        assert len(feature_rows) == 1
        assert len(feature_rows[0]) == 25, f"Expected 25 features, got {len(feature_rows[0])}"
        return [self.label]


_tests: list = []
_passed = 0
_failed = 0


def test(fn):
    _tests.append(fn)
    return fn


def run_all():
    global _passed, _failed
    print("=" * 80)
    print("RUNNING FLOW ENGINE & TRAFFIC CLASSIFICATION TEST SUITE")
    print("=" * 80)
    for fn in _tests:
        try:
            fn()
            _passed += 1
            print(f"  PASS  {fn.__name__}")
        except AssertionError as e:
            _failed += 1
            print(f"  FAIL  {fn.__name__}  ->  {e}")
        except Exception as e:
            _failed += 1
            print(f"  FAIL  {fn.__name__}  ->  EXCEPTION: {e}")

    print("=" * 80)
    print(f"RESULTS: {_passed} passed, {_failed} failed, {_passed + _failed} total")
    print("=" * 80)
    return _failed == 0


@test
def test_flow_record_feature_extraction():
    """Verify FlowRecord extracts all 25 features accurately from synthetic packet stream."""
    record = FlowRecord(initiator_ip="192.168.1.10", window_size=50, stride=10)

    for i in range(20):
        # Alternate forward and backward directions
        src = "192.168.1.10" if i % 2 == 0 else "192.168.1.20"
        dst = "192.168.1.20" if i % 2 == 0 else "192.168.1.10"
        meta = {
            "timestamp": 100.0 + i * 0.05,
            "wire_bytes": 100 + i * 10,
            "src_ip": src,
            "dst_ip": dst,
        }
        record.update(meta)

    features = record.extract_features()
    assert features is not None, "Features should not be None for 20 packets"
    assert len(features) == 25, f"Expected 25 features, got {len(features)}"

    assert features["total_packets"] == 20.0
    assert features["forward_packets"] == 10.0
    assert features["backward_packets"] == 10.0
    assert features["forward_packet_ratio"] == 0.5
    assert features["backward_packet_ratio"] == 0.5
    assert features["minimum_packet_size"] == 100.0
    assert features["maximum_packet_size"] == 100 + 19 * 10
    assert features["flow_duration_seconds"] > 0.0
    assert features["packets_per_second"] > 0.0
    assert features["bytes_per_second"] > 0.0
    assert features["mean_inter_arrival_time"] > 0.0


@test
def test_flow_engine_window_stride_trigger():
    """Verify FlowEngine triggers inference when window fills and on stride intervals."""
    model = MockMLModel("MALWARE_C2_SUSPECT")
    engine = FlowEngine(window_size=20, stride=5, idle_timeout=10.0, min_packets=5)

    all_verdicts: list[FlowVerdict] = []

    # Feed first 19 packets -> Window not yet full (window_size=20), no verdict expected
    for i in range(19):
        pkt = {
            "timestamp": 10.0 + i * 0.1,
            "wire_bytes": 200,
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
        }
        verdicts = engine.process_packet(pkt, model=model)
        all_verdicts.extend(verdicts)

    assert len(all_verdicts) == 0, "No verdicts should trigger before window is full"

    # Packet 20: Window reaches 20 packets (full) -> triggers 1st verdict
    pkt_20 = {
        "timestamp": 11.9,
        "wire_bytes": 200,
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
    }
    v20 = engine.process_packet(pkt_20, model=model)
    assert len(v20) == 1, "Expected 1 verdict when window reaches full size 20"
    assert v20[0].verdict == "MALWARE_C2_SUSPECT"
    assert v20[0].trigger_type == "WINDOW_STRIDE"
    assert v20[0].packet_count == 20

    # Next 4 packets (packets 21 to 24) -> stride (5) not yet reached
    for i in range(21, 25):
        pkt = {
            "timestamp": 12.0 + (i - 20) * 0.1,
            "wire_bytes": 200,
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
        }
        v = engine.process_packet(pkt, model=model)
        assert len(v) == 0, f"No verdict expected at packet {i}"

    # Packet 25 -> Stride of 5 reached! -> triggers 2nd verdict
    pkt_25 = {
        "timestamp": 12.5,
        "wire_bytes": 200,
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
    }
    v25 = engine.process_packet(pkt_25, model=model)
    assert len(v25) == 1, "Expected 1 verdict on stride interval"
    assert v25[0].trigger_type == "WINDOW_STRIDE"
    assert model.call_count == 2


@test
def test_flow_engine_idle_timeout_trigger():
    """Verify inactive flows trigger timeout prediction and are purged from active state."""
    model = MockMLModel("BENIGN_VOIP")
    engine = FlowEngine(window_size=50, stride=10, idle_timeout=3.0, min_packets=5)

    # 1. Flow A sends 12 packets from t=1.0 to t=2.1 (does not reach window_size=50)
    for i in range(12):
        pkt = {
            "timestamp": 1.0 + i * 0.1,
            "wire_bytes": 150,
            "src_ip": "172.16.0.1",
            "dst_ip": "172.16.0.2",
        }
        engine.process_packet(pkt, model=model)

    flow_key_a = ("172.16.0.1", "172.16.0.2")
    assert flow_key_a in engine.active_flows, "Flow A should be active"

    # 2. At t=6.0 (delta = 3.9s > idle_timeout 3.0s), an unrelated packet arrives for Flow B
    pkt_b = {
        "timestamp": 6.0,
        "wire_bytes": 500,
        "src_ip": "192.168.100.1",
        "dst_ip": "192.168.100.2",
    }
    verdicts = engine.process_packet(pkt_b, model=model)

    # Inactive Flow A should have been evaluated and purged
    timeout_verdicts = [v for v in verdicts if v.trigger_type == "IDLE_TIMEOUT"]
    assert len(timeout_verdicts) == 1, "Expected 1 idle timeout verdict for Flow A"
    assert timeout_verdicts[0].flow_key == flow_key_a
    assert timeout_verdicts[0].verdict == "BENIGN_VOIP"
    assert timeout_verdicts[0].packet_count == 12

    # Flow A must be removed from active flows
    assert flow_key_a not in engine.active_flows, "Flow A should have been removed after timeout"


@test
def test_bidirectional_flow_key_grouping():
    """Verify forward and reverse packets are correctly aggregated in the same flow."""
    engine = FlowEngine(window_size=20, stride=5)

    p_fwd = {"timestamp": 1.0, "wire_bytes": 100, "src_ip": "10.1.1.1", "dst_ip": "10.2.2.2"}
    p_bwd = {"timestamp": 1.1, "wire_bytes": 200, "src_ip": "10.2.2.2", "dst_ip": "10.1.1.1"}

    engine.process_packet(p_fwd)
    engine.process_packet(p_bwd)

    assert len(engine.active_flows) == 1
    expected_key = ("10.1.1.1", "10.2.2.2")
    assert expected_key in engine.active_flows

    flow = engine.get_flow(expected_key)
    assert flow is not None
    assert flow.packet_count == 2
    assert list(flow.is_forward) == [True, False]


@test
def test_instance_isolation_and_reset():
    """Verify distinct FlowEngine instances do not share state, and reset works as expected."""
    engine1 = FlowEngine(window_size=30)
    engine2 = FlowEngine(window_size=30)

    p1 = {"timestamp": 1.0, "wire_bytes": 100, "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"}
    engine1.process_packet(p1)

    assert len(engine1.active_flows) == 1
    assert len(engine2.active_flows) == 0, "Engine 2 must remain isolated"

    engine1.reset()
    assert len(engine1.active_flows) == 0, "Reset should clear all flows"


@test
def test_backward_compatible_module_api():
    """Verify module-level process_packet helper operates with original signature."""
    model = MockMLModel("TEST_VERDICT")
    p = {"timestamp": 5.0, "wire_bytes": 100, "src_ip": "3.3.3.3", "dst_ip": "4.4.4.4"}

    verdicts = process_packet(model, p, window_size=5, stride=2)
    assert isinstance(verdicts, list)


@test
def test_realtime_packet_dispatcher():
    """Verify RealtimePacketDispatcher evaluates RFC compliance and ML flow verdicts in a single call."""
    model = MockMLModel("VPN_DATA")
    dispatcher = RealtimePacketDispatcher(ml_model=model)

    # Send a valid ESP packet
    esp_meta = {
        "plane": "data",
        "timestamp": 10.0,
        "src_ip": "192.168.1.1",
        "dst_ip": "192.168.1.2",
        "src_port": None,
        "dst_port": None,
        "is_natt": False,
        "spi": "0x1234abcd",
        "seq_num": 1,
        "wire_bytes": 128,
    }

    rfc_results, flow_verdicts = dispatcher.dispatch(esp_meta)

    # 1. RFC Compliance check passed
    assert len(rfc_results) > 0
    assert any(r.status == RuleStatus.PASS and r.rule_id == "ESP-REPLAY-WINDOW-001" for r in rfc_results)

    # 2. Duplicate packet sent -> RFC engine detects replay attack
    esp_dup = dict(esp_meta)
    esp_dup["timestamp"] = 10.05
    rfc_results_dup, _ = dispatcher.dispatch(esp_dup)

    dup_fails = [r for r in rfc_results_dup if r.rule_id == "ESP-REPLAY-DUP-001" and r.status == RuleStatus.FAIL]
    assert len(dup_fails) == 1, "RFC engine must detect duplicate packet replay"


if __name__ == "__main__":
    success = run_all()
    sys.exit(0 if success else 1)
