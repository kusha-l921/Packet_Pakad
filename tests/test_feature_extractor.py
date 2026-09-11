"""Unit tests verifying mathematical correctness of feature extraction in feature_extractor.py."""

import math
from person2_engine.src.feature_extractor import extract_flow_features, flow_features_to_vector
from person2_engine.src.flow_models import Flow, FlowKey, FlowPacketRecord


def make_dummy_flow(packet_specs: list[tuple[float, int, str]]) -> Flow:
    """Helper to construct a Flow with specified (timestamp, length, direction) tuples."""
    key = FlowKey.create(4, "10.0.0.1", "10.0.0.2", 1000, 80, "TCP")
    flow = Flow(
        flow_id=key.to_flow_id(),
        flow_key=key,
        forward_src_ip="10.0.0.1",
        forward_dst_ip="10.0.0.2",
        forward_src_port=1000,
        forward_dst_port=80,
    )

    for idx, (ts, length, direction) in enumerate(packet_specs, 1):
        if direction == "FORWARD":
            flow.forward_packets += 1
            flow.forward_bytes += length
        else:
            flow.backward_packets += 1
            flow.backward_bytes += length

        flow.total_bytes += length
        flow.packets.append(
            FlowPacketRecord(
                packet_index=idx,
                timestamp=ts,
                length=length,
                direction=direction,
                protocols=["TCP"],
            )
        )
    return flow


def test_packet_and_byte_counts():
    """Verify exact total, forward, and backward packet and byte counts."""
    specs = [
        (10.0, 100, "FORWARD"),
        (10.1, 200, "BACKWARD"),
        (10.2, 300, "FORWARD"),
        (10.3, 400, "BACKWARD"),
    ]
    flow = make_dummy_flow(specs)
    feats = extract_flow_features(flow)

    assert feats["total_packets"] == 4.0
    assert feats["forward_packets"] == 2.0
    assert feats["backward_packets"] == 2.0
    assert feats["total_bytes"] == 1000.0
    assert feats["forward_bytes"] == 400.0
    assert feats["backward_bytes"] == 600.0


def test_packet_size_statistics():
    """Verify min, max, mean, stddev, and median packet size calculations."""
    specs = [
        (1.0, 100, "FORWARD"),
        (1.1, 200, "FORWARD"),
        (1.2, 300, "FORWARD"),
        (1.3, 400, "FORWARD"),
        (1.4, 500, "FORWARD"),
    ]
    flow = make_dummy_flow(specs)
    feats = extract_flow_features(flow)

    assert feats["minimum_packet_size"] == 100.0
    assert feats["maximum_packet_size"] == 500.0
    assert feats["mean_packet_size"] == 300.0
    assert feats["median_packet_size"] == 300.0

    # Sample standard deviation of [100, 200, 300, 400, 500] is sqrt(25000) ~ 158.1139
    expected_std = math.sqrt(sum((x - 300) ** 2 for x in [100, 200, 300, 400, 500]) / 4)
    assert abs(feats["standard_deviation_packet_size"] - expected_std) < 0.01


def test_directional_mean_sizes():
    """Verify directional mean size features."""
    specs = [
        (1.0, 100, "FORWARD"),
        (1.1, 200, "FORWARD"),
        (1.2, 600, "BACKWARD"),
    ]
    flow = make_dummy_flow(specs)
    feats = extract_flow_features(flow)

    assert feats["forward_mean_packet_size"] == 150.0  # (100+200)/2
    assert feats["backward_mean_packet_size"] == 600.0


def test_duration_and_rates():
    """Verify flow duration and rate (packets/sec, bytes/sec) calculations."""
    specs = [
        (10.0, 100, "FORWARD"),
        (12.0, 200, "FORWARD"),
        (14.0, 300, "FORWARD"),
    ]
    # Duration is 14.0 - 10.0 = 4.0 seconds
    flow = make_dummy_flow(specs)
    feats = extract_flow_features(flow)

    assert feats["flow_duration_seconds"] == 4.0
    assert feats["packets_per_second"] == 3.0 / 4.0  # 0.75
    assert feats["bytes_per_second"] == 600.0 / 4.0  # 150.0


def test_inter_arrival_time_calculations():
    """Verify inter-arrival time mean, min, max, and stddev."""
    specs = [
        (1.0, 100, "FORWARD"),
        (1.2, 100, "FORWARD"),  # IAT = 0.2
        (1.5, 100, "FORWARD"),  # IAT = 0.3
        (2.0, 100, "FORWARD"),  # IAT = 0.5
    ]
    flow = make_dummy_flow(specs)
    feats = extract_flow_features(flow)

    # IATs: [0.2, 0.3, 0.5]
    # mean: 1.0 / 3 = 0.333333
    # min: 0.2, max: 0.5
    assert abs(feats["mean_inter_arrival_time"] - (1.0 / 3.0)) < 0.001
    assert abs(feats["minimum_inter_arrival_time"] - 0.2) < 0.001
    assert abs(feats["maximum_inter_arrival_time"] - 0.5) < 0.001
    assert feats["standard_deviation_inter_arrival_time"] > 0.0


def test_directional_ratios():
    """Verify directional packet and byte ratios."""
    specs = [
        (1.0, 100, "FORWARD"),
        (1.1, 100, "FORWARD"),
        (1.2, 100, "FORWARD"),
        (1.3, 100, "BACKWARD"),
    ]
    # 3 forward, 1 backward; total = 4 packets, 400 bytes
    flow = make_dummy_flow(specs)
    feats = extract_flow_features(flow)

    assert feats["forward_packet_ratio"] == 0.75
    assert feats["backward_packet_ratio"] == 0.25
    assert feats["forward_byte_ratio"] == 0.75
    assert feats["backward_byte_ratio"] == 0.25


def test_maximum_packets_in_one_second():
    """Verify maximum packets in any 1-second window calculation."""
    specs = [
        (1.0, 50, "FORWARD"),
        (1.2, 50, "FORWARD"),
        (1.4, 50, "FORWARD"),
        (1.6, 50, "FORWARD"),  # 4 packets in [1.0, 2.0]
        (5.0, 50, "FORWARD"),  # Gap
        (5.1, 50, "FORWARD"),  # 2 packets in [5.0, 6.0]
    ]
    flow = make_dummy_flow(specs)
    feats = extract_flow_features(flow)

    assert feats["maximum_packets_in_one_second"] == 4.0


def test_edge_case_single_packet():
    """Verify single packet flow avoids division by zero and sets schema defaults."""
    specs = [(5.0, 120, "FORWARD")]
    flow = make_dummy_flow(specs)
    feats = extract_flow_features(flow)

    assert feats["total_packets"] == 1.0
    assert feats["forward_packets"] == 1.0
    assert feats["backward_packets"] == 0.0
    assert feats["flow_duration_seconds"] == 0.0
    assert feats["packets_per_second"] == 0.0
    assert feats["bytes_per_second"] == 0.0
    assert feats["mean_inter_arrival_time"] == 0.0
    assert feats["minimum_inter_arrival_time"] == 0.0
    assert feats["maximum_inter_arrival_time"] == 0.0
    assert feats["standard_deviation_inter_arrival_time"] == 0.0
    assert feats["maximum_packets_in_one_second"] == 1.0
    assert feats["forward_packet_ratio"] == 1.0
    assert feats["backward_packet_ratio"] == 0.0

    # Ensure no NaN or Inf
    for k, v in feats.items():
        assert not math.isnan(v), f"Feature {k} was NaN"
        assert not math.isinf(v), f"Feature {k} was Inf"


def test_edge_case_zero_duration_multi_packet():
    """Verify multiple packets with identical timestamps (zero duration) handle rates safely."""
    specs = [
        (10.0, 100, "FORWARD"),
        (10.0, 200, "BACKWARD"),
    ]
    flow = make_dummy_flow(specs)
    feats = extract_flow_features(flow)

    assert feats["flow_duration_seconds"] == 0.0
    assert feats["packets_per_second"] == 0.0
    assert feats["bytes_per_second"] == 0.0
    assert feats["maximum_packets_in_one_second"] == 2.0


def test_vector_generation():
    """Verify flow_features_to_vector converts features to a clean 25-element float list."""
    specs = [
        (1.0, 100, "FORWARD"),
        (1.5, 200, "BACKWARD"),
    ]
    flow = make_dummy_flow(specs)
    feats = extract_flow_features(flow)
    vec = flow_features_to_vector({"features": feats})

    assert isinstance(vec, list)
    assert len(vec) == 25
    assert all(isinstance(x, float) for x in vec)
    assert all(not math.isnan(x) for x in vec)
    assert all(not math.isinf(x) for x in vec)
