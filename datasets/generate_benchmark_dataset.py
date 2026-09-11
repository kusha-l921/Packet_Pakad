"""Synthetic flow dataset generator for test fixtures and pipeline validation.

DISCLAIMER:
This script produces SYNTHETIC statistical flow data.
These synthetic datasets are strictly development and automated testing fixtures.
They MUST NOT be used as real-world benchmarks, and synthetic accuracy metrics
MUST NOT be reported as real-world model performance.
All primary real-world benchmark data is derived directly from raw PCAP captures
via person2_engine.src.pcap_dataset_adapter.
"""

import csv
import math
from pathlib import Path
import random
import sys
import numpy as np

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent.resolve()))

DATASETS_DIR = Path(__file__).parent



def generate_flow_features(category: str, rng: random.Random) -> dict:
    """Generate a single flow feature record with realistic encrypted statistical characteristics."""
    if category == "web":
        # Web browsing: moderate bursts, mixed request/response
        fwd_pkts = rng.randint(8, 45)
        bwd_pkts = rng.randint(12, 75)
        total_pkts = fwd_pkts + bwd_pkts

        fwd_mean = rng.uniform(250.0, 550.0)
        bwd_mean = rng.uniform(600.0, 1150.0)
        fwd_bytes = fwd_pkts * fwd_mean
        bwd_bytes = bwd_pkts * bwd_mean
        total_bytes = fwd_bytes + bwd_bytes

        min_sz = rng.uniform(54.0, 80.0)
        max_sz = rng.uniform(1300.0, 1514.0)
        mean_sz = total_bytes / total_pkts
        std_sz = rng.uniform(250.0, 500.0)
        med_sz = rng.uniform(400.0, 900.0)

        duration = rng.uniform(1.5, 18.0)
        mean_iat = duration / max(total_pkts - 1, 1)
        min_iat = rng.uniform(0.0001, 0.002)
        max_iat = rng.uniform(mean_iat * 1.5, min(duration, mean_iat * 5.0))
        std_iat = rng.uniform(mean_iat * 0.5, mean_iat * 1.2)
        max_pkts_1s = rng.uniform(5.0, min(float(total_pkts), 35.0))

    elif category == "video":
        # Video streaming: high volume, large payload, high download ratio
        fwd_pkts = rng.randint(25, 90)
        bwd_pkts = rng.randint(180, 750)
        total_pkts = fwd_pkts + bwd_pkts

        fwd_mean = rng.uniform(80.0, 180.0)
        bwd_mean = rng.uniform(1100.0, 1420.0)
        fwd_bytes = fwd_pkts * fwd_mean
        bwd_bytes = bwd_pkts * bwd_mean
        total_bytes = fwd_bytes + bwd_bytes

        min_sz = rng.uniform(54.0, 75.0)
        max_sz = rng.uniform(1420.0, 1514.0)
        mean_sz = total_bytes / total_pkts
        std_sz = rng.uniform(400.0, 600.0)
        med_sz = rng.uniform(1150.0, 1380.0)

        duration = rng.uniform(10.0, 60.0)
        mean_iat = duration / max(total_pkts - 1, 1)
        min_iat = rng.uniform(0.00005, 0.0008)
        max_iat = rng.uniform(mean_iat * 1.8, min(duration, 3.5))
        std_iat = rng.uniform(mean_iat * 0.4, mean_iat * 1.1)
        max_pkts_1s = rng.uniform(30.0, min(float(total_pkts), 120.0))

    elif category == "voip":
        # VoIP: highly symmetric, small consistent packets, periodic arrival
        fwd_pkts = rng.randint(80, 400)
        bwd_pkts = int(fwd_pkts * rng.uniform(0.92, 1.08))
        total_pkts = fwd_pkts + bwd_pkts

        fwd_mean = rng.uniform(90.0, 180.0)
        bwd_mean = rng.uniform(90.0, 180.0)
        fwd_bytes = fwd_pkts * fwd_mean
        bwd_bytes = bwd_pkts * bwd_mean
        total_bytes = fwd_bytes + bwd_bytes

        min_sz = rng.uniform(60.0, 85.0)
        max_sz = rng.uniform(190.0, 260.0)
        mean_sz = total_bytes / total_pkts
        std_sz = rng.uniform(15.0, 45.0)  # Very low variance
        med_sz = mean_sz

        duration = total_pkts * 0.02 * rng.uniform(0.9, 1.1)  # ~20ms packet intervals
        mean_iat = 0.02
        min_iat = rng.uniform(0.015, 0.019)
        max_iat = rng.uniform(0.022, 0.045)
        std_iat = rng.uniform(0.002, 0.006)
        max_pkts_1s = rng.uniform(40.0, 60.0)

    elif category == "file_transfer":
        # File transfer / Bulk: maximum MTU packets, high throughput, asymmetric
        fwd_pkts = rng.randint(20, 70)
        bwd_pkts = rng.randint(200, 950)
        total_pkts = fwd_pkts + bwd_pkts

        fwd_mean = rng.uniform(60.0, 95.0)  # ACKs
        bwd_mean = rng.uniform(1350.0, 1480.0)  # Full segments
        fwd_bytes = fwd_pkts * fwd_mean
        bwd_bytes = bwd_pkts * bwd_mean
        total_bytes = fwd_bytes + bwd_bytes

        min_sz = rng.uniform(54.0, 68.0)
        max_sz = rng.uniform(1460.0, 1514.0)
        mean_sz = total_bytes / total_pkts
        std_sz = rng.uniform(500.0, 650.0)
        med_sz = rng.uniform(1380.0, 1460.0)

        duration = rng.uniform(2.0, 25.0)
        mean_iat = duration / max(total_pkts - 1, 1)
        min_iat = rng.uniform(0.00001, 0.0003)
        max_iat = rng.uniform(mean_iat * 1.5, min(duration, 1.5))
        std_iat = rng.uniform(mean_iat * 0.3, mean_iat * 0.9)
        max_pkts_1s = rng.uniform(80.0, min(float(total_pkts), 250.0))

    else:  # interactive (SSH / Chat / Shell)
        # Interactive: sporadic small packets, long idle periods
        fwd_pkts = rng.randint(10, 50)
        bwd_pkts = rng.randint(10, 60)
        total_pkts = fwd_pkts + bwd_pkts

        fwd_mean = rng.uniform(70.0, 160.0)
        bwd_mean = rng.uniform(85.0, 220.0)
        fwd_bytes = fwd_pkts * fwd_mean
        bwd_bytes = bwd_pkts * bwd_mean
        total_bytes = fwd_bytes + bwd_bytes

        min_sz = rng.uniform(54.0, 70.0)
        max_sz = rng.uniform(250.0, 600.0)
        mean_sz = total_bytes / total_pkts
        std_sz = rng.uniform(40.0, 110.0)
        med_sz = rng.uniform(75.0, 130.0)

        duration = rng.uniform(15.0, 90.0)
        mean_iat = duration / max(total_pkts - 1, 1)
        min_iat = rng.uniform(0.001, 0.02)
        max_iat = rng.uniform(3.0, min(duration, 15.0))  # User typing delays
        std_iat = rng.uniform(mean_iat * 0.8, mean_iat * 2.0)
        max_pkts_1s = rng.uniform(2.0, 8.0)

    pps = float(total_pkts) / max(duration, 0.001)
    bps = total_bytes / max(duration, 0.001)
    fwd_pkt_ratio = float(fwd_pkts) / float(total_pkts)
    bwd_pkt_ratio = float(bwd_pkts) / float(total_pkts)
    fwd_byte_ratio = fwd_bytes / max(total_bytes, 1.0)
    bwd_byte_ratio = bwd_bytes / max(total_bytes, 1.0)

    return {
        "total_packets": round(float(total_pkts), 1),
        "forward_packets": round(float(fwd_pkts), 1),
        "backward_packets": round(float(bwd_pkts), 1),
        "total_bytes": round(total_bytes, 1),
        "forward_bytes": round(fwd_bytes, 1),
        "backward_bytes": round(bwd_bytes, 1),
        "minimum_packet_size": round(min_sz, 1),
        "maximum_packet_size": round(max_sz, 1),
        "mean_packet_size": round(mean_sz, 4),
        "standard_deviation_packet_size": round(std_sz, 4),
        "median_packet_size": round(med_sz, 2),
        "forward_mean_packet_size": round(fwd_mean, 4),
        "backward_mean_packet_size": round(bwd_mean, 4),
        "flow_duration_seconds": round(duration, 6),
        "packets_per_second": round(pps, 4),
        "bytes_per_second": round(bps, 4),
        "mean_inter_arrival_time": round(mean_iat, 6),
        "minimum_inter_arrival_time": round(min_iat, 6),
        "maximum_inter_arrival_time": round(max_iat, 6),
        "standard_deviation_inter_arrival_time": round(std_iat, 6),
        "forward_packet_ratio": round(fwd_pkt_ratio, 4),
        "backward_packet_ratio": round(bwd_pkt_ratio, 4),
        "forward_byte_ratio": round(fwd_byte_ratio, 4),
        "backward_byte_ratio": round(bwd_byte_ratio, 4),
        "maximum_packets_in_one_second": round(max_pkts_1s, 1),
        "label": category,
    }


def main():
    from person2_engine.src.feature_schema import FEATURE_ORDER

    fieldnames = list(FEATURE_ORDER) + ["label"]
    categories = ["web", "video", "voip", "file_transfer", "interactive"]

    # 1. Generate full benchmark dataset: 100 samples per class = 500 samples
    rng_bench = random.Random(42)
    bench_rows = []
    for cat in categories:
        for _ in range(100):
            bench_rows.append(generate_flow_features(cat, rng_bench))
    rng_bench.shuffle(bench_rows)

    bench_file = DATASETS_DIR / "benchmark_encrypted_flows.csv"
    with open(bench_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(bench_rows)
    print(f"Generated {len(bench_rows)} samples -> {bench_file}")

    # 2. Generate small test fixture: 4 samples per class = 20 samples
    rng_test = random.Random(1337)
    test_rows = []
    for cat in categories:
        for _ in range(4):
            test_rows.append(generate_flow_features(cat, rng_test))
    rng_test.shuffle(test_rows)

    test_file = DATASETS_DIR / "test_fixture_small.csv"
    with open(test_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(test_rows)
    print(f"Generated {len(test_rows)} samples -> {test_file}")


if __name__ == "__main__":
    main()
