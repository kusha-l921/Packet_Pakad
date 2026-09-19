import json
import time
import os

import pyshark
from scapy.all import IP, UDP, Raw

# Import extraction, aggregation, and processing routines
import metadataExtractor
import FlowEngine
from FlowRecord import FlowRecord


# =========================================================================
# 1. MOCK ML MODEL
# =========================================================================

class MockMLModel:
    """
    Mock model used to verify pipeline integration without external weights.
    """

    def predict(self, feature_vectors):
        predictions = []

        for vec in feature_vectors:
            # Feature index 8 = mean_packet_size
            mean_pkt_size = vec[8]

            if mean_pkt_size > 800:
                predictions.append("Bulk_Transfer")
            else:
                predictions.append("Interactive_C2")

        return predictions


# =========================================================================
# 2. PYSHARK FIXTURE LOADER
# =========================================================================

FIXTURE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_fixtures")


def load_pyshark_packet(pcap_filename):
    """Load the first packet from a pcap fixture via PyShark."""
    path = os.path.join(FIXTURE_DIR, pcap_filename)
    cap = pyshark.FileCapture(path)
    pkt = next(iter(cap))
    cap.close()
    return pkt


# =========================================================================
# 3. SYNTHETIC ESP PACKET GENERATOR (Scapy — unchanged)
# =========================================================================

def create_synthetic_esp_packet(
    src,
    dst,
    spi,
    seq,
    payload_size,
    timestamp
):
    """
    Builds a synthetic native ESP packet.

    ESP:
        IP protocol = 50

    First 4 bytes:
        SPI

    Next 4 bytes:
        Sequence number

    Remaining bytes:
        Synthetic encrypted payload
    """

    # Accept values such as:
    # "0xa1b2c3d4"
    # "a1b2c3d4"
    # 0xa1b2c3d4

    if isinstance(spi, str):
        spi_int = int(spi, 16)
    else:
        spi_int = int(spi)

    seq_int = int(seq)

    esp_header = (
        spi_int.to_bytes(4, "big") +
        seq_int.to_bytes(4, "big")
    )

    encrypted_payload = b"\xaa" * payload_size

    pkt = (
        IP(
            src=src,
            dst=dst,
            proto=50
        )
        /
        Raw(
            load=esp_header + encrypted_payload
        )
    )

    # Scapy timestamp
    pkt.time = timestamp

    return pkt


# =========================================================================
# 4. FLOW PROCESSING
# =========================================================================

active_flows = {}

IDLE_TIMEOUT = 5.0
MIN_PACKETS = 10


def process_packet(
    model,
    esp_meta,
    window_size=50,
    stride=10
):
    """
    Process extracted ESP metadata.

    Triggers:
        1. Window/stride prediction
        2. Idle timeout prediction
    """

    if not esp_meta:
        return

    # ---------------------------------------------------------------------
    # Timestamp
    # ---------------------------------------------------------------------

    current_time = esp_meta["timestamp"]

    # ---------------------------------------------------------------------
    # Bidirectional flow key
    #
    # Sorting IP addresses means:
    #
    # A -> B
    # B -> A
    #
    # belong to the same flow.
    # ---------------------------------------------------------------------

    flow_key = tuple(
        sorted(
            [
                esp_meta["src_ip"],
                esp_meta["dst_ip"]
            ]
        )
    )

    # ---------------------------------------------------------------------
    # Create flow if necessary
    # ---------------------------------------------------------------------

    if flow_key not in active_flows:

        active_flows[flow_key] = FlowRecord(
            initiator_ip=esp_meta["src_ip"],
            window_size=window_size,
            stride=stride
        )

    flow = active_flows[flow_key]

    # ---------------------------------------------------------------------
    # Update flow
    # ---------------------------------------------------------------------

    if flow.update(esp_meta):

        features = flow.extract_features()

        if features:

            feature_vector = list(features.values())

            prediction = model.predict(
                [feature_vector]
            )[0]

            print(
                f"  [WINDOW TRIGGER] "
                f"Flow {flow_key} "
                f"(pkt count: {len(flow.timestamps)}) "
                f"-> Prediction: {prediction}"
            )

    # ---------------------------------------------------------------------
    # Idle timeout detection
    # ---------------------------------------------------------------------

    expired = []

    for key, record in list(active_flows.items()):

        if record.is_idle(
            current_time,
            timeout_seconds=IDLE_TIMEOUT
        ):

            # Only classify if enough packets were collected
            if len(record.timestamps) >= MIN_PACKETS:

                features = record.extract_features()

                if features:

                    feature_vector = list(
                        features.values()
                    )

                    prediction = model.predict(
                        [feature_vector]
                    )[0]

                    print(
                        f"  [TIMEOUT TRIGGER] "
                        f"Inactive Flow {key} "
                        f"-> Prediction: {prediction}"
                    )

            # Reset state before removing
            record.packets_since_last_predict = 0

            expired.append(key)

    # ---------------------------------------------------------------------
    # Delete expired flows
    # ---------------------------------------------------------------------

    for key in expired:
        del active_flows[key]


# =========================================================================
# 5. TEST 1
# =========================================================================

def run_test_1():

    print(
        "=== TEST 1: Control Plane PQC Metadata Extraction ==="
    )

    # -------------------------------------------------------------
    # Load synthetic IKEv2 packet from pcap fixture
    # -------------------------------------------------------------

    ike_pkt = load_pyshark_packet("ikev2_sa_init_notify.pcap")

    print("\nLoaded IKEv2 SA_INIT + Notify packet from fixture")

    # -------------------------------------------------------------
    # Extract metadata
    # -------------------------------------------------------------

    ike_meta = metadataExtractor.extract_ikeV2_metadata(
        ike_pkt
    )

    if ike_meta is None:
        raise AssertionError(
            "metadataExtractor returned None for IKEv2 packet"
        )

    # -------------------------------------------------------------
    # Print extracted information
    # -------------------------------------------------------------

    output_path = "ikev2_metadata.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(ike_meta, f, indent=2, default=str)

    print("\n--- Extracted IKEv2 Metadata (JSON) ---")
    print(json.dumps(ike_meta, indent=2, default=str))
    print(f"--> Saved to file: {output_path}")
    print("---------------------------------------\n")

    print(
        f"Exchange Type: "
        f"{ike_meta.get('exchange_type')}"
    )

    # Verify IKEv2 metadata extraction
    assert ike_meta.get("exchange_type") == 34, "Exchange type mismatch!"
    assert ike_meta.get("notify", {}).get("present") is True, "Notify payload missed!"

    print(
        "[PASS] IKEv2 SA_INIT metadata extraction validated.\n"
    )

    # -------------------------------------------------------------
    # Test IKE_AUTH packet
    # -------------------------------------------------------------
    print("--- Testing IKEv2 IKE_AUTH Packet ---")
    auth_pkt = load_pyshark_packet("ikev2_auth_cert.pcap")
    auth_meta = metadataExtractor.extract_ikeV2_metadata(auth_pkt)

    auth_output_path = "ikev2_auth_metadata.json"
    with open(auth_output_path, "w", encoding="utf-8") as f:
        json.dump(auth_meta, f, indent=2, default=str)

    print("\n--- Extracted IKEv2 IKE_AUTH Metadata (JSON) ---")
    print(json.dumps(auth_meta, indent=2, default=str))
    print(f"--> Saved to file: {auth_output_path}")
    print("-------------------------------------------------\n")

    assert auth_meta.get("exchange_type") == 35, "IKE_AUTH exchange type mismatch!"
    assert auth_meta.get("IKE_AUTH", {}).get("certificate", {}).get("present") is True, "Certificate payload missed!"
    assert auth_meta.get("IKE_AUTH", {}).get("authentication", {}).get("present") is True, "AUTH payload missed!"

    print("[PASS] IKEv2 IKE_AUTH metadata extraction validated.\n")


# =========================================================================
# 6. TEST 2
# =========================================================================

def run_test_2(model, t_start):

    print(
        "=== TEST 2: Data Plane Window & Stride Trigger "
        "(Window=50, Stride=10) ==="
    )

    # -------------------------------------------------------------
    # Simulate bidirectional conversation:
    #
    # Forward:
    #     192.168.1.100 -> 10.0.0.1
    #     Large packets
    #
    # Backward:
    #     10.0.0.1 -> 192.168.1.100
    #     Small ACK packets
    # -------------------------------------------------------------

    sim_time = t_start

    for i in range(1, 75):

        # 20 ms inter-arrival time
        sim_time += 0.02

        # ---------------------------------------------------------
        # Forward direction
        # ---------------------------------------------------------

        if i % 2 == 1:

            pkt = create_synthetic_esp_packet(
                src="192.168.1.100",
                dst="10.0.0.1",
                spi="0xa1b2c3d4",
                seq=i,
                payload_size=1200,
                timestamp=sim_time
            )

        # ---------------------------------------------------------
        # Reverse direction
        # ---------------------------------------------------------

        else:

            pkt = create_synthetic_esp_packet(
                src="10.0.0.1",
                dst="192.168.1.100",
                spi="0xd4c3b2a1",
                seq=i,
                payload_size=64,
                timestamp=sim_time
            )

        # ---------------------------------------------------------
        # Extract ESP metadata
        # ---------------------------------------------------------

        esp_meta = metadataExtractor.extract_esp_metadata(
            pkt
        )

        # ---------------------------------------------------------
        # Process packet
        # ---------------------------------------------------------

        process_packet(
            model,
            esp_meta,
            window_size=50,
            stride=10
        )

    print(
        "[PASS] Window triggers executed successfully.\n"
    )

    return sim_time


# =========================================================================
# 7. TEST 3
# =========================================================================

def run_test_3(model, sim_time):

    print(
        "=== TEST 3: Data Plane Timeout Trigger ==="
    )

    # -------------------------------------------------------------
    # Jump time forward by 6 seconds.
    #
    # IDLE_TIMEOUT = 5 seconds
    #
    # Therefore the existing flow should expire.
    # -------------------------------------------------------------

    sim_time += 6.0

    # -------------------------------------------------------------
    # Create heartbeat packet from another flow.
    #
    # This causes process_packet() to inspect all active flows
    # and expire the old one.
    # -------------------------------------------------------------

    dummy_heartbeat = create_synthetic_esp_packet(
        src="172.16.0.1",
        dst="172.16.0.2",
        spi="0x99999999",
        seq=1,
        payload_size=50,
        timestamp=sim_time
    )

    esp_meta = metadataExtractor.extract_esp_metadata(
        dummy_heartbeat
    )

    process_packet(
        model,
        esp_meta,
        window_size=50,
        stride=10
    )

    # -------------------------------------------------------------
    # Verify old flow was removed
    # -------------------------------------------------------------

    old_flow_key = (
        "10.0.0.1",
        "192.168.1.100"
    )

    assert old_flow_key not in active_flows, (
        "Idle flow was not evicted!"
    )

    print(
        "[PASS] Idle timeout trigger and cleanup validated.\n"
    )


# =========================================================================
# 8. MAIN
# =========================================================================

if __name__ == "__main__":

    print("=" * 70)
    print("SIH-160 PQC / ESP PIPELINE TEST")
    print("=" * 70)

    # -------------------------------------------------------------
    # Create mock ML model
    # -------------------------------------------------------------

    model = MockMLModel()

    # -------------------------------------------------------------
    # Synthetic base timestamp
    # -------------------------------------------------------------

    t_start = 1700000000.0

    try:

        # =========================================================
        # TEST 1
        # =========================================================

        run_test_1()

        # =========================================================
        # TEST 2
        # =========================================================

        sim_time = run_test_2(
            model,
            t_start
        )

        # =========================================================
        # TEST 3
        # =========================================================

        run_test_3(
            model,
            sim_time
        )

        # =========================================================
        # ALL TESTS PASSED
        # =========================================================

        print("=" * 70)
        print("ALL TESTS PASSED")
        print("=" * 70)

    except Exception as e:

        print("\n" + "=" * 70)
        print("TEST FAILED")
        print("=" * 70)

        print(
            f"{type(e).__name__}: {e}"
        )

        raise
