"""
test_sessionAggregator.py — Comprehensive Test Suite for the In-Memory Session Aggregator.

Validates:
  • SPI demultiplexing & bi-directional indexing (initiator_spi <-> responder_spi)
  • Directional segregation (Initiator request store vs Responder response store)
  • RFC 9370 Multi-KE intermediate rounds accumulation
  • Handshake completion trigger on IKE_AUTH response
  • Zero disk I/O and RAM buffering
  • 19-D Vector Engine integration (build_vector)
  • 12-Category RFC Compliance Rule Engine integration (evaluate)
  • Child SA ESP data-plane packet correlation & seq tracking
  • Thread safety under concurrent ingestion
"""

from __future__ import annotations

import sys
import threading
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from session_aggregator import (
    SessionAggregator,
    SessionLifecycleState,
    SessionState,
    _normalize_spi,
)

# ═══════════════════════════════════════════════════════════════════════════
#  Minimal Test Harness
# ═══════════════════════════════════════════════════════════════════════════

_tests: list = []
_passed = 0
_failed = 0


def test(fn):
    _tests.append(fn)
    return fn


def run_all():
    global _passed, _failed
    print("=" * 80)
    print("RUNNING IN-MEMORY SESSION AGGREGATOR TEST SUITE")
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


# ═══════════════════════════════════════════════════════════════════════════
#  Fixtures
# ═══════════════════════════════════════════════════════════════════════════

INIT_SPI = "0x1122334455667788"
RESP_SPI = "0x8877665544332211"
CHILD_SPI = "0xaabbccdd"


def _make_sa_init_req(init_spi=INIT_SPI):
    return {
        "exchange_type": 34,
        "common": {
            "plane": "control",
            "timestamp": 100.0,
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1",
            "src_port": 500,
            "dst_port": 500,
            "initiator_spi": init_spi,
            "responder_spi": None,
            "exchange_type": 34,
            "is_response": False,
            "message_id": 0,
            "ike_version": 2,
        },
        "IKE_SA_INIT": {
            "exchange": "IKE_SA_INIT",
            "proposals": [{
                "proposal_num": 1,
                "protocol_id": 1,
                "transforms": {
                    "encryption": [{"id": 20, "length": 256}],  # AES-256-GCM
                    "prf": [{"id": 6}],                          # SHA-384
                    "integrity": [{"id": 0}],                    # NONE
                    "dh_group": [{"id": 20}],                    # ECP-384
                    "extended_sequence_numbers": [{"id": 1}],
                    "additional_key_exchange_1": [{"id": 37}],   # ML-KEM-1024
                },
            }],
            "key_exchange": {"group_id": 20, "key_data_len": 96},
        },
        "notify": {
            "present": True,
            "notify_types": [16431, 16443],  # SIGNATURE_HASH_ALGORITHMS, RFC 7427
            "messages": [
                {"type": 16431, "data": "0x00030004"},
                {"type": 16443, "data": None},
            ],
        },
    }


def _make_sa_init_resp(init_spi=INIT_SPI, resp_spi=RESP_SPI):
    return {
        "exchange_type": 34,
        "common": {
            "plane": "control",
            "timestamp": 100.05,
            "src_ip": "10.0.0.1",
            "dst_ip": "192.168.1.100",
            "src_port": 500,
            "dst_port": 500,
            "initiator_spi": init_spi,
            "responder_spi": resp_spi,
            "exchange_type": 34,
            "is_response": True,
            "message_id": 0,
            "ike_version": 2,
        },
        "IKE_SA_INIT": {
            "exchange": "IKE_SA_INIT",
            "proposals": [{
                "proposal_num": 1,
                "protocol_id": 1,
                "transforms": {
                    "encryption": [{"id": 20, "length": 256}],
                    "prf": [{"id": 6}],
                    "integrity": [{"id": 0}],
                    "dh_group": [{"id": 20}],
                    "extended_sequence_numbers": [{"id": 1}],
                    "additional_key_exchange_1": [{"id": 37}],
                },
            }],
            "key_exchange": {"group_id": 20, "key_data_len": 96},
        },
        "notify": {
            "present": True,
            "notify_types": [16443],
            "messages": [{"type": 16443, "data": None}],
        },
    }


def _make_auth_req(init_spi=INIT_SPI, resp_spi=RESP_SPI):
    return {
        "exchange_type": 35,
        "common": {
            "plane": "control",
            "timestamp": 100.10,
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1",
            "src_port": 500,
            "dst_port": 500,
            "initiator_spi": init_spi,
            "responder_spi": resp_spi,
            "exchange_type": 35,
            "is_response": False,
            "message_id": 1,
            "ike_version": 2,
        },
        "IKE_AUTH": {
            "exchange": "IKE_AUTH",
            "authentication": {
                "present": True,
                "auth_type": 14,  # Digital Signature (RFC 7427)
                "data": "0x112233",
            },
            "certificate": {
                "present": True,
                "encoding": 4,
                "data": "0x308201",
                "cert_key_len": 384,
            },
            "child_sa": {
                "present": True,
                "proposals": [{
                    "proposal_num": 1,
                    "protocol_id": 3,
                    "spi": CHILD_SPI,
                    "transforms": {
                        "encryption": [{"id": 20, "length": 256}],
                        "integrity": [{"id": 0}],
                        "dh_group": [{"id": 20}],
                        "extended_sequence_numbers": [{"id": 1}],
                    },
                }],
            },
            "traffic_selectors": {"initiator": [{"ts_type": 7}], "responder": []},
        },
    }


def _make_auth_resp(init_spi=INIT_SPI, resp_spi=RESP_SPI):
    return {
        "exchange_type": 35,
        "common": {
            "plane": "control",
            "timestamp": 100.15,
            "src_ip": "10.0.0.1",
            "dst_ip": "192.168.1.100",
            "src_port": 500,
            "dst_port": 500,
            "initiator_spi": init_spi,
            "responder_spi": resp_spi,
            "exchange_type": 35,
            "is_response": True,
            "message_id": 1,
            "ike_version": 2,
        },
        "IKE_AUTH": {
            "exchange": "IKE_AUTH",
            "authentication": {
                "present": True,
                "auth_type": 14,  # Digital Signature
                "data": "0x445566",
            },
            "certificate": {
                "present": True,
                "encoding": 4,
                "data": "0x308202",
                "cert_key_len": 384,
            },
            "child_sa": {
                "present": True,
                "proposals": [{
                    "proposal_num": 1,
                    "protocol_id": 3,
                    "spi": "0xddeeff00",
                    "transforms": {
                        "encryption": [{"id": 20, "length": 256}],
                        "integrity": [{"id": 0}],
                        "dh_group": [{"id": 20}],
                        "extended_sequence_numbers": [{"id": 1}],
                    },
                }],
            },
            "traffic_selectors": {"initiator": [], "responder": [{"ts_type": 7}]},
        },
    }


# ═══════════════════════════════════════════════════════════════════════════
#  Test Cases
# ═══════════════════════════════════════════════════════════════════════════

@test
def test_spi_demux_and_bidirectional_indexing():
    """Verify in-memory session demux by initiator_spi and secondary lookup via responder_spi."""
    agg = SessionAggregator()
    s1 = agg.ingest_packet(_make_sa_init_req())
    assert s1 is not None
    assert s1.initiator_spi == INIT_SPI
    assert s1.responder_spi is None
    assert s1.state == SessionLifecycleState.INITIATED

    # Responder sends response with responder_spi
    s2 = agg.ingest_packet(_make_sa_init_resp())
    assert s2 is s1
    assert s2.responder_spi == RESP_SPI
    assert s2.state == SessionLifecycleState.INIT_RESPONDED

    # Verify bi-directional lookup
    by_init = agg.get_session(INIT_SPI)
    by_resp = agg.get_session(RESP_SPI)
    assert by_init is s1
    assert by_resp is s1


@test
def test_directional_segregation():
    """Verify request payloads store into initiator_store and response payloads into responder_store."""
    agg = SessionAggregator()
    agg.ingest_packet(_make_sa_init_req())

    session = agg.get_session(INIT_SPI)
    assert session is not None
    assert len(session.initiator_store.sa_init_proposals) == 1
    assert len(session.responder_store.sa_init_proposals) == 0

    agg.ingest_packet(_make_sa_init_resp())
    assert len(session.responder_store.sa_init_proposals) == 1


@test
def test_notification_merging():
    """Verify notifications across exchanges are merged into unified, deduplicated pool."""
    agg = SessionAggregator()
    agg.ingest_packet(_make_sa_init_req())
    agg.ingest_packet(_make_sa_init_resp())

    session = agg.get_session(INIT_SPI)
    assert session is not None
    assert 16431 in session.notify_types
    assert 16443 in session.notify_types
    assert len(session.notify_messages) == 3  # 2 from req + 1 from resp


@test
def test_multi_ke_intermediate_rounds():
    """Verify RFC 9370 Multi-KE intermediate rounds are buffered in sequence."""
    agg = SessionAggregator()
    agg.ingest_packet(_make_sa_init_req())
    agg.ingest_packet(_make_sa_init_resp())

    # Send IKE_INTERMEDIATE request & response
    inter_req = {
        "exchange_type": 38,
        "common": {
            "plane": "control",
            "timestamp": 100.08,
            "initiator_spi": INIT_SPI,
            "responder_spi": RESP_SPI,
            "exchange_type": 38,
            "is_response": False,
            "message_id": 1,
        },
        "IKE_INTERMEDIATE": {
            "exchange": "IKE_INTERMEDIATE",
            "key_exchange": {"group_id": 37, "key_data_len": 1568},  # ML-KEM-1024
        },
    }
    inter_resp = {
        "exchange_type": 38,
        "common": {
            "plane": "control",
            "timestamp": 100.09,
            "initiator_spi": INIT_SPI,
            "responder_spi": RESP_SPI,
            "exchange_type": 38,
            "is_response": True,
            "message_id": 1,
        },
        "IKE_INTERMEDIATE": {
            "exchange": "IKE_INTERMEDIATE",
            "key_exchange": {"group_id": 37, "key_data_len": 1568},
        },
    }

    agg.ingest_packet(inter_req)
    agg.ingest_packet(inter_resp)

    session = agg.get_session(INIT_SPI)
    assert session is not None
    assert session.state == SessionLifecycleState.INTERMEDIATE_IN_PROGRESS
    assert len(session.intermediate_rounds) == 2
    assert session.intermediate_rounds[0].direction == "request"
    assert session.intermediate_rounds[1].direction == "response"
    assert session.intermediate_rounds[0].key_exchange["group_id"] == 37


@test
def test_handshake_completion_trigger():
    """Verify IKE_AUTH response locks the handshake state and triggers completion callback."""
    agg = SessionAggregator()
    callback_fired = []

    def on_complete(sess, canonical):
        callback_fired.append((sess.initiator_spi, canonical["common"]["completed"]))

    agg.on_handshake_complete(on_complete)

    agg.ingest_packet(_make_sa_init_req())
    agg.ingest_packet(_make_sa_init_resp())
    agg.ingest_packet(_make_auth_req())

    session = agg.get_session(INIT_SPI)
    assert session is not None
    assert session.state == SessionLifecycleState.AUTH_REQUESTED
    assert len(callback_fired) == 0

    # Ingest IKE_AUTH response -> trigger completion!
    agg.ingest_packet(_make_auth_resp())
    assert session.state == SessionLifecycleState.HANDSHAKE_COMPLETED
    assert session.is_handshake_complete() is True
    assert len(callback_fired) == 1
    assert callback_fired[0] == (INIT_SPI, True)
    assert session.completed_at == 100.15


@test
def test_canonical_dict_19d_vector_engine_integration():
    """Verify canonical composite dictionary directly feeds into 19-D Vector Engine."""
    agg = SessionAggregator()
    agg.ingest_packet(_make_sa_init_req())
    agg.ingest_packet(_make_sa_init_resp())
    agg.ingest_packet(_make_auth_req())
    agg.ingest_packet(_make_auth_resp())

    # Build 19-D vector
    vec = agg.build_crypto_vector(INIT_SPI)
    assert isinstance(vec, list)
    assert len(vec) == 19, f"Expected 19 dimensions, got {len(vec)}"
    for i, v in enumerate(vec):
        assert 0.0 <= v <= 1.0, f"d[{i}] = {v} is out of [0, 1] range"

    # Verify key dimensions:
    # d[0] Classical DH (ECP-384 / id 20) -> 1.0
    assert abs(vec[0] - 1.0) < 1e-5
    # d[2] PQC KEM presence (ML-KEM-1024 / id 37) -> 1.0
    assert abs(vec[2] - 1.0) < 1e-5
    # d[6] PFS status (Child SA has DH group 20) -> 1.0
    assert abs(vec[6] - 1.0) < 1e-5
    # d[7] AES-256-GCM -> 1.0
    assert abs(vec[7] - 1.0) < 1e-5
    # d[16] IKEv2 -> 1.0
    assert abs(vec[16] - 1.0) < 1e-5


@test
def test_canonical_dict_rfc_rule_engine_integration():
    """Verify canonical composite dictionary evaluates cleanly across all 12 RFC categories."""
    agg = SessionAggregator()
    agg.ingest_packet(_make_sa_init_req())
    agg.ingest_packet(_make_sa_init_resp())
    agg.ingest_packet(_make_auth_req())
    agg.ingest_packet(_make_auth_resp())

    report = agg.evaluate_compliance(INIT_SPI)
    assert report is not None
    assert len(report.all_results) > 0
    # Zero critical failures on this compliant CNSA2 configuration
    assert len(report.critical_failures) == 0


@test
def test_posture_classification_integration():
    """Verify cosine similarity classification works on aggregated session."""
    agg = SessionAggregator()
    agg.ingest_packet(_make_sa_init_req())
    agg.ingest_packet(_make_sa_init_resp())
    agg.ingest_packet(_make_auth_req())
    agg.ingest_packet(_make_auth_resp())

    posture = agg.classify_posture(INIT_SPI)
    assert isinstance(posture, dict)
    assert "best_match" in posture
    assert "best_score" in posture
    assert posture["best_score"] > 0.8  # Strong match with modern profile


@test
def test_cert_audit_integration():
    """Verify certificate health audit integrates cleanly on aggregated session."""
    agg = SessionAggregator()
    agg.ingest_packet(_make_sa_init_req())
    agg.ingest_packet(_make_sa_init_resp())
    agg.ingest_packet(_make_auth_req())
    agg.ingest_packet(_make_auth_resp())

    cert_report = agg.audit_certificates(INIT_SPI)
    assert cert_report is not None
    assert hasattr(cert_report, "overall_health_status")
    assert hasattr(cert_report, "peers")


@test
def test_esp_telemetry_correlation():
    """Verify data-plane ESP packets correlate to parent session via Child SA SPI."""
    agg = SessionAggregator()
    agg.ingest_packet(_make_sa_init_req())
    agg.ingest_packet(_make_sa_init_resp())
    agg.ingest_packet(_make_auth_req())
    agg.ingest_packet(_make_auth_resp())

    # Send ESP packets with negotiated Child SA SPI
    esp1 = {
        "plane": "data",
        "timestamp": 100.20,
        "spi": CHILD_SPI,
        "seq_num": 1,
        "wire_bytes": 1420,
        "is_natt": False,
    }
    esp2 = {
        "plane": "data",
        "timestamp": 100.21,
        "spi": CHILD_SPI,
        "seq_num": 2,
        "wire_bytes": 840,
        "is_natt": False,
    }

    s_esp1 = agg.ingest_packet(esp1)
    s_esp2 = agg.ingest_packet(esp2)
    assert s_esp1 is not None
    assert s_esp2 is not None

    session = agg.get_session(INIT_SPI)
    assert session is not None
    assert session.data_plane.packet_count == 2
    assert session.data_plane.byte_count == 2260
    assert session.data_plane.last_seq == 2
    assert session.data_plane.seq_numbers == [1, 2]


@test
def test_thread_safety_concurrent_ingest():
    """Verify safe concurrent ingestion across multiple threads without data corruption."""
    agg = SessionAggregator()
    num_sessions = 10
    threads = []

    def worker(sess_idx: int):
        init_spi = f"0x{sess_idx:016x}"
        resp_spi = f"0x{sess_idx + 1000:016x}"
        agg.ingest_packet(_make_sa_init_req(init_spi=init_spi))
        agg.ingest_packet(_make_sa_init_resp(init_spi=init_spi, resp_spi=resp_spi))
        agg.ingest_packet(_make_auth_req(init_spi=init_spi, resp_spi=resp_spi))
        agg.ingest_packet(_make_auth_resp(init_spi=init_spi, resp_spi=resp_spi))

    for i in range(1, num_sessions + 1):
        t = threading.Thread(target=worker, args=(i,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    active = agg.get_active_sessions()
    assert len(active) == num_sessions
    for s in active:
        assert s.is_handshake_complete() is True


@test
def test_ipsec_mode_tunnel_and_transport():
    """Verify IPsec SA mode discrimination between default TUNNEL and USE_TRANSPORT_MODE (16391)."""
    # 1. Default Tunnel Mode
    agg_tunnel = SessionAggregator()
    agg_tunnel.ingest_packet(_make_sa_init_req(init_spi="0x1111111111111111"))
    agg_tunnel.ingest_packet(_make_sa_init_resp(init_spi="0x1111111111111111", resp_spi="0x2222222222222222"))
    agg_tunnel.ingest_packet(_make_auth_req(init_spi="0x1111111111111111", resp_spi="0x2222222222222222"))
    agg_tunnel.ingest_packet(_make_auth_resp(init_spi="0x1111111111111111", resp_spi="0x2222222222222222"))
    canon_tunnel = agg_tunnel.get_canonical_session_dict("0x1111111111111111")
    assert canon_tunnel["ipsec_mode"] == "TUNNEL"
    assert canon_tunnel["IKE_AUTH"]["child_sa"]["mode"] == "TUNNEL"
    assert canon_tunnel["IKE_AUTH"]["child_sa"]["is_transport_mode"] is False

    # 2. Transport Mode via Notification 16391
    agg_trans = SessionAggregator()
    auth_req_trans = _make_auth_req(init_spi="0x3333333333333333", resp_spi="0x4444444444444444")
    auth_req_trans["notify"] = {
        "present": True,
        "notify_types": [16391],
        "messages": [{"type": 16391, "name": "USE_TRANSPORT_MODE"}],
    }
    agg_trans.ingest_packet(_make_sa_init_req(init_spi="0x3333333333333333"))
    agg_trans.ingest_packet(_make_sa_init_resp(init_spi="0x3333333333333333", resp_spi="0x4444444444444444"))
    agg_trans.ingest_packet(auth_req_trans)
    agg_trans.ingest_packet(_make_auth_resp(init_spi="0x3333333333333333", resp_spi="0x4444444444444444"))
    canon_trans = agg_trans.get_canonical_session_dict("0x3333333333333333")
    assert canon_trans["ipsec_mode"] == "TRANSPORT"
    assert canon_trans["IKE_AUTH"]["child_sa"]["mode"] == "TRANSPORT"
    assert canon_trans["IKE_AUTH"]["child_sa"]["is_transport_mode"] is True

    # 3. Transport Mode via Daemon Auth Metadata
    agg_daemon = SessionAggregator()
    agg_daemon.ingest_packet(_make_sa_init_req(init_spi="0x5555555555555555"))
    agg_daemon.ingest_packet(_make_sa_init_resp(init_spi="0x5555555555555555", resp_spi="0x6666666666666666"))
    agg_daemon.ingest_packet(_make_auth_req(init_spi="0x5555555555555555", resp_spi="0x6666666666666666"))
    agg_daemon.ingest_packet(_make_auth_resp(init_spi="0x5555555555555555", resp_spi="0x6666666666666666"))
    agg_daemon.attach_daemon_credentials("0x5555555555555555", {"mode": "TRANSPORT"})
    canon_daemon = agg_daemon.get_canonical_session_dict("0x5555555555555555")
    assert canon_daemon["ipsec_mode"] == "TRANSPORT"
    assert canon_daemon["IKE_AUTH"]["child_sa"]["mode"] == "TRANSPORT"
    assert canon_daemon["IKE_AUTH"]["child_sa"]["is_transport_mode"] is True


if __name__ == "__main__":
    success = run_all()
    sys.exit(0 if success else 1)
