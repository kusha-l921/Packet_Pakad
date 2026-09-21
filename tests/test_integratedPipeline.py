"""
tests/test_integratedPipeline.py — Comprehensive End-to-End Pipeline Integration Test Suite.

Validates the complete execution chain:
  1. Packet / session metadata ingestion
  2. In-memory correlation state machine (SessionAggregator)
  3. 19-D Cryptographic Vector Engine & Policy Cosine Classification
  4. 12-Category RFC Compliance Rule Engine
  5. X.509 PKI & Certificate Health Auditing Engine
  6. Machine Learning ESP Traffic Flow Telemetry Engine (25 features)
  7. Intermediate JSON reports persistence for cross-validation
  8. Standalone RAG layer data exporter & private key sanitization
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

# Ensure repository root is on sys.path
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from flow_engine import MLModelAdapter
from pipeline.integratedPipeline import IntegratedPipeline
from pipeline.ragExporter import (
    REPORT_FILENAMES,
    RagExporter,
    export_from_memory,
    export_rag_data,
)


def build_synthetic_multi_ke_session() -> tuple[dict[str, Any], dict[str, Any]]:
    """Generates a comprehensive RFC 9370 Multi-KE test session dictionary and auth metadata."""
    session_dict: dict[str, Any] = {
        "common": {
            "initiator_spi": "0x1122334455667788",
            "responder_spi": "0x8877665544332211",
            "protocol_version": 2,
            "endpoints": {
                "initiator_ip": "192.168.1.105",
                "responder_ip": "10.0.0.1",
                "initiator_port": 500,
                "responder_port": 500,
            },
            "timestamps": {
                "first_seen": 1789825000.0,
                "last_seen": 1789825000.185,
                "handshake_duration_ms": 185.0,
            },
        },
        "IKE_SA_INIT": {
            "proposals": [
                {
                    "proposal_num": 1,
                    "protocol_id": 1,
                    "spi": None,
                    "transforms": {
                        "encryption": [{"id": 20, "name": "ENCR_AES_GCM_16", "length": 256, "key_length": 256}],
                        "prf": [{"id": 6, "name": "PRF_HMAC_SHA2_384"}],
                        "integrity": [{"id": 0, "name": "NONE"}],
                        "dh_group": [{"id": 20, "name": "384-bit random ECP group"}],
                        "extended_sequence_numbers": [{"id": 1, "name": "ESN"}],
                        "additional_key_exchange_1": [{"id": 37, "name": "ML-KEM-1024"}],
                    },
                }
            ],
            "key_exchange": {
                "group": 20,
                "pubkey_len": 96,
            },
            "additional_key_exchanges": [
                {"transform_type": 6, "group": 37, "name": "ML-KEM-1024"},
            ],
            "notify": {
                "present": True,
                "notify_types": [16430, 16431, 16443],
                "messages": [
                    {"type": 16430, "name": "ADDITIONAL_KEY_EXCHANGE"},
                    {"type": 16431, "name": "SIGNATURE_HASH_ALGORITHMS", "data": "0x00030004"},
                    {"type": 16443, "name": "INTERMEDIATE_EXCHANGE_SUPPORTED"},
                ],
            },
        },
        "IKE_INTERMEDIATE": [
            {
                "round": 1,
                "key_exchange": {"group": 37, "pubkey_len": 1568},
            },
        ],
        "IKE_AUTH": {
            "authentication": {
                "auth_type": 14,
                "auth_method": 14,
            },
            "initiator_auth": {
                "auth_method": 14,
                "identity": {"type": 2, "value": "client.quantum.gov"},
            },
            "responder_auth": {
                "auth_method": 14,
                "identity": {"type": 2, "value": "gateway.quantum.gov"},
            },
            "traffic_selectors": {
                "initiator": [{"ts_type": 7, "ip_proto": 0, "start_addr": "192.168.1.0", "end_addr": "192.168.1.255"}],
                "responder": [{"ts_type": 7, "ip_proto": 0, "start_addr": "10.0.0.0", "end_addr": "10.0.255.255"}],
            },
            "child_sa": {
                "proposals": [
                    {
                        "proposal_num": 1,
                        "protocol_id": 3,
                        "spi": "0xc001beef",
                        "transforms": {
                            "encryption": [{"id": 20, "name": "ENCR_AES_GCM_16", "length": 256, "key_length": 256}],
                            "extended_sequence_numbers": [{"id": 1, "name": "ESN"}],
                        },
                    }
                ]
            },
        },
        "data_plane": {
            "spi": "0xc001beef",
            "packet_count": 250,
            "byte_count": 185000,
            "seq_numbers": list(range(1, 251)),
            "last_seq": 250,
            "is_natt": False,
        },
    }

    now = time.time()
    auth_metadata: dict[str, Any] = {
        "source": "daemon_api",
        "daemon_type": "strongswan",
        "initiator": {
            "identity": {"type": 2, "value": "client.quantum.gov"},
            "auth_method": 14,
            "certificates": [
                {
                    "encoding": 4,
                    "type": "end_entity",
                    "subject": "CN=client.quantum.gov, O=Quantum Org",
                    "issuer": "CN=Quantum CA, O=Quantum Org",
                    "cert_key_type_oid": "1.3.6.1.4.1.2.267.12.8.7",
                    "cert_key_len": 2560,
                    "cert_sig_algo_oid": "1.3.6.1.4.1.2.267.12.8.7",
                    "not_before": now - 3600,
                    "not_after": now + (180 * 86400),
                    "is_ca": False,
                    "san": ["client.quantum.gov"],
                    "key_usage": ["digitalSignature"],
                }
            ],
        },
        "responder": {
            "identity": {"type": 2, "value": "gateway.quantum.gov"},
            "auth_method": 14,
            "certificates": [
                {
                    "encoding": 4,
                    "type": "end_entity",
                    "subject": "CN=gateway.quantum.gov, O=Quantum Org",
                    "issuer": "CN=Quantum CA, O=Quantum Org",
                    "cert_key_type_oid": "1.3.6.1.4.1.2.267.12.8.7",
                    "cert_key_len": 2560,
                    "cert_sig_algo_oid": "1.3.6.1.4.1.2.267.12.8.7",
                    "not_before": now - 3600,
                    "not_after": now + (180 * 86400),
                    "is_ca": False,
                    "san": ["gateway.quantum.gov"],
                    "key_usage": ["digitalSignature"],
                }
            ],
        },
    }

    return session_dict, auth_metadata

# ═══════════════════════════════════════════════════════════════════════════
#  Test Harness Runner
# ═══════════════════════════════════════════════════════════════════════════

_tests: list = []
_passed = 0
_failed = 0


def test(fn):
    _tests.append(fn)
    return fn


def _run_all():
    global _passed, _failed
    print("=" * 80)
    print("RUNNING END-TO-END INTEGRATED PIPELINE TEST SUITE")
    print("=" * 80)
    for fn in _tests:
        try:
            fn()
            _passed += 1
            print(f"  PASS  {fn.__name__}")
        except AssertionError as e:
            _failed += 1
            import traceback
            print(f"  FAIL  {fn.__name__}  ->  {e}\n{traceback.format_exc()}")
        except Exception as e:
            _failed += 1
            import traceback
            print(f"  FAIL  {fn.__name__}  ->  EXCEPTION: {e}\n{traceback.format_exc()}")

    print("=" * 80)
    print(f"RESULTS: {_passed} passed, {_failed} failed, {_passed + _failed} total")
    print("=" * 80)
    return _failed == 0


# ═══════════════════════════════════════════════════════════════════════════
#  Test Cases
# ═══════════════════════════════════════════════════════════════════════════

@test
def test_e2e_synthetic_pipeline_execution():
    """Validates full pipeline execution, analytical evaluation, and report persistence."""
    temp_dir = Path(tempfile.mkdtemp(prefix="sih_pipeline_test_"))
    try:
        pipeline = IntegratedPipeline(output_dir=temp_dir, verbose=False)
        session_dict, auth_meta = build_synthetic_multi_ke_session()

        result = pipeline.process_session_dict(session_dict, auth_metadata=auth_meta)
        session_id = result["session_id"]
        assert session_id == "0x1122334455667788", f"Unexpected session ID: {session_id}"

        persisted = result["persisted_files"]
        assert len(persisted) == 6, f"Expected 6 persisted report files, got {len(persisted)}"

        # 1. Verify Canonical Session JSON
        canon_path = Path(persisted["canonical_session"])
        assert canon_path.is_file()
        with open(canon_path, "r", encoding="utf-8") as f:
            canon = json.load(f)
        assert canon["session_id"] == "0x1122334455667788"
        assert canon["common"]["completed"] is True
        assert len(canon["IKE_SA_INIT"]["proposals"]) > 0

        # 2. Verify RFC Compliance Report JSON
        rfc_path = Path(persisted["rfc_compliance"])
        assert rfc_path.is_file()
        with open(rfc_path, "r", encoding="utf-8") as f:
            rfc = json.load(f)
        assert "overall_rfc_status" in rfc
        assert "cryptographic_posture" in rfc
        assert "category_summaries" in rfc

        # 3. Verify Crypto Vector Posture JSON
        vec_path = Path(persisted["vector_posture"])
        assert vec_path.is_file()
        with open(vec_path, "r", encoding="utf-8") as f:
            vec_data = json.load(f)
        assert len(vec_data["vector_19d"]) == 19
        assert len(vec_data["dimension_names"]) == 19
        for val in vec_data["vector_19d"]:
            assert 0.0 <= val <= 1.0, f"Vector element out of bounds: {val}"
        assert vec_data["best_match"] in (
            "CNSA_2_0",
            "NIST_PQC_TRANSITIONAL",
            "RFC8247_CLASSICAL_BASELINE",
            "NIST_SP800_131A_DEPRECATED",
        )

        # 4. Verify Certificate Health Report JSON
        cert_path = Path(persisted["cert_health"])
        assert cert_path.is_file()
        with open(cert_path, "r", encoding="utf-8") as f:
            cert_data = json.load(f)
        assert "overall_health_status" in cert_data
        assert "peers" in cert_data or "peer_audits" in cert_data

        # 5. Verify Traffic Flow Report JSON
        flow_path = Path(persisted["traffic_flow"])
        assert flow_path.is_file()
        with open(flow_path, "r", encoding="utf-8") as f:
            flow_data = json.load(f)
        assert "features" in flow_data
        assert flow_data["packet_count"] > 0

        # 6. Verify Unified RAG Payload JSON
        rag_path = Path(persisted["unified_rag_payload"])
        assert rag_path.is_file()
        with open(rag_path, "r", encoding="utf-8") as f:
            rag_data = json.load(f)
        assert rag_data["schema_version"] == "1.0" or rag_data.get("rag_export_metadata", {}).get("schema_version") == "1.0"
        assert "summaries" in rag_data
        assert "raw_sources" in rag_data
        assert rag_data["summaries"]["cryptographic_posture"]["closest_policy_anchor"] == vec_data["best_match"]
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@test
def test_packet_by_packet_ingestion_and_auto_export():
    """Simulates per-packet wire ingestion through IKE_AUTH completion trigger."""
    temp_dir = Path(tempfile.mkdtemp(prefix="sih_wire_test_"))
    try:
        pipeline = IntegratedPipeline(output_dir=temp_dir, auto_export_on_complete=True)

        init_spi = "0x9988776655443322"
        resp_spi = "0x1122334455667788"

        # 1. IKE_SA_INIT Request
        pkt_init_req = {
            "common": {
                "initiator_spi": init_spi,
                "responder_spi": "0x0000000000000000",
                "is_response": False,
                "exchange_type": 34,
                "message_id": 0,
                "src_ip": "10.0.1.5",
                "dst_ip": "10.0.1.1",
                "src_port": 500,
                "dst_port": 500,
            },
            "IKE_SA_INIT": {
                "proposals": [
                    {
                        "proposal_num": 1,
                        "protocol_id": 1,
                        "transforms": {
                            "encryption": [{"id": 20, "name": "ENCR_AES_GCM_16", "length": 256}],
                            "prf": [{"id": 7, "name": "PRF_HMAC_SHA2_512"}],
                            "integrity": [{"id": 0, "name": "NONE"}],
                            "dh_group": [{"id": 19, "name": "256-bit random ECP group"}],
                            "extended_sequence_numbers": [{"id": 1, "name": "ESN"}],
                        },
                    }
                ],
                "key_exchange": {"group": 19, "pubkey_len": 64},
            },
        }
        res1 = pipeline.ingest_ike_packet(pkt_init_req)
        assert res1 == init_spi

        # 2. IKE_SA_INIT Response
        pkt_init_resp = {
            "common": {
                "initiator_spi": init_spi,
                "responder_spi": resp_spi,
                "is_response": True,
                "exchange_type": 34,
                "message_id": 0,
            },
            "IKE_SA_INIT": {
                "proposals": pkt_init_req["IKE_SA_INIT"]["proposals"],
                "key_exchange": {"group": 19, "pubkey_len": 64},
            },
        }
        pipeline.ingest_ike_packet(pkt_init_resp)

        # 3. IKE_AUTH Request
        pkt_auth_req = {
            "common": {
                "initiator_spi": init_spi,
                "responder_spi": resp_spi,
                "is_response": False,
                "exchange_type": 35,
                "message_id": 1,
            },
            "IKE_AUTH": {
                "authentication": {"auth_method": 14, "auth_type": 14},
                "traffic_selectors": {
                    "initiator": [{"ts_type": 7, "ip_proto": 0}],
                    "responder": [{"ts_type": 7, "ip_proto": 0}],
                },
                "child_sa": {
                    "proposals": [
                        {
                            "proposal_num": 1,
                            "protocol_id": 3,
                            "spi": "0x55aa55aa",
                            "transforms": {
                                "encryption": [{"id": 20, "length": 256}],
                                "extended_sequence_numbers": [{"id": 1}],
                            },
                        }
                    ]
                },
            },
        }
        pipeline.ingest_ike_packet(pkt_auth_req)

        # 4. IKE_AUTH Response (Triggers Handshake Completion & Report Export)
        pkt_auth_resp = {
            "common": {
                "initiator_spi": init_spi,
                "responder_spi": resp_spi,
                "is_response": True,
                "exchange_type": 35,
                "message_id": 1,
            },
            "IKE_AUTH": pkt_auth_req["IKE_AUTH"],
        }
        pipeline.ingest_ike_packet(pkt_auth_resp)

        # 5. Ingest ESP data plane packets
        now = time.time()
        for i in range(1, 30):
            esp_pkt = {
                "plane": "data",
                "spi": "0x55aa55aa",
                "seq_num": i,
                "wire_bytes": 1200,
                "src_ip": "10.0.1.5",
                "dst_ip": "10.0.1.1",
                "timestamp": now + (i * 0.01),
            }
            pipeline.ingest_esp_packet(esp_pkt)

        # Export reports and verify files
        persisted = pipeline.export_session_reports(init_spi)
        assert len(persisted) >= 5
        assert (temp_dir / "intermediate_canonical_session.json").is_file()
        assert (temp_dir / "unified_rag_payload.json").is_file()
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@test
def test_rag_exporter_discovery_and_sanitization():
    """Verifies that RagExporter discovers files, detects missing ones, and scrubs private keys."""
    temp_dir = Path(tempfile.mkdtemp(prefix="sih_rag_test_"))
    try:
        # Create a partial set of JSON files
        canon_file = temp_dir / REPORT_FILENAMES["canonical_session"]
        canon_content = {
            "session_id": "0xTESTSESSION",
            "common": {
                "src_ip": "1.2.3.4",
                "dst_ip": "5.6.7.8",
                "src_port": 500,
                "dst_port": 500,
            },
            # Inadvertent sensitive private key injection
            "inadvertent_private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----",
        }
        with open(canon_file, "w", encoding="utf-8") as f:
            json.dump(canon_content, f)

        # Vector file
        vec_file = temp_dir / REPORT_FILENAMES["vector_posture"]
        with open(vec_file, "w", encoding="utf-8") as f:
            json.dump({"vector_19d": [1.0] * 19, "best_match": "CNSA_2_0"}, f)

        exporter = RagExporter(output_dir=temp_dir)
        payload = exporter.export(target_dir=temp_dir, write_to_disk=True)

        meta = payload["rag_export_metadata"]
        assert meta["total_found"] == 2
        assert meta["total_expected"] == 5
        assert REPORT_FILENAMES["rfc_compliance"] in meta["missing_files"]
        assert REPORT_FILENAMES["cert_health"] in meta["missing_files"]

        # Assert private key material was sanitized
        raw_canon = payload["raw_sources"]["canonical_session"]
        assert raw_canon["inadvertent_private_key"] == "[REDACTED_SENSITIVE_KEY_MATERIAL]"

        # Verify disk output exists
        unified_file = temp_dir / "unified_rag_payload.json"
        assert unified_file.is_file()
        with open(unified_file, "r", encoding="utf-8") as f:
            saved_content = f.read()
        assert "BEGIN RSA PRIVATE KEY" not in saved_content
        assert "[REDACTED_SENSITIVE_KEY_MATERIAL]" in saved_content
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


class _MockTrafficClassifier:
    """Mock classifier for testing pluggable ML lifecycle in test suite."""

    def predict(self, X: list[list[float]]) -> list[str]:
        results = []
        for vec in X:
            # packets_per_second is index 14
            pps = vec[14] if len(vec) > 14 else 0.0
            if pps > 5000.0:
                results.append("ANOMALOUS_HIGH_RATE_BURST")
            else:
                results.append("BENIGN_IPSEC")
        return results


@test
def test_ml_model_adapter_lifecycle():
    """Verifies MLModelAdapter protocol conformance and pluggable classifier handling."""
    # 1. Unloaded model (default)
    adapter_empty = MLModelAdapter(model=None)
    assert not adapter_empty.is_loaded
    empty_verdict = adapter_empty.classify_flow({"total_packets": 200.0})
    assert empty_verdict["verdict"] is None
    assert empty_verdict["is_model_loaded"] is False

    # 2. Pluggable classifier model
    adapter_mock = MLModelAdapter(model=_MockTrafficClassifier(), model_name="mock_traffic_model")
    assert adapter_mock.is_loaded
    dummy_features = {
        "packets_per_second": 100.0,
        "bytes_per_second": 50000.0,
    }
    fb_verdict = adapter_mock.classify_flow(dummy_features)
    assert fb_verdict["verdict"] == "BENIGN_IPSEC"
    assert fb_verdict["feature_count"] == 25

    # 3. Burst anomaly test
    burst_features = {
        "packets_per_second": 8000.0,
        "bytes_per_second": 120_000_000.0,
    }
    burst_verdict = adapter_mock.classify_flow(burst_features)
    assert burst_verdict["verdict"] == "ANOMALOUS_HIGH_RATE_BURST"


@test
def test_ipsec_mode_pipeline_propagation():
    """Verify that ipsec_mode (TUNNEL vs TRANSPORT) correctly propagates through all report files and RAG payload."""
    temp_dir = Path(tempfile.mkdtemp(prefix="sih_mode_test_"))
    try:
        # Case A: Default TUNNEL mode
        pipeline_tunnel = IntegratedPipeline(output_dir=temp_dir / "tunnel")
        s_dict_tunnel, a_meta_tunnel = build_synthetic_multi_ke_session()
        res_tunnel = pipeline_tunnel.process_session_dict(s_dict_tunnel, a_meta_tunnel)

        rag_payload_tunnel = res_tunnel["rag_payload"]
        assert rag_payload_tunnel["metadata"]["ipsec_mode"] == "TUNNEL"
        assert rag_payload_tunnel["summaries"]["rfc_compliance"]["ipsec_mode"] == "TUNNEL"
        assert rag_payload_tunnel["raw_sources"]["canonical_session"]["ipsec_mode"] == "TUNNEL"
        assert rag_payload_tunnel["raw_sources"]["rfc_compliance"]["ipsec_mode"] == "TUNNEL"

        # Case B: TRANSPORT mode via Notification 16391
        pipeline_trans = IntegratedPipeline(output_dir=temp_dir / "trans")
        s_dict_trans, a_meta_trans = build_synthetic_multi_ke_session()
        s_dict_trans["notify"] = {
            "present": True,
            "notify_types": [16391],
            "messages": [{"type": 16391, "name": "USE_TRANSPORT_MODE"}],
        }
        res_trans = pipeline_trans.process_session_dict(s_dict_trans, a_meta_trans)

        rag_payload_trans = res_trans["rag_payload"]
        assert rag_payload_trans["metadata"]["ipsec_mode"] == "TRANSPORT"
        assert rag_payload_trans["summaries"]["rfc_compliance"]["ipsec_mode"] == "TRANSPORT"
        assert rag_payload_trans["raw_sources"]["canonical_session"]["ipsec_mode"] == "TRANSPORT"
        assert rag_payload_trans["raw_sources"]["rfc_compliance"]["ipsec_mode"] == "TRANSPORT"
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


# ═══════════════════════════════════════════════════════════════════════════
#  Main Entry
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    success = _run_all()
    sys.exit(0 if success else 1)
