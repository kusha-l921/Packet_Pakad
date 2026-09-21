"""
test_rfcRuleEngine.py — Comprehensive Test Suite for the RFC Health & Compliance Engine.

Validates all 12 RFC categories, decoupled security postures, PQC classifications,
hybrid binding invariants, sliding window replay detection, sequence number rollover,
and ingestion boundaries.

Run:
    python test_rfcRuleEngine.py
"""

from __future__ import annotations

import sys
from pathlib import Path
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
from rfc_engine.rfcEngineModels import (
    HybridClassification,
    PqcClassification,
    RuleCategory,
    RuleStatus,
    SecurityPosture,
)
from rfc_engine.rfcRuleEngine import RfcRuleEngine

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
    print("RUNNING RFC HEALTH AND COMPLIANCE ENGINE TEST SUITE")
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
#  Test Cases
# ═══════════════════════════════════════════════════════════════════════════

@test
def test_rfc8247_classical_baseline():
    """Test standard RFC 8247 Classical Baseline: AES-128-CBC, SHA-256 PRF, MODP-2048."""
    session = {
        "common": {"ike_version": 2, "src_port": 500, "dst_port": 500},
        "IKE_SA_INIT": {
            "proposals": [{
                "proposal_num": 1, "protocol_id": 1,
                "transforms": {
                    "encryption": [{"id": 12, "length": 128}],   # AES-128-CBC (MUST)
                    "prf":        [{"id": 5}],                    # HMAC-SHA2-256 (MUST)
                    "integrity":  [{"id": 12}],                   # HMAC-SHA2-256-128 (MUST)
                    "dh_group":   [{"id": 14}],                   # MODP-2048 (MUST)
                    "extended_sequence_numbers": [{"id": 0}],
                },
            }],
            "key_exchange": {"group_id": 14, "key_data_len": 256},
        },
        "IKE_AUTH": {
            "authentication": {"present": True, "auth_type": 1},  # Legacy RSA (SHOULD NOT)
            "child_sa": {
                "present": True,
                "proposals": [{
                    "proposal_num": 1, "protocol_id": 3,
                    "transforms": {
                        "encryption": [{"id": 12, "length": 128}],
                        "integrity": [{"id": 12}],
                        "dh_group": [{"id": 14}],
                    },
                }],
            },
            "traffic_selectors": {
                "initiator": [{"start_address": "10.0.0.1", "end_address": "10.0.0.255"}],
                "responder": [{"start_address": "10.1.0.1", "end_address": "10.1.0.255"}],
            },
        },
        "notify": {"present": False, "notify_types": [], "messages": []},
    }

    engine = RfcRuleEngine()
    report = engine.evaluate(session)

    # Legacy RSA (auth_type 1) triggers a WARNING (RFC 7427 recommended)
    assert report.overall_rfc_status == RuleStatus.WARNING, f"Expected WARNING, got {report.overall_rfc_status}"
    assert len(report.critical_failures) == 0, f"Expected 0 failures, got {len(report.critical_failures)}"
    assert len(report.warnings) > 0, "Expected at least 1 warning for legacy RSA"
    assert report.cryptographic_posture == SecurityPosture.ACCEPTABLE
    assert report.pqc_classification == PqcClassification.NONE
    assert report.hybrid_classification == HybridClassification.NOT_HYBRID


@test
def test_cnsa2_pqc_hybrid_profile():
    """Test CNSA 2.0 Profile with RFC 9370 Multi-KE combining ECDH P-384 + ML-KEM-1024."""
    session = {
        "common": {"ike_version": 2, "src_port": 500, "dst_port": 500},
        "IKE_SA_INIT": {
            "proposals": [{
                "proposal_num": 1, "protocol_id": 1,
                "transforms": {
                    "encryption": [{"id": 20, "length": 256}],   # AES-256-GCM (MUST)
                    "prf":        [{"id": 6}],                    # HMAC-SHA2-384 (SHOULD)
                    "integrity":  [{"id": 0}],                    # NONE (MUST with AEAD)
                    "dh_group":   [{"id": 20}],                   # ECDH P-384 (SHOULD)
                    "extended_sequence_numbers": [{"id": 1}],     # ESN (MUST)
                    "additional_key_exchange_1": [{"id": 37}],    # ML-KEM-1024 (RFC 9370)
                },
            }],
            "key_exchange": {"group_id": 20, "key_data_len": 96},
        },
        "IKE_AUTH": {
            "authentication": {"present": True, "auth_type": 14}, # Digital Signature (RFC 7427)
            "certificate": {
                "present": True,
                "encoding": 4,
                "cert_key_type_oid": "2.16.840.1.101.3.4.3.19",   # ML-DSA-87
                "cert_key_len": 2592,
                "cert_sig_algo_oid": "2.16.840.1.101.3.4.3.19",
            },
            "child_sa": {
                "present": True,
                "proposals": [{
                    "proposal_num": 1, "protocol_id": 3,
                    "transforms": {
                        "encryption": [{"id": 20, "length": 256}],
                        "integrity": [{"id": 0}],
                        "dh_group": [{"id": 37}],
                        "extended_sequence_numbers": [{"id": 1}],
                    },
                }],
            },
            "traffic_selectors": {
                "initiator": [{"start_address": "192.168.1.0", "end_address": "192.168.1.255"}],
                "responder": [{"start_address": "192.168.2.0", "end_address": "192.168.2.255"}],
            },
        },
        "notify": {
            "present": True,
            "notify_types": [16430, 16438, 16440, 16443],        # FRAG, INTERMEDIATE, MULTI_KE, HASH_ALGOS
            "messages": [],
        },
        "sig_pqc_id": 20,
    }

    engine = RfcRuleEngine()
    report = engine.evaluate(session)

    assert report.overall_rfc_status == RuleStatus.PASS, f"Expected PASS, got {report.overall_rfc_status}"
    assert len(report.critical_failures) == 0
    assert report.cryptographic_posture == SecurityPosture.STRONG
    assert report.pqc_classification == PqcClassification.PQC_KEM
    assert report.hybrid_classification == HybridClassification.HYBRID


@test
def test_deprecated_broken_suite():
    """Test broken profile: 3DES, MD5 PRF, MD5 Integ, MODP-1024, IKEv1."""
    session = {
        "common": {"ike_version": 1, "src_port": 500, "dst_port": 500},
        "exchange_type": 1,  # IKEv1 Main Mode
        "IKE_SA_INIT": {
            "proposals": [{
                "proposal_num": 1, "protocol_id": 1,
                "transforms": {
                    "encryption": [{"id": 3, "length": 192}],    # 3DES (MUST NOT)
                    "prf":        [{"id": 1}],                    # MD5 PRF (MUST NOT)
                    "integrity":  [{"id": 1}],                    # MD5-96 Integ (MUST NOT)
                    "dh_group":   [{"id": 2}],                    # MODP-1024 (MUST NOT)
                    "extended_sequence_numbers": [{"id": 0}],
                },
            }],
        },
        "IKE_AUTH": {
            "authentication": {"present": True, "auth_type": 3},  # DSS (MUST NOT)
            "certificate": {
                "cert_sig_algo_oid": "1.2.840.113549.1.1.4",      # md5WithRSA (BROKEN)
            },
        },
    }

    engine = RfcRuleEngine()
    report = engine.evaluate(session)

    assert report.overall_rfc_status == RuleStatus.FAIL, f"Expected FAIL, got {report.overall_rfc_status}"
    assert len(report.critical_failures) >= 5, f"Expected >= 5 failures, got {len(report.critical_failures)}"
    assert report.cryptographic_posture == SecurityPosture.BROKEN
    assert report.pqc_classification == PqcClassification.NONE
    assert report.hybrid_classification == HybridClassification.NOT_HYBRID


@test
def test_aead_integrity_violation():
    """Verify that pairing AEAD (AES-GCM-16) with traditional integrity fails under RFC 8247."""
    session = {
        "common": {"ike_version": 2},
        "IKE_SA_INIT": {
            "proposals": [{
                "proposal_num": 1, "protocol_id": 1,
                "transforms": {
                    "encryption": [{"id": 20, "length": 256}],  # AES-GCM-16 (AEAD)
                    "prf":        [{"id": 5}],
                    "integrity":  [{"id": 12}],                  # Traditional HMAC-SHA2-256 (VIOLATION)
                    "dh_group":   [{"id": 19}],
                },
            }],
            "key_exchange": {"group_id": 19, "key_data_len": 64},
        },
    }

    engine = RfcRuleEngine()
    report = engine.evaluate(session)

    # Check for failure in AEAD pairing
    aead_fails = [f for f in report.critical_failures if f.rule_id == "IKE-ENCR-AEAD-PAIRING-001"]
    assert len(aead_fails) == 1, "Expected IKE-ENCR-AEAD-PAIRING-001 critical failure"
    assert aead_fails[0].severity.value == "CRITICAL"


@test
def test_nonaead_missing_integrity():
    """Verify that pairing non-AEAD (AES-CBC) with INTEG=0 (NONE) fails under RFC 8247."""
    session = {
        "common": {"ike_version": 2},
        "IKE_SA_INIT": {
            "proposals": [{
                "proposal_num": 1, "protocol_id": 1,
                "transforms": {
                    "encryption": [{"id": 12, "length": 128}],  # AES-CBC (Non-AEAD)
                    "prf":        [{"id": 5}],
                    "integrity":  [{"id": 0}],                   # NONE (VIOLATION for non-AEAD)
                    "dh_group":   [{"id": 14}],
                },
            }],
            "key_exchange": {"group_id": 14, "key_data_len": 256},
        },
    }

    engine = RfcRuleEngine()
    report = engine.evaluate(session)

    nonaead_fails = [f for f in report.critical_failures if f.rule_id == "IKE-ENCR-NONAEAD-PAIRING-001"]
    assert len(nonaead_fails) == 1, "Expected IKE-ENCR-NONAEAD-PAIRING-001 critical failure"
    assert nonaead_fails[0].severity.value == "CRITICAL"


@test
def test_ppk_distinction():
    """Verify RFC 8784 Post-quantum Pre-Shared Key (PPK) is classified as PPK, NOT PQC KEM or HYBRID."""
    session = {
        "common": {"ike_version": 2},
        "IKE_SA_INIT": {
            "proposals": [{
                "proposal_num": 1, "protocol_id": 1,
                "transforms": {
                    "encryption": [{"id": 20, "length": 256}],
                    "prf":        [{"id": 5}],
                    "integrity":  [{"id": 0}],
                    "dh_group":   [{"id": 19}],                  # Classical ECDH P-256
                },
            }],
            "key_exchange": {"group_id": 19, "key_data_len": 64},
        },
        "notify": {
            "present": True,
            "notify_types": [16435],                             # USE_PPK (RFC 8784)
            "messages": [{"type": 16435}],
        },
    }

    engine = RfcRuleEngine()
    report = engine.evaluate(session)

    assert report.pqc_classification == PqcClassification.PPK, f"Expected PPK, got {report.pqc_classification}"
    assert report.hybrid_classification == HybridClassification.NOT_HYBRID, (
        f"Expected NOT_HYBRID, got {report.hybrid_classification}"
    )


@test
def test_runtime_anti_replay_duplicate_detection():
    """Verify runtime telemetry engine flags duplicate sequence numbers as critical replay violations."""
    telemetry = {
        "data_plane": {
            "spi": "0xaabbccdd",
            "is_natt": False,
            "packets": [
                {"seq_num": 1, "wire_bytes": 100, "timestamp": 1.0},
                {"seq_num": 2, "wire_bytes": 100, "timestamp": 1.1},
                {"seq_num": 3, "wire_bytes": 100, "timestamp": 1.2},
                {"seq_num": 2, "wire_bytes": 100, "timestamp": 1.3},  # DUPLICATE!
                {"seq_num": 4, "wire_bytes": 100, "timestamp": 1.4},
            ],
        }
    }

    engine = RfcRuleEngine(replay_window_size=64)
    # Empty session dict
    report = engine.evaluate({}, telemetry_dict=telemetry)

    dup_fails = [f for f in report.critical_failures if f.rule_id == "ESP-REPLAY-DUP-001"]
    assert len(dup_fails) == 1, "Expected duplicate sequence number critical failure"
    assert dup_fails[0].severity.value == "CRITICAL"


@test
def test_runtime_anti_replay_trailing_edge_drop():
    """Verify runtime telemetry flags packets falling behind the sliding window trailing edge."""
    # Window size 64: if seq reaches 100, valid window is [37, 100]. Seq 10 falls behind.
    packets = [{"seq_num": i, "wire_bytes": 100, "timestamp": float(i)} for i in range(1, 101)]
    packets.append({"seq_num": 10, "wire_bytes": 100, "timestamp": 102.0})  # Trailing drop!

    telemetry = {
        "data_plane": {
            "spi": "0xaabbccdd",
            "is_natt": False,
            "packets": packets,
        }
    }

    engine = RfcRuleEngine(replay_window_size=64)
    report = engine.evaluate({}, telemetry_dict=telemetry)

    window_fails = [f for f in report.critical_failures if f.rule_id == "ESP-REPLAY-WINDOW-001"]
    assert len(window_fails) == 1, "Expected trailing edge drop failure"


@test
def test_runtime_sequence_number_rollover():
    """Verify 32-bit sequence number rollover without ESN flags critical failure."""
    max_32 = 0xFFFFFFFF
    telemetry = {
        "data_plane": {
            "spi": "0xaabbccdd",
            "is_natt": False,
            "esn": False,
            "packets": [
                {"seq_num": max_32, "wire_bytes": 100, "timestamp": 1.0},
            ],
        }
    }

    engine = RfcRuleEngine()
    report = engine.evaluate({}, telemetry_dict=telemetry)

    rollover_fails = [f for f in report.critical_failures if f.rule_id == "ESP-SEQ-ROLLOVER-001"]
    assert len(rollover_fails) == 1, "Expected sequence number rollover failure"
    assert rollover_fails[0].severity.value == "CRITICAL"


@test
def test_missing_data_plane_not_verifiable():
    """Verify that absent runtime telemetry produces NOT_VERIFIABLE rather than guessing."""
    session = {
        "common": {"ike_version": 2},
        "IKE_SA_INIT": {
            "proposals": [{
                "transforms": {
                    "encryption": [{"id": 20, "length": 256}],
                    "prf": [{"id": 5}],
                    "integrity": [{"id": 0}],
                    "dh_group": [{"id": 19}],
                }
            }],
            "key_exchange": {"group_id": 19, "key_data_len": 64},
        },
    }

    engine = RfcRuleEngine()
    report = engine.evaluate(session, telemetry_dict=None)

@test
def test_single_packet_streaming():
    """Verify feeding ESP packets one by one updates sliding window state and detects replays."""
    engine = RfcRuleEngine(replay_window_size=64)

    # 1. Packet 1 arrives -> PASS
    p1 = {"seq_num": 1, "spi": "0x1234", "wire_bytes": 100}
    r1 = engine.process_esp_packet(p1)
    assert any(r.status == RuleStatus.PASS for r in r1)

    # 2. Packet 2 arrives -> PASS
    p2 = {"seq_num": 2, "spi": "0x1234", "wire_bytes": 100}
    r2 = engine.process_esp_packet(p2)
    assert any(r.status == RuleStatus.PASS for r in r2)

    # 3. Duplicate Packet 2 arrives -> FAIL (CRITICAL)
    p2_dup = {"seq_num": 2, "spi": "0x1234", "wire_bytes": 100}
    r2_dup = engine.process_esp_packet(p2_dup)
    dup_fail = [r for r in r2_dup if r.rule_id == "ESP-REPLAY-DUP-001" and r.status == RuleStatus.FAIL]
    assert len(dup_fail) == 1, "Expected duplicate sequence number failure"
    assert dup_fail[0].severity.value == "CRITICAL"

    # 4. Advance to seq 100 -> PASS
    p100 = {"seq_num": 100, "spi": "0x1234", "wire_bytes": 100}
    r100 = engine.process_esp_packet(p100)
    assert any(r.status == RuleStatus.PASS for r in r100)

    # 5. Old packet seq 10 arrives (outside window [37, 100]) -> FAIL (HIGH)
    p10 = {"seq_num": 10, "spi": "0x1234", "wire_bytes": 100}
    r10 = engine.process_esp_packet(p10)
    window_fail = [r for r in r10 if r.rule_id == "ESP-REPLAY-WINDOW-001" and r.status == RuleStatus.FAIL]
    assert len(window_fail) == 1, "Expected trailing edge drop failure"


@test
def test_auth_metadata_integration():
    """Verify that auth_metadata in session delegates to certHealthEngine and produces findings."""
    session = {
        "IKE_SA_INIT": {
            "proposals": [{
                "transforms": {
                    "encryption": [{"id": 20, "length": 256}],
                    "prf": [{"id": 6}],
                    "integrity": [{"id": 0}],
                    "dh_group": [{"id": 20}],
                    "extended_sequence_numbers": [{"id": 1}],
                }
            }]
        },
        "IKE_AUTH": {
            "authentication": {"present": True, "auth_type": 14},
            "child_sa": {
                "proposals": [{
                    "protocol_id": 3,
                    "transforms": {
                        "encryption": [{"id": 20, "length": 256}],
                        "integrity": [{"id": 0}],
                        "extended_sequence_numbers": [{"id": 1}],
                    }
                }]
            }
        },
        "auth_metadata": {
            "initiator": {
                "identity": "client.example.com",
                "auth_method": 14,
                "certificates": [{
                    "encoding": 4,
                    "subject": "CN=client.example.com",
                    "cert_key_type_oid": "1.2.840.10045.2.1",
                    "cert_key_len": 256,
                    "cert_sig_algo_oid": "1.2.840.10045.4.3.2",
                    "not_before": 1000,
                    "not_after": 2000,  # clearly expired long ago
                    "is_ca": False,
                    "san": ["client.example.com"],
                }]
            }
        }
    }

    engine = RfcRuleEngine()
    report = engine.evaluate(session)
    cert_fails = [f for f in report.critical_failures if f.rule_id == "CERT-HEALTH-EXPIRED-001"]
    assert len(cert_fails) >= 1, "Expected CERT-HEALTH-EXPIRED-001 failure from certHealthEngine"


if __name__ == "__main__":
    success = run_all()
    sys.exit(0 if success else 1)


