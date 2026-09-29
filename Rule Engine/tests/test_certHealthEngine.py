"""
test_certHealthEngine.py — Comprehensive Test Suite for PKI and Certificate Health Engine.

Validates all 10 rules, standards ratings (CNSA 2.0, NIST Modern, RFC 8247, Deprecated),
validity windows, early expiration warnings, CA hierarchy, SAN matching, and dual outputs.
"""

import sys
from pathlib import Path
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
import time

from cert_engine.certHealthEngine import (
    CertHealthEngine,
    CertHealthStatus,
    CertRatingTier,
    RuleStatus,
    Severity,
    evaluate_auth_health,
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
    print("RUNNING CERTIFICATE HEALTH & PKI ENGINE TEST SUITE")
    print("=" * 80)

    for fn in _tests:
        try:
            fn()
            _passed += 1
            print(f"  PASS  {fn.__name__}")
        except AssertionError as e:
            _failed += 1
            print(f"  FAIL  {fn.__name__} -> {e}")
        except Exception as e:
            _failed += 1
            print(f"  FAIL  {fn.__name__} -> EXCEPTION: {e}")

    print("=" * 80)
    print(f"RESULTS: {_passed} passed, {_failed} failed, {_passed + _failed} total")
    print("=" * 80)
    return _failed == 0


# Reference timestamp: 2026-09-21 12:00:00 UTC (1789992000)
REF_TIME = 1789992000.0


# ═══════════════════════════════════════════════════════════════════════════
#  Test Cases
# ═══════════════════════════════════════════════════════════════════════════

@test
def test_modern_cnsa2_mutual_auth():
    """Test fully compliant CNSA 2.0 ML-DSA-87 mutual authentication."""
    auth_meta = {
        "initiator": {
            "identity": {"type": 2, "value": "client.acme.com"},
            "auth_method": 14,
            "certificates": [
                {
                    "encoding": 4,
                    "type": "end_entity",
                    "subject": "CN=client.acme.com",
                    "issuer": "CN=Acme PQC Intermediate CA",
                    "cert_key_type_oid": "2.16.840.1.101.3.4.3.19",  # ML-DSA-87
                    "cert_key_len": 256,
                    "cert_sig_algo_oid": "2.16.840.1.101.3.4.3.19",
                    "not_before": int(REF_TIME - 30 * 86400),
                    "not_after": int(REF_TIME + 300 * 86400),
                    "is_ca": False,
                    "san": ["client.acme.com"],
                    "key_usage": ["digitalSignature"],
                },
                {
                    "encoding": 4,
                    "type": "intermediate_ca",
                    "subject": "CN=Acme PQC Intermediate CA",
                    "issuer": "CN=Acme PQC Root CA",
                    "cert_key_type_oid": "2.16.840.1.101.3.4.3.19",
                    "cert_key_len": 256,
                    "cert_sig_algo_oid": "2.16.840.1.101.3.4.3.19",
                    "not_before": int(REF_TIME - 365 * 86400),
                    "not_after": int(REF_TIME + 730 * 86400),
                    "is_ca": True,
                    "san": [],
                    "key_usage": ["keyCertSign", "cRLSign"],
                }
            ]
        },
        "responder": {
            "identity": {"type": 1, "value": "198.51.100.1"},
            "auth_method": 14,
            "certificates": [
                {
                    "encoding": 4,
                    "type": "end_entity",
                    "subject": "CN=vpn-gw.acme.com",
                    "issuer": "CN=Acme PQC Intermediate CA",
                    "cert_key_type_oid": "2.16.840.1.101.3.4.3.19",
                    "cert_key_len": 256,
                    "cert_sig_algo_oid": "2.16.840.1.101.3.4.3.19",
                    "not_before": int(REF_TIME - 30 * 86400),
                    "not_after": int(REF_TIME + 300 * 86400),
                    "is_ca": False,
                    "san": ["198.51.100.1", "vpn-gw.acme.com"],
                    "key_usage": ["digitalSignature"],
                }
            ]
        }
    }

    report = evaluate_auth_health(auth_meta, reference_time=REF_TIME)
    assert report.overall_health_status == CertHealthStatus.HEALTHY
    assert report.is_compliant is True
    assert len(report.critical_failures) == 0

    init_leaf = report.peers["initiator"].leaf_cert
    assert init_leaf is not None
    assert init_leaf.rating.tier == CertRatingTier.CNSA_2_0
    assert init_leaf.rating.score == 1.00
    assert init_leaf.rating.security_bits == 256
    assert init_leaf.rating.cnsa_2_0_compliant is True


@test
def test_expired_leaf_certificate():
    """Expired certificate must trigger FAIL / CRITICAL and EXPIRED health status."""
    auth_meta = {
        "initiator": {
            "identity": "client.acme.com",
            "auth_method": 14,
            "certificates": [{
                "encoding": 4,
                "type": "end_entity",
                "subject": "CN=client.acme.com",
                "issuer": "CN=Acme CA",
                "cert_key_type_oid": "1.2.840.10045.2.1",
                "cert_key_len": 256,
                "cert_sig_algo_oid": "1.2.840.10045.4.3.2",
                "not_before": int(REF_TIME - 400 * 86400),
                "not_after": int(REF_TIME - 5 * 86400),  # expired 5 days ago
                "is_ca": False,
                "san": ["client.acme.com"],
            }]
        }
    }

    report = evaluate_auth_health(auth_meta, reference_time=REF_TIME)
    assert report.overall_health_status == CertHealthStatus.EXPIRED
    assert report.is_compliant is False
    assert len(report.critical_failures) >= 1

    exp_finding = next(f for f in report.critical_failures if f.rule_id == "CERT-HEALTH-EXPIRED-001")
    assert "Expired" in exp_finding.observed
    assert "CRITICAL: Immediately renew" in exp_finding.remediation


@test
def test_expiring_soon_warning():
    """Certificate expiring within 30 days must trigger WARNING / EXPIRING_SOON."""
    auth_meta = {
        "responder": {
            "identity": "10.0.0.1",
            "auth_method": 14,
            "certificates": [{
                "encoding": 4,
                "type": "end_entity",
                "subject": "CN=10.0.0.1",
                "cert_key_type_oid": "1.2.840.113549.1.1.1",
                "cert_key_len": 2048,
                "cert_sig_algo_oid": "1.2.840.113549.1.1.11",
                "not_before": int(REF_TIME - 300 * 86400),
                "not_after": int(REF_TIME + 12 * 86400),  # 12 days remaining
                "is_ca": False,
                "san": ["10.0.0.1"],
            }]
        }
    }

    report = evaluate_auth_health(auth_meta, reference_time=REF_TIME)
    assert report.overall_health_status == CertHealthStatus.EXPIRING_SOON
    assert report.is_compliant is True  # still valid today, so technically compliant with a warning
    assert len(report.warnings) >= 1

    warn_finding = next(w for w in report.warnings if w.rule_id == "CERT-HEALTH-EXPIRING-002")
    assert "12.0 days" in warn_finding.observed
    assert "WARNING: Initiate certificate renewal" in warn_finding.remediation


@test
def test_not_yet_valid_certificate():
    """Certificate with future start date must trigger NOT_YET_VALID."""
    auth_meta = {
        "initiator": {
            "identity": "client.acme.com",
            "certificates": [{
                "encoding": 4,
                "subject": "CN=client.acme.com",
                "cert_key_type_oid": "1.2.840.10045.2.1",
                "cert_key_len": 256,
                "cert_sig_algo_oid": "1.2.840.10045.4.3.2",
                "not_before": int(REF_TIME + 2 * 86400),  # starts in 2 days
                "not_after": int(REF_TIME + 365 * 86400),
                "is_ca": False,
                "san": ["client.acme.com"],
            }]
        }
    }

    report = evaluate_auth_health(auth_meta, reference_time=REF_TIME)
    assert report.overall_health_status == CertHealthStatus.NOT_YET_VALID
    assert report.is_compliant is False

    nyv_finding = next(f for f in report.all_findings if f.rule_id == "CERT-HEALTH-NOT-YET-VALID-003")
    assert "Not active until" in nyv_finding.observed
    assert "Check system time synchronization via NTP" in nyv_finding.remediation


@test
def test_san_identity_mismatch():
    """Identity mismatch between IKE ID and SAN/CN must trigger warning and advice."""
    auth_meta = {
        "initiator": {
            "identity": "attacker.com",
            "certificates": [{
                "encoding": 4,
                "subject": "CN=legitimate.acme.com",
                "cert_key_type_oid": "1.2.840.10045.2.1",
                "cert_key_len": 256,
                "cert_sig_algo_oid": "1.2.840.10045.4.3.2",
                "not_before": int(REF_TIME - 100 * 86400),
                "not_after": int(REF_TIME + 100 * 86400),
                "is_ca": False,
                "san": ["legitimate.acme.com", "alt.acme.com"],
            }]
        }
    }

    report = evaluate_auth_health(auth_meta, reference_time=REF_TIME)
    mismatch = next(f for f in report.all_findings if f.rule_id == "CERT-IDENTITY-SAN-004")
    assert mismatch.status == RuleStatus.WARNING
    assert "does not match any Subject Alternative Name" in mismatch.reason
    assert "Ensure the peer configuration specifies a matching IKE identity" in mismatch.remediation


@test
def test_intermediate_ca_lacking_ca_flag():
    """Intermediate CA with is_ca = False must trigger critical hierarchy violation."""
    auth_meta = {
        "initiator": {
            "identity": "client.acme.com",
            "certificates": [
                {
                    "type": "end_entity",
                    "subject": "CN=client.acme.com",
                    "is_ca": False,
                    "cert_key_type_oid": "1.2.840.10045.2.1",
                    "cert_key_len": 256,
                    "cert_sig_algo_oid": "1.2.840.10045.4.3.2",
                    "not_before": int(REF_TIME - 10 * 86400),
                    "not_after": int(REF_TIME + 100 * 86400),
                    "san": ["client.acme.com"],
                },
                {
                    "type": "intermediate_ca",
                    "subject": "CN=Subordinate Intermediate CA",
                    "is_ca": False,  # BUG: CA flag missing!
                    "cert_key_type_oid": "1.2.840.10045.2.1",
                    "cert_key_len": 256,
                    "cert_sig_algo_oid": "1.2.840.10045.4.3.2",
                    "not_before": int(REF_TIME - 10 * 86400),
                    "not_after": int(REF_TIME + 100 * 86400),
                }
            ]
        }
    }

    report = evaluate_auth_health(auth_meta, reference_time=REF_TIME)
    assert report.overall_health_status == CertHealthStatus.CRITICAL_DEFECT
    ca_flag_fail = next(f for f in report.critical_failures if f.rule_id == "CERT-CHAIN-CA-FLAG-005")
    assert "lacks the X.509 Basic Constraints extension 'cA=TRUE'" in ca_flag_fail.reason
    assert "basicConstraints = critical, CA:TRUE" in ca_flag_fail.remediation


@test
def test_missing_digital_signature_key_usage():
    """Key Usage present without digitalSignature must fail RFC 7427 requirement."""
    auth_meta = {
        "initiator": {
            "identity": "client.acme.com",
            "certificates": [{
                "subject": "CN=client.acme.com",
                "cert_key_type_oid": "1.2.840.10045.2.1",
                "cert_key_len": 256,
                "cert_sig_algo_oid": "1.2.840.10045.4.3.2",
                "not_before": int(REF_TIME - 10 * 86400),
                "not_after": int(REF_TIME + 100 * 86400),
                "is_ca": False,
                "san": ["client.acme.com"],
                "key_usage": ["keyEncipherment", "dataEncipherment"],  # missing digitalSignature!
            }]
        }
    }

    report = evaluate_auth_health(auth_meta, reference_time=REF_TIME)
    ku_finding = next(f for f in report.all_findings if f.rule_id == "CERT-EXT-KEYUSAGE-007")
    assert ku_finding.status == RuleStatus.FAIL
    assert "missing the 'digitalSignature' bit" in ku_finding.reason


@test
def test_broken_sig_in_intermediate_ca():
    """Even if leaf cert is strong, broken SHA-1 in Intermediate CA must fail whole chain."""
    auth_meta = {
        "initiator": {
            "identity": "client.acme.com",
            "certificates": [
                {
                    "type": "end_entity",
                    "subject": "CN=client.acme.com",
                    "cert_key_type_oid": "1.2.840.10045.2.1",
                    "cert_key_len": 384,
                    "cert_sig_algo_oid": "1.2.840.10045.4.3.3",  # SHA-384
                    "not_before": int(REF_TIME - 10 * 86400),
                    "not_after": int(REF_TIME + 100 * 86400),
                    "is_ca": False,
                    "san": ["client.acme.com"],
                },
                {
                    "type": "intermediate_ca",
                    "subject": "CN=Legacy CA",
                    "cert_key_type_oid": "1.2.840.113549.1.1.1",
                    "cert_key_len": 2048,
                    "cert_sig_algo_oid": "1.2.840.113549.1.1.5",  # BROKEN: sha1WithRSAEncryption
                    "not_before": int(REF_TIME - 10 * 86400),
                    "not_after": int(REF_TIME + 100 * 86400),
                    "is_ca": True,
                }
            ]
        }
    }

    report = evaluate_auth_health(auth_meta, reference_time=REF_TIME)
    assert report.overall_health_status == CertHealthStatus.CRITICAL_DEFECT
    sig_fail = next(f for f in report.critical_failures if f.rule_id == "CERT-CRYPTO-SIG-009")
    assert "SHA-1 hash is cryptographically broken" in sig_fail.reason
    assert "CRITICAL: Re-issue certificate immediately using secure signature algorithm" in sig_fail.remediation


@test
def test_sub_2048_rsa_key_length():
    """RSA 1024 must be flagged as DEPRECATED_BROKEN."""
    auth_meta = {
        "responder": {
            "identity": "gw.example.com",
            "certificates": [{
                "subject": "CN=gw.example.com",
                "cert_key_type_oid": "1.2.840.113549.1.1.1",
                "cert_key_len": 1024,  # INSUFFICIENT
                "cert_sig_algo_oid": "1.2.840.113549.1.1.11",
                "not_before": int(REF_TIME - 10 * 86400),
                "not_after": int(REF_TIME + 100 * 86400),
                "is_ca": False,
                "san": ["gw.example.com"],
            }]
        }
    }

    report = evaluate_auth_health(auth_meta, reference_time=REF_TIME)
    leaf = report.peers["responder"].leaf_cert
    assert leaf.rating.tier == CertRatingTier.DEPRECATED_BROKEN
    assert leaf.rating.score == 0.00
    assert "below the strict minimum 2048 bits" in leaf.rating.reason


@test
def test_non_x509_encoding_graceful_bypass():
    """Non-4 encoding must emit informative notice without crashing."""
    auth_meta = {
        "initiator": {
            "identity": "user@example.com",
            "certificates": [{
                "encoding": 2,  # PGP
                "data": "0x1234",
            }]
        }
    }

    report = evaluate_auth_health(auth_meta, reference_time=REF_TIME)
    notice = next(f for f in report.all_findings if f.rule_id == "CERT-ENCODING-000")
    assert notice.status == RuleStatus.INFORMATIONAL
    assert "not standard X.509" in notice.reason


@test
def test_legacy_session_fallback():
    """Legacy session with session['IKE_AUTH']['certificate'] should be audited seamlessly."""
    legacy_session = {
        "IKE_AUTH": {
            "exchange": "IKE_AUTH",
            "authentication": {"present": True, "auth_type": 14},
            "certificate": {
                "present": True,
                "encoding": 4,
                "subject": "CN=legacy.example.com",
                "cert_key_type_oid": "1.2.840.10045.2.1",
                "cert_key_len": 256,
                "cert_sig_algo_oid": "1.2.840.10045.4.3.2",
                "not_before": int(REF_TIME - 10 * 86400),
                "not_after": int(REF_TIME + 100 * 86400),
            }
        }
    }

    report = evaluate_auth_health(legacy_session, reference_time=REF_TIME)
    assert report.overall_health_status == CertHealthStatus.HEALTHY
    assert "peer" in report.peers
    assert report.peers["peer"].leaf_cert.subject == "CN=legacy.example.com"


@test
def test_output_formats():
    """Ensure both to_dict() and generate_summary() produce complete outputs."""
    auth_meta = {
        "initiator": {
            "identity": "client.acme.com",
            "auth_method": 14,
            "certificates": [{
                "subject": "CN=client.acme.com",
                "cert_key_type_oid": "1.2.840.10045.2.1",
                "cert_key_len": 256,
                "cert_sig_algo_oid": "1.2.840.10045.4.3.2",
                "not_before": int(REF_TIME - 10 * 86400),
                "not_after": int(REF_TIME + 15 * 86400),  # expiring soon
                "is_ca": False,
                "san": ["client.acme.com"],
            }]
        }
    }

    report = evaluate_auth_health(auth_meta, reference_time=REF_TIME)
    dict_out = report.to_dict()
    assert "overall_health_status" in dict_out
    assert "peers" in dict_out
    assert dict_out["summary"]["total_certificates_audited"] == 1

    summary_text = report.generate_summary()
    assert "IPSEC / IKEV2 CERTIFICATE HEALTH & PKI AUDIT REPORT" in summary_text
    assert "EXPIRING_SOON" in summary_text
    assert "CN=client.acme.com" in summary_text


if __name__ == "__main__":
    ok = run_all()
    sys.exit(0 if ok else 1)
