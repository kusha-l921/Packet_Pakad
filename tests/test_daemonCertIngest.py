"""
test_daemonCertIngest.py — Unit tests for daemon certificate ingestion and CLI utility.
"""

import datetime
import os
import sys
import tempfile
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from cert_engine.certHealthEngine import CertHealthStatus, evaluate_auth_health
from cert_engine.daemonCertIngest import (
    attach_auth_to_session,
    build_auth_metadata,
    build_peer_credentials,
    ingest_from_directory,
    parse_cert_source,
)

_tests = []
_passed = 0
_failed = 0


def test(fn):
    _tests.append(fn)
    return fn


def _generate_test_cert_pem(common_name: str, is_ca: bool = False) -> bytes:
    key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(12345)
        .not_valid_before(datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=is_ca,
                crl_sign=is_ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    cert = builder.sign(key, hashes.SHA384())
    from cryptography.hazmat.primitives import serialization
    return cert.public_bytes(serialization.Encoding.PEM)


@test
def test_parse_pem_source():
    pem_bytes = _generate_test_cert_pem("server.example.com", is_ca=False)
    parsed = parse_cert_source(pem_bytes, is_leaf=True)
    assert parsed["encoding"] == 4
    assert parsed["type"] == "end_entity"
    assert parsed["is_ca"] is False
    assert parsed["cert_key_len"] == 384
    assert "server.example.com" in parsed["san"]


@test
def test_build_peer_credentials_and_metadata():
    leaf_pem = _generate_test_cert_pem("server.example.com", is_ca=False)
    ca_pem = _generate_test_cert_pem("ca.example.com", is_ca=True)

    peer = build_peer_credentials(
        peer_name="responder",
        leaf_cert=leaf_pem,
        intermediate_certs=[ca_pem],
        identity_value="server.example.com",
    )
    assert peer["identity"]["value"] == "server.example.com"
    assert len(peer["certificates"]) == 2
    assert peer["certificates"][0]["type"] == "end_entity"
    assert peer["certificates"][1]["type"] == "intermediate_ca"

    auth_meta = build_auth_metadata(responder=peer)
    assert auth_meta["source"] == "daemon_api"
    assert "responder" in auth_meta


@test
def test_attach_auth_to_session():
    session = {"IKE_SA_INIT": {"exchange": "IKE_SA_INIT"}}
    auth_meta = {"source": "daemon_api", "initiator": {}}
    attached = attach_auth_to_session(session, auth_meta)
    assert "auth_metadata" in attached
    assert attached["auth_metadata"]["source"] == "daemon_api"


@test
def test_directory_scan_and_audit():
    with tempfile.TemporaryDirectory() as tmpdir:
        leaf_pem = _generate_test_cert_pem("vpn.corp.com", is_ca=False)
        ca_pem = _generate_test_cert_pem("corp-ca.corp.com", is_ca=True)
        
        leaf_file = Path(tmpdir) / "leaf.pem"
        ca_file = Path(tmpdir) / "ca.pem"
        leaf_file.write_bytes(leaf_pem)
        ca_file.write_bytes(ca_pem)

        auth_meta = ingest_from_directory(tmpdir, identity_value="vpn.corp.com")
        assert "responder" in auth_meta
        assert len(auth_meta["responder"]["certificates"]) == 2

        report = evaluate_auth_health(auth_meta, reference_time=1789992000.0)
        assert report.is_compliant is True
        assert report.overall_health_status == CertHealthStatus.HEALTHY


def run_all():
    global _passed, _failed
    print("=" * 80)
    print("RUNNING DAEMON CERTIFICATE INGESTION TEST SUITE")
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


if __name__ == "__main__":
    import sys
    sys.exit(0 if run_all() else 1)
