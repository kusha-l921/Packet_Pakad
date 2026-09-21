"""
daemonCertIngest.py — Out-of-Band Certificate Ingestion & Daemon API Connector.

In RFC 7296 (IKEv2), IKE_AUTH payloads (CERT, AUTH, ID) are encrypted inside
Payload 46 (SK). Passive wire sniffers cannot inspect certificates on the wire.
This dedicated script provides the out-of-band connector to ingest X.509 credentials
directly from:
  1. strongSwan VICI API (/var/run/charon.vici or python-vici)
  2. Local certificate files on disk (.pem, .crt, .der)
  3. Certificate directories (/etc/ipsec.d/certs/, /etc/swanctl/x509/)
  4. Webhook / REST JSON payloads

It normalizes credentials into the standardized `auth_metadata` schema and invokes
`certHealthEngine.py` for health, lifecycle, and cryptographic audits.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from .certHealthEngine import (
    CertHealthEngine,
    CertHealthReport,
    evaluate_auth_health,
    parse_x509_certificate,
)


def load_cert_bytes(file_path: str | Path) -> bytes:
    """Read certificate bytes from a PEM, CRT, or DER file on disk."""
    p = Path(file_path)
    if not p.is_file():
        raise FileNotFoundError(f"Certificate file not found: {p}")
    return p.read_bytes()


def parse_cert_source(
    source: str | bytes | Path,
    is_leaf: bool = True,
    san_override: list[str] | None = None,
) -> dict[str, Any]:
    """Parse certificate from a file path or raw bytes into a standardized dict.
    
    Supports both PEM and DER encodings.
    """
    if isinstance(source, (str, Path)):
        p = Path(source)
        if p.is_file():
            cert_bytes = p.read_bytes()
        elif isinstance(source, str) and ("-----BEGIN CERTIFICATE-----" in source):
            cert_bytes = source.encode("utf-8")
        else:
            raise FileNotFoundError(f"Certificate file not found: {source}")
    elif isinstance(source, bytes):
        cert_bytes = source
    else:
        raise TypeError(f"Unsupported certificate source type: {type(source)}")

    parsed = parse_x509_certificate(cert_bytes)
    
    cert_dict: dict[str, Any] = {
        "encoding": 4,  # X.509 Certificate - Signature (RFC 7296 Section 3.6)
        "type": "end_entity" if is_leaf else "intermediate_ca",
        "is_ca": not is_leaf,
    }
    cert_dict.update(parsed)

    if san_override is not None:
        cert_dict["san"] = san_override

    return cert_dict


def build_peer_credentials(
    peer_name: str,
    leaf_cert: str | bytes | Path,
    intermediate_certs: list[str | bytes | Path] | None = None,
    identity_value: str | None = None,
    identity_type: int = 2,  # ID_FQDN by default
    auth_method: int = 14,   # Digital Signature (RFC 7427)
) -> dict[str, Any]:
    """Build standardized peer credential dictionary with leaf and optional intermediate CAs."""
    certs = [parse_cert_source(leaf_cert, is_leaf=True)]
    
    if intermediate_certs:
        for ca in intermediate_certs:
            certs.append(parse_cert_source(ca, is_leaf=False))

    return {
        "identity": {
            "type": identity_type,
            "value": identity_value or (certs[0].get("san", [""])[0] if certs[0].get("san") else "unknown"),
        },
        "auth_method": auth_method,
        "certificates": certs,
    }


def build_auth_metadata(
    initiator: dict[str, Any] | None = None,
    responder: dict[str, Any] | None = None,
    source: str = "daemon_api",
    daemon_type: str = "strongswan",
) -> dict[str, Any]:
    """Assemble complete `auth_metadata` structure for rfcControlPlane and certHealthEngine."""
    meta: dict[str, Any] = {
        "source": source,
        "daemon_type": daemon_type,
    }
    if initiator:
        meta["initiator"] = initiator
    if responder:
        meta["responder"] = responder
    return meta


def attach_auth_to_session(session: dict[str, Any], auth_metadata: dict[str, Any]) -> dict[str, Any]:
    """Inject out-of-band `auth_metadata` into an existing packet-derived session dictionary."""
    session["auth_metadata"] = auth_metadata
    return session


def ingest_from_directory(
    dir_path: str | Path,
    identity_value: str | None = None,
) -> dict[str, Any]:
    """Scan a directory for .crt, .pem, .cer, or .der files and assemble credentials.
    
    The first non-CA certificate found is designated the leaf; any certificates
    with Basic Constraints cA=True are treated as intermediate CAs.
    """
    p = Path(dir_path)
    if not p.is_dir():
        raise NotADirectoryError(f"Directory not found: {p}")

    cert_files = sorted([
        f for f in p.iterdir()
        if f.suffix.lower() in (".pem", ".crt", ".cer", ".der")
    ])
    if not cert_files:
        raise FileNotFoundError(f"No certificate files (.pem, .crt, .der) found in {dir_path}")

    leaf_path: Path | None = None
    ca_paths: list[Path] = []

    for f in cert_files:
        try:
            parsed = parse_cert_source(f)
            if parsed.get("is_ca"):
                ca_paths.append(f)
            elif leaf_path is None:
                leaf_path = f
            else:
                ca_paths.append(f)
        except Exception:
            continue

    if leaf_path is None and ca_paths:
        leaf_path = ca_paths.pop(0)

    if leaf_path is None:
        raise ValueError(f"Could not parse any valid certificates from {dir_path}")

    peer_cred = build_peer_credentials(
        peer_name="responder",
        leaf_cert=leaf_path,
        intermediate_certs=ca_paths,
        identity_value=identity_value,
    )
    return build_auth_metadata(responder=peer_cred, source="directory_scan")


def ingest_from_vici(
    socket_path: str = "/var/run/charon.vici",
) -> dict[str, Any]:
    """Ingest certificates directly from strongSwan's VICI UNIX domain socket.
    
    If python `vici` package is installed and strongSwan is running, queries
    `list-certs` and extracts active X.509 certificates.
    """
    try:
        import vici  # type: ignore
        session = vici.Session(socket_path=socket_path)
        certs_found = []
        for cert in session.list_certs():
            data = cert.get("data")
            if data:
                certs_found.append(data)
        
        if certs_found:
            peer_cred = build_peer_credentials(
                peer_name="responder",
                leaf_cert=certs_found[0],
                intermediate_certs=certs_found[1:] if len(certs_found) > 1 else None,
            )
            return build_auth_metadata(responder=peer_cred, source="vici_socket")
        else:
            return {"source": "vici_socket", "status": "no_certificates_loaded", "responder": {}}
    except ImportError:
        return {
            "source": "vici_socket",
            "status": "vici_module_not_installed",
            "note": "Install 'vici' (pip install vici) or use file-based certificate ingestion.",
        }
    except Exception as e:
        return {
            "source": "vici_socket",
            "status": "connection_error",
            "error": str(e),
            "note": f"Could not connect to strongSwan VICI socket at {socket_path}.",
        }


# ═══════════════════════════════════════════════════════════════════════════
#  CLI Interface
# ═══════════════════════════════════════════════════════════════════════════

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Ingest X.509 certificates from daemon APIs or disk files and audit compliance."
    )
    parser.add_argument("--leaf", "-l", help="Path to leaf / end-entity certificate file (.pem, .crt, .der)")
    parser.add_argument("--ca", "-c", action="append", default=[], help="Path to intermediate CA certificate file (can repeat)")
    parser.add_argument("--id", "-i", help="Expected peer identity (FQDN or IP) to verify SAN/Identity match")
    parser.add_argument("--dir", "-d", help="Directory containing certificate files to scan and ingest")
    parser.add_argument("--vici", action="store_true", help="Ingest from strongSwan VICI UNIX socket")
    parser.add_argument("--vici-socket", default="/var/run/charon.vici", help="Path to strongSwan VICI socket")
    parser.add_argument("--audit", action="store_true", default=True, help="Run health and compliance audit immediately (default: True)")
    parser.add_argument("--json", action="store_true", help="Output results as formatted JSON")

    args = parser.parse_args()

    auth_metadata: dict[str, Any] = {}

    if args.vici:
        auth_metadata = ingest_from_vici(socket_path=args.vici_socket)
        if "error" in auth_metadata or "note" in auth_metadata:
            print(f"VICI notice: {auth_metadata.get('note') or auth_metadata.get('error')}", file=sys.stderr)
            if not auth_metadata.get("responder"):
                return 1

    elif args.dir:
        auth_metadata = ingest_from_directory(args.dir, identity_value=args.id)

    elif args.leaf:
        peer = build_peer_credentials(
            peer_name="responder",
            leaf_cert=args.leaf,
            intermediate_certs=args.ca if args.ca else None,
            identity_value=args.id,
        )
        auth_metadata = build_auth_metadata(responder=peer, source="file_ingest")

    else:
        parser.print_help()
        print("\nExample usage:")
        print("  python daemonCertIngest.py --leaf certs/server.crt --ca certs/ca.crt --id vpn.example.com")
        print("  python daemonCertIngest.py --dir /etc/ipsec.d/certs/ --id vpn.example.com")
        print("  python daemonCertIngest.py --vici")
        return 0

    if args.audit:
        report = evaluate_auth_health(auth_metadata)
        if args.json:
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(report.generate_summary())
        return 0 if report.is_compliant else 1

    print(json.dumps(auth_metadata, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
