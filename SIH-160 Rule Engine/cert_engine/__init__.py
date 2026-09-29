"""
cert_engine — Dedicated PKI & X.509 Certificate Health Engine Package.

Provides auditing of X.509 (Encoding 4) credentials, validity windows,
expiration warnings, CA hierarchy checks, SAN identity matching, and out-of-band
daemon API ingestion (strongSwan VICI, Libreswan, and local files).
"""

from __future__ import annotations

from .certHealthEngine import (
    CertEvaluation,
    CertFinding,
    CertHealthEngine,
    CertHealthReport,
    CertHealthStatus,
    CertRating,
    CertRatingTier,
    PeerCertAudit,
    RuleStatus,
    Severity,
    evaluate_auth_health,
    parse_ikev2_cert_payload,
    parse_x509_certificate,
    rate_certificate_crypto,
)
from .daemonCertIngest import (
    attach_auth_to_session,
    build_auth_metadata,
    build_peer_credentials,
    ingest_from_directory,
    ingest_from_vici,
    parse_cert_source,
)

__all__ = [
    "CertHealthEngine",
    "CertHealthReport",
    "CertHealthStatus",
    "CertRatingTier",
    "RuleStatus",
    "Severity",
    "CertFinding",
    "CertRating",
    "CertEvaluation",
    "PeerCertAudit",
    "evaluate_auth_health",
    "parse_x509_certificate",
    "parse_ikev2_cert_payload",
    "rate_certificate_crypto",
    "build_auth_metadata",
    "build_peer_credentials",
    "attach_auth_to_session",
    "ingest_from_directory",
    "ingest_from_vici",
    "parse_cert_source",
]
