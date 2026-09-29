"""
certHealthEngine.py — Standalone PKI & Certificate Health Compliance Engine.

Dedicated engine for auditing X.509 (Encoding 4) certificate health, certificate chains,
validity windows, and cryptographic strength against NSA CNSA 2.0, NIST SP 800-52r2,
NIST SP 800-131A, and RFC 8247 guidelines.

Features:
  • Multi-Peer Auditing (Initiator and Responder)
  • Full Chain Inspection (End-Entity Leaf + Intermediate CAs)
  • Health & Lifecycle Checks (Expiration, Not-Yet-Valid, 30-Day / 7-Day Early Warnings)
  • CA Hierarchy Validation (Basic Constraints cA flags on leaf vs intermediate)
  • Identity Matching (IKE ID vs Subject Alternative Names / Subject CN)
  • Standards-Based Rating (CNSA 2.0, NIST Modern, RFC 8247, Deprecated/Broken)
  • Hardcoded Reasons & Actionable Recommendations for every finding
  • Dual Output (JSON report and Human-Readable ASCII Summary)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


# ═══════════════════════════════════════════════════════════════════════════
#  Enums & Classifications
# ═══════════════════════════════════════════════════════════════════════════

class CertRatingTier(str, Enum):
    CNSA_2_0 = "CNSA_2_0"                     # Quantum-Resistant (ML-DSA-87 / 256-bit)
    NIST_MODERN = "NIST_MODERN"               # Modern Baseline (128/192-bit)
    RFC8247_ACCEPTABLE = "RFC8247_ACCEPTABLE" # Classical Baseline (RSA-2048 / 112-bit)
    DEPRECATED_BROKEN = "DEPRECATED_BROKEN"   # Prohibited / Broken (<112-bit)


class CertHealthStatus(str, Enum):
    HEALTHY = "HEALTHY"
    EXPIRING_SOON = "EXPIRING_SOON"
    EXPIRED = "EXPIRED"
    NOT_YET_VALID = "NOT_YET_VALID"
    CRITICAL_DEFECT = "CRITICAL_DEFECT"


class RuleStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    INFORMATIONAL = "INFORMATIONAL"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


# ═══════════════════════════════════════════════════════════════════════════
#  Cryptographic OID Registries
# ═══════════════════════════════════════════════════════════════════════════

# Public Key Algorithm Names & Security
CERT_KEY_TYPE_NAMES: dict[str, str] = {
    "1.2.840.10040.4.1": "DSA",
    "1.2.840.113549.1.1.1": "RSA (rsaEncryption)",
    "1.2.840.113549.1.1.10": "RSASSA-PSS",
    "1.2.840.10045.2.1": "ECDSA (id-ecPublicKey)",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
}

# Signature Algorithm Names & Security
CERT_SIG_ALGO_NAMES: dict[str, str] = {
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.2.840.10040.4.3": "dsa-with-sha1",
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
}

BROKEN_SIG_OIDS = {
    "1.2.840.113549.1.1.4": "MD5 hash is cryptographically broken (collision attacks)",
    "1.2.840.113549.1.1.5": "SHA-1 hash is cryptographically broken (RFC 8247 prohibited)",
    "1.2.840.10045.4.1": "SHA-1 hash is cryptographically broken (RFC 8247 prohibited)",
    "1.2.840.10040.4.3": "DSA with SHA-1 is prohibited and obsolete",
}

BROKEN_KEY_OIDS = {
    "1.2.840.10040.4.1": "DSA algorithm is obsolete and prohibited by RFC 8247 §3",
}

PQC_KEY_OIDS = {
    "2.16.840.1.101.3.4.3.17",
    "2.16.840.1.101.3.4.3.18",
    "2.16.840.1.101.3.4.3.19",
}


# ═══════════════════════════════════════════════════════════════════════════
#  Data Models
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class CertFinding:
    """Individual rule evaluation finding for a specific certificate."""
    rule_id: str
    status: RuleStatus
    severity: Severity
    target: str
    condition: str
    observed: Any
    expected: str
    reason: str
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "status": self.status.value,
            "severity": self.severity.value,
            "target": self.target,
            "condition": self.condition,
            "observed": str(self.observed) if self.observed is not None else "None",
            "expected": self.expected,
            "reason": self.reason,
            "remediation": self.remediation,
        }


@dataclass
class CertRating:
    """Cryptographic standards rating for a certificate."""
    tier: CertRatingTier
    score: float
    security_bits: int
    cnsa_2_0_compliant: bool
    nist_modern_compliant: bool
    rfc8247_compliant: bool
    reason: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier.value,
            "score": round(self.score, 2),
            "security_bits": self.security_bits,
            "cnsa_2_0_compliant": self.cnsa_2_0_compliant,
            "nist_modern_compliant": self.nist_modern_compliant,
            "rfc8247_compliant": self.rfc8247_compliant,
            "reason": self.reason,
            "recommendation": self.recommendation,
        }


@dataclass
class CertEvaluation:
    """Comprehensive evaluation record for a single certificate."""
    index: int
    cert_type: str  # "end_entity" (leaf) or "intermediate_ca" or "root_ca"
    subject: str
    issuer: str
    serial_number: str | None
    is_ca: bool
    key_type_oid: str | None
    key_type_name: str
    key_bits: int | None
    sig_algo_oid: str | None
    sig_algo_name: str
    not_before: int | None
    not_after: int | None
    days_until_expiration: float | None
    health_status: CertHealthStatus
    rating: CertRating
    findings: list[CertFinding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "cert_type": self.cert_type,
            "subject": self.subject,
            "issuer": self.issuer,
            "serial_number": self.serial_number,
            "is_ca": self.is_ca,
            "key_type_oid": self.key_type_oid,
            "key_type_name": self.key_type_name,
            "key_bits": self.key_bits,
            "sig_algo_oid": self.sig_algo_oid,
            "sig_algo_name": self.sig_algo_name,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "days_until_expiration": round(self.days_until_expiration, 1) if self.days_until_expiration is not None else None,
            "health_status": self.health_status.value,
            "rating": self.rating.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class PeerCertAudit:
    """Aggregated certificate and identity audit for a single peer (Initiator or Responder)."""
    peer: str
    identity: Any
    auth_method: int | None
    peer_status: CertHealthStatus
    chain_length: int
    leaf_cert: CertEvaluation | None = None
    chain_certs: list[CertEvaluation] = field(default_factory=list)
    findings: list[CertFinding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "peer": self.peer,
            "identity": self.identity,
            "auth_method": self.auth_method,
            "peer_status": self.peer_status.value,
            "chain_length": self.chain_length,
            "leaf_certificate": self.leaf_cert.to_dict() if self.leaf_cert else None,
            "chain_certificates": [c.to_dict() for c in self.chain_certs],
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class CertHealthReport:
    """Master evaluation report produced by the Certificate Health Engine."""
    overall_health_status: CertHealthStatus
    is_compliant: bool
    reference_time: float
    peers: dict[str, PeerCertAudit] = field(default_factory=dict)
    all_findings: list[CertFinding] = field(default_factory=list)

    @property
    def critical_failures(self) -> list[CertFinding]:
        return [f for f in self.all_findings if f.status == RuleStatus.FAIL and f.severity == Severity.CRITICAL]

    @property
    def warnings(self) -> list[CertFinding]:
        return [f for f in self.all_findings if f.status == RuleStatus.WARNING]

    @property
    def passed_rules(self) -> list[CertFinding]:
        return [f for f in self.all_findings if f.status == RuleStatus.PASS]

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_health_status": self.overall_health_status.value,
            "is_compliant": self.is_compliant,
            "reference_time": self.reference_time,
            "summary": {
                "total_certificates_audited": sum(p.chain_length for p in self.peers.values()),
                "critical_failures_count": len(self.critical_failures),
                "warnings_count": len(self.warnings),
                "passed_count": len(self.passed_rules),
            },
            "peers": {name: peer.to_dict() for name, peer in self.peers.items()},
            "findings": [f.to_dict() for f in self.all_findings],
        }

    def generate_summary(self) -> str:
        """Format human-readable ASCII summary for CLI / logs."""
        lines = []
        lines.append("=" * 80)
        lines.append("           IPSEC / IKEV2 CERTIFICATE HEALTH & PKI AUDIT REPORT")
        lines.append("=" * 80)
        lines.append(f"OVERALL HEALTH:  {self.overall_health_status.value}")
        lines.append(f"COMPLIANT:       {'YES' if self.is_compliant else 'NO'}")
        ref_dt = datetime.fromtimestamp(self.reference_time, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        lines.append(f"EVALUATED AT:    {ref_dt}")
        lines.append("-" * 80)

        for peer_name, peer in self.peers.items():
            lines.append(f"PEER: {peer_name.upper()} (Status: {peer.peer_status.value})")
            lines.append(f"  Identity:    {peer.identity}")
            lines.append(f"  Auth Method: {peer.auth_method} (14 = Digital Signature RFC 7427)")
            lines.append(f"  Cert Chain:  {peer.chain_length} certificate(s)")

            if peer.leaf_cert:
                lc = peer.leaf_cert
                lines.append(f"  ├── Leaf Cert: {lc.subject or 'Unknown'}")
                lines.append(f"  │   ├── Health:     {lc.health_status.value} (Expires in: {lc.days_until_expiration:.1f} days)" if lc.days_until_expiration is not None else f"  │   ├── Health:     {lc.health_status.value}")
                lines.append(f"  │   ├── Key:        {lc.key_type_name} ({lc.key_bits or '?'} bits)")
                lines.append(f"  │   ├── Signature:  {lc.sig_algo_name}")
                lines.append(f"  │   └── Rating:     {lc.rating.tier.value} ({lc.rating.security_bits}-bit security equivalent)")

            for idx, cc in enumerate(peer.chain_certs, 1):
                lines.append(f"  └── Chain #{idx}: {cc.subject} (is_ca: {cc.is_ca}, Rating: {cc.rating.tier.value})")

        if self.critical_failures or self.warnings:
            lines.append("-" * 80)
            lines.append("CRITICAL ISSUES & WARNINGS:")
            for f in self.critical_failures:
                lines.append(f"  [CRITICAL] [{f.rule_id}] {f.target}: {f.reason}")
                lines.append(f"             Remediation: {f.remediation}")
            for w in self.warnings:
                lines.append(f"  [WARNING]  [{w.rule_id}] {w.target}: {w.reason}")
                lines.append(f"             Remediation: {w.remediation}")

        lines.append("=" * 80)
        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════
#  X.509 Binary DER Parser
# ═══════════════════════════════════════════════════════════════════════════

def parse_x509_certificate(cert_data: bytes) -> dict:
    """Parse X.509 DER certificate bytes into a rich metadata dictionary.
    
    Extracts key type OID, key length in bits, signature algorithm OID,
    lifecycle timestamps (not_before, not_after), Subject / Issuer DNs,
    serial number, basic constraints (is_ca), Subject Alternative Names (SAN),
    and Key Usage flags.
    """
    if not cert_data:
        return {}

    cert_key_type_oid = None
    cert_key_len = None
    cert_sig_algo_oid = None
    not_before = None
    not_after = None
    subject = None
    issuer = None
    serial_number = None
    is_ca = False
    san_list = []
    key_usage_list = []

    try:
        import cryptography.x509 as x509
        from cryptography.x509.oid import ExtensionOID
        if isinstance(cert_data, str):
            cert_data = cert_data.encode("utf-8")
        if b"-----BEGIN CERTIFICATE-----" in cert_data:
            parsed_cert = x509.load_pem_x509_certificate(cert_data)
        else:
            parsed_cert = x509.load_der_x509_certificate(cert_data)

        # Public key algorithm OID
        if hasattr(parsed_cert, "public_key_algorithm_oid"):
            cert_key_type_oid = str(parsed_cert.public_key_algorithm_oid.dotted_string)

        # Signature algorithm OID
        if hasattr(parsed_cert, "signature_algorithm_oid"):
            cert_sig_algo_oid = str(parsed_cert.signature_algorithm_oid.dotted_string)

        # Public key length in bits
        pub_key = parsed_cert.public_key()
        if hasattr(pub_key, "key_size"):
            cert_key_len = int(pub_key.key_size)
        elif hasattr(pub_key, "curve") and hasattr(pub_key.curve, "key_size"):
            cert_key_len = int(pub_key.curve.key_size)
        elif hasattr(pub_key, "public_bytes_raw"):
            cert_key_len = len(pub_key.public_bytes_raw()) * 8

        # Validity timestamps (Unix epoch seconds)
        if hasattr(parsed_cert, "not_valid_before_utc"):
            not_before = int(parsed_cert.not_valid_before_utc.timestamp())
        elif hasattr(parsed_cert, "not_valid_before"):
            not_before = int(parsed_cert.not_valid_before.timestamp())

        if hasattr(parsed_cert, "not_valid_after_utc"):
            not_after = int(parsed_cert.not_valid_after_utc.timestamp())
        elif hasattr(parsed_cert, "not_valid_after"):
            not_after = int(parsed_cert.not_valid_after.timestamp())

        # Subject & Issuer DNs (RFC 4514 format)
        if hasattr(parsed_cert, "subject"):
            subject = parsed_cert.subject.rfc4514_string()
        if hasattr(parsed_cert, "issuer"):
            issuer = parsed_cert.issuer.rfc4514_string()

        # Serial Number (hex)
        if hasattr(parsed_cert, "serial_number"):
            serial_number = hex(parsed_cert.serial_number)

        # Basic Constraints: is_ca
        try:
            bc_ext = parsed_cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
            is_ca = bool(bc_ext.value.ca)
        except Exception:
            is_ca = False

        # Subject Alternative Names (SAN)
        try:
            san_ext = parsed_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            for name in san_ext.value:
                san_list.append(str(name.value))
        except Exception:
            san_list = []

        # Key Usage
        try:
            ku_ext = parsed_cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            ku_val = ku_ext.value
            for attr_name in (
                "digital_signature", "content_commitment", "key_encipherment",
                "data_encipherment", "key_agreement", "key_cert_sign",
                "crl_sign", "encipher_only", "decipher_only"
            ):
                try:
                    if getattr(ku_val, attr_name):
                        parts = attr_name.split("_")
                        camel = parts[0] + "".join(p.capitalize() for p in parts[1:])
                        key_usage_list.append(camel)
                except ValueError:
                    pass
        except Exception:
            key_usage_list = []

    except Exception:
        pass

    return {
        "cert_key_type_oid": cert_key_type_oid,
        "cert_key_len": cert_key_len,
        "cert_sig_algo_oid": cert_sig_algo_oid,
        "not_before": not_before,
        "not_after": not_after,
        "subject": subject,
        "issuer": issuer,
        "serial_number": serial_number,
        "is_ca": is_ca,
        "san": san_list,
        "key_usage": key_usage_list,
    }


def parse_ikev2_cert_payload(data: bytes | None) -> dict | None:
    """Parse IKEv2 CERT payload data (RFC 7296 Section 3.6).
    
    Byte 0: Certificate Encoding (4 = X.509 Certificate - Signature).
    Bytes 1+: Raw Certificate Data.
    """
    if not data or len(data) < 1:
        return None
    encoding = data[0]
    cert_data = data[1:] if len(data) > 1 else None

    result = {
        "encoding": encoding,
        "supported": (encoding == 4),
        "data": f"0x{cert_data.hex()}" if cert_data else None,
        "cert_key_type_oid": None,
        "cert_key_len": None,
        "cert_sig_algo_oid": None,
        "not_before": None,
        "not_after": None,
        "subject": None,
        "issuer": None,
        "serial_number": None,
        "is_ca": False,
        "san": [],
        "key_usage": [],
    }

    if encoding == 4 and cert_data:
        x509_meta = parse_x509_certificate(cert_data)
        result.update(x509_meta)
    elif encoding != 4:
        result["note"] = f"Certificate encoding {encoding} is not standard X.509 (Encoding 4)"

    return result


# ═══════════════════════════════════════════════════════════════════════════
#  Rating & Standards Evaluation Helper
# ═══════════════════════════════════════════════════════════════════════════

def rate_certificate_crypto(
    key_type_oid: str | None,
    key_bits: int | None,
    sig_algo_oid: str | None,
) -> CertRating:
    """Rate a certificate against CNSA 2.0, NIST SP 800-52r2, and RFC 8247."""
    key_name = CERT_KEY_TYPE_NAMES.get(key_type_oid or "", key_type_oid or "Unknown")
    sig_name = CERT_SIG_ALGO_NAMES.get(sig_algo_oid or "", sig_algo_oid or "Unknown")

    # 1. Prohibited / Broken Checks
    if sig_algo_oid in BROKEN_SIG_OIDS:
        return CertRating(
            tier=CertRatingTier.DEPRECATED_BROKEN,
            score=0.00,
            security_bits=0,
            cnsa_2_0_compliant=False,
            nist_modern_compliant=False,
            rfc8247_compliant=False,
            reason=f"Certificate signature uses broken algorithm '{sig_name}' ({BROKEN_SIG_OIDS[sig_algo_oid]}). Strictly prohibited by RFC 8247 §3.",
            recommendation=f"CRITICAL: Re-issue certificate immediately using secure signature algorithm (SHA-256, SHA-384, or ML-DSA-87).",
        )

    if key_type_oid in BROKEN_KEY_OIDS:
        return CertRating(
            tier=CertRatingTier.DEPRECATED_BROKEN,
            score=0.00,
            security_bits=0,
            cnsa_2_0_compliant=False,
            nist_modern_compliant=False,
            rfc8247_compliant=False,
            reason=f"Public key algorithm '{key_name}' is obsolete and prohibited ({BROKEN_KEY_OIDS[key_type_oid]}).",
            recommendation="CRITICAL: Re-issue certificate with modern public key (ECDSA P-384, Ed25519, RSA-3072, or ML-DSA-87).",
        )

    # Sub-2048 RSA check
    is_rsa = key_type_oid in ("1.2.840.113549.1.1.1", "1.2.840.113549.1.1.10")
    if is_rsa and key_bits is not None and key_bits < 2048:
        return CertRating(
            tier=CertRatingTier.DEPRECATED_BROKEN,
            score=0.00,
            security_bits=80 if key_bits <= 1024 else 96,
            cnsa_2_0_compliant=False,
            nist_modern_compliant=False,
            rfc8247_compliant=False,
            reason=f"RSA key length {key_bits} bits is below the strict minimum 2048 bits required by RFC 8247 §3 and NIST SP 800-131A.",
            recommendation="Upgrade public key to at least RSA 2048-bit (112-bit security) or preferably ECDSA P-384 / ML-DSA-87.",
        )

    # Sub-256 ECC check
    is_ecc = key_type_oid == "1.2.840.10045.2.1"
    if is_ecc and key_bits is not None and key_bits < 256:
        return CertRating(
            tier=CertRatingTier.DEPRECATED_BROKEN,
            score=0.00,
            security_bits=80,
            cnsa_2_0_compliant=False,
            nist_modern_compliant=False,
            rfc8247_compliant=False,
            reason=f"ECC key length {key_bits} bits is below the minimum 256 bits required by NIST SP 800-131A.",
            recommendation="Upgrade ECC key to at least P-256 (128-bit security) or P-384 (192-bit security).",
        )

    # 2. CNSA 2.0 (Post-Quantum 256-bit Security)
    if key_type_oid == "2.16.840.1.101.3.4.3.19" or key_type_oid == "1.3.101.113":  # ML-DSA-87 or Ed448
        return CertRating(
            tier=CertRatingTier.CNSA_2_0,
            score=1.00,
            security_bits=256,
            cnsa_2_0_compliant=True,
            nist_modern_compliant=True,
            rfc8247_compliant=True,
            reason=f"{key_name} provides NIST Security Category 5 (256-bit quantum-resistant security), fully compliant with NSA CNSA 2.0 mandate.",
            recommendation="Optimal post-quantum configuration. No cryptographic upgrade required.",
        )

    # Transitionally CNSA 2.0 acceptable classical (ECDSA P-384 with SHA-384)
    if is_ecc and key_bits == 384 and sig_algo_oid in ("1.2.840.10045.4.3.3", "1.2.840.10045.4.3.4"):
        return CertRating(
            tier=CertRatingTier.NIST_MODERN,
            score=0.90,
            security_bits=192,
            cnsa_2_0_compliant=False,  # classical, but meets transitional CNSA 1.0 / high NIST
            nist_modern_compliant=True,
            rfc8247_compliant=True,
            reason=f"ECDSA P-384 with {sig_name} provides 192-bit classical security. Exceeds standard NIST requirements but lacks quantum resistance.",
            recommendation="To achieve CNSA 2.0 quantum resistance before 2030, plan migration to ML-DSA-87 (FIPS 204).",
        )

    # 3. NIST Modern Baseline (128-bit Security)
    is_nist_modern_key = (
        (is_ecc and (key_bits or 256) >= 256)
        or key_type_oid == "1.3.101.112"  # Ed25519
        or key_type_oid in ("2.16.840.1.101.3.4.3.17", "2.16.840.1.101.3.4.3.18")  # ML-DSA-44/65
        or (is_rsa and (key_bits or 0) >= 3072)
    )
    if is_nist_modern_key:
        return CertRating(
            tier=CertRatingTier.NIST_MODERN,
            score=0.75,
            security_bits=128,
            cnsa_2_0_compliant=False,
            nist_modern_compliant=True,
            rfc8247_compliant=True,
            reason=f"{key_name} ({key_bits or 256} bits) with {sig_name} provides 128-bit modern classical security per NIST SP 800-52r2.",
            recommendation="Meets current modern baselines. For future quantum safety, plan migration to ML-DSA (FIPS 204).",
        )

    # 4. RFC 8247 Classical Baseline (RSA-2048 / 112-bit Security)
    if is_rsa and (key_bits or 2048) >= 2048:
        return CertRating(
            tier=CertRatingTier.RFC8247_ACCEPTABLE,
            score=0.55,
            security_bits=112,
            cnsa_2_0_compliant=False,
            nist_modern_compliant=False,
            rfc8247_compliant=True,
            reason=f"RSA-2048 provides only 112-bit symmetric equivalent security. Acceptable under legacy RFC 8247, but deprecated by NIST SP 800-52r2 and vulnerable to quantum cryptanalysis.",
            recommendation="Upgrade to ECDSA P-384 or ML-DSA-87 (PQC) to satisfy NIST and CNSA 2.0 guidelines.",
        )

    # Fallback
    return CertRating(
        tier=CertRatingTier.RFC8247_ACCEPTABLE,
        score=0.50,
        security_bits=112,
        cnsa_2_0_compliant=False,
        nist_modern_compliant=False,
        rfc8247_compliant=True,
        reason=f"Certificate public key {key_name} meets basic classical criteria.",
        recommendation="Consider upgrading to modern 128-bit (ECDSA P-256) or 256-bit PQC (ML-DSA-87) algorithms.",
    )


# ═══════════════════════════════════════════════════════════════════════════
#  Certificate Health Evaluation Engine
# ═══════════════════════════════════════════════════════════════════════════

class CertHealthEngine:
    """Standalone PKI and X.509 Certificate Health Rule Engine."""

    def __init__(self, expiry_warning_days: int = 30, critical_warning_days: int = 7):
        self.expiry_warning_days = expiry_warning_days
        self.critical_warning_days = critical_warning_days

    def evaluate_certificate(
        self,
        cert_dict: dict[str, Any],
        peer: str,
        index: int,
        is_leaf: bool,
        peer_identity: Any,
        reference_time: float,
    ) -> CertEvaluation:
        """Evaluate a single certificate in a peer's chain."""
        findings: list[CertFinding] = []
        target = f"{peer}:{'leaf' if is_leaf else f'ca#{index}'}"

        encoding = cert_dict.get("encoding", 4)
        if encoding != 4:
            finding = CertFinding(
                rule_id="CERT-ENCODING-000",
                status=RuleStatus.INFORMATIONAL,
                severity=Severity.INFORMATIONAL,
                target=target,
                condition="Certificate encoding check",
                observed=f"Encoding {encoding}",
                expected="Encoding 4 (X.509 Certificate - Signature)",
                reason=f"Certificate encoding {encoding} is not standard X.509 (Encoding 4). Skipping deep X.509 inspection.",
                remediation="Configure VPN peer to use standard X.509 certificates (Encoding 4).",
            )
            findings.append(finding)

        subject = cert_dict.get("subject") or "Unknown Subject"
        issuer = cert_dict.get("issuer") or "Unknown Issuer"
        serial = cert_dict.get("serial_number")
        is_ca = bool(cert_dict.get("is_ca", False))
        not_before = cert_dict.get("not_before")
        not_after = cert_dict.get("not_after")
        key_oid = cert_dict.get("cert_key_type_oid")
        key_len = cert_dict.get("cert_key_len")
        sig_oid = cert_dict.get("cert_sig_algo_oid")
        san_list = cert_dict.get("san", [])
        key_usage = cert_dict.get("key_usage", [])

        # ── Health & Lifecycle Checks ───────────────────────────────────
        health_status = CertHealthStatus.HEALTHY
        days_until_exp = None

        if not_after is not None:
            seconds_left = not_after - reference_time
            days_until_exp = seconds_left / 86400.0
            exp_date_str = datetime.fromtimestamp(not_after, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

            if seconds_left < 0:
                health_status = CertHealthStatus.EXPIRED
                days_ago = abs(days_until_exp)
                findings.append(CertFinding(
                    rule_id="CERT-HEALTH-EXPIRED-001",
                    status=RuleStatus.FAIL,
                    severity=Severity.CRITICAL,
                    target=target,
                    condition="Certificate validity expiration check",
                    observed=f"Expired {days_ago:.1f} days ago ({exp_date_str})",
                    expected="Certificate validity period MUST be active (not_after > current_time)",
                    reason=f"Certificate expired on {exp_date_str} ({days_ago:.1f} days ago). An expired certificate invalidates peer trust and causes immediate connection rejection or security vulnerability.",
                    remediation="CRITICAL: Immediately renew and deploy a replacement certificate from your CA. Update the daemon certificate store and reload credentials.",
                ))
            elif days_until_exp <= self.expiry_warning_days:
                health_status = CertHealthStatus.EXPIRING_SOON
                sev = Severity.HIGH if days_until_exp <= self.critical_warning_days else Severity.MEDIUM
                findings.append(CertFinding(
                    rule_id="CERT-HEALTH-EXPIRING-002",
                    status=RuleStatus.WARNING,
                    severity=sev,
                    target=target,
                    condition="Certificate expiration early-warning threshold",
                    observed=f"Expires in {days_until_exp:.1f} days ({exp_date_str})",
                    expected=f"Certificate validity SHOULD exceed {self.expiry_warning_days} days",
                    reason=f"Certificate will expire in {days_until_exp:.1f} days (on {exp_date_str}). VPN connection will fail upon expiration.",
                    remediation=f"WARNING: Initiate certificate renewal with your CA within {int(days_until_exp)} days to avoid service interruption.",
                ))
            else:
                findings.append(CertFinding(
                    rule_id="CERT-HEALTH-EXPIRED-001",
                    status=RuleStatus.PASS,
                    severity=Severity.INFORMATIONAL,
                    target=target,
                    condition="Certificate expiration status",
                    observed=f"Valid ({days_until_exp:.1f} days remaining)",
                    expected="Active certificate",
                    reason="Certificate is within active validity period.",
                    remediation="None required.",
                ))

        if not_before is not None:
            if not_before > reference_time:
                health_status = CertHealthStatus.NOT_YET_VALID
                start_date_str = datetime.fromtimestamp(not_before, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                findings.append(CertFinding(
                    rule_id="CERT-HEALTH-NOT-YET-VALID-003",
                    status=RuleStatus.FAIL,
                    severity=Severity.HIGH,
                    target=target,
                    condition="Certificate activation date check",
                    observed=f"Not active until {start_date_str}",
                    expected="Certificate validity period MUST have started (not_before <= current_time)",
                    reason=f"Certificate validity period begins in the future ({start_date_str}). This usually indicates server clock skew or premature deployment.",
                    remediation="Check system time synchronization via NTP ('chrony' or 'ntpd'). If system clock is correct, wait until the validity start time before activating.",
                ))

        # ── CA Hierarchy & Basic Constraints ────────────────────────────
        if is_leaf:
            if is_ca:
                findings.append(CertFinding(
                    rule_id="CERT-CHAIN-LEAF-FLAG-006",
                    status=RuleStatus.WARNING,
                    severity=Severity.MEDIUM,
                    target=target,
                    condition="Leaf certificate Basic Constraints check",
                    observed="is_ca = TRUE",
                    expected="End-entity certificate MUST have is_ca = FALSE",
                    reason="End-entity (leaf) certificate is configured as a Certificate Authority (cA=TRUE). This violates the principle of least privilege.",
                    remediation="Re-issue the client/server certificate with 'basicConstraints = CA:FALSE' to prevent misuse as an unauthorized signing CA.",
                ))
        else:
            # Intermediate CA in chain
            if not is_ca:
                health_status = CertHealthStatus.CRITICAL_DEFECT
                findings.append(CertFinding(
                    rule_id="CERT-CHAIN-CA-FLAG-005",
                    status=RuleStatus.FAIL,
                    severity=Severity.CRITICAL,
                    target=target,
                    condition="Intermediate CA Basic Constraints check",
                    observed="is_ca = FALSE",
                    expected="Intermediate CA certificates MUST have is_ca = TRUE",
                    reason=f"Intermediate certificate '{subject}' lacks the X.509 Basic Constraints extension 'cA=TRUE'. It cannot legally sign subordinate certificates (RFC 5280 §4.2.1.9).",
                    remediation="Re-issue the intermediate certificate with 'basicConstraints = critical, CA:TRUE' and an appropriate path length constraint.",
                ))

        # ── Key Usage Extension ─────────────────────────────────────────
        if key_usage:
            if is_leaf and "digitalSignature" not in key_usage:
                findings.append(CertFinding(
                    rule_id="CERT-EXT-KEYUSAGE-007",
                    status=RuleStatus.FAIL,
                    severity=Severity.HIGH,
                    target=target,
                    condition="Key Usage digitalSignature extension check",
                    observed=f"Key usage flags: {key_usage}",
                    expected="Must include 'digitalSignature' for IKEv2 authentication",
                    reason="Certificate Key Usage extension is present but missing the 'digitalSignature' bit, which is required for IKEv2 authentication (RFC 7427).",
                    remediation="Re-issue certificate with keyUsage including 'digitalSignature' (and optionally 'keyEncipherment' / 'serverAuth' / 'clientAuth').",
                ))

        # ── Identity / SAN Matching (Leaf Only) ─────────────────────────
        if is_leaf and peer_identity is not None:
            id_val = peer_identity.get("value") if isinstance(peer_identity, dict) else str(peer_identity)
            if id_val:
                # Check SAN and Subject CN
                matched = False
                if id_val in san_list:
                    matched = True
                elif f"CN={id_val}" in subject:
                    matched = True

                if not matched:
                    findings.append(CertFinding(
                        rule_id="CERT-IDENTITY-SAN-004",
                        status=RuleStatus.WARNING,
                        severity=Severity.HIGH,
                        target=target,
                        condition="IKE identity to Certificate SAN/CN matching",
                        observed=f"IKE ID '{id_val}' not in SANs ({san_list}) or Subject ({subject})",
                        expected=f"Presented IKE identity MUST match certificate SAN or Subject CN (RFC 7296 §3.5)",
                        reason=f"The presented IKE identity '{id_val}' does not match any Subject Alternative Name (SAN DNS/IP) or Subject CN in the certificate (RFC 7296 §3.5).",
                        remediation=f"Ensure the peer configuration specifies a matching IKE identity ('leftid'/'rightid'), or re-issue the certificate with the correct SAN extension (e.g. subjectAltName = DNS:{id_val} or IP:{id_val}).",
                    ))
                else:
                    findings.append(CertFinding(
                        rule_id="CERT-IDENTITY-SAN-004",
                        status=RuleStatus.PASS,
                        severity=Severity.INFORMATIONAL,
                        target=target,
                        condition="IKE identity to Certificate SAN/CN match",
                        observed=f"IKE ID '{id_val}' matches certificate identity",
                        expected="Identity match verified",
                        reason="IKE Identity is correctly bound to certificate Subject Alternative Name / Subject CN.",
                        remediation="None required.",
                    ))

        # ── Cryptographic Rating & Standards Compliance ─────────────────
        rating = rate_certificate_crypto(key_oid, key_len, sig_oid)
        if rating.tier == CertRatingTier.DEPRECATED_BROKEN:
            health_status = CertHealthStatus.CRITICAL_DEFECT
            findings.append(CertFinding(
                rule_id="CERT-CRYPTO-SIG-009",
                status=RuleStatus.FAIL,
                severity=Severity.CRITICAL,
                target=target,
                condition="Certificate cryptographic security baseline",
                observed=f"Key: {key_oid} ({key_len} bits), Sig: {sig_oid}",
                expected="Secure public key and modern signature algorithm (SHA-256+ / ML-DSA)",
                reason=rating.reason,
                remediation=rating.recommendation,
            ))
        else:
            findings.append(CertFinding(
                rule_id="CERT-CRYPTO-SIG-009",
                status=RuleStatus.PASS,
                severity=Severity.INFORMATIONAL,
                target=target,
                condition="Certificate signature and key security",
                observed=f"{CERT_KEY_TYPE_NAMES.get(key_oid or '', key_oid)} ({key_len}b) / {CERT_SIG_ALGO_NAMES.get(sig_oid or '', sig_oid)}",
                expected="RFC 8247 compliant cryptographic suite",
                reason=rating.reason,
                remediation=rating.recommendation,
            ))

        return CertEvaluation(
            index=index,
            cert_type="end_entity" if is_leaf else "intermediate_ca",
            subject=subject,
            issuer=issuer,
            serial_number=serial,
            is_ca=is_ca,
            key_type_oid=key_oid,
            key_type_name=CERT_KEY_TYPE_NAMES.get(key_oid or "", key_oid or "Unknown"),
            key_bits=key_len,
            sig_algo_oid=sig_oid,
            sig_algo_name=CERT_SIG_ALGO_NAMES.get(sig_oid or "", sig_oid or "Unknown"),
            not_before=not_before,
            not_after=not_after,
            days_until_expiration=days_until_exp,
            health_status=health_status,
            rating=rating,
            findings=findings,
        )

    def evaluate_auth_health(
        self,
        auth_metadata: dict[str, Any],
        reference_time: float | None = None,
    ) -> CertHealthReport:
        """Evaluate complete auth_metadata dictionary containing initiator and responder credentials."""
        if reference_time is None:
            reference_time = time.time()

        peers_audit: dict[str, PeerCertAudit] = {}
        all_findings: list[CertFinding] = []
        overall_status = CertHealthStatus.HEALTHY
        is_compliant = True

        # Normalize input: support either direct auth_metadata or top-level session
        if "auth_metadata" in auth_metadata:
            auth_meta = auth_metadata["auth_metadata"]
        else:
            auth_meta = auth_metadata

        for peer_name in ("initiator", "responder"):
            peer_data = auth_meta.get(peer_name)
            if not peer_data or not isinstance(peer_data, dict):
                continue

            identity = peer_data.get("identity")
            auth_method = peer_data.get("auth_method")
            cert_list = peer_data.get("certificates", [])

            # Support single 'certificate' fallback
            if not cert_list and "certificate" in peer_data:
                cert_list = [peer_data["certificate"]]

            peer_evaluations: list[CertEvaluation] = []
            peer_findings: list[CertFinding] = []
            peer_status = CertHealthStatus.HEALTHY

            for idx, c_dict in enumerate(cert_list):
                if not isinstance(c_dict, dict):
                    continue
                is_leaf = (idx == 0 or c_dict.get("type") in ("end_entity", "leaf"))

                eval_res = self.evaluate_certificate(
                    cert_dict=c_dict,
                    peer=peer_name,
                    index=idx,
                    is_leaf=is_leaf,
                    peer_identity=identity if is_leaf else None,
                    reference_time=reference_time,
                )
                peer_evaluations.append(eval_res)
                peer_findings.extend(eval_res.findings)
                all_findings.extend(eval_res.findings)

                # Escalate peer status
                if eval_res.health_status == CertHealthStatus.EXPIRED:
                    peer_status = CertHealthStatus.EXPIRED
                    overall_status = CertHealthStatus.EXPIRED
                    is_compliant = False
                elif eval_res.health_status == CertHealthStatus.CRITICAL_DEFECT:
                    if peer_status != CertHealthStatus.EXPIRED:
                        peer_status = CertHealthStatus.CRITICAL_DEFECT
                    if overall_status != CertHealthStatus.EXPIRED:
                        overall_status = CertHealthStatus.CRITICAL_DEFECT
                    is_compliant = False
                elif eval_res.health_status == CertHealthStatus.NOT_YET_VALID:
                    if peer_status not in (CertHealthStatus.EXPIRED, CertHealthStatus.CRITICAL_DEFECT):
                        peer_status = CertHealthStatus.NOT_YET_VALID
                    if overall_status not in (CertHealthStatus.EXPIRED, CertHealthStatus.CRITICAL_DEFECT):
                        overall_status = CertHealthStatus.NOT_YET_VALID
                    is_compliant = False
                elif eval_res.health_status == CertHealthStatus.EXPIRING_SOON:
                    if peer_status == CertHealthStatus.HEALTHY:
                        peer_status = CertHealthStatus.EXPIRING_SOON
                    if overall_status == CertHealthStatus.HEALTHY:
                        overall_status = CertHealthStatus.EXPIRING_SOON

            leaf_cert = peer_evaluations[0] if peer_evaluations else None
            chain_certs = peer_evaluations[1:] if len(peer_evaluations) > 1 else []

            peers_audit[peer_name] = PeerCertAudit(
                peer=peer_name,
                identity=identity,
                auth_method=auth_method,
                peer_status=peer_status,
                chain_length=len(peer_evaluations),
                leaf_cert=leaf_cert,
                chain_certs=chain_certs,
                findings=peer_findings,
            )

        # Handle legacy session structure if peers_audit is empty
        if not peers_audit and "IKE_AUTH" in auth_metadata:
            legacy_cert = auth_metadata["IKE_AUTH"].get("certificate")
            if legacy_cert and legacy_cert.get("present"):
                eval_res = self.evaluate_certificate(
                    cert_dict=legacy_cert,
                    peer="peer",
                    index=0,
                    is_leaf=True,
                    peer_identity=None,
                    reference_time=reference_time,
                )
                all_findings.extend(eval_res.findings)
                overall_status = eval_res.health_status
                is_compliant = (overall_status not in (CertHealthStatus.EXPIRED, CertHealthStatus.CRITICAL_DEFECT, CertHealthStatus.NOT_YET_VALID))
                peers_audit["peer"] = PeerCertAudit(
                    peer="peer",
                    identity="unknown",
                    auth_method=auth_metadata["IKE_AUTH"].get("authentication", {}).get("auth_type"),
                    peer_status=overall_status,
                    chain_length=1,
                    leaf_cert=eval_res,
                    chain_certs=[],
                    findings=eval_res.findings,
                )

        return CertHealthReport(
            overall_health_status=overall_status,
            is_compliant=is_compliant,
            reference_time=reference_time,
            peers=peers_audit,
            all_findings=all_findings,
        )


# Global default engine instance
default_cert_health_engine = CertHealthEngine()


def evaluate_auth_health(
    auth_metadata: dict[str, Any],
    reference_time: float | None = None,
    expiry_warning_days: int = 30,
    critical_warning_days: int = 7,
) -> CertHealthReport:
    """Public convenience function to evaluate certificate health on auth_metadata."""
    engine = CertHealthEngine(
        expiry_warning_days=expiry_warning_days,
        critical_warning_days=critical_warning_days,
    )
    return engine.evaluate_auth_health(auth_metadata, reference_time=reference_time)
