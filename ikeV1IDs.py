"""
IANA IKEv1 / ISAKMP Parameters — number-to-name lookup tables.

Sources (both registries are officially "closed" per RFC 9395, meaning no
further values will be assigned, but existing values remain in use by
deployed IKEv1 implementations):
  - "Internet Key Exchange (IKE) Attributes" (Phase 1, RFC 2409)
    https://www.iana.org/assignments/ipsec-registry
  - "'Magic Numbers' for ISAKMP Protocol" (Phase 2 / DOI-specific, RFC 2407/2408)
    https://www.iana.org/assignments/isakmp-registry

This module contains ONLY data (dicts). No functions, no classes, no parsing
logic. Ranges labeled "Reserved" / "Unassigned" / "Reserved for private use"
are omitted since they aren't single discrete key->name pairs; only
individually-assigned numeric values are included below.
"""

# =========================================================================
# Phase 1 / IKE Attributes (RFC 2409) — from ipsec-registry
# =========================================================================

# Attribute Classes (the 16-bit attribute "type" field itself)
IKEV1_ATTRIBUTE_CLASSES = {
    1: "Encryption Algorithm",
    2: "Hash Algorithm",
    3: "Authentication Method",
    4: "Group Description",
    5: "Group Type",
    6: "Group Prime/Irreducible Polynomial",
    7: "Group Generator One",
    8: "Group Generator Two",
    9: "Group Curve A",
    10: "Group Curve B",
    11: "Life Type",
    12: "Life Duration",
    13: "PRF",
    14: "Key Length",
    15: "Field Size",
    16: "Group Order",
}

# Encryption Algorithm Class Values (Attribute Class 1)
IKEV1_ENCRYPTION_ALGORITHMS = {
    0: "Reserved",
    1: "DES-CBC",
    2: "IDEA-CBC",
    3: "Blowfish-CBC",
    4: "RC5-R16-B64-CBC",
    5: "3DES-CBC",
    6: "CAST-CBC",
    7: "AES-CBC",
    8: "CAMELLIA-CBC",
}

# Hash Algorithm (Attribute Class 2)
IKEV1_HASH_ALGORITHMS = {
    0: "Reserved",
    1: "MD5",
    2: "SHA",
    3: "Tiger",
    4: "SHA2-256",
    5: "SHA2-384",
    6: "SHA2-512",
}

# IPSEC Authentication Methods (Attribute Class 3)
IKEV1_AUTHENTICATION_METHODS = {
    0: "Reserved",
    1: "pre-shared key",
    2: "DSS signatures",
    3: "RSA signatures",
    4: "Encryption with RSA",
    5: "Revised encryption with RSA",
    6: "Reserved (was Encryption with El-Gamal)",
    7: "Reserved (was Revised encryption with El-Gamal)",
    8: "Reserved (was ECDSA signatures)",
    9: "ECDSA with SHA-256 on the P-256 curve",
    10: "ECDSA with SHA-384 on the P-384 curve",
    11: "ECDSA with SHA-512 on the P-521 curve",
}

# Group Description / Diffie-Hellman groups (Attribute Class 4)
IKEV1_GROUP_DESCRIPTIONS = {
    0: "Reserved",
    1: "default 768-bit MODP group",
    2: "alternate 1024-bit MODP group",
    3: "EC2N group on GP[2^155]",
    4: "EC2N group on GP[2^185]",
    5: "1536-bit MODP group",
    6: "EC2N group over GF[2^163]",
    7: "EC2N group over GF[2^163]",
    8: "EC2N group over GF[2^283]",
    9: "EC2N group over GF[2^283]",
    10: "EC2N group over GF[2^409]",
    11: "EC2N group over GF[2^409]",
    12: "EC2N group over GF[2^571]",
    13: "EC2N group over GF[2^571]",
    14: "2048-bit MODP group",
    15: "3072-bit MODP group",
    16: "4096-bit MODP group",
    17: "6144-bit MODP group",
    18: "8192-bit MODP group",
    19: "256-bit random ECP group",
    20: "384-bit random ECP group",
    21: "521-bit random ECP group",
    22: "1024-bit MODP Group with 160-bit Prime Order Subgroup",
    23: "2048-bit MODP Group with 224-bit Prime Order Subgroup",
    24: "2048-bit MODP Group with 256-bit Prime Order Subgroup",
    25: "192-bit Random ECP Group",
    26: "224-bit Random ECP Group",
    27: "224-bit Brainpool ECP group",
    28: "256-bit Brainpool ECP group",
    29: "384-bit Brainpool ECP group",
    30: "512-bit Brainpool ECP group",
}

# Group Type (Attribute Class 5)
IKEV1_GROUP_TYPES = {
    0: "Reserved",
    1: "MODP (modular exponentiation group)",
    2: "ECP (elliptic curve group over GF[P])",
    3: "EC2N (elliptic curve group over GF[2^N])",
}

# Life Type (Attribute Class 11)
IKEV1_LIFE_TYPES = {
    0: "Reserved",
    1: "seconds",
    2: "kilobytes",
}

# Phase 1 / Phase 2 Exchange Types
IKEV1_EXCHANGE_TYPES = {
    0: "NONE",
    1: "Base",
    2: "Identity Protection",
    3: "Authentication Only",
    4: "Aggressive",
    5: "Informational",
    32: "Quick Mode",
    33: "New Group Mode",
}

# ISAKMP Domain of Interpretation (DOI)
IKEV1_DOI = {
    0: "ISAKMP",
    1: "IPSEC",
    2: "GDOI",
}

# Next Payload Types
IKEV1_NEXT_PAYLOAD_TYPES = {
    0: "NONE",
    1: "Security Association (SA)",
    2: "Proposal (P)",
    3: "Transform (T)",
    4: "Key Exchange (KE)",
    5: "Identification (ID)",
    6: "Certificate (CERT)",
    7: "Certificate Request (CR)",
    8: "Hash (HASH)",
    9: "Signature (SIG)",
    10: "Nonce (NONCE)",
    11: "Notification (N)",
    12: "Delete (D)",
    13: "Vendor ID (VID)",
    14: "Reserved, not to be used",
    15: "SA KEK Payload (SAK)",
    16: "SA TEK Payload (SAT)",
    17: "Key Download (KD)",
    18: "Sequence Number (SEQ)",
    19: "Proof of Possession (POP)",
    20: "NAT Discovery (NAT-D)",
    21: "NAT Original Address (NAT-OA)",
    22: "Group Associated Policy (GAP)",
}

# Notify Messages - Error Types (Phase 1 registry, range 1-8191)
IKEV1_NOTIFY_ERROR_TYPES = {
    1: "INVALID-PAYLOAD-TYPE",
    2: "DOI-NOT-SUPPORTED",
    3: "SITUATION-NOT-SUPPORTED",
    4: "INVALID-COOKIE",
    5: "INVALID-MAJOR-VERSION",
    6: "INVALID-MINOR-VERSION",
    7: "INVALID-EXCHANGE-TYPE",
    8: "INVALID-FLAGS",
    9: "INVALID-MESSAGE-ID",
    10: "INVALID-PROTOCOL-ID",
    11: "INVALID-SPI",
    12: "INVALID-TRANSFORM-ID",
    13: "ATTRIBUTES-NOT-SUPPORTED",
    14: "NO-PROPOSAL-CHOSEN",
    15: "BAD-PROPOSAL-SYNTAX",
    16: "PAYLOAD-MALFORMED",
    17: "INVALID-KEY-INFORMATION",
    18: "INVALID-ID-INFORMATION",
    19: "INVALID-CERT-ENCODING",
    20: "INVALID-CERTIFICATE",
    21: "CERT-TYPE-UNSUPPORTED",
    22: "INVALID-CERT-AUTHORITY",
    23: "INVALID-HASH-INFORMATION",
    24: "AUTHENTICATION-FAILED",
    25: "INVALID-SIGNATURE",
    26: "ADDRESS-NOTIFICATION",
    27: "NOTIFY-SA-LIFETIME",
    28: "CERTIFICATE-UNAVAILABLE",
    29: "UNSUPPORTED-EXCHANGE-TYPE",
    30: "UNEQUAL-PAYLOAD-LENGTHS",
}

# Notify Messages - Status Types (Phase 1 registry, range 16384-24575)
IKEV1_NOTIFY_STATUS_TYPES = {
    16384: "CONNECTED",
}


# =========================================================================
# ISAKMP "Magic Numbers" / Phase 2 & DOI-specific (RFC 2407/2408)
# from isakmp-registry
# =========================================================================

# IPSEC Situation Definition (32-bit bitmask, not a simple enum)
ISAKMP_SITUATION_FLAGS = {
    0x01: "SIT_IDENTITY_ONLY",
    0x02: "SIT_SECRECY",
    0x04: "SIT_INTEGRITY",
}

# IPSEC Security Protocol Identifiers
ISAKMP_SECURITY_PROTOCOL_IDENTIFIERS = {
    0: "RESERVED",
    1: "PROTO_ISAKMP",
    2: "PROTO_IPSEC_AH",
    3: "PROTO_IPSEC_ESP",
    4: "PROTO_IPCOMP",
    5: "PROTO_GIGABEAM_RADIO",
}

# IPSEC ISAKMP Transform Identifiers (key exchange protocol for negotiation)
ISAKMP_TRANSFORM_IDENTIFIERS = {
    0: "RESERVED",
    1: "KEY_IKE",
}

# IPSEC AH Transform Identifiers
ISAKMP_AH_TRANSFORM_IDENTIFIERS = {
    2: "AH_MD5",
    3: "AH_SHA",
    4: "AH_DES",
    5: "AH_SHA2-256",
    6: "AH_SHA2-384",
    7: "AH_SHA2-512",
    8: "AH_RIPEMD",
    9: "AH_AES-XCBC-MAC",
    10: "AH_RSA",
    11: "AH_AES-128-GMAC",
    12: "AH_AES-192-GMAC",
    13: "AH_AES-256-GMAC",
}

# IPSEC ESP Transform Identifiers
ISAKMP_ESP_TRANSFORM_IDENTIFIERS = {
    0: "RESERVED",
    1: "ESP_DES_IV64",
    2: "ESP_DES",
    3: "ESP_3DES",
    4: "ESP_RC5",
    5: "ESP_IDEA",
    6: "ESP_CAST",
    7: "ESP_BLOWFISH",
    8: "ESP_3IDEA",
    9: "ESP_DES_IV32",
    10: "ESP_RC4",
    11: "ESP_NULL",
    12: "ESP_AES-CBC",
    13: "ESP_AES-CTR",
    14: "ESP_AES-CCM_8",
    15: "ESP_AES-CCM_12",
    16: "ESP_AES-CCM_16",
    18: "ESP_AES-GCM_8",
    19: "ESP_AES-GCM_12",
    20: "ESP_AES-GCM_16",
    21: "ESP_SEED_CBC",
    22: "ESP_CAMELLIA",
    23: "ESP_NULL_AUTH_AES-GMAC",
}

# IPSEC IPCOMP Transform Identifiers
ISAKMP_IPCOMP_TRANSFORM_IDENTIFIERS = {
    0: "RESERVED",
    1: "IPCOMP_OUI",
    2: "IPCOMP_DEFLATE",
    3: "IPCOMP_LZS",
    4: "IPCOMP_LZJH",
}

# IPSEC Security Association Attribute types (16-bit type field used in
# Phase 2 / Quick Mode SA attributes)
ISAKMP_SA_ATTRIBUTE_TYPES = {
    1: "SA Life Type",
    2: "SA Life Duration",
    3: "Group Description",
    4: "Encapsulation Mode",
    5: "Authentication Algorithm",
    6: "Key Length",
    7: "Key Rounds",
    8: "Compress Dictionary Size",
    9: "Compress Private Algorithm",
    10: "ECN Tunnel",
    11: "Extended (64-bit) Sequence Number",
    12: "Authentication Key Length",
    13: "Signature Encoding Algorithm",
    14: "Address Preservation",
    15: "SA Direction",
}

# SA Life Type Values (SA Attribute type 1)
ISAKMP_SA_LIFE_TYPES = {
    0: "Reserved",
    1: "seconds",
    2: "kilobytes",
}

# Encapsulation Mode (SA Attribute type 4)
ISAKMP_ENCAPSULATION_MODES = {
    0: "Reserved",
    1: "Tunnel",
    2: "Transport",
    3: "UDP-Encapsulated-Tunnel",
    4: "UDP-Encapsulated-Transport",
}

# Authentication Algorithm (SA Attribute type 5)
ISAKMP_AUTHENTICATION_ALGORITHMS = {
    0: "Reserved",
    1: "HMAC-MD5",
    2: "HMAC-SHA",
    3: "DES-MAC",
    4: "KPDK",
    5: "HMAC-SHA2-256",
    6: "HMAC-SHA2-384",
    7: "HMAC-SHA2-512",
    8: "HMAC-RIPEMD",
    9: "AES-XCBC-MAC",
    10: "SIG-RSA",
    11: "AES-128-GMAC",
    12: "AES-192-GMAC",
    13: "AES-256-GMAC",
}

# ECN Tunnel (SA Attribute type 10)
ISAKMP_ECN_TUNNEL = {
    0: "Reserved",
    1: "Allowed",
    2: "Forbidden",
}

# Extended (64-bit) Sequence Number (SA Attribute type 11)
ISAKMP_EXTENDED_SEQUENCE_NUMBER = {
    0: "RESERVED",
    1: "64-bit Sequence Number",
}

# Signature Encoding Algorithm Values (SA Attribute type 13)
ISAKMP_SIGNATURE_ENCODING_ALGORITHMS = {
    0: "Reserved",
    1: "RSASSA-PKCS1-v1_5",
    2: "RSASSA-PSS",
}

# Address Preservation (SA Attribute type 14)
ISAKMP_ADDRESS_PRESERVATION = {
    0: "Reserved",
    1: "None",
    2: "Source-Only",
    3: "Destination-Only",
    4: "Source-and-Destination",
}

# SA Direction (SA Attribute type 15)
ISAKMP_SA_DIRECTION = {
    0: "Reserved",
    1: "Sender-Only",
    2: "Receiver-Only",
    3: "Symmetric",
}

# IPSEC Identification Type
ISAKMP_IDENTIFICATION_TYPES = {
    0: "RESERVED",
    1: "ID_IPV4_ADDR",
    2: "ID_FQDN",
    3: "ID_USER_FQDN",
    4: "ID_IPV4_ADDR_SUBNET",
    5: "ID_IPV6_ADDR",
    6: "ID_IPV6_ADDR_SUBNET",
    7: "ID_IPV4_ADDR_RANGE",
    8: "ID_IPV6_ADDR_RANGE",
    9: "ID_DER_ASN1_DN",
    10: "ID_DER_ASN1_GN",
    11: "ID_KEY_ID",
    12: "ID_LIST",
}

# IPSEC Notify Message Types - Status Types (DOI-specific, range 24576-32767)
ISAKMP_NOTIFY_STATUS_TYPES = {
    24576: "RESPONDER-LIFETIME",
    24577: "REPLAY-STATUS",
    24578: "INITIAL-CONTACT",
    # --- RFC 3706 Dead Peer Detection (DPD) ---
    36136: "R-U-THERE",
    36137: "R-U-THERE-ACK",
}

# ISAKMP / IKEv1 Certificate Encodings (RFC 2408 section 3.9)
IKEV1_CERTIFICATE_ENCODINGS = {
    0: "None",
    1: "PKCS #7 wrapped X.509 certificate",
    2: "PGP Certificate",
    3: "DNS Signed Key",
    4: "X.509 Certificate - Signature",
    5: "X.509 Certificate - Key Exchange",
    6: "Kerberos Tokens",
    7: "Certificate Revocation List (CRL)",
    8: "Authority Revocation List (ARL)",
    9: "SPKI Certificate",
    10: "X.509 Certificate - Attribute",
    11: "Raw RSA Key",
    12: "Hash and URL of X.509 certificate",
    13: "Hash and URL of X.509 bundle",
}

IKEV1_SIGNATURE_ENCODING_ALGORITHMS = ISAKMP_SIGNATURE_ENCODING_ALGORITHMS