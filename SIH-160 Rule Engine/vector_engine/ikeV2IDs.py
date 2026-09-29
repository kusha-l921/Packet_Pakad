"""
IANA IKEv2 Parameters — number-to-name lookup tables.

Source: https://www.iana.org/assignments/ikev2-parameters
(registry snapshot as of the "Last Updated" date shown on that page)

This module contains ONLY data (dicts). No functions, no classes, no parsing
logic. Ranges labeled "Reserved" / "Unassigned" / "Reserved for Private Use"
in the registry are omitted since they aren't single discrete key->name pairs;
only individually-assigned numeric values are included below.
"""

# IKEv2 Exchange Types
IKEV2_EXCHANGE_TYPES = {
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL",
    38: "IKE_SESSION_RESUME",
    39: "GSA_AUTH",
    40: "GSA_REGISTRATION",
    41: "GSA_REKEY",
    42: "GSA_INBAND_REKEY",
    43: "IKE_INTERMEDIATE",
    44: "IKE_FOLLOWUP_KE",
}

# IKEv2 Payload Types
IKEV2_PAYLOAD_TYPES = {
    0: "No Next Payload",
    33: "Security Association (SA)",
    34: "Key Exchange (KE)",
    35: "Identification - Initiator (IDi)",
    36: "Identification - Responder (IDr)",
    37: "Certificate (CERT)",
    38: "Certificate Request (CERTREQ)",
    39: "Authentication (AUTH)",
    40: "Nonce (Ni, Nr)",
    41: "Notify (N)",
    42: "Delete (D)",
    43: "Vendor ID (V)",
    44: "Traffic Selector - Initiator (TSi)",
    45: "Traffic Selector - Responder (TSr)",
    46: "Encrypted and Authenticated (SK)",
    47: "Configuration (CP)",
    48: "Extensible Authentication (EAP)",
    49: "Generic Secure Password Method (GSPM)",
    50: "Group Identification (IDg)",
    51: "Group Security Association (GSA)",
    52: "Key Download (KD)",
    53: "Encrypted and Authenticated Fragment (SKF)",
    54: "Puzzle Solution (PS)",
}

# Transform Type Values (the "Type" field inside a Transform payload)
IKEV2_TRANSFORM_TYPES = {
    0: "Reserved",
    1: "Encryption Algorithm (ENCR)",
    2: "Pseudo-random Function (PRF)",
    3: "Integrity Algorithm (INTEG)",
    4: "Key Exchange Method (KE)",
    5: "Sequence Numbers (SN)",
    6: "Additional Key Exchange 1 (ADDKE1)",
    7: "Additional Key Exchange 2 (ADDKE2)",
    8: "Additional Key Exchange 3 (ADDKE3)",
    9: "Additional Key Exchange 4 (ADDKE4)",
    10: "Additional Key Exchange 5 (ADDKE5)",
    11: "Additional Key Exchange 6 (ADDKE6)",
    12: "Additional Key Exchange 7 (ADDKE7)",
    13: "Key Wrap Algorithm (KWA)",
    14: "Group Controller Authentication Method (GCAUTH)",
}

# IKEv2 Transform Attribute Types
IKEV2_TRANSFORM_ATTRIBUTE_TYPES = {
    14: "Key Length (in bits)",
    18: "Signature Algorithm Identifier",
}

# Transform Type 1 - Encryption Algorithm Transform IDs
IKEV2_ENCRYPTION_ALGORITHMS = {
    0: "Reserved",
    1: "ENCR_DES_IV64",
    2: "ENCR_DES",
    3: "ENCR_3DES",
    4: "ENCR_RC5",
    5: "ENCR_IDEA",
    6: "ENCR_CAST",
    7: "ENCR_BLOWFISH",
    8: "ENCR_3IDEA",
    9: "ENCR_DES_IV32",
    10: "Reserved",
    11: "ENCR_NULL",
    12: "ENCR_AES_CBC",
    13: "ENCR_AES_CTR",
    14: "ENCR_AES_CCM_8",
    15: "ENCR_AES_CCM_12",
    16: "ENCR_AES_CCM_16",
    18: "ENCR_AES_GCM_8",
    19: "ENCR_AES_GCM_12",
    20: "ENCR_AES_GCM_16",
    21: "ENCR_NULL_AUTH_AES_GMAC",
    22: "Reserved for IEEE P1619 XTS-AES",
    23: "ENCR_CAMELLIA_CBC",
    24: "ENCR_CAMELLIA_CTR",
    25: "ENCR_CAMELLIA_CCM_8",
    26: "ENCR_CAMELLIA_CCM_12",
    27: "ENCR_CAMELLIA_CCM_16",
    28: "ENCR_CHACHA20_POLY1305",
    29: "ENCR_AES_CCM_8_IIV",
    30: "ENCR_AES_GCM_16_IIV",
    31: "ENCR_CHACHA20_POLY1305_IIV",
    32: "ENCR_KUZNYECHIK_MGM_KTREE",
    33: "ENCR_MAGMA_MGM_KTREE",
    34: "ENCR_KUZNYECHIK_MGM_MAC_KTREE",
    35: "ENCR_MAGMA_MGM_MAC_KTREE",
}

# Transform Type 2 - Pseudorandom Function Transform IDs
IKEV2_PRF_ALGORITHMS = {
    0: "Reserved",
    1: "PRF_HMAC_MD5",
    2: "PRF_HMAC_SHA1",
    3: "PRF_HMAC_TIGER",
    4: "PRF_AES128_XCBC",
    5: "PRF_HMAC_SHA2_256",
    6: "PRF_HMAC_SHA2_384",
    7: "PRF_HMAC_SHA2_512",
    8: "PRF_AES128_CMAC",
    9: "PRF_HMAC_STREEBOG_512",
}

# Transform Type 3 - Integrity Algorithm Transform IDs
IKEV2_INTEGRITY_ALGORITHMS = {
    0: "NONE",
    1: "AUTH_HMAC_MD5_96",
    2: "AUTH_HMAC_SHA1_96",
    3: "AUTH_DES_MAC",
    4: "AUTH_KPDK_MD5",
    5: "AUTH_AES_XCBC_96",
    6: "AUTH_HMAC_MD5_128",
    7: "AUTH_HMAC_SHA1_160",
    8: "AUTH_AES_CMAC_96",
    9: "AUTH_AES_128_GMAC",
    10: "AUTH_AES_192_GMAC",
    11: "AUTH_AES_256_GMAC",
    12: "AUTH_HMAC_SHA2_256_128",
    13: "AUTH_HMAC_SHA2_384_192",
    14: "AUTH_HMAC_SHA2_512_256",
}

# Transform Type 4 - Key Exchange Method Transform IDs (formerly "D-H Group")
IKEV2_KEY_EXCHANGE_METHODS = {
    0: "NONE",
    1: "768-bit MODP Group",
    2: "1024-bit MODP Group",
    5: "1536-bit MODP Group",
    14: "2048-bit MODP Group",
    15: "3072-bit MODP Group",
    16: "4096-bit MODP Group",
    17: "6144-bit MODP Group",
    18: "8192-bit MODP Group",
    19: "256-bit random ECP group",
    20: "384-bit random ECP group",
    21: "521-bit random ECP group",
    22: "1024-bit MODP Group with 160-bit Prime Order Subgroup",
    23: "2048-bit MODP Group with 224-bit Prime Order Subgroup",
    24: "2048-bit MODP Group with 256-bit Prime Order Subgroup",
    25: "192-bit Random ECP Group",
    26: "224-bit Random ECP Group",
    27: "brainpoolP224r1",
    28: "brainpoolP256r1",
    29: "brainpoolP384r1",
    30: "brainpoolP512r1",
    31: "Curve25519",
    32: "Curve448",
    33: "GOST3410_2012_256",
    34: "GOST3410_2012_512",
    35: "ml-kem-512",
    36: "ml-kem-768",
    37: "ml-kem-1024",
    38: "FrodoKEM-640-AES",
    39: "FrodoKEM-976-AES",
    40: "FrodoKEM-1344-AES",
    1035: "X25519 + ML-KEM-768",
    1036: "ECDH P-256 + ML-KEM-768",
    1037: "X448 + ML-KEM-1024",
    1038: "ECDH P-384 + ML-KEM-1024",
}

# Transform Type 5 - Sequence Numbers Transform IDs (formerly "ESN")
IKEV2_SEQUENCE_NUMBERS_TYPES = {
    0: "32-bit Sequential Numbers",
    1: "Partially Transmitted 64-bit Sequential Numbers",
    2: "32-bit Unspecified Numbers",
}

# Transform Type 13 - Key Wrap Algorithm Transform IDs
IKEV2_KEY_WRAP_ALGORITHMS = {
    0: "Reserved",
    1: "KW_5649_128",
    2: "KW_5649_192",
    3: "KW_5649_256",
    4: "KW_ARX",
}

# Transform Type 14 - Group Controller Authentication Method Transform IDs
IKEV2_GROUP_CONTROLLER_AUTH_METHODS = {
    0: "Reserved",
    1: "Implicit",
    2: "Digital Signature",
}

# IKEv2 Identification Payload ID Types
IKEV2_ID_TYPES = {
    0: "Reserved",
    1: "ID_IPV4_ADDR",
    2: "ID_FQDN",
    3: "ID_RFC822_ADDR",
    4: "Unassigned",
    5: "ID_IPV6_ADDR",
    9: "ID_DER_ASN1_DN",
    10: "ID_DER_ASN1_GN",
    11: "ID_KEY_ID",
    12: "ID_FC_NAME",
    13: "ID_NULL",
}

# IKEv2 Certificate Encodings
IKEV2_CERTIFICATE_ENCODINGS = {
    0: "Reserved",
    1: "PKCS #7 wrapped X.509 certificate",
    2: "PGP Certificate",
    3: "DNS Signed Key",
    4: "X.509 Certificate - Signature",
    5: "Reserved",
    6: "Kerberos Token",
    7: "Certificate Revocation List (CRL)",
    8: "Authority Revocation List (ARL)",
    9: "SPKI Certificate",
    10: "X.509 Certificate - Attribute",
    11: "Raw RSA Key (DEPRECATED)",
    12: "Hash and URL of X.509 certificate",
    13: "Hash and URL of X.509 bundle",
    14: "OCSP Content",
    15: "Raw Public Key",
}

# IKEv2 Authentication Method
IKEV2_AUTHENTICATION_METHODS = {
    0: "Reserved",
    1: "RSA Digital Signature",
    2: "Shared Key Message Integrity Code",
    3: "DSS Digital Signature",
    9: "ECDSA with SHA-256 on the P-256 curve",
    10: "ECDSA with SHA-384 on the P-384 curve",
    11: "ECDSA with SHA-512 on the P-521 curve",
    12: "Generic Secure Password Authentication Method",
    13: "NULL Authentication",
    14: "Digital Signature",
}

# IKEv2 Notify Message Error Types
IKEV2_NOTIFY_ERROR_TYPES = {
    0: "Reserved",
    1: "UNSUPPORTED_CRITICAL_PAYLOAD",
    4: "INVALID_IKE_SPI",
    5: "INVALID_MAJOR_VERSION",
    7: "INVALID_SYNTAX",
    9: "INVALID_MESSAGE_ID",
    11: "INVALID_SPI",
    14: "NO_PROPOSAL_CHOSEN",
    17: "INVALID_KE_PAYLOAD",
    24: "AUTHENTICATION_FAILED",
    34: "SINGLE_PAIR_REQUIRED",
    35: "NO_ADDITIONAL_SAS",
    36: "INTERNAL_ADDRESS_FAILURE",
    37: "FAILED_CP_REQUIRED",
    38: "TS_UNACCEPTABLE",
    39: "INVALID_SELECTORS",
    40: "UNACCEPTABLE_ADDRESSES",
    41: "UNEXPECTED_NAT_DETECTED",
    42: "USE_ASSIGNED_HoA",
    43: "TEMPORARY_FAILURE",
    44: "CHILD_SA_NOT_FOUND",
    45: "INVALID_GROUP_ID",
    46: "AUTHORIZATION_FAILED",
    47: "STATE_NOT_FOUND",
    48: "TS_MAX_QUEUE",
    49: "REGISTRATION_FAILED",
}

# IKEv2 Notify Message Status Types
IKEV2_NOTIFY_STATUS_TYPES = {
    16384: "INITIAL_CONTACT",
    16385: "SET_WINDOW_SIZE",
    16386: "ADDITIONAL_TS_POSSIBLE",
    16387: "IPCOMP_SUPPORTED",
    16388: "NAT_DETECTION_SOURCE_IP",
    16389: "NAT_DETECTION_DESTINATION_IP",
    16390: "COOKIE",
    16391: "USE_TRANSPORT_MODE",
    16392: "HTTP_CERT_LOOKUP_SUPPORTED",
    16393: "REKEY_SA",
    16394: "ESP_TFC_PADDING_NOT_SUPPORTED",
    16395: "NON_FIRST_FRAGMENTS_ALSO",
    16396: "MOBIKE_SUPPORTED",
    16397: "ADDITIONAL_IP4_ADDRESS",
    16398: "ADDITIONAL_IP6_ADDRESS",
    16399: "NO_ADDITIONAL_ADDRESSES",
    16400: "UPDATE_SA_ADDRESSES",
    16401: "COOKIE2",
    16402: "NO_NATS_ALLOWED",
    16403: "AUTH_LIFETIME",
    16404: "MULTIPLE_AUTH_SUPPORTED",
    16405: "ANOTHER_AUTH_FOLLOWS",
    16406: "REDIRECT_SUPPORTED",
    16407: "REDIRECT",
    16408: "REDIRECTED_FROM",
    16409: "TICKET_LT_OPAQUE",
    16410: "TICKET_REQUEST",
    16411: "TICKET_ACK",
    16412: "TICKET_NACK",
    16413: "TICKET_OPAQUE",
    16414: "LINK_ID",
    16415: "USE_WESP_MODE",
    16416: "ROHC_SUPPORTED",
    16417: "EAP_ONLY_AUTHENTICATION",
    16418: "CHILDLESS_IKEV2_SUPPORTED",
    16419: "QUICK_CRASH_DETECTION",
    16420: "IKEV2_MESSAGE_ID_SYNC_SUPPORTED",
    16421: "IPSEC_REPLAY_COUNTER_SYNC_SUPPORTED",
    16422: "IKEV2_MESSAGE_ID_SYNC",
    16423: "IPSEC_REPLAY_COUNTER_SYNC",
    16424: "SECURE_PASSWORD_METHODS",
    16425: "PSK_PERSIST",
    16426: "PSK_CONFIRM",
    16427: "ERX_SUPPORTED",
    16428: "IFOM_CAPABILITY",
    16429: "GROUP_SENDER",
    16430: "IKEV2_FRAGMENTATION_SUPPORTED",
    16431: "SIGNATURE_HASH_ALGORITHMS_PRE_RFC7427",  # Draft-era alias
    16432: "CLONE_IKE_SA_SUPPORTED",
    16433: "CLONE_IKE_SA",
    16434: "PUZZLE",
    16435: "USE_PPK",                                 # RFC 8784
    16436: "PPK_IDENTITY",                            # RFC 8784
    16437: "NO_PPK_AUTH",                             # RFC 8784
    16438: "INTERMEDIATE_EXCHANGE_SUPPORTED",         # RFC 9242
    16439: "IP4_ALLOWED",
    16440: "ADDITIONAL_KEY_EXCHANGE",                 # RFC 9370 (corrected from 16441)
    16441: "IP6_ALLOWED",                             # Corrected RFC 7296 assignment
    16442: "USE_AGGFRAG",
    16443: "SIGNATURE_HASH_ALGORITHMS",               # RFC 7427 (corrected from SUPPORTED_AUTH_METHODS)
    16444: "SA_RESOURCE_INFO",
    16445: "USE_PPK_INT",
    16446: "PPK_IDENTITY_KEY",
    16447: "IKE_SA_INIT_FULL_TRANSCRIPT_AUTH",
}

# IKEv2 Notification IPCOMP Transform IDs (used inside Notify value 16387)
IKEV2_IPCOMP_TRANSFORM_IDS = {
    0: "Reserved",
    1: "IPCOMP_OUI",
    2: "IPCOMP_DEFLATE",
    3: "IPCOMP_LZS",
    4: "IPCOMP_LZJH",
}

# IKEv2 Security Protocol Identifiers
IKEV2_SECURITY_PROTOCOL_IDENTIFIERS = {
    0: "Reserved",
    1: "IKE",
    2: "AH",
    3: "ESP",
    4: "FC_ESP_HEADER",
    5: "FC_CT_AUTHENTICATION",
    6: "GIKE_UPDATE",
}

# IKEv2 Traffic Selector Types
IKEV2_TRAFFIC_SELECTOR_TYPES = {
    7: "TS_IPV4_ADDR_RANGE",
    8: "TS_IPV6_ADDR_RANGE",
    9: "TS_FC_ADDR_RANGE",
    10: "TS_SECLABEL",
}

# IKEv2 Configuration Payload CFG Types
IKEV2_CFG_TYPES = {
    0: "Reserved",
    1: "CFG_REQUEST",
    2: "CFG_REPLY",
    3: "CFG_SET",
    4: "CFG_ACK",
}

# IKEv2 Configuration Payload Attribute Types
IKEV2_CFG_ATTRIBUTE_TYPES = {
    0: "Reserved",
    1: "INTERNAL_IP4_ADDRESS",
    2: "INTERNAL_IP4_NETMASK",
    3: "INTERNAL_IP4_DNS",
    4: "INTERNAL_IP4_NBNS",
    5: "Reserved",
    6: "INTERNAL_IP4_DHCP",
    7: "APPLICATION_VERSION",
    8: "INTERNAL_IP6_ADDRESS",
    9: "Reserved",
    10: "INTERNAL_IP6_DNS",
    11: "Reserved",
    12: "INTERNAL_IP6_DHCP",
    13: "INTERNAL_IP4_SUBNET",
    14: "SUPPORTED_ATTRIBUTES",
    15: "INTERNAL_IP6_SUBNET",
    16: "MIP6_HOME_PREFIX",
    17: "INTERNAL_IP6_LINK",
    18: "INTERNAL_IP6_PREFIX",
    19: "HOME_AGENT_ADDRESS",
    20: "P_CSCF_IP4_ADDRESS",
    21: "P_CSCF_IP6_ADDRESS",
    22: "FTT_KAT",
    23: "EXTERNAL_SOURCE_IP4_NAT_INFO",
    24: "TIMEOUT_PERIOD_FOR_LIVENESS_CHECK",
    25: "INTERNAL_DNS_DOMAIN",
    26: "INTERNAL_DNSSEC_TA",
    27: "ENCDNS_IP4",
    28: "ENCDNS_IP6",
    29: "ENCDNS_DIGEST_INFO",
}

# IKEv2 Gateway Identity Types
IKEV2_GATEWAY_IDENTITY_TYPES = {
    0: "Reserved",
    1: "IPv4 address of the VPN gateway",
    2: "IPv6 address of the VPN gateway",
    3: "FQDN of the VPN gateway",
}

# ROHC Attribute Types
IKEV2_ROHC_ATTRIBUTE_TYPES = {
    0: "Reserved",
    1: "Maximum Context Identifier (MAX_CID)",
    2: "ROHC Profile (ROHC_PROFILE)",
    3: "ROHC Integrity Algorithm (ROHC_INTEG)",
    4: "ROHC ICV Length in bytes (ROHC_ICV_LEN)",
    5: "Maximum Reconstructed Reception Unit (MRRU)",
}

# IKEv2 Secure Password Methods
IKEV2_SECURE_PASSWORD_METHODS = {
    0: "Reserved",
    1: "PACE",
    2: "AugPAKE",
    3: "Secure PSK Authentication",
}

# IKEv2 Hash Algorithms (used in RFC 7427 Digital Signature auth / SIGNATURE_HASH_ALGORITHMS)
IKEV2_HASH_ALGORITHMS = {
    0: "Reserved",
    1: "SHA1",
    2: "SHA2-256",
    3: "SHA2-384",
    4: "SHA2-512",
    5: "Identity",
    6: "STREEBOG_256",
    7: "STREEBOG_512",
}

# IKEv2 Post-quantum Preshared Key ID Types
IKEV2_PPK_ID_TYPES = {
    0: "Reserved",
    1: "PPK_ID_OPAQUE",
    2: "PPK_ID_FIXED",
}

# Group SA Attributes
IKEV2_GSA_ATTRIBUTES = {
    0: "Reserved",
    1: "GSA_KEY_LIFETIME",
    2: "GSA_INITIAL_MESSAGE_ID",
    3: "GSA_NEXT_SPI",
}

# Group-Wide Policy Attributes
IKEV2_GROUP_WIDE_POLICY_ATTRIBUTES = {
    0: "Reserved",
    1: "GWP_ATD",
    2: "GWP_DTD",
    3: "GWP_SENDER_ID_BITS",
}

# Group Key Bag Attributes
IKEV2_GROUP_KEY_BAG_ATTRIBUTES = {
    0: "Reserved",
    1: "SA_KEY",
}

# Member Key Bag Attributes
IKEV2_MEMBER_KEY_BAG_ATTRIBUTES = {
    0: "Reserved",
    1: "WRAP_KEY",
    2: "AUTH_KEY",
    3: "GM_SENDER_ID",
}

# RFC 7427 / IANA IKEv2 Hash and Signature Algorithm Registry
IKEV2_SIGNATURE_ALGORITHMS = {
    0: "Reserved",
    1: "RSA Digital Signature (legacy PKCS#1 v1.5)",
    2: "SHA1 with DSA",
    3: "SHA256 with DSA",
    4: "SHA384 with DSA",
    5: "SHA512 with DSA",
    8: "ECDSA with SHA-256 on P-256",
    9: "ECDSA with SHA-384 on P-384",
    10: "ECDSA with SHA-512 on P-521",
    11: "RSASSA-PSS with SHA-256",
    12: "RSASSA-PSS with SHA-384",
    13: "RSASSA-PSS with SHA-512",
    14: "Ed25519",
    15: "Ed448",
    18: "ML-DSA-44",
    19: "ML-DSA-65",
    20: "ML-DSA-87",
    21: "Falcon-512",
    22: "Falcon-1024",
    23: "SLH-DSA-SHA2-128s",
    24: "LMS (Stateful Hash-Based Signature)",
}