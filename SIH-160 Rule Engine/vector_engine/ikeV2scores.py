# =============================================================================
# IKEv2 Cryptographic Suite Scores for 23-D Vector Engine
# =============================================================================

# d[7]: INIT_SA_ENCR_ALGO (Transform Type 1)
IKEV2_ENCRYPTION_SCORES = {
    0: 0.00,   # Reserved
    1: 0.00,   # DES_IV64 - Deprecated
    2: 0.00,   # DES - Deprecated
    3: 0.25,   # 3DES - Legacy
    4: 0.00,   # RC5 - Deprecated
    5: 0.00,   # IDEA - Deprecated
    6: 0.00,   # CAST - Deprecated
    7: 0.00,   # Blowfish - Deprecated
    8: 0.00,   # 3IDEA - Deprecated
    9: 0.00,   # DES_IV32 - Deprecated
    10: 0.00,  # Reserved
    11: 0.00,  # NULL - Not allowed

    12: 0.50,  # AES-CBC
    13: 0.55,  # AES-CTR

    14: 0.80,  # AES-CCM-8
    15: 0.85,  # AES-CCM-12
    16: 0.90,  # AES-CCM-16

    18: 0.80,  # AES-GCM-8
    19: 0.90,  # AES-GCM-12
    20: 1.00,  # AES-GCM-16 (Standard CNSA / RFC AEAD)

    21: 0.00,  # NULL-AUTH-AES-GMAC - Not allowed
    22: 0.00,  # Reserved

    23: 0.50,  # Camellia-CBC
    24: 0.55,  # Camellia-CTR
    25: 0.80,  # Camellia-CCM-8
    26: 0.85,  # Camellia-CCM-12
    27: 0.90,  # Camellia-CCM-16

    28: 1.00,  # ChaCha20-Poly1305

    29: 0.00,  # AES-CCM-8-IIV
    30: 0.00,  # AES-GCM-16-IIV
    31: 0.00,  # ChaCha20-Poly1305-IIV
}

# d[9]: INIT_SA_PRF_ALGO (Transform Type 2)
IKEV2_PRF_SCORES = {
    0: 0.00,   # Reserved
    1: 0.00,   # PRF_HMAC_MD5 - Deprecated / MUST NOT
    2: 0.00,   # PRF_HMAC_SHA1 - Deprecated
    3: 0.00,   # PRF_HMAC_TIGER - Deprecated
    4: 0.70,   # PRF_AES128_XCBC
    5: 0.60,   # PRF_HMAC_SHA2_256
    6: 1.00,   # PRF_HMAC_SHA2_384 (CNSA 2.0)
    7: 1.00,   # PRF_HMAC_SHA2_512 (CNSA 2.0)
    8: 0.75,   # PRF_AES128_CMAC
    9: 0.90,   # PRF_HMAC_STREEBOG_512
}

# d[10]: INIT_SA_INTEG_ALGO (Transform Type 3)
IKEV2_INTEGRITY_SCORES = {
    0: 1.00,   # NONE (Valid for AEAD combined mode ciphers like AES-GCM / Poly1305)
    1: 0.00,   # AUTH_HMAC_MD5_96 - Deprecated
    2: 0.00,   # AUTH_HMAC_SHA1_96 - Deprecated
    3: 0.00,   # AUTH_DES_MAC - Deprecated
    4: 0.00,   # AUTH_KPDK_MD5 - Deprecated
    5: 0.70,   # AUTH_AES_XCBC_96
    6: 0.00,   # AUTH_HMAC_MD5_128 - Deprecated
    7: 0.00,   # AUTH_HMAC_SHA1_160 - Deprecated
    8: 0.75,   # AUTH_AES_CMAC_96
    9: 0.80,   # AUTH_AES_128_GMAC
    10: 0.85,  # AUTH_AES_192_GMAC
    11: 0.90,  # AUTH_AES_256_GMAC
    12: 0.60,  # AUTH_HMAC_SHA2_256_128
    13: 1.00,  # AUTH_HMAC_SHA2_384_192
    14: 1.00,  # AUTH_HMAC_SHA2_512_256
}

# d[0]: INIT_KEM_CLASSICAL_ALGO (Transform Type 4)
IKEV2_CLASSICAL_DH_SCORES = {
    0: 0.00,   # NONE
    1: 0.00,   # 768-bit MODP (Broken)
    2: 0.00,   # 1024-bit MODP (Broken)
    5: 0.00,   # 1536-bit MODP (Deprecated)
    14: 0.50,  # 2048-bit MODP
    15: 0.50,  # 3072-bit MODP
    16: 0.50,  # 4096-bit MODP
    17: 0.50,  # 6144-bit MODP
    18: 0.50,  # 8192-bit MODP
    19: 1.00,  # 256-bit random ECP (Modern ECDH)
    20: 1.00,  # 384-bit random ECP (Modern ECDH)
    21: 1.00,  # 521-bit random ECP (Modern ECDH)
    27: 0.75,  # brainpoolP224r1
    28: 1.00,  # brainpoolP256r1
    29: 1.00,  # brainpoolP384r1
    30: 1.00,  # brainpoolP512r1
    31: 1.00,  # Curve25519 (Modern ECDH)
    32: 1.00,  # Curve448 (Modern ECDH)
}

# d[2]: INIT_KEM_PQC_PRESENCE & ALGO (Transform Type 4 / RFC 9370 ADDKE)
IKEV2_PQC_KEM_SCORES = {
    0: 0.00,   # None
    35: 0.20,  # ML-KEM-512 (Category 1)
    36: 0.60,  # ML-KEM-768 (Category 3)
    37: 1.00,  # ML-KEM-1024 (Category 5)
    38: 0.20,  # FrodoKEM-640 (Category 1)
    39: 0.60,  # FrodoKEM-976 (Category 3)
    40: 1.00,  # FrodoKEM-1344 (Category 5)
}

# Transform Type 4 - Direct Hybrid / Composite Key Exchange IDs
IKEV2_HYBRID_COMPOSITE_KE_SCORES = {
    # id: (classical_algo_score, classical_security_bits, pqc_algo_score, pqc_security_bits)
    1035: (1.00, 128, 0.60, 192),  # X25519 (128-bit) + ML-KEM-768 (192-bit)
    1036: (1.00, 128, 0.60, 192),  # ECDH P-256 (128-bit) + ML-KEM-768 (192-bit)
    1037: (1.00, 224, 1.00, 256),  # X448 (224-bit) + ML-KEM-1024 (256-bit)
    1038: (1.00, 192, 1.00, 256),  # ECDH P-384 (192-bit) + ML-KEM-1024 (256-bit)
}

# d[4]: INIT_KEM_PQC_HYBRID_BINDING
IKEV2_HYBRID_BINDING_SCORES = {
    "MULTI_KE": 1.00,      # RFC 9370
    "PPK": 0.50,           # RFC 8784
    "PURE_OR_NONE": 0.00,
}

# d[11]: INIT_SA_ESN_CAPABILITY (Transform Type 5)
IKEV2_SEQUENCE_NUMBER_SCORES = {
    0: 0.00,   # Standard 32-bit Sequential Numbers
    1: 1.00,   # Extended 64-bit Sequence Numbers (ESN)
}

# d[12]: AUTH_SIG_CLASSICAL_ALGO
IKEV2_AUTH_METHOD_SCORES = {
    0: 0.00,   # Reserved
    1: 0.50,   # RSA Digital Signature (PKCS#1 v1.5)
    2: 0.00,   # Shared Key MIC (PSK)
    9: 1.00,   # ECDSA P-256
    10: 1.00,  # ECDSA P-384
    11: 1.00,  # ECDSA P-521
    13: 0.00,  # NULL Authentication
    14: 1.00,  # Ed25519
}

# d[14]: AUTH_SIG_PQC_ALGO
IKEV2_SIGNATURE_PQC_SCORES = {
    0: 0.00,   # None
    18: 0.40,  # ML-DSA-44 (Category 2)
    19: 0.60,  # ML-DSA-65 (Category 3)
    20: 1.00,  # ML-DSA-87 (Category 5)
    21: 1.00,  # SLH-DSA-256 (Category 5)
}

# d[15]: AUTH_HASH_DIGEST_ALGO
IKEV2_HASH_SCORES = {
    0: 0.00,   # Reserved
    1: 0.00,   # SHA1 (Broken)
    2: 0.60,   # SHA2-256
    3: 1.00,   # SHA2-384
    4: 1.00,   # SHA2-512
}

# d[16]: AUTH_CERT_KEY_TYPE
IKEV2_CERT_KEY_TYPE_SCORES = {
    "1.2.840.10040.4.1": 0.00,        # DSA (Legacy)
    "1.2.840.113549.1.1.1": 0.50,     # RSA (rsaEncryption)
    "1.2.840.113549.1.1.10": 0.50,    # RSASSA-PSS
    "1.2.840.10045.2.1": 0.75,        # id-ecPublicKey
    "1.3.101.112": 0.75,              # Ed25519
    "1.3.101.113": 0.75,              # Ed448
    "2.16.840.1.101.3.4.3.17": 1.00,  # ML-DSA-44
    "2.16.840.1.101.3.4.3.18": 1.00,  # ML-DSA-65
    "2.16.840.1.101.3.4.3.19": 1.00,  # ML-DSA-87
    **{"2.16.840.1.101.3.4.3.%d" % n: 1.00 for n in range(20, 32)},  # SLH-DSA
}

# d[18]: AUTH_CERT_SIG_ALGO
IKEV2_CERT_SIG_ALGO_SCORES = {
    "1.2.840.113549.1.1.4": 0.00,     # md5WithRSAEncryption
    "1.2.840.113549.1.1.5": 0.00,     # sha1WithRSAEncryption
    "1.2.840.113549.1.1.11": 0.60,    # sha256WithRSAEncryption
    "1.2.840.10045.4.1": 0.00,        # ecdsa-with-SHA1
    "1.2.840.10045.4.3.2": 0.60,      # ecdsa-with-SHA256
    "1.2.840.10045.4.3.3": 1.00,      # ecdsa-with-SHA384
    "1.2.840.10045.4.3.4": 1.00,      # ecdsa-with-SHA512
    "1.2.840.10040.4.3": 0.00,        # dsa-with-sha1
    "2.16.840.1.101.3.4.3.17": 1.00,  # ML-DSA-44
    "2.16.840.1.101.3.4.3.18": 1.00,  # ML-DSA-65
    "2.16.840.1.101.3.4.3.19": 1.00,  # ML-DSA-87
}