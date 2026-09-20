# --- Key Exchange Methods ---

IKEV2_DH_KEY_BITS = {
    0: 0,      # NONE
    1: 64,     # 768-bit MODP Group (Weak)
    2: 80,     # 1024-bit MODP Group (Weak)
    5: 88,     # 1536-bit MODP Group (Weak)
    14: 112,   # 2048-bit MODP Group
    15: 128,   # 3072-bit MODP Group
    16: 150,   # 4096-bit MODP Group
    17: 192,   # 6144-bit MODP Group
    18: 256,   # 8192-bit MODP Group
    19: 128,   # 256-bit random ECP group (NIST P-256)
    20: 192,   # 384-bit random ECP group (NIST P-384)
    21: 256,   # 521-bit random ECP group (NIST P-521)
    22: 80,    # 1024-bit MODP Group with 160-bit Prime Order Subgroup
    23: 112,   # 2048-bit MODP Group with 224-bit Prime Order Subgroup
    24: 112,   # 2048-bit MODP Group with 256-bit Prime Order Subgroup
    25: 96,    # 192-bit Random ECP Group
    26: 112,   # 224-bit Random ECP Group
    27: 112,   # brainpoolP224r1
    28: 128,   # brainpoolP256r1
    29: 192,   # brainpoolP384r1
    30: 256,   # brainpoolP512r1
    31: 128,   # Curve25519
    32: 256,   # Curve448 (Rounded to 256-bit tier)
    33: 128,   # GOST3410_2012_256
    34: 256,   # GOST3410_2012_512
}



IKEV2_PQC_KEM_BITS = {
    35: 128,   # ml-kem-512
    36: 192,   # ml-kem-768
    37: 256,   # ml-kem-1024
    38: 128,   # FrodoKEM-640-AES
    39: 192,   # FrodoKEM-976-AES
    40: 256,   # FrodoKEM-1344-AES
}

IKEV2_HYBRID_KEM_BITS = {
    1035: 192,  # X25519 + ML-KEM-768
    1036: 192,  # ECDH P-256 + ML-KEM-768
    1037: 256,  # X448 + ML-KEM-1024
    1038: 256,  # ECDH P-384 + ML-KEM-1024
}


# --- Authentication Methods ---

IKEV2_AUTH_KEY_BITS = {
    0: 0,
    1: 112,
    2: 0,
    3: 80,
    9: 128,
    10: 192,
    11: 256,
    12: 0,
    13: 0,
    14: 0,
}


# --- Encryption Algorithms ---

IKEV2_AEAD_ENCR_IDS = frozenset({
    14, 15, 16, 18, 19, 20, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
})


# --- Signature Algorithms ---

IKEV2_SIG_ALGO_KEY_BITS = {
    0: 0,
    1: 112,       # Legacy RSA
    2: 80,        # Broken SHA1-DSA
    3: 112,       # Baseline DSA
    4: 128,       
    5: 128,       
    8: 128,       # ECDSA P-256
    9: 192,       # ECDSA P-384
    10: 256,      # ECDSA P-521
    11: 112,      
    12: 128,      
    13: 128,      
    14: 128,      # Ed25519
    15: 256,      # Ed448 (Normalized to 256-bit tier)
    18: 128,      # ML-DSA-44 (NIST Category 2 / 128-bit)
    19: 192,      # ML-DSA-65 (NIST Category 3 / 192-bit)
    20: 256,      # ML-DSA-87 (NIST Category 5 / 256-bit)
    21: 128,      # Falcon-512 (128-bit)
    22: 192,      # Falcon-1024 (192-bit)
    23: 128,      # SLH-DSA-SHA2-128s (128-bit)
    24: 128,      # LMS Stateful Hash (Baseline 128-bit)
}

IKEV2_SIG_ALGO_PQC_IDS = frozenset({
    18, 19, 20, 21, 22, 23, 24,
})


# --- Certificate Key Bits (Symmetric Security Equivalent / NIST Classification) ---

IKEV2_CERT_KEY_BITS = {
    # PQC Algorithms (NIST FIPS 204 / 205)
    "2.16.840.1.101.3.4.3.17": 128,  # ML-DSA-44 (NIST Category 2 / 128-bit)
    "2.16.840.1.101.3.4.3.18": 192,  # ML-DSA-65 (NIST Category 3 / 192-bit)
    "2.16.840.1.101.3.4.3.19": 256,  # ML-DSA-87 (NIST Category 5 / 256-bit - CNSA 2.0)
    # Classical / ECC
    "1.2.840.10045.2.1": 128,        # id-ecPublicKey (NIST P-256)
    "1.3.101.112": 128,              # Ed25519
    "1.3.101.113": 256,              # Ed448
    # RSA
    "1.2.840.113549.1.1.1": 112,     # RSA (default 2048-bit baseline)
    "1.2.840.113549.1.1.10": 112,    # RSASSA-PSS
}

