try:
    import numpy as np
except ImportError:
    np = None


class baseVector:
    def __init__(self, name: str, vector: list[float], dict: dict | None = None):
        self.name = name
        self.vector = vector
        self.dict = dict

    def __iter__(self):
        return iter(self.vector)

    def __getitem__(self, idx):
        return self.vector[idx]

    def __len__(self):
        return len(self.vector)

    def to_numpy(self, normalize: bool = False):
        """Convert vector to a numpy.ndarray(shape=(19,), dtype=np.float32).

        If normalize is True, returns unit L2-normalized vector for cosine similarity.
        """
        if np is None:
            raise ImportError("numpy is required for to_numpy()")
        arr = np.array(self.vector, dtype=np.float32)
        if normalize:
            norm = float(np.linalg.norm(arr))
            if norm > 0.0:
                arr = arr / norm
        return arr


# =============================================================================
# 1. CNSA 2.0 IPsec Profile (Quantum-Resistant Anchor)
# =============================================================================

CNSA2_DICT = {
    "IKE_SA_INIT": {
        "proposals": [{
            "transforms": {
                "encryption": [{"id": 20, "length": 256}],
                "prf": [{"id": 6}],
                "integrity": [{"id": 0}],
                "dh_group": [{"id": 20}],
                "extended_sequence_numbers": [{"id": 1}],
                "additional_key_exchange_1": [{"id": 37}],
            }
        }]
    },
    "IKE_AUTH": {
        "authentication": {
            "auth_type": 14,
        },
        "child_sa": {
            "proposals": [{
                "transforms": {
                    "encryption": [{"id": 20, "length": 256}],
                    "integrity": [{"id": 0}],
                    "dh_group": [{"id": 37}],
                }
            }]
        },
    },
    "notify": {
        "present": True,
        "notify_types": [
            16430,
            16438,
            16443,
        ],
        "messages": [],
    },
    "common": {
        "src_port": 500,
        "dst_port": 500,
    },
    "sig_pqc_id": 20,
    "hash_algo_id": 5,
    "cert_key_type_oid": "2.16.840.1.101.3.4.3.19",
    "cert_key_len": 2592,
    "cert_sig_algo_oid": "2.16.840.1.101.3.4.3.19",
}

CNSA2_VECTOR_RAW = [
    1.00,  # d[ 0]  INIT_KEM_CLASSICAL_ALGO (ECDH P-384)
    0.75,  # d[ 1]  INIT_KEM_CLASSICAL_KEY_LEN (192 bits / 256)
    1.00,  # d[ 2]  INIT_KEM_PQC_PRESENCE (ML-KEM-1024)
    1.00,  # d[ 3]  INIT_KEM_PQC_KEY_LEN (256 bits / 256)
    1.00,  # d[ 4]  INIT_KEM_PQC_HYBRID_BINDING (RFC 9370 Multi-KE)
    0.33,  # d[ 5]  INIT_KEM_MULTI_KE_ROUNDS (1 additional round -> 1/3)
    1.00,  # d[ 6]  INIT_KEM_PFS_STATUS (Ephemeral Child SA enabled)
    1.00,  # d[ 7]  INIT_SA_ENCR_ALGO (AES-256-GCM / ID 20)
    1.00,  # d[ 8]  INIT_SA_ENCR_KEY_LEN (256 bits / 256)
    1.00,  # d[ 9]  INIT_SA_PRF_ALGO (PRF_HMAC_SHA2_384)
    1.00,  # d[10]  INIT_SA_INTEG_ALGO (AUTH_NONE with AEAD)
    1.00,  # d[11]  INIT_SA_ESN_CAPABILITY (ESN enabled)
    1.00,  # d[12]  AUTH_SIG_CLASSICAL_ALGO (Digital Signature / RFC 7427)
    1.00,  # d[13]  AUTH_SIG_CLASSICAL_KEY_LEN (256 bits / 256)
    1.00,  # d[14]  AUTH_SIG_PQC_ALGO (ML-DSA-87 / ID 20)
    1.00,  # d[15]  AUTH_HASH_DIGEST_ALGO (SHA2-384 / SHA2-512)
    1.00,  # d[16]  PROTO_IKE_VERSION (IKEv2)
    1.00,  # d[17]  PROTO_NOTIFY_16443_EXPLICIT (RFC 7427 present)
    1.00,  # d[18]  PROTO_NAT_TRAVERSAL (Native ESP)
]

CNSA2_VECTOR = baseVector(
    name="CNSA 2.0 IPsec Profile",
    vector=CNSA2_VECTOR_RAW,
    dict=CNSA2_DICT,
)


# =============================================================================
# 2. NIST PQC Transitional (FIPS 203 + RFC 8247 / NIST SP 800-77 Rev. 1)
# =============================================================================

NIST_PQC_TRANSITIONAL_DICT = {
    "IKE_SA_INIT": {
        "proposals": [{
            "transforms": {
                "encryption": [{"id": 20, "length": 256}],
                "prf": [{"id": 5}],
                "integrity": [{"id": 0}],
                "dh_group": [{"id": 31}],
                "extended_sequence_numbers": [{"id": 1}],
                "additional_key_exchange_1": [{"id": 36}],
            }
        }]
    },
    "IKE_AUTH": {
        "authentication": {
            "auth_type": 9,
        },
        "child_sa": {
            "proposals": [{
                "transforms": {
                    "encryption": [{"id": 20, "length": 256}],
                    "integrity": [{"id": 0}],
                    "dh_group": [{"id": 31}],
                }
            }]
        },
    },
    "notify": {
        "present": True,
        "notify_types": [
            16440,
            16443,
        ],
        "messages": [],
    },
    "common": {
        "src_port": 500,
        "dst_port": 500,
    },
    "hash_algo_id": 2,
    "cert_key_type_oid": "1.2.840.10045.2.1",
    "cert_sig_algo_oid": "1.2.840.10045.4.3.2",
}

NIST_PQC_TRANSITIONAL_VECTOR_RAW = [
    1.00,  # d[ 0]  INIT_KEM_CLASSICAL_ALGO (Curve25519 / P-256)
    0.50,  # d[ 1]  INIT_KEM_CLASSICAL_KEY_LEN (128 bits / 256)
    0.60,  # d[ 2]  INIT_KEM_PQC_PRESENCE (ML-KEM-768)
    0.75,  # d[ 3]  INIT_KEM_PQC_KEY_LEN (192 bits / 256)
    1.00,  # d[ 4]  INIT_KEM_PQC_HYBRID_BINDING (RFC 9370 Multi-KE)
    0.33,  # d[ 5]  INIT_KEM_MULTI_KE_ROUNDS (1 additional round -> 1/3)
    1.00,  # d[ 6]  INIT_KEM_PFS_STATUS (Ephemeral Child SA enabled)
    1.00,  # d[ 7]  INIT_SA_ENCR_ALGO (AES-256-GCM / ID 20)
    1.00,  # d[ 8]  INIT_SA_ENCR_KEY_LEN (256 bits / 256)
    0.60,  # d[ 9]  INIT_SA_PRF_ALGO (PRF_HMAC_SHA2_256)
    1.00,  # d[10]  INIT_SA_INTEG_ALGO (AUTH_NONE with AEAD)
    1.00,  # d[11]  INIT_SA_ESN_CAPABILITY (ESN enabled)
    1.00,  # d[12]  AUTH_SIG_CLASSICAL_ALGO (ECDSA P-256 / ID 9)
    0.50,  # d[13]  AUTH_SIG_CLASSICAL_KEY_LEN (128 bits / 256)
    0.00,  # d[14]  AUTH_SIG_PQC_ALGO (None)
    0.60,  # d[15]  AUTH_HASH_DIGEST_ALGO (SHA2-256)
    1.00,  # d[16]  PROTO_IKE_VERSION (IKEv2)
    1.00,  # d[17]  PROTO_NOTIFY_16443_EXPLICIT (RFC 7427 present)
    1.00,  # d[18]  PROTO_NAT_TRAVERSAL (Native ESP)
]

NIST_PQC_TRANSITIONAL_VECTOR = baseVector(
    name="NIST PQC Transitional IPsec Profile",
    vector=NIST_PQC_TRANSITIONAL_VECTOR_RAW,
    dict=NIST_PQC_TRANSITIONAL_DICT,
)


# =============================================================================
# 3. RFC 8247 Classical Baseline (IETF Standard Classical / SNDL Vulnerable)
# =============================================================================

RFC8247_CLASSICAL_DICT = {
    "IKE_SA_INIT": {
        "proposals": [{
            "transforms": {
                "encryption": [{"id": 12, "length": 128}],
                "prf": [{"id": 5}],
                "integrity": [{"id": 12}],
                "dh_group": [{"id": 14}],
                "extended_sequence_numbers": [{"id": 0}],
            }
        }]
    },
    "IKE_AUTH": {
        "authentication": {
            "auth_type": 1,
        },
        "child_sa": {
            "proposals": [{
                "transforms": {
                    "encryption": [{"id": 12, "length": 128}],
                    "integrity": [{"id": 12}],
                    "dh_group": [{"id": 14}],
                }
            }]
        },
    },
    "notify": {
        "present": False,
        "notify_types": [],
        "messages": [],
    },
    "common": {
        "src_port": 500,
        "dst_port": 500,
    },
    "hash_algo_id": 2,
    "cert_key_type_oid": "1.2.840.113549.1.1.1",
    "cert_sig_algo_oid": "1.2.840.113549.1.1.11",
}

RFC8247_CLASSICAL_VECTOR_RAW = [
    0.50,  # d[ 0]  INIT_KEM_CLASSICAL_ALGO (MODP-2048 / ID 14)
    0.44,  # d[ 1]  INIT_KEM_CLASSICAL_KEY_LEN (112 bits / 256 = 0.4375)
    0.00,  # d[ 2]  INIT_KEM_PQC_PRESENCE (None)
    0.00,  # d[ 3]  INIT_KEM_PQC_KEY_LEN (None)
    0.00,  # d[ 4]  INIT_KEM_PQC_HYBRID_BINDING (None)
    0.00,  # d[ 5]  INIT_KEM_MULTI_KE_ROUNDS (0 rounds)
    1.00,  # d[ 6]  INIT_KEM_PFS_STATUS (Ephemeral Child SA enabled)
    0.50,  # d[ 7]  INIT_SA_ENCR_ALGO (AES-128-CBC / ID 12)
    0.50,  # d[ 8]  INIT_SA_ENCR_KEY_LEN (128 bits / 256)
    0.60,  # d[ 9]  INIT_SA_PRF_ALGO (PRF_HMAC_SHA2_256)
    0.60,  # d[10]  INIT_SA_INTEG_ALGO (AUTH_HMAC_SHA2_256_128 / ID 12)
    0.00,  # d[11]  INIT_SA_ESN_CAPABILITY (Standard 32-bit sequence numbers)
    0.50,  # d[12]  AUTH_SIG_CLASSICAL_ALGO (RSA PKCS#1 v1.5 / ID 1)
    0.44,  # d[13]  AUTH_SIG_CLASSICAL_KEY_LEN (112 bits / 256 = 0.4375)
    0.00,  # d[14]  AUTH_SIG_PQC_ALGO (None)
    0.60,  # d[15]  AUTH_HASH_DIGEST_ALGO (SHA2-256)
    1.00,  # d[16]  PROTO_IKE_VERSION (IKEv2)
    0.00,  # d[17]  PROTO_NOTIFY_16443_EXPLICIT (RFC 7427 absent)
    1.00,  # d[18]  PROTO_NAT_TRAVERSAL (Native ESP)
]

RFC8247_CLASSICAL_VECTOR = baseVector(
    name="RFC 8247 Classical Baseline IPsec Profile",
    vector=RFC8247_CLASSICAL_VECTOR_RAW,
    dict=RFC8247_CLASSICAL_DICT,
)


# =============================================================================
# 4. NIST SP 800-131A Deprecated (Broken / Immediate Reject Floor)
# =============================================================================

NIST_SP800_131A_DEPRECATED_DICT = {
    "IKE_SA_INIT": {
        "proposals": [{
            "transforms": {
                "encryption": [{"id": 3, "length": 192}],
                "prf": [{"id": 1}],
                "integrity": [{"id": 1}],
                "dh_group": [{"id": 2}],
                "extended_sequence_numbers": [{"id": 0}],
            }
        }]
    },
    "IKE_AUTH": {
        "authentication": {
            "auth_type": 2,
        },
        "child_sa": {
            "proposals": []
        },
    },
    "notify": {
        "present": False,
        "notify_types": [],
        "messages": [],
    },
    "common": {
        "src_port": 4500,
        "dst_port": 4500,
    },
    "hash_algo_id": 1,
    "cert_key_type_oid": "1.2.840.10040.4.1",
    "cert_sig_algo_oid": "1.2.840.10040.4.3",
}

NIST_SP800_131A_DEPRECATED_VECTOR_RAW = [
    0.00,  # d[ 0]  INIT_KEM_CLASSICAL_ALGO (MODP-1024 / ID 2 - Broken)
    0.31,  # d[ 1]  INIT_KEM_CLASSICAL_KEY_LEN (80 bits / 256 = 0.3125)
    0.00,  # d[ 2]  INIT_KEM_PQC_PRESENCE (None)
    0.00,  # d[ 3]  INIT_KEM_PQC_KEY_LEN (None)
    0.00,  # d[ 4]  INIT_KEM_PQC_HYBRID_BINDING (None)
    0.00,  # d[ 5]  INIT_KEM_MULTI_KE_ROUNDS (0 rounds)
    0.00,  # d[ 6]  INIT_KEM_PFS_STATUS (Non-PFS / Static keying)
    0.25,  # d[ 7]  INIT_SA_ENCR_ALGO (3DES-CBC / ID 3 - Legacy)
    0.75,  # d[ 8]  INIT_SA_ENCR_KEY_LEN (192 bits / 256)
    0.00,  # d[ 9]  INIT_SA_PRF_ALGO (PRF_HMAC_MD5 - Deprecated)
    0.00,  # d[10]  INIT_SA_INTEG_ALGO (AUTH_HMAC_MD5_96 - Deprecated)
    0.00,  # d[11]  INIT_SA_ESN_CAPABILITY (Standard 32-bit sequence numbers)
    0.00,  # d[12]  AUTH_SIG_CLASSICAL_ALGO (PSK / ID 2 - Deprecated)
    0.00,  # d[13]  AUTH_SIG_CLASSICAL_KEY_LEN (0 bits)
    0.00,  # d[14]  AUTH_SIG_PQC_ALGO (None)
    0.00,  # d[15]  AUTH_HASH_DIGEST_ALGO (MD5 / ID 0 / SHA-1)
    0.00,  # d[16]  PROTO_IKE_VERSION (IKEv1 - RFC 9395 Deprecated)
    0.00,  # d[17]  PROTO_NOTIFY_16443_EXPLICIT (RFC 7427 absent)
    0.50,  # d[18]  PROTO_NAT_TRAVERSAL (NAT-T UDP 4500)
]

NIST_SP800_131A_DEPRECATED_VECTOR = baseVector(
    name="NIST SP 800-131A Deprecated IPsec Profile",
    vector=NIST_SP800_131A_DEPRECATED_VECTOR_RAW,
    dict=NIST_SP800_131A_DEPRECATED_DICT,
)


# =============================================================================
# Normalized Numpy Reference Vectors (for Cosine Similarity)
# =============================================================================

if np is not None:
    CNSA2_NP_NORMALIZED = CNSA2_VECTOR.to_numpy(normalize=True)
    NIST_PQC_TRANSITIONAL_NP_NORMALIZED = NIST_PQC_TRANSITIONAL_VECTOR.to_numpy(normalize=True)
    RFC8247_CLASSICAL_NP_NORMALIZED = RFC8247_CLASSICAL_VECTOR.to_numpy(normalize=True)
    NIST_SP800_131A_DEPRECATED_NP_NORMALIZED = NIST_SP800_131A_DEPRECATED_VECTOR.to_numpy(normalize=True)
else:
    CNSA2_NP_NORMALIZED = None
    NIST_PQC_TRANSITIONAL_NP_NORMALIZED = None
    RFC8247_CLASSICAL_NP_NORMALIZED = None
    NIST_SP800_131A_DEPRECATED_NP_NORMALIZED = None


# Registry of all policy anchors
POLICY_ANCHORS: dict[str, baseVector] = {
    "CNSA_2_0": CNSA2_VECTOR,
    "NIST_PQC_TRANSITIONAL": NIST_PQC_TRANSITIONAL_VECTOR,
    "RFC8247_CLASSICAL_BASELINE": RFC8247_CLASSICAL_VECTOR,
    "NIST_SP800_131A_DEPRECATED": NIST_SP800_131A_DEPRECATED_VECTOR,
}
