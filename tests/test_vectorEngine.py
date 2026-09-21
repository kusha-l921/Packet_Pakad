"""
test_vectorEngine.py -- Unit tests for the IKEv2 23-D Vector Engine.

Run:  python -m pytest test_vectorEngine.py -v
  or: python test_vectorEngine.py
"""

import sys
from pathlib import Path
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# ═══════════════════════════════════════════════════════════════════════════
#  Minimal test runner (no pytest dependency required)
# ═══════════════════════════════════════════════════════════════════════════

_tests: list = []
_passed = 0
_failed = 0


def test(fn):
    _tests.append(fn)
    return fn


def _run_all():
    global _passed, _failed
    for fn in _tests:
        try:
            fn()
            _passed += 1
            print(f"  PASS  {fn.__name__}")
        except AssertionError as e:
            _failed += 1
            print(f"  FAIL  {fn.__name__}  ->  {e}")
        except Exception as e:
            _failed += 1
            print(f"  FAIL  {fn.__name__}  ->  EXCEPTION: {e}")

    print(f"\n  {_passed} passed, {_failed} failed, {_passed + _failed} total")
    return _failed == 0


def _approx(a, b, tol=1e-6):
    assert abs(a - b) < tol, f"expected ~{b}, got {a}"


try:
    from vector_engine.vectorEngine import (
        D, DIMENSION_NAMES,
        merge_session_metadata,
        build_vector,
    )
    from vector_engine import baseVectors, ikeV2IDs, ikeV2Lookups
    from vector_engine.baseVectors import (
        POLICY_ANCHORS,
        NIST_PQC_TRANSITIONAL_VECTOR,
        NIST_PQC_TRANSITIONAL_DICT,
        RFC8247_CLASSICAL_VECTOR,
        RFC8247_CLASSICAL_DICT,
        NIST_SP800_131A_DEPRECATED_VECTOR,
        NIST_SP800_131A_DEPRECATED_DICT,
        CNSA2_VECTOR,
        baseVector,
    )
except ImportError:
    from vectorEngine import (
        D, DIMENSION_NAMES,
        merge_session_metadata,
        build_vector,
    )
    import baseVectors, ikeV2IDs, ikeV2Lookups
    from baseVectors import (
        POLICY_ANCHORS,
        NIST_PQC_TRANSITIONAL_VECTOR,
        NIST_PQC_TRANSITIONAL_DICT,
        RFC8247_CLASSICAL_VECTOR,
        RFC8247_CLASSICAL_DICT,
        NIST_SP800_131A_DEPRECATED_VECTOR,
        NIST_SP800_131A_DEPRECATED_DICT,
        CNSA2_VECTOR,
        baseVector,
    )


# ═══════════════════════════════════════════════════════════════════════════
#  Fixtures -- synthetic IKEv2 session metadata
# ═══════════════════════════════════════════════════════════════════════════

def _modern_sa_init():
    """AES-GCM-256, P-384 DH, SHA-384 PRF, ESN, ML-KEM-1024 add'l KE."""
    return {
        "exchange_type": 34,
        "common": {"src_port": 500, "dst_port": 500},
        "IKE_SA_INIT": {
            "exchange": "IKE_SA_INIT",
            "proposals": [{
                "proposal_num": 1, "protocol_id": 1, "spi": None,
                "transforms": {
                    "encryption":    [{"id": 20, "length": 256}],
                    "prf":           [{"id": 6,  "length": None}],
                    "integrity":     [{"id": 0,  "length": None}],
                    "dh_group":      [{"id": 20, "length": None}],
                    "extended_sequence_numbers": [{"id": 1, "length": None}],
                    "additional_key_exchange_1": [{"id": 37, "length": None}],
                    "additional_key_exchange_2": [],
                    "additional_key_exchange_3": [],
                    "additional_key_exchange_4": [],
                    "additional_key_exchange_5": [],
                    "additional_key_exchange_6": [],
                    "additional_key_exchange_7": [],
                },
            }],
        },
        "notify": {
            "present": True,
            "notify_types": [16431],
            "messages": [{"type": 16431, "data": "0x00030004"}],
        },
    }


def _modern_auth():
    """ECDSA P-384, Child SA with PFS (DH group 20), Notify 16443."""
    return {
        "exchange_type": 35,
        "common": {"src_port": 500, "dst_port": 500},
        "IKE_AUTH": {
            "exchange": "IKE_AUTH",
            "authentication": {
                "present": True, "auth_type": 10, "data": None,
            },
            "certificate": {"present": True, "encoding": 4, "data": None},
            "child_sa": {
                "present": True,
                "proposals": [{
                    "proposal_num": 1, "protocol_id": 3, "spi": "0xaabb",
                    "transforms": {
                        "encryption":    [{"id": 20, "length": 256}],
                        "prf":           [],
                        "integrity":     [{"id": 0,  "length": None}],
                        "dh_group":      [{"id": 20, "length": None}],
                        "extended_sequence_numbers": [{"id": 1, "length": None}],
                        "additional_key_exchange_1": [],
                        "additional_key_exchange_2": [],
                        "additional_key_exchange_3": [],
                        "additional_key_exchange_4": [],
                        "additional_key_exchange_5": [],
                        "additional_key_exchange_6": [],
                        "additional_key_exchange_7": [],
                    },
                }],
            },
            "traffic_selectors": {"initiator": [], "responder": []},
        },
        "notify": {
            "present": True,
            "notify_types": [16443],
            "messages": [{"type": 16443, "data": None}],
        },
    }


def _legacy_sa_init():
    """AES-CBC-128, MODP-2048, SHA-256 PRF, no PQC, no ESN."""
    return {
        "exchange_type": 34,
        "common": {"src_port": 500, "dst_port": 500},
        "IKE_SA_INIT": {
            "exchange": "IKE_SA_INIT",
            "proposals": [{
                "proposal_num": 1, "protocol_id": 1, "spi": None,
                "transforms": {
                    "encryption":    [{"id": 12, "length": 128}],
                    "prf":           [{"id": 5,  "length": None}],
                    "integrity":     [{"id": 12, "length": None}],
                    "dh_group":      [{"id": 14, "length": None}],
                    "extended_sequence_numbers": [{"id": 0, "length": None}],
                    "additional_key_exchange_1": [],
                    "additional_key_exchange_2": [],
                    "additional_key_exchange_3": [],
                    "additional_key_exchange_4": [],
                    "additional_key_exchange_5": [],
                    "additional_key_exchange_6": [],
                    "additional_key_exchange_7": [],
                },
            }],
        },
    }


def _legacy_auth():
    """RSA sig, no PFS child SA."""
    return {
        "exchange_type": 35,
        "common": {"src_port": 500, "dst_port": 500},
        "IKE_AUTH": {
            "exchange": "IKE_AUTH",
            "authentication": {
                "present": True, "auth_type": 1, "data": None,
            },
            "certificate": {"present": False, "encoding": None, "data": None},
            "child_sa": {
                "present": True,
                "proposals": [{
                    "proposal_num": 1, "protocol_id": 3, "spi": "0xccdd",
                    "transforms": {
                        "encryption":    [{"id": 12, "length": 128}],
                        "prf":           [],
                        "integrity":     [{"id": 12, "length": None}],
                        "dh_group":      [],
                        "extended_sequence_numbers": [{"id": 0, "length": None}],
                        "additional_key_exchange_1": [],
                        "additional_key_exchange_2": [],
                        "additional_key_exchange_3": [],
                        "additional_key_exchange_4": [],
                        "additional_key_exchange_5": [],
                        "additional_key_exchange_6": [],
                        "additional_key_exchange_7": [],
                    },
                }],
            },
            "traffic_selectors": {"initiator": [], "responder": []},
        },
    }


def _broken_sa_init():
    """DES, 768-bit MODP, MD5 PRF, no PQC."""
    return {
        "exchange_type": 34,
        "common": {"src_port": 4500, "dst_port": 4500},
        "IKE_SA_INIT": {
            "exchange": "IKE_SA_INIT",
            "proposals": [{
                "proposal_num": 1, "protocol_id": 1, "spi": None,
                "transforms": {
                    "encryption":    [{"id": 2, "length": 64}],
                    "prf":           [{"id": 1, "length": None}],
                    "integrity":     [{"id": 1, "length": None}],
                    "dh_group":      [{"id": 1, "length": None}],
                    "extended_sequence_numbers": [],
                    "additional_key_exchange_1": [],
                    "additional_key_exchange_2": [],
                    "additional_key_exchange_3": [],
                    "additional_key_exchange_4": [],
                    "additional_key_exchange_5": [],
                    "additional_key_exchange_6": [],
                    "additional_key_exchange_7": [],
                },
            }],
        },
    }


def _broken_auth():
    """PSK, no cert, NAT-T."""
    return {
        "exchange_type": 35,
        "common": {"src_port": 4500, "dst_port": 4500},
        "IKE_AUTH": {
            "exchange": "IKE_AUTH",
            "authentication": {
                "present": True, "auth_type": 2, "data": None,
            },
            "certificate": {"present": False, "encoding": None, "data": None},
            "child_sa": {"present": False, "proposals": []},
            "traffic_selectors": {"initiator": [], "responder": []},
        },
    }


# ═══════════════════════════════════════════════════════════════════════════
#  Tests -- vector shape & bounds
# ═══════════════════════════════════════════════════════════════════════════

@test
def test_vector_length_is_19():
    session = merge_session_metadata(_modern_sa_init(), _modern_auth())
    vec = build_vector(session)
    assert len(vec) == 19, f"Expected 19, got {len(vec)}"


@test
def test_all_values_in_0_1_range():
    session = merge_session_metadata(_modern_sa_init(), _modern_auth())
    vec = build_vector(session)
    for i, v in enumerate(vec):
        assert 0.0 <= v <= 1.0, f"d[{i}] = {v} out of [0,1]"


@test
def test_dimension_count_matches_names():
    assert len(DIMENSION_NAMES) == D, f"DIMENSION_NAMES has {len(DIMENSION_NAMES)} entries, expected {D}"


@test
def test_empty_session_yields_zero_vector_except_d16():
    vec = build_vector({})
    for i, v in enumerate(vec):
        if i == 16:
            assert v == 1.0, f"d[16] should be 1.0 for IKEv2, got {v}"
        elif i == 18:
            assert v == 1.0, f"d[18] should default to 1.0 (native), got {v}"
        else:
            assert v == 0.0, f"d[{i}] should be 0.0 for empty session, got {v}"


# ═══════════════════════════════════════════════════════════════════════════
#  Tests -- modern session (per-dimension)
# ═══════════════════════════════════════════════════════════════════════════

@test
def test_modern_session_d0_is_1():
    """P-384 DH -> classical DH score 1.0."""
    session = merge_session_metadata(_modern_sa_init())
    vec = build_vector(session)
    _approx(vec[0], 1.0)


@test
def test_modern_session_d7_aes_gcm():
    """AES-GCM-16 (id=20) -> 1.0."""
    session = merge_session_metadata(_modern_sa_init())
    vec = build_vector(session)
    _approx(vec[7], 1.0)


@test
def test_modern_session_d8_key_len_256():
    """256-bit key -> 256/256 = 1.0."""
    session = merge_session_metadata(_modern_sa_init())
    vec = build_vector(session)
    _approx(vec[8], 1.0)


@test
def test_modern_session_d10_aead_none():
    """AEAD cipher + integrity NONE -> 1.0."""
    session = merge_session_metadata(_modern_sa_init())
    vec = build_vector(session)
    _approx(vec[10], 1.0)


@test
def test_modern_session_d2_pqc_present():
    """ML-KEM-1024 via additional_key_exchange_1 -> score 1.0."""
    session = merge_session_metadata(_modern_sa_init())
    vec = build_vector(session)
    _approx(vec[2], 1.0)


@test
def test_modern_session_d4_multi_ke_binding():
    """additional_key_exchange present -> MULTI_KE -> 1.0."""
    session = merge_session_metadata(_modern_sa_init())
    vec = build_vector(session)
    _approx(vec[4], 1.0)


@test
def test_modern_session_d5_multi_ke_rounds():
    """1 additional KE round -> 1/3 ~ 0.333."""
    session = merge_session_metadata(_modern_sa_init())
    vec = build_vector(session)
    _approx(vec[5], 1.0 / 3.0, tol=0.01)


@test
def test_modern_session_d6_pfs():
    """Child SA with DH group -> PFS = 1.0."""
    session = merge_session_metadata(_modern_sa_init(), _modern_auth())
    vec = build_vector(session)
    _approx(vec[6], 1.0)


@test
def test_modern_session_d11_esn():
    """ESN id=1 -> 1.0."""
    session = merge_session_metadata(_modern_sa_init())
    vec = build_vector(session)
    _approx(vec[11], 1.0)


@test
def test_modern_session_d12_ecdsa():
    """ECDSA P-384 (auth_type=10) -> 1.0."""
    session = merge_session_metadata(_modern_sa_init(), _modern_auth())
    vec = build_vector(session)
    _approx(vec[12], 1.0)


@test
def test_modern_session_d15_hash_from_notify():
    """Notify 16431 data '0x00030004' -> SHA-384(3)=1.0, SHA-512(4)=1.0 -> best 1.0."""
    session = merge_session_metadata(_modern_sa_init(), _modern_auth())
    vec = build_vector(session)
    _approx(vec[15], 1.0)


@test
def test_modern_session_d16_ikev2():
    """IKEv2 -> 1.0."""
    session = merge_session_metadata(_modern_sa_init())
    vec = build_vector(session)
    _approx(vec[16], 1.0)


@test
def test_modern_session_d17_notify_16443():
    """Notify 16443 present -> 1.0."""
    session = merge_session_metadata(_modern_sa_init(), _modern_auth())
    vec = build_vector(session)
    _approx(vec[17], 1.0)


@test
def test_modern_session_d18_native_esp():
    """Port 500 -> native ESP -> 1.0."""
    session = merge_session_metadata(_modern_sa_init())
    vec = build_vector(session)
    _approx(vec[18], 1.0)


# ═══════════════════════════════════════════════════════════════════════════
#  Tests -- legacy session
# ═══════════════════════════════════════════════════════════════════════════

@test
def test_legacy_session_d0_modp2048():
    """MODP-2048 (id=14) -> 0.5."""
    session = merge_session_metadata(_legacy_sa_init())
    vec = build_vector(session)
    _approx(vec[0], 0.5)


@test
def test_legacy_session_d7_aes_cbc():
    """AES-CBC (id=12) -> 0.5."""
    session = merge_session_metadata(_legacy_sa_init())
    vec = build_vector(session)
    _approx(vec[7], 0.5)


@test
def test_legacy_session_no_pqc():
    """No PQC in legacy -> d[2],d[3],d[4],d[5] all 0.0."""
    session = merge_session_metadata(_legacy_sa_init(), _legacy_auth())
    vec = build_vector(session)
    for dim in [2, 3, 4, 5]:
        _approx(vec[dim], 0.0)


@test
def test_legacy_session_no_pfs():
    """No DH in child SA -> PFS = 0.0."""
    session = merge_session_metadata(_legacy_sa_init(), _legacy_auth())
    vec = build_vector(session)
    _approx(vec[6], 0.0)


# ═══════════════════════════════════════════════════════════════════════════
#  Tests -- broken session
# ═══════════════════════════════════════════════════════════════════════════

@test
def test_broken_session_d18_nat_t():
    """Port 4500 -> NAT-T -> 0.5."""
    session = merge_session_metadata(_broken_sa_init(), _broken_auth())
    vec = build_vector(session)
    _approx(vec[18], 0.5)


@test
def test_broken_session_d7_des():
    """DES (id=2) -> 0.0."""
    session = merge_session_metadata(_broken_sa_init())
    vec = build_vector(session)
    _approx(vec[7], 0.0)


@test
def test_broken_session_d9_md5():
    """HMAC-MD5 PRF (id=1) -> 0.0."""
    session = merge_session_metadata(_broken_sa_init())
    vec = build_vector(session)
    _approx(vec[9], 0.0)


# ═══════════════════════════════════════════════════════════════════════════
#  Tests -- merge utility
# ═══════════════════════════════════════════════════════════════════════════

@test
def test_merge_none_inputs():
    result = merge_session_metadata(None, None)
    assert result == {}


@test
def test_merge_notify_concatenation():
    d1 = {"notify": {"present": True, "notify_types": [16431], "messages": [{"type": 16431}]}}
    d2 = {"notify": {"present": True, "notify_types": [16443], "messages": [{"type": 16443}]}}
    merged = merge_session_metadata(d1, d2)
    assert 16431 in merged["notify"]["notify_types"]
    assert 16443 in merged["notify"]["notify_types"]
    assert len(merged["notify"]["messages"]) == 2


@test
def test_merge_preserves_both_exchanges():
    sa_init = _modern_sa_init()
    auth = _modern_auth()
    merged = merge_session_metadata(sa_init, auth)
    assert "IKE_SA_INIT" in merged
    assert "IKE_AUTH" in merged


# ═══════════════════════════════════════════════════════════════════════════
#  Tests -- hybrid composite KE
# ═══════════════════════════════════════════════════════════════════════════

@test
def test_hybrid_composite_ke_1038():
    """Hybrid composite KE id=1038 (ECDH P-384 + ML-KEM-1024)."""
    session = {
        "common": {"src_port": 500, "dst_port": 500},
        "IKE_SA_INIT": {
            "proposals": [{
                "proposal_num": 1, "protocol_id": 1, "spi": None,
                "transforms": {
                    "encryption":    [{"id": 20, "length": 256}],
                    "prf":           [{"id": 6,  "length": None}],
                    "integrity":     [{"id": 0,  "length": None}],
                    "dh_group":      [{"id": 1038, "length": None}],
                    "extended_sequence_numbers": [{"id": 1, "length": None}],
                    "additional_key_exchange_1": [],
                    "additional_key_exchange_2": [],
                    "additional_key_exchange_3": [],
                    "additional_key_exchange_4": [],
                    "additional_key_exchange_5": [],
                    "additional_key_exchange_6": [],
                    "additional_key_exchange_7": [],
                },
            }],
        },
    }
    vec = build_vector(session)
    _approx(vec[0], 1.0)              # classical: ECDH P-384 -> 1.0
    _approx(vec[1], 192.0 / 256.0)    # 192 security bits / 256
    _approx(vec[2], 1.0)              # PQC: ML-KEM-1024 -> 1.0
    _approx(vec[3], 256.0 / 256.0)    # 256 bits
    _approx(vec[4], 1.0)              # hybrid binding implicit


@test
def test_ikev2_lookups_exhaustive_coverage():
    """Verify that ikeV2Lookups.py covers 100% of IDs from ikeV2IDs.py without redundant overlap."""
    from vector_engine import ikeV2IDs, ikeV2Lookups

    # 1. Classical KE Methods (0-34) in IKEV2_DH_KEY_BITS
    for k in [0, 1, 2, 5, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34]:
        assert k in ikeV2Lookups.IKEV2_DH_KEY_BITS, f"Missing classical KE ID {k} in IKEV2_DH_KEY_BITS"

    # PQC KEM IDs (35-40) in IKEV2_PQC_KEM_BITS
    for k in [35, 36, 37, 38, 39, 40]:
        assert k in ikeV2Lookups.IKEV2_PQC_KEM_BITS, f"Missing PQC ID {k} in IKEV2_PQC_KEM_BITS"

    # 2. Authentication Methods: every ID in IKEV2_AUTHENTICATION_METHODS must be in IKEV2_AUTH_KEY_BITS
    for k in ikeV2IDs.IKEV2_AUTHENTICATION_METHODS:
        assert k in ikeV2Lookups.IKEV2_AUTH_KEY_BITS, f"Missing AUTH ID {k} in IKEV2_AUTH_KEY_BITS"

    # 3. AEAD Ciphers
    for cipher_id in [18, 19, 20, 28, 29, 30]:
        assert cipher_id in ikeV2Lookups.IKEV2_AEAD_ENCR_IDS, f"Missing AEAD cipher {cipher_id}"

    # 4. Signature Algorithm bit strengths
    for algo_id in [1, 2, 3, 9, 10, 11, 12, 13, 14]:
        assert algo_id in ikeV2Lookups.IKEV2_SIG_ALGO_KEY_BITS, f"Missing sig algo {algo_id}"


# ═══════════════════════════════════════════════════════════════════════════
#  Tests -- Policy Centroid Vectors (baseVectors.py)
# ═══════════════════════════════════════════════════════════════════════════

@test
def test_policy_anchors_dimensions_and_bounds():
    """All policy anchors must be exactly 19-dimensional with values in [0.0, 1.0]."""
    from vector_engine.baseVectors import POLICY_ANCHORS
    for name, anchor in POLICY_ANCHORS.items():
        assert len(anchor) == 19, f"{name} length is {len(anchor)}, expected 19"
        for i, val in enumerate(anchor):
            assert 0.0 <= val <= 1.0, f"{name} d[{i}] = {val} out of [0, 1]"


@test
def test_policy_anchors_numpy_conversion_and_normalization():
    """Verify numpy conversion to shape (19,) and unit L2-norm."""
    try:
        import numpy as np
    except ImportError:
        return

    from vector_engine.baseVectors import POLICY_ANCHORS
    for name, anchor in POLICY_ANCHORS.items():
        arr = anchor.to_numpy(normalize=False)
        assert arr.shape == (19,), f"{name} shape is {arr.shape}, expected (19,)"
        assert arr.dtype == np.float32, f"{name} dtype is {arr.dtype}, expected float32"

        arr_norm = anchor.to_numpy(normalize=True)
        norm = float(np.linalg.norm(arr_norm))
        assert abs(norm - 1.0) < 1e-5, f"{name} L2 norm is {norm}, expected ~1.0"


@test
def test_nist_pqc_matches_build_vector():
    """NIST_PQC_TRANSITIONAL_VECTOR must match build_vector output on its dict."""
    from vector_engine.baseVectors import NIST_PQC_TRANSITIONAL_VECTOR, NIST_PQC_TRANSITIONAL_DICT
    built = build_vector(NIST_PQC_TRANSITIONAL_DICT)
    for i in range(19):
        _approx(NIST_PQC_TRANSITIONAL_VECTOR[i], built[i], tol=0.01)


@test
def test_rfc8247_matches_build_vector():
    """RFC8247_CLASSICAL_VECTOR must match build_vector output on its dict."""
    from vector_engine.baseVectors import RFC8247_CLASSICAL_VECTOR, RFC8247_CLASSICAL_DICT
    built = build_vector(RFC8247_CLASSICAL_DICT)
    for i in range(19):
        _approx(RFC8247_CLASSICAL_VECTOR[i], built[i], tol=0.01)


@test
def test_nist_131a_matches_build_vector_except_ikev1():
    """NIST_SP800_131A_DEPRECATED_VECTOR matches build_vector with d[16]=0.0 for IKEv1."""
    from vector_engine.baseVectors import NIST_SP800_131A_DEPRECATED_VECTOR, NIST_SP800_131A_DEPRECATED_DICT
    built = build_vector(NIST_SP800_131A_DEPRECATED_DICT)
    built[16] = 0.0  # IKEv1 RFC 9395 deprecated
    for i in range(19):
        _approx(NIST_SP800_131A_DEPRECATED_VECTOR[i], built[i], tol=0.01)


@test
def test_policy_anchor_cosine_distances():
    """Verify cryptographic separation via cosine similarity."""
    try:
        import numpy as np
    except ImportError:
        return

    from vector_engine.baseVectors import (
        CNSA2_NP_NORMALIZED,
        NIST_PQC_TRANSITIONAL_NP_NORMALIZED,
        RFC8247_CLASSICAL_NP_NORMALIZED,
        NIST_SP800_131A_DEPRECATED_NP_NORMALIZED,
    )
    # Modern PQC profiles should be closer to each other than to deprecated
    sim_cnsa_nist_pqc = float(np.dot(CNSA2_NP_NORMALIZED, NIST_PQC_TRANSITIONAL_NP_NORMALIZED))
    sim_nist_pqc_rfc = float(np.dot(NIST_PQC_TRANSITIONAL_NP_NORMALIZED, RFC8247_CLASSICAL_NP_NORMALIZED))
    sim_pqc_deprecated = float(np.dot(NIST_PQC_TRANSITIONAL_NP_NORMALIZED, NIST_SP800_131A_DEPRECATED_NP_NORMALIZED))

    assert sim_cnsa_nist_pqc > 0.85, f"CNSA 2.0 and NIST PQC should be close, got {sim_cnsa_nist_pqc}"
    assert sim_nist_pqc_rfc > 0.75, f"NIST PQC and RFC 8247 should be moderately close, got {sim_nist_pqc_rfc}"
    assert sim_pqc_deprecated < 0.50, f"PQC and Deprecated should have low similarity, got {sim_pqc_deprecated}"


# ═══════════════════════════════════════════════════════════════════════════
#  Runner
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("\n  IKEv2 19-D Vector Engine -- Test Suite")
    print("  " + "=" * 50)
    ok = _run_all()
    sys.exit(0 if ok else 1)

