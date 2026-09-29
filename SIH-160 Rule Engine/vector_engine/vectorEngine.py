"""
vectorEngine.py — Pure-Python 19-Dimensional Cryptographic Vector Engine

Consumes merged IKEv2 session metadata dictionaries produced by
metadataExtractor.extract_ikeV2_metadata(), projects each session into a
normalised 19-D score vector.

Public API
──────────
    merge_session_metadata(*dicts)      → dict
    build_vector(session_dict)          → list[float]   (len = 19)
"""

from __future__ import annotations

from typing import Any

from .ikeV2scores import (
    IKEV2_CLASSICAL_DH_SCORES,
    IKEV2_PQC_KEM_SCORES,
    IKEV2_HYBRID_COMPOSITE_KE_SCORES,
    IKEV2_HYBRID_BINDING_SCORES,
    IKEV2_SEQUENCE_NUMBER_SCORES,
    IKEV2_ENCRYPTION_SCORES,
    IKEV2_PRF_SCORES,
    IKEV2_INTEGRITY_SCORES,
    IKEV2_AUTH_METHOD_SCORES,
    IKEV2_SIGNATURE_PQC_SCORES,
    IKEV2_HASH_SCORES,
)
from .ikeV2Lookups import (
    IKEV2_DH_KEY_BITS,
    IKEV2_PQC_KEM_BITS,
    IKEV2_AUTH_KEY_BITS,
    IKEV2_AEAD_ENCR_IDS,
    IKEV2_SIG_ALGO_KEY_BITS,
)


# ═══════════════════════════════════════════════════════════════════════════
#  Constants
# ═══════════════════════════════════════════════════════════════════════════

D = 19  # Vector dimensionality

DIMENSION_NAMES: list[str] = [
    # --- Phase 1: IKE_SA_INIT ---
    "INIT_KEM_CLASSICAL_ALGO",          # d[0]
    "INIT_KEM_CLASSICAL_KEY_LEN",       # d[1]
    "INIT_KEM_PQC_PRESENCE",            # d[2]
    "INIT_KEM_PQC_KEY_LEN",             # d[3]
    "INIT_KEM_PQC_HYBRID_BINDING",      # d[4]
    "INIT_KEM_MULTI_KE_ROUNDS",         # d[5]
    "INIT_KEM_PFS_STATUS",              # d[6]
    "INIT_SA_ENCR_ALGO",                # d[7]
    "INIT_SA_ENCR_KEY_LEN",             # d[8]
    "INIT_SA_PRF_ALGO",                 # d[9]
    "INIT_SA_INTEG_ALGO",               # d[10]
    "INIT_SA_ESN_CAPABILITY",           # d[11]
    # --- Phase 2: IKE_AUTH ---
    "AUTH_SIG_CLASSICAL_ALGO",          # d[12]
    "AUTH_SIG_CLASSICAL_KEY_LEN",       # d[13]
    "AUTH_SIG_PQC_ALGO",                # d[14]
    "AUTH_HASH_DIGEST_ALGO",            # d[15]
    # --- Phase 3: Protocol & Tunnel ---
    "PROTO_IKE_VERSION",                # d[16]
    "PROTO_NOTIFY_16443_EXPLICIT",      # d[17]
    "PROTO_NAT_TRAVERSAL",              # d[18]
]


# ═══════════════════════════════════════════════════════════════════════════
#  Session-merging utility
# ═══════════════════════════════════════════════════════════════════════════

def merge_session_metadata(*dicts: dict | None) -> dict:
    """Shallow-merge per-packet metadata dicts into one session dict.

    Later dicts override earlier ones for conflicting top-level keys,
    **except** ``"notify"`` whose ``messages`` / ``notify_types`` lists
    are concatenated.
    """
    merged: dict[str, Any] = {}
    all_notify_msgs: list[dict] = []
    all_notify_types: list[int] = []

    for d in dicts:
        if d is None:
            continue
        for key, val in d.items():
            if key == "notify" and isinstance(val, dict):
                all_notify_msgs.extend(val.get("messages", []))
                all_notify_types.extend(val.get("notify_types", []))
            else:
                merged[key] = val

    if all_notify_msgs:
        merged["notify"] = {
            "present": True,
            "notify_types": all_notify_types,
            "messages": all_notify_msgs,
        }

    return merged


# ═══════════════════════════════════════════════════════════════════════════
#  Internal helpers
# ═══════════════════════════════════════════════════════════════════════════

def _clip(val: float, lo: float = 0.0, hi: float = 1.0) -> float:
    """Clamp *val* to [lo, hi]."""
    return max(lo, min(hi, val))


def _first(lst: list[dict], key: str = "id", default: Any = None) -> Any:
    """Return ``lst[0][key]`` or *default*."""
    if lst:
        return lst[0].get(key, default)
    return default


def _init_transforms(session: dict) -> dict:
    """Return the transforms dict from the first IKE_SA_INIT proposal."""
    proposals = session.get("IKE_SA_INIT", {}).get("proposals", [])
    if proposals:
        return proposals[0].get("transforms", {})
    return {}


def _notify_types_set(session: dict) -> set[int]:
    """Return the set of notify-type IDs across all notify messages."""
    notify = session.get("notify", {})
    return set(notify.get("notify_types", []))


def _count_additional_ke(transforms: dict) -> int:
    """Count how many additional_key_exchange_N slots are populated."""
    count = 0
    for i in range(1, 8):
        if transforms.get(f"additional_key_exchange_{i}"):
            count += 1
    return count


# ═══════════════════════════════════════════════════════════════════════════
#  Notify-data parser  (helper for d[15])
# ═══════════════════════════════════════════════════════════════════════════

def _extract_best_hash_from_notify(session: dict) -> float:
    """Parse Notify 16431 payload data to find the strongest hash algorithm.

    The data field contains a list of 2-byte hash algorithm identifiers
    (see IKEV2_HASH_ALGORITHMS from ikeV2IDs).
    Returns the highest score found.
    """
    for msg in session.get("notify", {}).get("messages", []):
        if msg.get("type") != 16431:
            continue
        data_hex = msg.get("data")
        if not isinstance(data_hex, str) or not data_hex.startswith("0x"):
            continue
        raw = data_hex[2:]
        best = 0.0
        # Each hash algo ID occupies 2 bytes (4 hex chars)
        for i in range(0, len(raw) - 3, 4):
            try:
                algo_id = int(raw[i : i + 4], 16)
                best = max(best, IKEV2_HASH_SCORES.get(algo_id, 0.0))
            except ValueError:
                continue
        return best
    return 0.0


# ═══════════════════════════════════════════════════════════════════════════
#  Vector builder  —  IKEv2 only
# ═══════════════════════════════════════════════════════════════════════════

def build_vector(session: dict) -> list[float]:
    """Project a merged IKEv2 session metadata dict into a 23-D vector.

    Each element is normalised to [0.0, 1.0].

    Parameters
    ----------
    session : dict
        Merged dict containing any of ``IKE_SA_INIT``, ``IKE_AUTH``,
        ``notify``, ``common`` keys as produced by
        :func:`merge_session_metadata`.

    Returns
    -------
    list[float]
        Length-23 score vector.
    """
    d: list[float] = [0.0] * D

    tx      = _init_transforms(session)
    common  = session.get("common", {})
    auth    = session.get("IKE_AUTH", {}).get("authentication", {})
    child_proposals = session.get("IKE_AUTH", {}).get("child_sa", {}).get("proposals", [])
    notifs  = _notify_types_set(session)

    # ── DH group ID ────────────────────────────────────────────────────
    dh_id: int | None = _first(tx.get("dh_group", []))

    is_hybrid_composite = (dh_id is not None and
                           dh_id in IKEV2_HYBRID_COMPOSITE_KE_SCORES)

    # ── Phase 1: IKE_SA_INIT (d[0]–d[11]) ─────────────────────────────

    if is_hybrid_composite:
        # Direct hybrid/composite KE carries both classical + PQC in one ID
        c_score, c_bits, p_score, p_bits = IKEV2_HYBRID_COMPOSITE_KE_SCORES[dh_id]
        d[0] = c_score
        d[1] = min(c_bits, 256) / 256.0
        d[2] = p_score
        d[3] = min(p_bits, 256) / 256.0
        d[4] = 1.0  # hybrid binding is implicit
    else:
        # ── d[0]: INIT_KEM_CLASSICAL_ALGO ──────────────────────────────
        if dh_id is not None:
            d[0] = IKEV2_CLASSICAL_DH_SCORES.get(dh_id, 0.0)
            d[1] = min(IKEV2_DH_KEY_BITS.get(dh_id, 0), 256) / 256.0

        # ── d[2]–d[3]: PQC KEM via additional_key_exchange_* transforms
        best_pqc_score = 0.0
        best_pqc_bits  = 0
        for i in range(1, 8):
            for entry in tx.get(f"additional_key_exchange_{i}", []):
                ke_id = entry.get("id")
                if ke_id is not None and ke_id in IKEV2_PQC_KEM_SCORES:
                    s = IKEV2_PQC_KEM_SCORES[ke_id]
                    if s > best_pqc_score:
                        best_pqc_score = s
                        best_pqc_bits = IKEV2_PQC_KEM_BITS.get(ke_id, 0)

        d[2] = best_pqc_score
        d[3] = min(best_pqc_bits, 256) / 256.0

        # ── d[4]: INIT_KEM_PQC_HYBRID_BINDING ─────────────────────────
        addke_count = _count_additional_ke(tx)
        if addke_count > 0:
            d[4] = IKEV2_HYBRID_BINDING_SCORES["MULTI_KE"]
        elif 16435 in notifs:          # USE_PPK  (RFC 8784)
            d[4] = IKEV2_HYBRID_BINDING_SCORES["PPK"]
        else:
            d[4] = IKEV2_HYBRID_BINDING_SCORES["PURE_OR_NONE"]

    # ── d[5]: INIT_KEM_MULTI_KE_ROUNDS ────────────────────────────────
    d[5] = _clip(_count_additional_ke(tx) / 3.0)

    # ── d[6]: INIT_KEM_PFS_STATUS ─────────────────────────────────────
    # PFS  ⟹  DH group present inside Child SA proposals (IKE_AUTH)
    pfs = any(
        cp.get("transforms", {}).get("dh_group", [])
        for cp in child_proposals
    )
    d[6] = 1.0 if pfs else 0.0

    # ── d[7]: INIT_SA_ENCR_ALGO ───────────────────────────────────────
    encr_id: int | None = _first(tx.get("encryption", []))
    if encr_id is not None:
        d[7] = IKEV2_ENCRYPTION_SCORES.get(encr_id, 0.0)

    # ── d[8]: INIT_SA_ENCR_KEY_LEN ───────────────────────────────────
    encr_key_len: int | None = _first(tx.get("encryption", []), "length")
    if encr_key_len is None:
        if encr_id == 3:
            encr_key_len = 192
        elif encr_id == 2:
            encr_key_len = 64
    if encr_key_len is not None:
        d[8] = min(encr_key_len, 256) / 256.0

    # ── d[9]: INIT_SA_PRF_ALGO ────────────────────────────────────────
    prf_id: int | None = _first(tx.get("prf", []))
    if prf_id is not None:
        d[9] = IKEV2_PRF_SCORES.get(prf_id, 0.0)

    # ── d[10]: INIT_SA_INTEG_ALGO ─────────────────────────────────────
    integ_id: int | None = _first(tx.get("integrity", []))
    if integ_id is not None:
        if encr_id in IKEV2_AEAD_ENCR_IDS and integ_id == 0:
            d[10] = 1.0           # AEAD + NONE is the strongest config
        else:
            d[10] = IKEV2_INTEGRITY_SCORES.get(integ_id, 0.0)

    # ── d[11]: INIT_SA_ESN_CAPABILITY ─────────────────────────────────
    esn_id: int | None = _first(tx.get("extended_sequence_numbers", []))
    if esn_id is not None:
        d[11] = IKEV2_SEQUENCE_NUMBER_SCORES.get(esn_id, 0.0)

    # ── Phase 2: IKE_AUTH (d[12]–d[19]) ───────────────────────────────

    auth_type: int | None = auth.get("auth_type")
    sig_pqc_id: int | None = session.get("sig_pqc_id")
    hash_algo_id: int | None = session.get("hash_algo_id")

    # ── d[12]: AUTH_SIG_CLASSICAL_ALGO ─────────────────────────────────
    if auth_type is not None:
        d[12] = IKEV2_AUTH_METHOD_SCORES.get(auth_type, 0.0)

    # ── d[13]: AUTH_SIG_CLASSICAL_KEY_LEN ──────────────────────────────
    sig_bits = (
        IKEV2_SIG_ALGO_KEY_BITS.get(sig_pqc_id)
        or IKEV2_AUTH_KEY_BITS.get(auth_type, 0)
        or session.get("IKE_AUTH", {}).get("certificate", {}).get("cert_key_len", 0)
    )
    d[13] = min(sig_bits, 256) / 256.0

    # ── d[14]: AUTH_SIG_PQC_ALGO ───────────────────────────────────────
    if sig_pqc_id is not None:
        d[14] = IKEV2_SIGNATURE_PQC_SCORES.get(sig_pqc_id, 0.0)

    # ── d[15]: AUTH_HASH_DIGEST_ALGO ──────────────────────────────────
    #    Source 1: explicit top-level field
    #    Source 2: parse Notify 16431 (SIGNATURE_HASH_ALGORITHMS) data
    if hash_algo_id is not None:
        d[15] = IKEV2_HASH_SCORES.get(hash_algo_id, 0.0)
    elif 16431 in notifs:
        d[15] = _extract_best_hash_from_notify(session)

    # ── Phase 3: Protocol & Tunnel (d[16]–d[18]) ─────────────────────

    # ── d[16]: PROTO_IKE_VERSION  (always 1.0 for IKEv2) ─────────────
    d[16] = 1.0

    # ── d[17]: PROTO_NOTIFY_16443_EXPLICIT ────────────────────────────
    d[17] = 1.0 if 16443 in notifs else 0.0

    # ── d[18]: PROTO_NAT_TRAVERSAL ────────────────────────────────────
    src_port = common.get("src_port")
    dst_port = common.get("dst_port")
    if src_port == 4500 or dst_port == 4500:
        d[18] = 0.5     # NAT-T UDP-encapsulated ESP
    else:
        d[18] = 1.0     # native ESP  (port 500 ↔ 500)

    return d


# Backward-compatible alias
build_19d_vector = build_vector
