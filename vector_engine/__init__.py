"""
vector_engine — 19-Dimensional Cryptographic Vector Engine & Policy Classifier.

Converts IKEv2 session parameters into normalized 19-dimensional numerical vectors
and classifies postures via cosine distance against policy anchors.
"""

from __future__ import annotations

from .vectorEngine import (
    D,
    DIMENSION_NAMES,
    build_19d_vector,
    build_vector,
    merge_session_metadata,
)
from .baseVectors import (
    CNSA2_VECTOR,
    NIST_PQC_TRANSITIONAL_VECTOR,
    NIST_SP800_131A_DEPRECATED_VECTOR,
    POLICY_ANCHORS,
    RFC8247_CLASSICAL_VECTOR,
)
from .cosineSimilarity import (
    classify_session,
    classify_vector,
    cosine_distance,
    cosine_similarity,
    get_anchor_similarity_matrix,
    print_anchor_matrix,
)

# Aliases
classify_vector_posture = classify_vector
classify_session_posture = classify_session

__all__ = [
    "D",
    "DIMENSION_NAMES",
    "build_19d_vector",
    "build_vector",
    "merge_session_metadata",
    "POLICY_ANCHORS",
    "CNSA2_VECTOR",
    "NIST_PQC_TRANSITIONAL_VECTOR",
    "RFC8247_CLASSICAL_VECTOR",
    "NIST_SP800_131A_DEPRECATED_VECTOR",
    "cosine_similarity",
    "cosine_distance",
    "classify_vector",
    "classify_session",
    "classify_vector_posture",
    "classify_session_posture",
    "get_anchor_similarity_matrix",
    "print_anchor_matrix",
]
