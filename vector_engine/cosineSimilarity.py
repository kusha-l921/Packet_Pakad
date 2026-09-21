from __future__ import annotations

import math
from typing import Any, Sequence

try:
    import numpy as np
except ImportError:
    np = None

from .baseVectors import POLICY_ANCHORS, baseVector
from .vectorEngine import build_vector


def cosine_similarity(
    u: Sequence[float] | Any,
    v: Sequence[float] | Any,
) -> float:
    if np is not None and isinstance(u, np.ndarray) and isinstance(v, np.ndarray):
        norm_u = float(np.linalg.norm(u))
        norm_v = float(np.linalg.norm(v))
        if norm_u == 0.0 or norm_v == 0.0:
            return 0.0
        dot = float(np.dot(u, v))
        return max(-1.0, min(1.0, dot / (norm_u * norm_v)))

    dot_val = 0.0
    sum_sq_u = 0.0
    sum_sq_v = 0.0
    min_len = min(len(u), len(v))

    for i in range(min_len):
        ui = float(u[i])
        vi = float(v[i])
        dot_val += ui * vi
        sum_sq_u += ui * ui
        sum_sq_v += vi * vi

    norm_u = math.sqrt(sum_sq_u)
    norm_v = math.sqrt(sum_sq_v)

    if norm_u == 0.0 or norm_v == 0.0:
        return 0.0

    sim = dot_val / (norm_u * norm_v)
    return max(-1.0, min(1.0, sim))


def cosine_distance(
    u: Sequence[float] | Any,
    v: Sequence[float] | Any,
) -> float:
    return 1.0 - cosine_similarity(u, v)


def classify_vector(
    vector: Sequence[float] | Any,
    anchors: dict[str, baseVector] | None = None,
) -> dict[str, Any]:
    if anchors is None:
        anchors = POLICY_ANCHORS

    rankings: list[dict[str, Any]] = []

    for name, anchor in anchors.items():
        sim = cosine_similarity(vector, anchor.vector)
        dist = 1.0 - sim
        rankings.append({
            "name": name,
            "display_name": anchor.name,
            "similarity": round(sim, 4),
            "similarity_percent": f"{sim * 100:.2f}%",
            "distance": round(dist, 4),
        })

    rankings.sort(key=lambda r: r["similarity"], reverse=True)
    best = rankings[0] if rankings else {}

    return {
        "best_match": best.get("name"),
        "display_name": best.get("display_name"),
        "best_score": best.get("similarity", 0.0),
        "best_distance": best.get("distance", 1.0),
        "rankings": rankings,
    }


def classify_session(
    session_dict: dict,
    anchors: dict[str, baseVector] | None = None,
) -> dict[str, Any]:
    vec = build_vector(session_dict)
    report = classify_vector(vec, anchors=anchors)
    report["vector"] = vec
    return report


def get_anchor_similarity_matrix(
    anchors: dict[str, baseVector] | None = None,
) -> tuple[list[str], Any]:
    if anchors is None:
        anchors = POLICY_ANCHORS

    names = list(anchors.keys())
    n = len(names)

    if np is not None:
        matrix = np.zeros((n, n), dtype=np.float32)
        for i, name_i in enumerate(names):
            vec_i = anchors[name_i].to_numpy(normalize=True)
            for j, name_j in enumerate(names):
                vec_j = anchors[name_j].to_numpy(normalize=True)
                matrix[i, j] = float(np.dot(vec_i, vec_j))
        return names, matrix

    py_matrix = []
    for i, name_i in enumerate(names):
        row = []
        for j, name_j in enumerate(names):
            row.append(cosine_similarity(anchors[name_i].vector, anchors[name_j].vector))
        py_matrix.append(row)
    return names, py_matrix


def print_anchor_matrix(anchors: dict[str, baseVector] | None = None) -> None:
    names, matrix = get_anchor_similarity_matrix(anchors)
    short_names = [n.replace("_BASELINE", "").replace("_DEPRECATED", "_DEP") for n in names]

    header_cols = "".join(f"{sn:>18}" for sn in short_names)
    print("\n" + "=" * (28 + 18 * len(names)))
    print("  POLICY ANCHOR COSINE SIMILARITY MATRIX")
    print("=" * (28 + 18 * len(names)))
    print(f"{'Policy Anchor':<28}{header_cols}")
    print("-" * (28 + 18 * len(names)))

    for i, name in enumerate(names):
        row_str = f"{name:<28}"
        for j in range(len(names)):
            val = float(matrix[i][j]) if not hasattr(matrix, 'shape') else float(matrix[i, j])
            row_str += f"{val:>18.4f}"
        print(row_str)
    print("=" * (28 + 18 * len(names)) + "\n")


if __name__ == "__main__":
    print("\n" + "=" * 65)
    print("  IPsec Policy Centroid Vector Engine -- Cosine Similarity Demo")
    print("=" * 65)

    print_anchor_matrix()

    print("  CLASSIFICATION OF CANONICAL POLICY DICTIONARIES:")
    print("-" * 65)

    for anchor_key, anchor in POLICY_ANCHORS.items():
        if anchor.dict:
            res = classify_session(anchor.dict)
            best = res["best_match"]
            score = res["best_score"]
            status = "MATCH" if best == anchor_key else "MISMATCH"
            print(f"  [{status}] Input: {anchor_key:<28} -> Classified: {best} ({score:.4f})")
            for rank in res["rankings"]:
                print(f"         - {rank['name']:<28} sim: {rank['similarity']:.4f}  dist: {rank['distance']:.4f}")
            print()
