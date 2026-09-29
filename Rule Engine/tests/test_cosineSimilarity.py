"""
test_cosineSimilarity.py -- Unit tests for cosine similarity and policy classification.

Run:  python test_cosineSimilarity.py
"""

import sys
from pathlib import Path
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
from vector_engine.cosineSimilarity import (
    cosine_similarity,
    cosine_distance,
    classify_vector,
    classify_session,
    get_anchor_similarity_matrix,
)
from vector_engine.baseVectors import (
    POLICY_ANCHORS,
    CNSA2_VECTOR,
    NIST_PQC_TRANSITIONAL_VECTOR,
    RFC8247_CLASSICAL_VECTOR,
    NIST_SP800_131A_DEPRECATED_VECTOR,
)

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


@test
def test_cosine_similarity_identical_vectors():
    u = [1.0, 0.5, 0.0, 1.0]
    sim = cosine_similarity(u, u)
    assert abs(sim - 1.0) < 1e-6, f"Expected 1.0, got {sim}"
    dist = cosine_distance(u, u)
    assert abs(dist - 0.0) < 1e-6, f"Expected 0.0, got {dist}"


@test
def test_cosine_similarity_orthogonal_vectors():
    u = [1.0, 0.0, 0.0]
    v = [0.0, 1.0, 0.0]
    sim = cosine_similarity(u, v)
    assert abs(sim - 0.0) < 1e-6, f"Expected 0.0, got {sim}"
    dist = cosine_distance(u, v)
    assert abs(dist - 1.0) < 1e-6, f"Expected 1.0, got {dist}"


@test
def test_cosine_similarity_zero_vector():
    u = [0.0, 0.0, 0.0]
    v = [1.0, 1.0, 1.0]
    assert cosine_similarity(u, v) == 0.0
    assert cosine_similarity(v, u) == 0.0


@test
def test_numpy_and_list_give_same_results():
    try:
        import numpy as np
    except ImportError:
        return
    u = [1.0, 0.5, 0.75, 0.0, 0.33]
    v = [0.5, 0.5, 0.0, 1.0, 0.0]
    sim_list = cosine_similarity(u, v)
    sim_np = cosine_similarity(np.array(u, dtype=np.float32), np.array(v, dtype=np.float32))
    assert abs(sim_list - sim_np) < 1e-5, f"Mismatch: list={sim_list}, np={sim_np}"


@test
def test_classification_exact_anchors():
    for name, anchor in POLICY_ANCHORS.items():
        res = classify_vector(anchor.vector)
        assert res["best_match"] == name, f"Expected {name}, got {res['best_match']}"
        assert abs(res["best_score"] - 1.0) < 1e-4, f"Expected ~1.0, got {res['best_score']}"


@test
def test_matrix_diagonal_is_one():
    names, matrix = get_anchor_similarity_matrix()
    for i in range(len(names)):
        diag = float(matrix[i][i]) if not hasattr(matrix, 'shape') else float(matrix[i, i])
        assert abs(diag - 1.0) < 1e-5, f"Diagonal [{i},{i}] is {diag}, expected 1.0"


if __name__ == "__main__":
    print("\n  Cosine Similarity Engine -- Test Suite")
    print("  " + "=" * 45)
    ok = _run_all()
    sys.exit(0 if ok else 1)
