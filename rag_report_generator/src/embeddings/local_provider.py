"""Deterministic local text-vectorization / embedding-style representation provider."""

import hashlib
import math
import re
from typing import Sequence

from .base import EmbeddingProvider


class DeterministicLocalEmbeddingProvider(EmbeddingProvider):
    """Generates a deterministic local text-vectorization / embedding-style representation on CPU.

    Note on Terminology & Architecture:
    This is a lightweight, CPU-friendly deterministic vectorizer that maps tokens and subword
    n-grams into a fixed 384-dimensional vector space using signed feature hashing, sublinear
    TF-weighting, and L2 normalization. The 384 dimensions represent the hash projection
    dimensionality, NOT a pretrained neural semantic embedding model.

    For pretrained neural semantic embeddings, use the optional SentenceTransformerEmbeddingProvider.
    """

    def __init__(self, dimension: int = 384, model_name: str = "deterministic-subword-tfidf-384") -> None:
        self._dimension = dimension
        self._model_name = model_name

    @property
    def dimension(self) -> int:
        return self._dimension

    @property
    def model_name(self) -> str:
        return self._model_name

    def _tokenize(self, text: str) -> list[str]:
        """Extract words, compound identifiers, and acronyms."""
        # Convert to lower, preserve underscores
        cleaned = text.lower()
        # Find alphanumeric tokens + underscores
        tokens = re.findall(r"\b[a-z0-9_]{2,}\b", cleaned)
        return tokens

    def _extract_features(self, text: str) -> dict[str, float]:
        """Extract words and character n-grams with frequency weights."""
        tokens = self._tokenize(text)
        features: dict[str, float] = {}

        for tok in tokens:
            # Word feature with high weight
            features[f"w:{tok}"] = features.get(f"w:{tok}", 0.0) + 1.5

            # If token contains underscores (e.g. UNUSUAL_HIGH_PACKET_RATE), also add parts
            if "_" in tok:
                for part in tok.split("_"):
                    if len(part) >= 2:
                        features[f"p:{part}"] = features.get(f"p:{part}", 0.0) + 1.0

            # Subword character 3-grams and 4-grams
            tok_len = len(tok)
            if tok_len >= 3:
                for n in (3, 4):
                    for i in range(tok_len - n + 1):
                        ngram = tok[i : i + n]
                        features[f"g:{ngram}"] = features.get(f"g:{ngram}", 0.0) + 0.5

        # Sublinear scaling: w = 1.0 + ln(count)
        scaled_features: dict[str, float] = {}
        for feat, count in features.items():
            scaled_features[feat] = 1.0 + math.log(count)

        return scaled_features

    def _hash_feature(self, feature: str) -> tuple[int, float]:
        """Deterministically map a feature string to a dimension index and a sign (+1.0 or -1.0)."""
        h = hashlib.sha256(feature.encode("utf-8")).digest()
        # First 4 bytes for index
        idx_val = int.from_bytes(h[:4], "big")
        idx = idx_val % self._dimension

        # 5th byte for sign
        sign = 1.0 if (h[4] % 2 == 0) else -1.0
        return idx, sign

    def _vectorize(self, text: str) -> list[float]:
        """Convert a single text into a dense L2-normalized vector of size self.dimension."""
        if not text or not text.strip():
            return [0.0] * self._dimension

        features = self._extract_features(text)
        if not features:
            return [0.0] * self._dimension

        vec = [0.0] * self._dimension
        for feat, weight in features.items():
            idx, sign = self._hash_feature(feat)
            vec[idx] += sign * weight

        # Compute L2 norm
        norm_sq = sum(x * x for x in vec)
        if norm_sq <= 0.0:
            return [0.0] * self._dimension

        norm = math.sqrt(norm_sq)
        return [x / norm for x in vec]

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        """Generate dense vector embeddings for a list of text strings."""
        return [self._vectorize(t) for t in texts]

    def embed_query(self, query: str) -> list[float]:
        """Generate a dense vector embedding for a single query string."""
        return self._vectorize(query)
