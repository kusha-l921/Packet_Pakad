"""Sentence-transformers embedding provider adapter."""

import logging
from typing import Any

from .base import EmbeddingProvider

logger = logging.getLogger(__name__)


class SentenceTransformerEmbeddingProvider(EmbeddingProvider):
    """Adapter for sentence-transformers library if installed in the environment."""

    def __init__(self, model_name: str = "all-MiniLM-L6-v2") -> None:
        self._model_name = model_name
        self._model: Any = None
        self._dimension = 384
        self._initialize_model()

    def _initialize_model(self) -> None:
        try:
            from sentence_transformers import SentenceTransformer
            logger.info(f"Loading SentenceTransformer model: {self._model_name}")
            self._model = SentenceTransformer(self._model_name)
            self._dimension = self._model.get_sentence_embedding_dimension()
        except ImportError as e:
            raise ImportError(
                "sentence-transformers is not installed. To use SentenceTransformerEmbeddingProvider, "
                "install it via 'pip install sentence-transformers' or use the default "
                "DeterministicLocalEmbeddingProvider."
            ) from e

    @property
    def dimension(self) -> int:
        return self._dimension

    @property
    def model_name(self) -> str:
        return self._model_name

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        if self._model is None:
            raise RuntimeError("Model is not initialized.")
        embeddings = self._model.encode(texts, normalize_embeddings=True)
        return [e.tolist() for e in embeddings]

    def embed_query(self, query: str) -> list[float]:
        if self._model is None:
            raise RuntimeError("Model is not initialized.")
        embedding = self._model.encode(query, normalize_embeddings=True)
        return embedding.tolist()
