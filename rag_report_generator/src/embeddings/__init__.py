"""Embeddings package for rag_report_generator."""

from .base import EmbeddingProvider
from .local_provider import DeterministicLocalEmbeddingProvider
from .sentence_transformer_provider import SentenceTransformerEmbeddingProvider
from .factory import get_embedding_provider

__all__ = [
    "EmbeddingProvider",
    "DeterministicLocalEmbeddingProvider",
    "SentenceTransformerEmbeddingProvider",
    "get_embedding_provider",
]
