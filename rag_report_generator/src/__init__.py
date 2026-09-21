"""rag_report_generator src root package."""

from .config import RAGConfig
from .models import Document, DocumentChunk, RetrievedEvidence, RetrievalResult, BuildStats
from .ingestion import DocumentLoader, DocumentNormalizer, SemanticChunker
from .embeddings import (
    EmbeddingProvider,
    DeterministicLocalEmbeddingProvider,
    SentenceTransformerEmbeddingProvider,
    get_embedding_provider,
)
from .retrieval import VectorStore, FlatCosineVectorStore, QueryBuilder, HybridRetriever

__all__ = [
    "RAGConfig",
    "Document",
    "DocumentChunk",
    "RetrievedEvidence",
    "RetrievalResult",
    "BuildStats",
    "DocumentLoader",
    "DocumentNormalizer",
    "SemanticChunker",
    "EmbeddingProvider",
    "DeterministicLocalEmbeddingProvider",
    "SentenceTransformerEmbeddingProvider",
    "get_embedding_provider",
    "VectorStore",
    "FlatCosineVectorStore",
    "QueryBuilder",
    "HybridRetriever",
]
