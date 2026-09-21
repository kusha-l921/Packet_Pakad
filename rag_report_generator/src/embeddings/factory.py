"""Factory to instantiate the appropriate embedding provider based on configuration."""

import logging

from ..config import RAGConfig
from .base import EmbeddingProvider
from .local_provider import DeterministicLocalEmbeddingProvider
from .sentence_transformer_provider import SentenceTransformerEmbeddingProvider

logger = logging.getLogger(__name__)


def get_embedding_provider(config: RAGConfig | None = None) -> EmbeddingProvider:
    """Instantiate the configured embedding provider.

    Provider Selection:
    1. Default Provider: DeterministicLocalEmbeddingProvider
       - Purpose: Zero network access, CPU-friendly, 100% reproducible, lightweight local
         text-vectorization / embedding-style representation.
       - Dimensionality: 384-dimensional hashed subword vector space.
       - Suitable for the small, project-specific knowledge base.

    2. Optional Provider: SentenceTransformerEmbeddingProvider
       - Purpose: True pretrained neural semantic embeddings (e.g. all-MiniLM-L6-v2).
       - Requires sentence-transformers package and model weights.
       - Optional upgrade path; not enabled by default to keep the system CPU-friendly.
    """
    cfg = config or RAGConfig()
    provider_name = cfg.embedding_provider_name.lower()

    if "sentence" in provider_name or "transformer" in provider_name:
        try:
            return SentenceTransformerEmbeddingProvider(model_name=cfg.embedding_model)
        except ImportError:
            logger.warning(
                "sentence-transformers not available. Falling back to DeterministicLocalEmbeddingProvider."
            )
            return DeterministicLocalEmbeddingProvider(
                dimension=cfg.embedding_dimension,
                model_name=cfg.embedding_model,
            )

    return DeterministicLocalEmbeddingProvider(
        dimension=cfg.embedding_dimension,
        model_name=cfg.embedding_model,
    )
