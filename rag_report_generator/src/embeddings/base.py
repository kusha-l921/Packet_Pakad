"""Abstract base class for embedding providers."""

from abc import ABC, abstractmethod


class EmbeddingProvider(ABC):
    """Interface for text embedding providers."""

    @abstractmethod
    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        """Generate dense vector embeddings for a list of text strings."""
        pass

    @abstractmethod
    def embed_query(self, query: str) -> list[float]:
        """Generate a dense vector embedding for a single query string."""
        pass

    @property
    @abstractmethod
    def dimension(self) -> int:
        """The dimensionality of the output embedding vectors."""
        pass

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Human-readable identifier for the embedding model."""
        pass
