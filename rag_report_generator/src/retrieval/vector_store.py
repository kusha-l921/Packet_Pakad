"""Vector store abstraction and FlatCosineVectorStore implementation."""

import hashlib
import json
import logging
import math
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from ..models.chunk import DocumentChunk

logger = logging.getLogger(__name__)


class VectorStore(ABC):
    """Abstract interface for local vector storage and similarity retrieval."""

    @abstractmethod
    def add_documents(self, chunks: list[DocumentChunk], embeddings: list[list[float]]) -> None:
        """Store document chunks and their associated embedding vectors."""
        pass

    @abstractmethod
    def search(
        self,
        query_embedding: list[float],
        top_k: int = 5,
        filters: dict[str, Any] | None = None,
    ) -> list[tuple[DocumentChunk, float]]:
        """Search for top_k most similar chunks, returning (chunk, similarity_score) pairs."""
        pass

    @abstractmethod
    def save(self, directory_path: Path | str) -> None:
        """Persist vector store index and chunks to disk."""
        pass

    @abstractmethod
    def load(self, directory_path: Path | str) -> None:
        """Reload vector store index and chunks from disk."""
        pass


class FlatCosineVectorStore(VectorStore):
    """Lightweight, CPU-only local vector store using exact cosine similarity."""

    def __init__(self, dimension: int = 384, version: str = "1.0") -> None:
        self.dimension = dimension
        self.version = version
        self.chunks: list[DocumentChunk] = []
        self.embeddings: list[list[float]] = []

    def add_documents(self, chunks: list[DocumentChunk], embeddings: list[list[float]]) -> None:
        """Store chunks and their corresponding dense vectors."""
        if len(chunks) != len(embeddings):
            raise ValueError(
                f"Mismatch: received {len(chunks)} chunks but {len(embeddings)} embedding vectors."
            )

        for chunk, vec in zip(chunks, embeddings):
            if len(vec) != self.dimension:
                raise ValueError(
                    f"Vector dimension mismatch: expected {self.dimension}, received {len(vec)}."
                )
            self.chunks.append(chunk)
            self.embeddings.append(vec)

        logger.info(f"Vector store holds {len(self.chunks)} total chunks.")

    def _matches_filters(self, chunk: DocumentChunk, filters: dict[str, Any] | None) -> bool:
        """Check if chunk attributes or metadata satisfy filter conditions."""
        if not filters:
            return True

        for key, target_val in filters.items():
            # Check top-level chunk attributes first
            if hasattr(chunk, key):
                val = getattr(chunk, key)
                if val != target_val:
                    return False
            # Check chunk metadata
            elif key in chunk.metadata:
                val = chunk.metadata[key]
                if isinstance(val, list) and not isinstance(target_val, list):
                    if target_val not in val:
                        return False
                elif val != target_val:
                    return False
            else:
                return False

        return True

    def search(
        self,
        query_embedding: list[float],
        top_k: int = 5,
        filters: dict[str, Any] | None = None,
    ) -> list[tuple[DocumentChunk, float]]:
        """Cosine similarity search across all indexed chunks."""
        if not self.chunks or not self.embeddings:
            return []

        if len(query_embedding) != self.dimension:
            raise ValueError(
                f"Query embedding dimension mismatch: expected {self.dimension}, got {len(query_embedding)}."
            )

        # Precompute query norm (or assume 1.0 if normalized)
        q_norm_sq = sum(q * q for q in query_embedding)
        q_norm = math.sqrt(q_norm_sq) if q_norm_sq > 0 else 1.0

        candidates: list[tuple[DocumentChunk, float]] = []

        for chunk, doc_vec in zip(self.chunks, self.embeddings):
            if not self._matches_filters(chunk, filters):
                continue

            # Dot product
            dot = sum(q * d for q, d in zip(query_embedding, doc_vec))
            # Normalized cosine similarity in [-1.0, 1.0]
            d_norm_sq = sum(d * d for d in doc_vec)
            d_norm = math.sqrt(d_norm_sq) if d_norm_sq > 0 else 1.0

            raw_cosine = dot / (q_norm * d_norm) if (q_norm * d_norm) > 0 else 0.0

            # Normalize cosine similarity to [0.0, 1.0]
            # When vectors are non-negative or zero-centered, (1.0 + raw_cosine) / 2.0 maps [-1, 1] to [0, 1]
            similarity = max(0.0, min(1.0, (1.0 + raw_cosine) / 2.0))
            candidates.append((chunk, similarity))

        # Sort by similarity descending
        candidates.sort(key=lambda x: x[1], reverse=True)
        return candidates[:top_k]

    def save(self, directory_path: Path | str) -> None:
        """Persist index metadata and chunk payload to a local folder."""
        dir_path = Path(directory_path).resolve()
        dir_path.mkdir(parents=True, exist_ok=True)

        metadata_file = dir_path / "index_metadata.json"
        data_file = dir_path / "chunks_and_vectors.json"

        # Checksum of serialized chunks
        payload = [
            {"chunk": chunk.to_dict(), "vector": vec}
            for chunk, vec in zip(self.chunks, self.embeddings)
        ]
        serialized_data = json.dumps(payload)
        checksum = hashlib.sha256(serialized_data.encode("utf-8")).hexdigest()

        index_metadata = {
            "version": self.version,
            "dimension": self.dimension,
            "chunk_count": len(self.chunks),
            "index_type": "FlatCosineVectorStore",
            "checksum": checksum,
        }

        metadata_file.write_text(json.dumps(index_metadata, indent=2), encoding="utf-8")
        data_file.write_text(serialized_data, encoding="utf-8")
        logger.info(f"Saved {len(self.chunks)} chunks to {dir_path}")

    def load(self, directory_path: Path | str) -> None:
        """Load index and chunks from a local folder."""
        dir_path = Path(directory_path).resolve()
        metadata_file = dir_path / "index_metadata.json"
        data_file = dir_path / "chunks_and_vectors.json"

        if not metadata_file.exists() or not data_file.exists():
            raise FileNotFoundError(
                f"Knowledge index not found at '{dir_path}'. Run: python scripts/build_knowledge_index.py"
            )

        try:
            meta_json = json.loads(metadata_file.read_text(encoding="utf-8"))
            stored_dim = meta_json.get("dimension")
            if stored_dim != self.dimension:
                raise ValueError(
                    f"Index dimension mismatch: index has {stored_dim}, but vector store configured for {self.dimension}."
                )

            data_json = json.loads(data_file.read_text(encoding="utf-8"))
        except Exception as e:
            raise RuntimeError(f"Failed to parse vector store index files in {dir_path}: {e}") from e

        loaded_chunks: list[DocumentChunk] = []
        loaded_embeddings: list[list[float]] = []

        for item in data_json:
            chunk = DocumentChunk.from_dict(item["chunk"])
            vec = item["vector"]
            loaded_chunks.append(chunk)
            loaded_embeddings.append(vec)

        self.chunks = loaded_chunks
        self.embeddings = loaded_embeddings
        logger.info(f"Loaded {len(self.chunks)} chunks from {dir_path}")
