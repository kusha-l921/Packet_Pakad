"""Configuration settings for rag_report_generator."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class RAGConfig:
    """Configuration container for RAG ingestion, text vectorization/embeddings, and retrieval.

    Embedding Notes:
    - `embedding_provider_name`: Defaults to 'deterministic-local-384' (a CPU-only deterministic
      text-vectorization / embedding-style representation using hashed subwords).
    - `embedding_dimension`: 384 dimensions represents the vector space dimensionality,
      not a pretrained 384-dimensional neural model.
    - For true pretrained semantic models, set embedding_provider_name to 'sentence-transformer'.
    """
    knowledge_base_path: Path = field(
        default_factory=lambda: Path(__file__).resolve().parent.parent / "knowledge_base"
    )
    index_path: Path = field(
        default_factory=lambda: Path(__file__).resolve().parent.parent / "storage" / "index"
    )
    embedding_provider_name: str = "deterministic-local-384"
    embedding_model: str = "deterministic-subword-tfidf-384"
    embedding_dimension: int = 384
    top_k: int = 5
    semantic_weight: float = 0.60
    exact_match_boost: float = 0.25
    keyword_weight: float = 0.15
    min_score_threshold: float = 0.10
    knowledge_base_version: str = "1.0"

    def __post_init__(self) -> None:
        self.knowledge_base_path = Path(self.knowledge_base_path).resolve()
        self.index_path = Path(self.index_path).resolve()

    def to_dict(self) -> dict[str, Any]:
        return {
            "knowledge_base_path": str(self.knowledge_base_path),
            "index_path": str(self.index_path),
            "embedding_provider_name": self.embedding_provider_name,
            "embedding_model": self.embedding_model,
            "embedding_dimension": self.embedding_dimension,
            "top_k": self.top_k,
            "semantic_weight": self.semantic_weight,
            "exact_match_boost": self.exact_match_boost,
            "keyword_weight": self.keyword_weight,
            "min_score_threshold": self.min_score_threshold,
            "knowledge_base_version": self.knowledge_base_version,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RAGConfig":
        kb_path = Path(data["knowledge_base_path"]) if "knowledge_base_path" in data else None
        idx_path = Path(data["index_path"]) if "index_path" in data else None
        kwargs: dict[str, Any] = {}
        if kb_path:
            kwargs["knowledge_base_path"] = kb_path
        if idx_path:
            kwargs["index_path"] = idx_path
        for k in (
            "embedding_provider_name",
            "embedding_model",
            "embedding_dimension",
            "top_k",
            "semantic_weight",
            "exact_match_boost",
            "keyword_weight",
            "min_score_threshold",
            "knowledge_base_version",
        ):
            if k in data:
                kwargs[k] = data[k]
        return cls(**kwargs)
