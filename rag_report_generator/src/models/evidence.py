"""Retrieved Evidence and Retrieval Result models."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class RetrievedEvidence:
    """Individual ranked piece of explanatory evidence retrieved from knowledge base."""
    evidence_id: str
    document_id: str
    title: str
    category: str
    section: str
    text: str
    score: float
    source: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "document_id": self.document_id,
            "title": self.title,
            "category": self.category,
            "section": self.section,
            "text": self.text,
            "score": round(self.score, 4),
            "source": self.source,
            "metadata": self.metadata,
        }


@dataclass
class RetrievalResult:
    """Standardized machine-readable retrieval response."""
    query: str
    retrieved_evidence: list[RetrievedEvidence]
    status: str
    knowledge_base_version: str = "1.0"

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "status": self.status,
            "knowledge_base_version": self.knowledge_base_version,
            "retrieved_evidence": [e.to_dict() for e in self.retrieved_evidence],
        }


@dataclass
class BuildStats:
    """Summary statistics for knowledge base indexing."""
    documents_count: int
    chunks_count: int
    embedding_dimension: int
    index_type: str
    knowledge_base_version: str
    status: str = "SUCCESS"
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "documents_count": self.documents_count,
            "chunks_count": self.chunks_count,
            "embedding_dimension": self.embedding_dimension,
            "index_type": self.index_type,
            "knowledge_base_version": self.knowledge_base_version,
            "status": self.status,
            "details": self.details,
        }
