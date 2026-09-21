"""DocumentChunk model representation."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class DocumentChunk:
    """Represents a coherent semantic chunk derived from a Document."""
    chunk_id: str
    document_id: str
    title: str
    category: str
    section: str
    text: str
    source: str
    version: str = "1.0"
    heading_level: int = 1
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "chunk_id": self.chunk_id,
            "document_id": self.document_id,
            "title": self.title,
            "category": self.category,
            "section": self.section,
            "text": self.text,
            "source": self.source,
            "version": self.version,
            "heading_level": self.heading_level,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DocumentChunk":
        return cls(
            chunk_id=data["chunk_id"],
            document_id=data["document_id"],
            title=data.get("title", ""),
            category=data.get("category", ""),
            section=data.get("section", ""),
            text=data.get("text", ""),
            source=data.get("source", ""),
            version=data.get("version", "1.0"),
            heading_level=data.get("heading_level", 1),
            metadata=data.get("metadata", {}),
        )
