"""Raw Document representation."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Document:
    """Represents a loaded raw document before semantic chunking."""
    document_id: str
    title: str
    category: str
    section: str
    source: str
    text: str
    version: str = "1.0"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "document_id": self.document_id,
            "title": self.title,
            "category": self.category,
            "section": self.section,
            "source": self.source,
            "text": self.text,
            "version": self.version,
            "metadata": self.metadata,
        }
