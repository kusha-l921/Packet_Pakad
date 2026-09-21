"""Document loader supporting Markdown with frontmatter, plain text, and JSON."""

import json
import logging
import re
from pathlib import Path
from typing import Any

import yaml

from ..models.document import Document
from .normalizer import DocumentNormalizer

logger = logging.getLogger(__name__)


class DocumentLoader:
    """Discovers and loads documents from a directory tree into Document model instances."""

    SUPPORTED_EXTENSIONS = {".md", ".markdown", ".txt", ".json"}

    def __init__(self, base_path: Path | str | None = None) -> None:
        self.base_path = Path(base_path).resolve() if base_path else None

    def load_file(self, file_path: Path | str) -> Document | None:
        """Load a single document from disk with full metadata extraction."""
        path = Path(file_path).resolve()
        if not path.is_file():
            logger.warning(f"File not found or not a regular file: {path}")
            return None

        ext = path.suffix.lower()
        if ext not in self.SUPPORTED_EXTENSIONS:
            logger.warning(f"Unsupported file extension {ext} for file: {path}")
            return None

        try:
            content = path.read_text(encoding="utf-8")
        except Exception as e:
            logger.error(f"Failed to read file {path}: {e}")
            return None

        normalized_content = DocumentNormalizer.normalize(content)
        if not normalized_content:
            logger.warning(f"Skipping empty document: {path}")
            return None

        # Compute relative source path
        if self.base_path and path.is_relative_to(self.base_path):
            rel_source = str(path.relative_to(self.base_path))
        else:
            rel_source = path.name

        # Infer category from parent directory if within a subfolder
        default_category = path.parent.name if path.parent.name != "knowledge_base" else "general"
        stem_id = path.stem

        if ext in {".md", ".markdown"}:
            return self._parse_markdown(path, normalized_content, rel_source, default_category, stem_id)
        elif ext == ".json":
            return self._parse_json(path, normalized_content, rel_source, default_category, stem_id)
        else:
            return self._parse_plaintext(path, normalized_content, rel_source, default_category, stem_id)

    def _parse_markdown(
        self,
        path: Path,
        content: str,
        rel_source: str,
        default_category: str,
        stem_id: str,
    ) -> Document:
        """Parse frontmatter and markdown body."""
        frontmatter: dict[str, Any] = {}
        body = content

        # Check for YAML frontmatter between --- markers
        fm_match = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)$", content, flags=re.DOTALL)
        if fm_match:
            raw_fm = fm_match.group(1)
            body = fm_match.group(2).strip()
            try:
                parsed_fm = yaml.safe_load(raw_fm)
                if isinstance(parsed_fm, dict):
                    frontmatter = parsed_fm
            except Exception as e:
                logger.warning(f"Malformed YAML frontmatter in {path}: {e}. Proceeding without frontmatter.")

        # Extract title from frontmatter or first # header
        title = frontmatter.get("title")
        if not title:
            h1_match = re.search(r"^#\s+(.+)$", body, flags=re.MULTILINE)
            title = h1_match.group(1).strip() if h1_match else stem_id.replace("_", " ").title()

        doc_id = str(frontmatter.get("document_id") or stem_id)
        category = str(frontmatter.get("category") or default_category)
        section = str(frontmatter.get("section") or title)
        version = str(frontmatter.get("version") or "1.0")

        metadata = dict(frontmatter)
        metadata.setdefault("topic", stem_id)
        metadata.setdefault("authority", "project_doc")
        metadata.setdefault("project_specific", True)

        return Document(
            document_id=doc_id,
            title=title,
            category=category,
            section=section,
            source=rel_source,
            text=body,
            version=version,
            metadata=metadata,
        )

    def _parse_json(
        self,
        path: Path,
        content: str,
        rel_source: str,
        default_category: str,
        stem_id: str,
    ) -> Document | None:
        """Parse structured JSON document."""
        try:
            data = json.loads(content)
        except Exception as e:
            logger.error(f"Malformed JSON in {path}: {e}")
            return None

        if not isinstance(data, dict):
            logger.warning(f"JSON root must be an object in {path}")
            return None

        text = data.get("text") or data.get("content") or json.dumps(data, indent=2)
        title = data.get("title") or stem_id.replace("_", " ").title()
        doc_id = str(data.get("document_id") or stem_id)
        category = str(data.get("category") or default_category)
        section = str(data.get("section") or title)
        version = str(data.get("version") or "1.0")

        metadata = {k: v for k, v in data.items() if k not in {"text", "content"}}
        return Document(
            document_id=doc_id,
            title=title,
            category=category,
            section=section,
            source=rel_source,
            text=DocumentNormalizer.normalize(text),
            version=version,
            metadata=metadata,
        )

    def _parse_plaintext(
        self,
        path: Path,
        content: str,
        rel_source: str,
        default_category: str,
        stem_id: str,
    ) -> Document:
        """Parse plain text document."""
        lines = [line.strip() for line in content.split("\n") if line.strip()]
        title = lines[0] if lines else stem_id.replace("_", " ").title()

        return Document(
            document_id=stem_id,
            title=title,
            category=default_category,
            section=title,
            source=rel_source,
            text=content,
            version="1.0",
            metadata={"authority": "project_doc", "project_specific": True},
        )

    def load_directory(self, dir_path: Path | str) -> list[Document]:
        """Recursively discover and load all supported documents in a directory."""
        directory = Path(dir_path).resolve()
        if not directory.is_dir():
            logger.error(f"Directory does not exist: {directory}")
            return []

        if not self.base_path:
            self.base_path = directory

        documents: list[Document] = []
        for file_path in sorted(directory.rglob("*")):
            if file_path.is_file() and file_path.suffix.lower() in self.SUPPORTED_EXTENSIONS:
                doc = self.load_file(file_path)
                if doc:
                    documents.append(doc)

        logger.info(f"Loaded {len(documents)} documents from {directory}")
        return documents
