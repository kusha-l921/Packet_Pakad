"""Semantic heading-aware document chunker."""

import logging
import re
from typing import Any

from ..models.chunk import DocumentChunk
from ..models.document import Document

logger = logging.getLogger(__name__)


class SemanticChunker:
    """Splits documents into semantically coherent chunks based on heading hierarchies."""

    def __init__(self, max_chunk_chars: int = 2500) -> None:
        self.max_chunk_chars = max_chunk_chars

    def chunk_document(self, doc: Document) -> list[DocumentChunk]:
        """Convert a Document into an ordered list of semantic DocumentChunks."""
        text = doc.text.strip()
        if not text:
            return []

        # Find all markdown headers: #, ##, ###, ####
        heading_pattern = re.compile(r"^(#{1,4})\s+(.+)$", re.MULTILINE)
        matches = list(heading_pattern.finditer(text))

        if not matches:
            # Fallback for plain text or documents with no headings
            return self._chunk_by_paragraphs(doc, text)

        chunks: list[DocumentChunk] = []
        chunk_idx = 0

        # Preamble before first heading if substantial
        first_match = matches[0]
        if first_match.start() > 0:
            preamble_text = text[: first_match.start()].strip()
            # Clean possible horizontal rules
            preamble_text = re.sub(r"^\s*---\s*$", "", preamble_text, flags=re.MULTILINE).strip()
            if len(preamble_text) > 40:
                chunk_id = f"{doc.document_id}_{chunk_idx:03d}"
                chunks.append(
                    DocumentChunk(
                        chunk_id=chunk_id,
                        document_id=doc.document_id,
                        title=doc.title,
                        category=doc.category,
                        section=f"{doc.title} (Overview)",
                        text=preamble_text,
                        source=doc.source,
                        version=doc.version,
                        heading_level=1,
                        metadata=self._build_chunk_metadata(doc, doc.title, preamble_text),
                    )
                )
                chunk_idx += 1

        # Process each heading block
        for i, match in enumerate(matches):
            level = len(match.group(1))
            heading_title = match.group(2).strip()

            start_pos = match.start()
            end_pos = matches[i + 1].start() if i + 1 < len(matches) else len(text)

            section_body = text[start_pos:end_pos].strip()
            # Strip trailing horizontal rule if present
            section_body = re.sub(r"\n\s*---\s*$", "", section_body).strip()

            # Skip trivial or empty sections (e.g. just a heading with no body before next sub-heading)
            lines = [line.strip() for line in section_body.split("\n") if line.strip()]
            if len(lines) <= 1 and i + 1 < len(matches) and len(matches[i + 1].group(1)) > level:
                # This is a parent container heading immediately followed by a subsection;
                # don't generate an empty chunk for it
                continue

            if not section_body:
                continue

            # If section is very large, split by paragraphs while preserving headers
            if len(section_body) > self.max_chunk_chars:
                sub_chunks = self._split_large_section(doc, heading_title, section_body, level, chunk_idx)
                chunks.extend(sub_chunks)
                chunk_idx += len(sub_chunks)
            else:
                chunk_id = f"{doc.document_id}_{chunk_idx:03d}"
                chunks.append(
                    DocumentChunk(
                        chunk_id=chunk_id,
                        document_id=doc.document_id,
                        title=doc.title,
                        category=doc.category,
                        section=heading_title,
                        text=section_body,
                        source=doc.source,
                        version=doc.version,
                        heading_level=level,
                        metadata=self._build_chunk_metadata(doc, heading_title, section_body),
                    )
                )
                chunk_idx += 1

        return chunks

    def _split_large_section(
        self,
        doc: Document,
        heading_title: str,
        section_text: str,
        level: int,
        start_idx: int,
    ) -> list[DocumentChunk]:
        """Split a large section at paragraph boundaries while preserving context."""
        paragraphs = section_text.split("\n\n")
        chunks: list[DocumentChunk] = []
        current_paras: list[str] = []
        current_len = 0
        part = 1
        idx = start_idx

        for para in paragraphs:
            para = para.strip()
            if not para:
                continue

            if current_len + len(para) > self.max_chunk_chars and current_paras:
                chunk_text = "\n\n".join(current_paras)
                sec_name = f"{heading_title} (Part {part})" if part > 1 else heading_title
                chunk_id = f"{doc.document_id}_{idx:03d}"
                chunks.append(
                    DocumentChunk(
                        chunk_id=chunk_id,
                        document_id=doc.document_id,
                        title=doc.title,
                        category=doc.category,
                        section=sec_name,
                        text=chunk_text,
                        source=doc.source,
                        version=doc.version,
                        heading_level=level,
                        metadata=self._build_chunk_metadata(doc, sec_name, chunk_text),
                    )
                )
                idx += 1
                part += 1
                # Include section header in continuation chunk for context
                current_paras = [f"### {heading_title} (Continued)", para]
                current_len = sum(len(p) for p in current_paras)
            else:
                current_paras.append(para)
                current_len += len(para)

        if current_paras:
            chunk_text = "\n\n".join(current_paras)
            sec_name = f"{heading_title} (Part {part})" if part > 1 else heading_title
            chunk_id = f"{doc.document_id}_{idx:03d}"
            chunks.append(
                DocumentChunk(
                    chunk_id=chunk_id,
                    document_id=doc.document_id,
                    title=doc.title,
                    category=doc.category,
                    section=sec_name,
                    text=chunk_text,
                    source=doc.source,
                    version=doc.version,
                    heading_level=level,
                    metadata=self._build_chunk_metadata(doc, sec_name, chunk_text),
                )
            )

        return chunks

    def _chunk_by_paragraphs(self, doc: Document, text: str) -> list[DocumentChunk]:
        """Fallback chunker for text without headings."""
        paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
        chunks: list[DocumentChunk] = []
        current_paras: list[str] = []
        current_len = 0
        idx = 0

        for para in paragraphs:
            if current_len + len(para) > self.max_chunk_chars and current_paras:
                chunk_text = "\n\n".join(current_paras)
                chunk_id = f"{doc.document_id}_{idx:03d}"
                chunks.append(
                    DocumentChunk(
                        chunk_id=chunk_id,
                        document_id=doc.document_id,
                        title=doc.title,
                        category=doc.category,
                        section=doc.title,
                        text=chunk_text,
                        source=doc.source,
                        version=doc.version,
                        heading_level=1,
                        metadata=self._build_chunk_metadata(doc, doc.title, chunk_text),
                    )
                )
                idx += 1
                current_paras = [para]
                current_len = len(para)
            else:
                current_paras.append(para)
                current_len += len(para)

        if current_paras:
            chunk_text = "\n\n".join(current_paras)
            chunk_id = f"{doc.document_id}_{idx:03d}"
            chunks.append(
                DocumentChunk(
                    chunk_id=chunk_id,
                    document_id=doc.document_id,
                    title=doc.title,
                    category=doc.category,
                    section=doc.title,
                    text=chunk_text,
                    source=doc.source,
                    version=doc.version,
                    heading_level=1,
                    metadata=self._build_chunk_metadata(doc, doc.title, chunk_text),
                )
            )

        return chunks

    def _build_chunk_metadata(self, doc: Document, section_title: str, text: str) -> dict[str, Any]:
        """Inherit and enrich metadata for a chunk."""
        meta = dict(doc.metadata)
        meta["section"] = section_title
        meta["document_id"] = doc.document_id
        meta["title"] = doc.title
        meta["category"] = doc.category
        meta["source"] = doc.source
        meta["version"] = doc.version

        # Extract keywords from section title and text
        tokens = re.findall(r"\b[A-Za-z0-9_]{3,}\b", section_title)
        existing_kw = set(meta.get("keywords") or [])
        for token in tokens:
            if not token.isdigit():
                existing_kw.add(token)
        meta["keywords"] = sorted(list(existing_kw))

        return meta

    def chunk_documents(self, documents: list[Document]) -> list[DocumentChunk]:
        """Process a list of documents into semantic chunks."""
        all_chunks: list[DocumentChunk] = []
        for doc in documents:
            chunks = self.chunk_document(doc)
            all_chunks.extend(chunks)
        logger.info(f"Generated {len(all_chunks)} semantic chunks from {len(documents)} documents")
        return all_chunks
