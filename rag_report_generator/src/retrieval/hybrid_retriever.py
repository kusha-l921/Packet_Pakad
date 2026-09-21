"""Hybrid retrieval engine combining vector similarity, exact identifier boosting, and keyword relevance."""

import logging
import re
from typing import Any

from ..config import RAGConfig
from ..embeddings.base import EmbeddingProvider
from ..models.chunk import DocumentChunk
from ..models.evidence import RetrievedEvidence, RetrievalResult
from .vector_store import VectorStore

logger = logging.getLogger(__name__)


class HybridRetriever:
    """Executes hybrid retrieval: semantic embedding similarity + exact match boost + keyword overlap."""

    # Explicit list of high-priority distinctive project tokens
    PROJECT_IDENTIFIERS = {
        # Behavioral indicators
        "UNUSUAL_HIGH_UPLOAD_VOLUME",
        "UNUSUAL_HIGH_PACKET_RATE",
        "UNUSUAL_BURST_ACTIVITY",
        "LONG_LIVED_HIGH_VOLUME_FLOW",
        "PERIODIC_LOW_VOLUME_ACTIVITY",
        "STRONG_DIRECTIONAL_ASYMMETRY",
        # IPsec domain status
        "TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED",
        "VERIFIED IPSEC",
        "VERIFIED_IPSEC",
        "allow_unverified_domain",
        # Evaluation modes
        "GROUP_ISOLATED",
        "WITHIN_CAPTURE_HOLDOUT",
        "OVERALL_MIXED_EVALUATION",
        # Uncertainty
        "LOW_CLASSIFICATION_CONFIDENCE",
        # Protocols
        "ESP",
        "AH",
        "IKE",
        "IKEv1",
        "IKEv2",
        "NAT-T",
        "NAT_T",
        # Features (all 25 Phase 2 flow features)
        "total_packets",
        "forward_packets",
        "backward_packets",
        "total_bytes",
        "forward_bytes",
        "backward_bytes",
        "minimum_packet_size",
        "maximum_packet_size",
        "mean_packet_size",
        "standard_deviation_packet_size",
        "median_packet_size",
        "forward_mean_packet_size",
        "backward_mean_packet_size",
        "flow_duration_seconds",
        "packets_per_second",
        "bytes_per_second",
        "mean_inter_arrival_time",
        "minimum_inter_arrival_time",
        "maximum_inter_arrival_time",
        "standard_deviation_inter_arrival_time",
        "forward_packet_ratio",
        "backward_packet_ratio",
        "forward_byte_ratio",
        "backward_byte_ratio",
        "maximum_packets_in_one_second",
    }

    # Authority rank weights for tie-breaking
    SOURCE_PRIORITY_ORDER = [
        "project_phase4_spec",
        "project_phase2_spec",
        "project_integration_spec",
        "project_phase3_spec",
        "project_phase3_5_spec",
        "project_domain_spec",
        "project_system_spec",
        "project_doc",
    ]

    def __init__(
        self,
        vector_store: VectorStore,
        embedding_provider: EmbeddingProvider,
        config: RAGConfig | None = None,
    ) -> None:
        self.vector_store = vector_store
        self.embedding_provider = embedding_provider
        self.config = config or RAGConfig()

    def _extract_query_tokens(self, query: str) -> set[str]:
        """Extract alphanumeric tokens from query string."""
        return set(re.findall(r"\b[a-zA-Z0-9_-]{2,}\b", query.lower()))

    def _compute_keyword_overlap(self, query_tokens: set[str], chunk: DocumentChunk) -> float:
        """Compute normalized token overlap score between query and chunk."""
        if not query_tokens:
            return 0.0

        chunk_text_lower = (f"{chunk.title} {chunk.section} {chunk.text}").lower()
        chunk_tokens = set(re.findall(r"\b[a-zA-Z0-9_-]{2,}\b", chunk_text_lower))

        overlap = query_tokens.intersection(chunk_tokens)
        return len(overlap) / len(query_tokens)

    def _detect_exact_identifier_match(self, query: str, chunk: DocumentChunk) -> bool:
        """Check if any distinctive project identifier in the query appears in the chunk's section or text."""
        query_text = query.strip()

        for ident in self.PROJECT_IDENTIFIERS:
            # Case-insensitive identifier boundary check in query
            pattern = rf"\b{re.escape(ident)}\b"
            if re.search(pattern, query_text, flags=re.IGNORECASE):
                # Check if this identifier is in chunk section or title or text
                if re.search(pattern, chunk.section, flags=re.IGNORECASE):
                    return True
                if re.search(pattern, chunk.title, flags=re.IGNORECASE):
                    return True
                if re.search(pattern, chunk.text, flags=re.IGNORECASE):
                    return True

        return False

    def _get_source_priority_weight(self, chunk: DocumentChunk) -> float:
        """Calculate small tie-breaking priority score based on document authority."""
        authority = chunk.metadata.get("authority", "project_doc")
        if authority in self.SOURCE_PRIORITY_ORDER:
            idx = self.SOURCE_PRIORITY_ORDER.index(authority)
            # Higher priority gets a tiny boost (up to 0.005) for deterministic ordering
            return (len(self.SOURCE_PRIORITY_ORDER) - idx) * 0.0005
        return 0.0

    def retrieve(
        self,
        query: str,
        top_k: int | None = None,
        filters: dict[str, Any] | None = None,
    ) -> RetrievalResult:
        """Retrieve and rank evidence chunks using hybrid scoring."""
        cleaned_query = query.strip()
        if not cleaned_query:
            return RetrievalResult(
                query=query,
                retrieved_evidence=[],
                status="NO_RELEVANT_EVIDENCE",
                knowledge_base_version=self.config.knowledge_base_version,
            )

        limit = top_k if top_k is not None else self.config.top_k

        # 1. Generate query embedding
        query_vec = self.embedding_provider.embed_query(cleaned_query)

        # 2. Query vector store for candidate pool (retrieve larger pool to allow hybrid re-ranking)
        candidate_pool_size = max(limit * 3, 20)
        semantic_candidates = self.vector_store.search(
            query_embedding=query_vec,
            top_k=candidate_pool_size,
            filters=filters,
        )

        if not semantic_candidates:
            return RetrievalResult(
                query=query,
                retrieved_evidence=[],
                status="NO_RELEVANT_EVIDENCE",
                knowledge_base_version=self.config.knowledge_base_version,
            )

        query_tokens = self._extract_query_tokens(cleaned_query)
        scored_evidence: list[tuple[DocumentChunk, float]] = []

        # 3. Hybrid score calculation
        for chunk, semantic_score in semantic_candidates:
            # Check for exact identifier match
            exact_match = self._detect_exact_identifier_match(cleaned_query, chunk)
            exact_boost = self.config.exact_match_boost if exact_match else 0.0

            # Section title bonus if query token matches section heading directly
            section_clean = chunk.section.lower()
            if any(t in section_clean for t in query_tokens if len(t) > 3):
                exact_boost += 0.05

            # Keyword overlap
            kw_overlap = self._compute_keyword_overlap(query_tokens, chunk)

            # Combined hybrid formula
            raw_score = (
                (self.config.semantic_weight * semantic_score)
                + exact_boost
                + (self.config.keyword_weight * kw_overlap)
                + self._get_source_priority_weight(chunk)
            )

            # Normalize / clamp to [0.0, 1.0]
            final_score = min(1.0, max(0.0, raw_score))

            if final_score >= self.config.min_score_threshold:
                scored_evidence.append((chunk, final_score))

        # 4. Sort strictly descending by final_score
        scored_evidence.sort(key=lambda x: x[1], reverse=True)

        if not scored_evidence:
            return RetrievalResult(
                query=query,
                retrieved_evidence=[],
                status="NO_RELEVANT_EVIDENCE",
                knowledge_base_version=self.config.knowledge_base_version,
            )

        # 5. Format top_k results with deterministic evidence IDs E001, E002...
        retrieved_list: list[RetrievedEvidence] = []
        for rank, (chunk, score) in enumerate(scored_evidence[:limit], start=1):
            ev_id = f"E{rank:03d}"
            retrieved_list.append(
                RetrievedEvidence(
                    evidence_id=ev_id,
                    document_id=chunk.document_id,
                    title=chunk.title,
                    category=chunk.category,
                    section=chunk.section,
                    text=chunk.text,
                    score=score,
                    source=chunk.source,
                    metadata=chunk.metadata,
                )
            )

        return RetrievalResult(
            query=query,
            retrieved_evidence=retrieved_list,
            status="SUCCESS",
            knowledge_base_version=self.config.knowledge_base_version,
        )
