"""Standalone RAG Knowledge Base, Retrieval, and Report Generation Subsystem (Parts 1 & 2)."""

import logging
from pathlib import Path
from typing import Any

from .src.config import RAGConfig
from .src.context.facts import extract_analysis_facts
from .src.context.query_plan import QueryPlanner, SectionQueryPlan
from .src.context.context_builder import ContextBuilder, AssembledContext
from .src.embeddings.factory import get_embedding_provider
from .src.generation.llm_provider import LLMProvider, MockLLMProvider
from .src.generation.ollama_provider import OllamaProvider
from .src.generation.markdown_renderer import MarkdownRenderer
from .src.generation.report_generator import ReportGenerator
from .src.ingestion.chunker import SemanticChunker
from .src.ingestion.loader import DocumentLoader
from .src.models.chunk import DocumentChunk
from .src.models.document import Document
from .src.models.evidence import BuildStats, RetrievalResult, RetrievedEvidence
from .src.models.facts import AnalysisFacts, FlowFact
from .src.models.report import Report
from .src.models.report_metadata import GeneratedReport, ReportConfig, ValidationSummary
from .src.retrieval.hybrid_retriever import HybridRetriever
from .src.retrieval.query_builder import QueryBuilder
from .src.retrieval.vector_store import FlatCosineVectorStore
from .src.validation.report_validator import ReportValidator
from .src.validation.fact_checker import FactChecker
from .src.validation.evidence_checker import EvidenceChecker
from .src.validation.terminology_checker import TerminologyChecker

logger = logging.getLogger(__name__)

# Package versions
RAG_KNOWLEDGE_BASE_VERSION = "1.0"
REPORT_SCHEMA_VERSION = "1.0"

_ACTIVE_VECTOR_STORE: FlatCosineVectorStore | None = None
_ACTIVE_CONFIG: RAGConfig | None = None


def build_index(config: RAGConfig | None = None) -> BuildStats:
    """Ingest documents, generate embeddings, and build the local vector index."""
    global _ACTIVE_VECTOR_STORE, _ACTIVE_CONFIG
    cfg = config or RAGConfig()

    kb_dir = cfg.knowledge_base_path
    if not kb_dir.exists():
        raise FileNotFoundError(
            f"Knowledge base directory not found at: {kb_dir}. "
            "Please ensure the curated knowledge base files exist."
        )

    loader = DocumentLoader(base_path=kb_dir)
    documents = loader.load_directory(kb_dir)
    if not documents:
        raise ValueError(f"No valid documents found in knowledge base directory: {kb_dir}")

    chunker = SemanticChunker()
    chunks = chunker.chunk_documents(documents)
    if not chunks:
        raise ValueError("Document chunking produced 0 chunks.")

    provider = get_embedding_provider(cfg)
    chunk_texts = [f"{c.title}\n{c.section}\n{c.text}" for c in chunks]
    embeddings = provider.embed_texts(chunk_texts)

    store = FlatCosineVectorStore(
        dimension=cfg.embedding_dimension,
        version=cfg.knowledge_base_version,
    )
    store.add_documents(chunks, embeddings)
    store.save(cfg.index_path)

    _ACTIVE_VECTOR_STORE = store
    _ACTIVE_CONFIG = cfg

    return BuildStats(
        documents_count=len(documents),
        chunks_count=len(chunks),
        embedding_dimension=cfg.embedding_dimension,
        index_type="FlatCosineVectorStore",
        knowledge_base_version=cfg.knowledge_base_version,
        status="SUCCESS",
        details={
            "knowledge_base_path": str(kb_dir),
            "index_path": str(cfg.index_path),
            "embedding_model": cfg.embedding_model,
        },
    )


def _get_or_load_vector_store(config: RAGConfig) -> FlatCosineVectorStore:
    """Retrieve in-memory store or load persisted store from disk."""
    global _ACTIVE_VECTOR_STORE, _ACTIVE_CONFIG

    if _ACTIVE_VECTOR_STORE is not None and _ACTIVE_CONFIG == config:
        return _ACTIVE_VECTOR_STORE

    store = FlatCosineVectorStore(
        dimension=config.embedding_dimension,
        version=config.knowledge_base_version,
    )
    store.load(config.index_path)
    _ACTIVE_VECTOR_STORE = store
    _ACTIVE_CONFIG = config
    return store


def retrieve(
    query: str,
    top_k: int = 5,
    filters: dict[str, Any] | None = None,
    config: RAGConfig | None = None,
) -> RetrievalResult:
    """Retrieve ranked evidence chunks for an arbitrary query string."""
    cfg = config or RAGConfig()
    store = _get_or_load_vector_store(cfg)
    provider = get_embedding_provider(cfg)
    retriever = HybridRetriever(
        vector_store=store,
        embedding_provider=provider,
        config=cfg,
    )
    return retriever.retrieve(query=query, top_k=top_k, filters=filters)


def retrieve_for_indicator(
    indicator: str,
    top_k: int = 3,
    config: RAGConfig | None = None,
) -> RetrievalResult:
    """Retrieve grounded explanatory evidence for a Phase 4 behavioral risk indicator."""
    query = QueryBuilder.build_indicator_query(indicator)
    return retrieve(
        query=query,
        top_k=top_k,
        filters={"category": "behavioral_indicator"},
        config=config,
    )


def retrieve_for_feature(
    feature_name: str,
    top_k: int = 3,
    config: RAGConfig | None = None,
) -> RetrievalResult:
    """Retrieve grounded explanatory evidence for a Phase 2 flow feature."""
    query = QueryBuilder.build_feature_query(feature_name)
    return retrieve(
        query=query,
        top_k=top_k,
        filters={"category": "feature"},
        config=config,
    )


def retrieve_for_domain_status(
    domain_status: str,
    top_k: int = 3,
    config: RAGConfig | None = None,
) -> RetrievalResult:
    """Retrieve grounded explanatory evidence for an IPsec domain validation status."""
    query = QueryBuilder.build_domain_query(domain_status)
    return retrieve(
        query=query,
        top_k=top_k,
        filters={"category": "integration"},
        config=config,
    )


def retrieve_for_evaluation_mode(
    eval_mode: str,
    top_k: int = 3,
    config: RAGConfig | None = None,
) -> RetrievalResult:
    """Retrieve grounded explanatory evidence for a dataset evaluation mode."""
    query = QueryBuilder.build_evaluation_query(eval_mode)
    return retrieve(
        query=query,
        top_k=top_k,
        filters={"category": "evaluation"},
        config=config,
    )


def retrieve_for_uncertainty(
    uncertainty_concept: str,
    top_k: int = 3,
    config: RAGConfig | None = None,
) -> RetrievalResult:
    """Retrieve grounded explanatory evidence for ML model uncertainty concepts."""
    query = QueryBuilder.build_uncertainty_query(uncertainty_concept)
    return retrieve(
        query=query,
        top_k=top_k,
        filters={"category": "classification"},
        config=config,
    )


# ====================================================================
# PART 2 — PUBLIC REPORT GENERATION API
# ====================================================================

def generate_report(
    analysis_result: dict[str, Any],
    retrieved_evidence: list[RetrievedEvidence],
    config: ReportConfig | None = None,
    provider: LLMProvider | None = None,
) -> GeneratedReport:
    """Generate structured and markdown report from Phase 5 JSON and RetrievedEvidence."""
    generator = ReportGenerator(config=config, provider=provider)
    return generator.generate(analysis_result, retrieved_evidence)


def generate_report_from_phase5(
    analysis_result: dict[str, Any],
    config: ReportConfig | None = None,
    rag_config: RAGConfig | None = None,
    provider: LLMProvider | None = None,
) -> GeneratedReport:
    logger.info("RAG started: extracting facts and constructing retrieval plan")
    cfg = config or ReportConfig()
    facts = extract_analysis_facts(analysis_result, max_flows=cfg.max_flows)
    plan = QueryPlanner.build_plan(facts)
    queries = plan.all_queries()
    logger.info("RAG queries generated: %d targeted queries planned", len(queries))

    gathered_evidence: list[RetrievedEvidence] = []
    seen_evidence_ids = set()
    for q in queries:
        res = retrieve(query=q, top_k=3, config=rag_config)
        for ev in res.retrieved_evidence:
            if ev.evidence_id not in seen_evidence_ids:
                seen_evidence_ids.add(ev.evidence_id)
                gathered_evidence.append(ev)

    logger.info("RAG evidence retrieved: %d unique evidence items gathered", len(gathered_evidence))

    return generate_report(
        analysis_result=analysis_result,
        retrieved_evidence=gathered_evidence,
        config=cfg,
        provider=provider,
    )


__all__ = [
    # Part 1
    "RAG_KNOWLEDGE_BASE_VERSION",
    "RAGConfig",
    "Document",
    "DocumentChunk",
    "RetrievedEvidence",
    "RetrievalResult",
    "BuildStats",
    "QueryBuilder",
    "FlatCosineVectorStore",
    "build_index",
    "retrieve",
    "retrieve_for_indicator",
    "retrieve_for_feature",
    "retrieve_for_domain_status",
    "retrieve_for_evaluation_mode",
    "retrieve_for_uncertainty",
    # Part 2
    "REPORT_SCHEMA_VERSION",
    "AnalysisFacts",
    "FlowFact",
    "extract_analysis_facts",
    "QueryPlanner",
    "SectionQueryPlan",
    "ContextBuilder",
    "AssembledContext",
    "ReportConfig",
    "ValidationSummary",
    "GeneratedReport",
    "Report",
    "LLMProvider",
    "MockLLMProvider",
    "OllamaProvider",
    "MarkdownRenderer",
    "ReportValidator",
    "FactChecker",
    "EvidenceChecker",
    "TerminologyChecker",
    "ReportGenerator",
    "generate_report",
    "generate_report_from_phase5",
]
