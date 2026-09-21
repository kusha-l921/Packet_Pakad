"""Command-line interface for rag_report_generator (Parts 1 & 2)."""

import argparse
import json
import sys
from pathlib import Path

from . import (
    RAGConfig,
    ReportConfig,
    build_index,
    generate_report_from_phase5,
    retrieve,
    retrieve_for_indicator,
    retrieve_for_feature,
    retrieve_for_domain_status,
)


def _cmd_build(args: argparse.Namespace) -> int:
    """Build or rebuild the knowledge base index."""
    cfg = RAGConfig()
    if args.kb_path:
        cfg.knowledge_base_path = Path(args.kb_path).resolve()
    if args.index_path:
        cfg.index_path = Path(args.index_path).resolve()

    print(f"Building knowledge index from: {cfg.knowledge_base_path}")
    try:
        stats = build_index(cfg)
        print("\nKnowledge Base Build")
        print("--------------------")
        print(f"Documents: {stats.documents_count}")
        print(f"Chunks: {stats.chunks_count}")
        print(f"Embedding dimension: {stats.embedding_dimension}")
        print(f"Index: {stats.index_type}")
        print(f"Version: {stats.knowledge_base_version}")
        print(f"Status: {stats.status}")
        return 0
    except Exception as e:
        print(f"Build failed: {e}", file=sys.stderr)
        return 1


def _cmd_retrieve(args: argparse.Namespace) -> int:
    """Retrieve ranked explanatory evidence for a given query."""
    cfg = RAGConfig()
    if args.index_path:
        cfg.index_path = Path(args.index_path).resolve()

    filters = {}
    if args.category:
        filters["category"] = args.category

    try:
        result = retrieve(
            query=args.query,
            top_k=args.top_k,
            filters=filters if filters else None,
            config=cfg,
        )
    except FileNotFoundError as e:
        print(f"\n{e}", file=sys.stderr)
        print("Run:\npython scripts/build_knowledge_index.py\n", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Retrieval error: {e}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
        return 0

    print(f"\nQuery:\n{result.query}\n")
    if result.status == "NO_RELEVANT_EVIDENCE" or not result.retrieved_evidence:
        print("Status: NO_RELEVANT_EVIDENCE (no matching evidence met the relevance threshold)\n")
        return 0

    print("Results:\n")
    for ev in result.retrieved_evidence:
        print(f"[{ev.evidence_id}]")
        print(f"Title: {ev.title}")
        print(f"Category: {ev.category}")
        print(f"Section: {ev.section}")
        print(f"Score: {ev.score:.4f}")
        print(f"Source: {ev.source}")
        print("\nText:")
        print(ev.text)
        print("-" * 60 + "\n")

    return 0


def _cmd_generate(args: argparse.Namespace) -> int:
    """Generate structured JSON and Markdown report from Phase 5 JSON."""
    input_path = Path(args.input).resolve()
    if not input_path.exists():
        print(f"Input file not found: {input_path}", file=sys.stderr)
        return 1

    try:
        with open(input_path, "r", encoding="utf-8") as f:
            phase5_data = json.load(f)
    except Exception as e:
        print(f"Failed to read input JSON: {e}", file=sys.stderr)
        return 1

    cfg = ReportConfig(
        llm_provider=args.provider,
        llm_model=args.model,
        temperature=args.temperature,
    )

    rag_cfg = RAGConfig()
    if args.index_path:
        rag_cfg.index_path = Path(args.index_path).resolve()

    res = generate_report_from_phase5(
        analysis_result=phase5_data,
        config=cfg,
        rag_config=rag_cfg,
    )

    if args.output and res.markdown:
        out_p = Path(args.output).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(res.markdown, encoding="utf-8")
        print(f"Markdown report written to: {out_p}")

    if args.json_output and res.report_json:
        out_j = Path(args.json_output).resolve()
        out_j.parent.mkdir(parents=True, exist_ok=True)
        out_j.write_text(json.dumps(res.report_json, indent=2), encoding="utf-8")
        print(f"JSON report written to: {out_j}")

    if not args.output and not args.json_output:
        if res.markdown:
            print(res.markdown)
        else:
            print(json.dumps(res.to_dict(), indent=2))

    if res.status != "SUCCESS":
        print(f"\nReport generation status: {res.status}", file=sys.stderr)
        if res.validation.get("errors"):
            print("Validation errors:", file=sys.stderr)
            for err in res.validation["errors"]:
                print(f" - {err}", file=sys.stderr)
        return 1

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="rag_report_generator",
        description="RAG Knowledge Base, Retrieval, and Report Generation Subsystem (Parts 1 & 2)",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Build command
    build_parser = subparsers.add_parser("build", help="Build or rebuild the knowledge base index")
    build_parser.add_argument("--kb-path", type=str, default=None, help="Custom path to knowledge base directory")
    build_parser.add_argument("--index-path", type=str, default=None, help="Custom path to index storage directory")

    # Retrieve command
    retrieve_parser = subparsers.add_parser("retrieve", help="Query the knowledge base for ranked evidence")
    retrieve_parser.add_argument("--query", "-q", type=str, required=True, help="Retrieval query string")
    retrieve_parser.add_argument("--top-k", "-k", type=int, default=5, help="Number of evidence chunks to retrieve")
    retrieve_parser.add_argument("--category", "-c", type=str, default=None, help="Optional category filter")
    retrieve_parser.add_argument("--index-path", type=str, default=None, help="Path to index storage directory")
    retrieve_parser.add_argument("--json", action="store_true", help="Output machine-readable JSON format")

    # Generate command
    gen_parser = subparsers.add_parser("generate", help="Generate report from Phase 5 JSON")
    gen_parser.add_argument("--input", "-i", type=str, required=True, help="Path to Phase 5 Unified JSON file")
    gen_parser.add_argument("--output", "-o", type=str, default=None, help="Output Markdown report path")
    gen_parser.add_argument("--json-output", type=str, default=None, help="Output structured JSON report path")
    gen_parser.add_argument("--provider", type=str, default="mock", choices=["mock", "ollama"], help="LLM provider")
    gen_parser.add_argument("--model", type=str, default="llama3.2", help="LLM model name")
    gen_parser.add_argument("--temperature", type=float, default=0.1, help="LLM sampling temperature")
    gen_parser.add_argument("--index-path", type=str, default=None, help="Path to vector index directory")

    args = parser.parse_args()

    if args.command == "build":
        return _cmd_build(args)
    elif args.command == "retrieve":
        return _cmd_retrieve(args)
    elif args.command == "generate":
        return _cmd_generate(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
