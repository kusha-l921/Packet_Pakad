#!/usr/bin/env python3
"""Build or rebuild the knowledge base index for rag_report_generator."""

import sys
from pathlib import Path

# Add project root to sys.path to allow execution from any working directory
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rag_report_generator import RAGConfig, build_index


def main() -> int:
    config = RAGConfig()
    print("========================================")
    print("Building RAG Knowledge Base Index")
    print(f"Source: {config.knowledge_base_path}")
    print(f"Target: {config.index_path}")
    print("========================================")

    try:
        stats = build_index(config)
        print("\nKnowledge Base Build")
        print("--------------------")
        print(f"Documents: {stats.documents_count}")
        print(f"Chunks: {stats.chunks_count}")
        print(f"Embedding dimension: {stats.embedding_dimension}")
        print(f"Index: {stats.index_type}")
        print(f"Version: {stats.knowledge_base_version}")
        print(f"Status: {stats.status}")
        print("--------------------")
        print("Index successfully built and saved to disk.")
        return 0
    except Exception as e:
        print(f"\nERROR: Failed to build knowledge index: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
