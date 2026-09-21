#!/usr/bin/env python3
"""Root script to build or rebuild the RAG knowledge index."""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from rag_report_generator.scripts.build_knowledge_index import main

if __name__ == "__main__":
    sys.exit(main())
