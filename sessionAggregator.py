"""
sessionAggregator.py — Top-level Facade for the Session Aggregator Module.

Provides direct access to the SessionAggregator engine and models,
delegating to session_aggregator.sessionAggregator.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure package root is in path
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from session_aggregator import (
    DataPlaneTelemetry,
    DirectionalStore,
    IntermediateRound,
    LifecycleEvent,
    SessionAggregator,
    SessionLifecycleState,
    SessionState,
    _normalize_spi,
)

__all__ = [
    "SessionAggregator",
    "SessionState",
    "SessionLifecycleState",
    "DirectionalStore",
    "IntermediateRound",
    "LifecycleEvent",
    "DataPlaneTelemetry",
    "_normalize_spi",
]

if __name__ == "__main__":
    print("=" * 70)
    print(" Session Aggregator Smoke Test")
    print("=" * 70)
    agg = SessionAggregator()
    print("[*] In-memory Session Aggregator initialized successfully.")
    print(f"[*] Active sessions: {len(agg.get_active_sessions())}")
    print("=" * 70)
