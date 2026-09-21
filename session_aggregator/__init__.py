"""
session_aggregator package.

Provides high-performance in-memory session aggregation, directional exchange
segregation, and analytical engine handoff for IKEv2 and IPsec traffic.
"""

from .sessionModels import (
    SessionLifecycleState,
    DirectionalStore,
    IntermediateRound,
    LifecycleEvent,
    DataPlaneTelemetry,
    SessionState,
)
from .sessionAggregator import SessionAggregator, _normalize_spi

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
