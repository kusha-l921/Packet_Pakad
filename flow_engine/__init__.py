"""
flow_engine — Machine Learning ESP Flow Classification & Telemetry Dispatcher.

Maintains sliding-window buffers for active ESP tunnels, computes statistical
traffic features, and coordinates ML prediction verdicts with the RFC rule engine.
"""

from __future__ import annotations

from .FlowRecord import FlowRecord
from .FlowEngine import (
    FlowEngine,
    FlowVerdict,
    RealtimePacketDispatcher,
    process_packet,
)

__all__ = [
    "FlowRecord",
    "FlowEngine",
    "FlowVerdict",
    "RealtimePacketDispatcher",
    "process_packet",
]
