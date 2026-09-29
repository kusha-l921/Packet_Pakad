"""
sessionModels.py — In-Memory Session Aggregator Models & Data Structures.

Provides strongly typed dataclasses and lifecycle state enums for tracking
IKEv2 sessions, directional exchange payloads, intermediate Multi-KE rounds,
and runtime ESP data-plane telemetry.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class SessionLifecycleState(str, Enum):
    """Lifecycle states of an IKEv2 Security Association negotiation."""
    INITIATED = "INITIATED"                           # Saw IKE_SA_INIT Request
    INIT_RESPONDED = "INIT_RESPONDED"                 # Saw IKE_SA_INIT Response
    INTERMEDIATE_IN_PROGRESS = "INTERMEDIATE_IN_PROGRESS"  # Saw IKE_INTERMEDIATE (RFC 9370 Multi-KE)
    AUTH_REQUESTED = "AUTH_REQUESTED"                 # Saw IKE_AUTH Request
    HANDSHAKE_COMPLETED = "HANDSHAKE_COMPLETED"       # Saw IKE_AUTH Response -> Locked Handshake
    REKEYED = "REKEYED"                               # Saw CREATE_CHILD_SA rekey event
    TERMINATED = "TERMINATED"                         # Saw INFORMATIONAL Delete payload


@dataclass
class DirectionalStore:
    """Stores payloads from a single peer direction (Initiator or Responder)."""
    sa_init_proposals: list[dict[str, Any]] = field(default_factory=list)
    child_sa_proposals: list[dict[str, Any]] = field(default_factory=list)
    key_exchange: dict[str, Any] | None = None
    nonce: str | None = None
    authentication: dict[str, Any] | None = None
    certificate: dict[str, Any] | None = None
    certificates: list[dict[str, Any]] = field(default_factory=list)
    traffic_selectors: list[dict[str, Any]] = field(default_factory=list)
    identity: dict[str, Any] | None = None
    vendor_ids: list[str] = field(default_factory=list)

    @property
    def proposals(self) -> list[dict[str, Any]]:
        """Convenience accessor returning IKE SA proposals if present, else Child SA proposals."""
        return self.sa_init_proposals if self.sa_init_proposals else self.child_sa_proposals

    @proposals.setter
    def proposals(self, val: list[dict[str, Any]]) -> None:
        self.sa_init_proposals = val


@dataclass
class IntermediateRound:
    """Represents an IKE_INTERMEDIATE exchange round (e.g. RFC 9370 Multi-KE rounds 1..7)."""
    round_number: int
    message_id: int
    direction: str                                    # "request" or "response"
    key_exchange: dict[str, Any] | None = None
    proposals: list[dict[str, Any]] = field(default_factory=list)
    notify: list[dict[str, Any]] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)


@dataclass
class LifecycleEvent:
    """Chronological record of runtime exchanges (CREATE_CHILD_SA, INFORMATIONAL, Rekey, DPD)."""
    timestamp: float
    exchange_type: int | str
    message_id: int | None
    direction: str                                    # "request" or "response"
    event_type: str                                   # "REKEY", "DELETE", "DPD_KEEPALIVE", "NOTIFICATION"
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class DataPlaneTelemetry:
    """Tracks runtime ESP / NAT-T data-plane packet metrics for a session's Child SA."""
    spi: str | None = None                            # Normalized hex "0x..."
    packet_count: int = 0
    byte_count: int = 0
    seq_numbers: list[int] = field(default_factory=list)
    last_seq: int = 0
    is_natt: bool = False
    last_seen: float = 0.0

    def record_packet(self, seq: int, wire_bytes: int, is_natt: bool = False, ts: float | None = None) -> None:
        self.packet_count += 1
        self.byte_count += wire_bytes
        self.is_natt = is_natt
        self.last_seen = ts if ts is not None else time.time()
        self.seq_numbers.append(seq)
        if seq > self.last_seq:
            self.last_seq = seq


@dataclass
class SessionState:
    """Complete in-memory tracking entry for an IKEv2 session."""
    initiator_spi: str
    responder_spi: str | None = None
    state: SessionLifecycleState = SessionLifecycleState.INITIATED

    # Directional segregation stores
    initiator_store: DirectionalStore = field(default_factory=DirectionalStore)
    responder_store: DirectionalStore = field(default_factory=DirectionalStore)

    # Multi-KE intermediate exchanges (RFC 9370 rounds)
    intermediate_rounds: list[IntermediateRound] = field(default_factory=list)

    # Ordered lifecycle log for post-handshake events
    lifecycle_events: list[LifecycleEvent] = field(default_factory=list)

    # Unified, deduplicated notifications across all exchanges
    notify_types: set[int] = field(default_factory=set)
    notify_messages: list[dict[str, Any]] = field(default_factory=list)

    # Correlated Child SA SPIs (inbound/outbound)
    child_sa_spis: set[str] = field(default_factory=set)

    # Runtime ESP telemetry
    data_plane: DataPlaneTelemetry = field(default_factory=DataPlaneTelemetry)

    # Common IP/Port endpoint metadata
    common: dict[str, Any] = field(default_factory=dict)

    # Ingested daemon / out-of-band X.509 authentication metadata
    auth_metadata: dict[str, Any] | None = None

    # Timestamps
    created_at: float = field(default_factory=time.time)
    completed_at: float | None = None
    has_exported_handshake: bool = False

    # Thread synchronization lock for safe concurrent packet ingestion
    lock: threading.RLock = field(default_factory=threading.RLock)

    def is_handshake_complete(self) -> bool:
        return self.state in (
            SessionLifecycleState.HANDSHAKE_COMPLETED,
            SessionLifecycleState.REKEYED,
            SessionLifecycleState.TERMINATED,
        )

    def get_duration_ms(self) -> float:
        """Returns handshake duration in milliseconds if complete, else elapsed time."""
        end = self.completed_at if self.completed_at is not None else time.time()
        return max(0.0, (end - self.created_at) * 1000.0)
