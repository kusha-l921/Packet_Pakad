"""
sessionAggregator.py — In-Memory Session Aggregator for IPsec / IKEv2 Analysis.

Acts as the middle-layer correlation state machine between per-packet metadata
extractors (metadataExtractor.py) and downstream analytical engines:
  • 19-D Cryptographic Vector Engine (vector_engine)
  • 12-Category RFC Compliance Rule Engine (rfc_engine)
  • PKI & Certificate Health Engine (cert_engine)
  • Flow & Traffic Classification Engine (flow_engine)

Zero disk I/O during active capture; all session accumulation, directional sorting,
and bi-directional SPI indexing occur entirely in RAM.
"""

from __future__ import annotations

import json
from pathlib import Path
import threading
import time
from typing import Any, Callable

from .sessionModels import (
    DataPlaneTelemetry,
    DirectionalStore,
    IntermediateRound,
    LifecycleEvent,
    SessionLifecycleState,
    SessionState,
)


def _normalize_spi(val: Any) -> str | None:
    """Normalize any SPI representation (int, hex str, bytes) to lowercase '0x...' string."""
    if val is None:
        return None
    if isinstance(val, int):
        return f"0x{val:016x}" if val > 0xFFFFFFFF else f"0x{val:08x}"
    s = str(val).strip().lower()
    if s in ("", "none", "0x0", "0x0000000000000000", "0x00000000"):
        return None
    if s.startswith("0x"):
        raw = s[2:]
    else:
        raw = s.replace(":", "")
    if not raw or all(c == "0" for c in raw):
        return None
    return f"0x{raw}"


class SessionAggregator:
    """High-performance, in-memory state machine for correlating IKEv2 and ESP traffic."""

    def __init__(self) -> None:
        # Primary session store keyed strictly by initiator_spi ("0x...")
        self.sessions_by_init_spi: dict[str, SessionState] = {}

        # Secondary bi-directional index: responder_spi -> initiator_spi
        self.init_spi_by_resp_spi: dict[str, str] = {}

        # Child SA index: child_spi (ESP SPI) -> initiator_spi
        self.init_spi_by_child_spi: dict[str, str] = {}

        # Global concurrency lock for cross-table mutations
        self._global_lock = threading.RLock()

        # Handshake completion observer callbacks: fn(session_state, canonical_dict)
        self._handshake_callbacks: list[Callable[[SessionState, dict[str, Any]], None]] = []

    # ═══════════════════════════════════════════════════════════════════════════
    #  Registration & Observers
    # ═══════════════════════════════════════════════════════════════════════════

    def on_handshake_complete(
        self, callback: Callable[[SessionState, dict[str, Any]], None]
    ) -> None:
        """Register a callback invoked when an IKEv2 session completes its IKE_AUTH exchange."""
        with self._global_lock:
            self._handshake_callbacks.append(callback)

    # ═══════════════════════════════════════════════════════════════════════════
    #  Packet Ingestion Entry Points
    # ═══════════════════════════════════════════════════════════════════════════

    def ingest_packet(self, pkt_metadata: dict[str, Any] | None) -> SessionState | None:
        """Demultiplex and ingest any metadata dictionary (IKEv2 control or ESP data plane)."""
        if not pkt_metadata or not isinstance(pkt_metadata, dict):
            return None

        # Check for pre-assembled composite full-handshake dictionary
        if "IKE_SA_INIT" in pkt_metadata and "IKE_AUTH" in pkt_metadata:
            return self.ingest_composite_session(pkt_metadata)

        plane = pkt_metadata.get("common", {}).get("plane") or pkt_metadata.get("plane")
        if plane == "data" or ("spi" in pkt_metadata and "seq_num" in pkt_metadata):
            return self.process_esp_packet(pkt_metadata)
        return self.process_ike_packet(pkt_metadata)

    def ingest_composite_session(self, composite_dict: dict[str, Any]) -> SessionState | None:
        """Ingest a pre-assembled composite session dictionary into the state machine."""
        common = composite_dict.get("common", {})
        init_spi = _normalize_spi(
            common.get("initiator_spi")
            or composite_dict.get("session_id")
            or composite_dict.get("initiator_spi")
        )
        resp_spi = _normalize_spi(
            common.get("responder_spi") or composite_dict.get("responder_spi")
        )
        if not init_spi:
            return None

        ts = float(common.get("timestamps", {}).get("first_seen") or time.time())
        with self._global_lock:
            if init_spi not in self.sessions_by_init_spi:
                session = SessionState(initiator_spi=init_spi, created_at=ts)
                self.sessions_by_init_spi[init_spi] = session
            else:
                session = self.sessions_by_init_spi[init_spi]

            if resp_spi:
                session.responder_spi = resp_spi
                self.init_spi_by_resp_spi[resp_spi] = init_spi

        with session.lock:
            # Populate endpoints & protocol
            endpoints = common.get("endpoints", {})
            for k in ("src_ip", "dst_ip", "src_port", "dst_port"):
                if k in endpoints:
                    session.common[k] = endpoints[k]
            if "initiator_ip" in endpoints and "src_ip" not in session.common:
                session.common["src_ip"] = endpoints["initiator_ip"]
            if "responder_ip" in endpoints and "dst_ip" not in session.common:
                session.common["dst_ip"] = endpoints["responder_ip"]
            if "protocol_version" in common:
                session.common["ike_version"] = common["protocol_version"]

            # Notifications
            self._merge_notifications(session, composite_dict)

            # IKE_SA_INIT
            init_data = composite_dict.get("IKE_SA_INIT", {})
            proposals = init_data.get("proposals", [])
            if not proposals and "proposal" in init_data:
                proposals = [init_data["proposal"]]
            session.initiator_store.sa_init_proposals = proposals
            session.responder_store.sa_init_proposals = proposals
            session.initiator_store.key_exchange = init_data.get("key_exchange")
            session.responder_store.key_exchange = init_data.get("key_exchange")

            # Multi-KE / IKE_INTERMEDIATE
            intermediates = composite_dict.get("IKE_INTERMEDIATE", [])
            if isinstance(intermediates, list):
                for idx, r in enumerate(intermediates, start=1):
                    ir = IntermediateRound(
                        round_number=r.get("round", idx),
                        message_id=idx,
                        direction="response",
                        key_exchange=r.get("key_exchange"),
                        proposals=r.get("proposals", []),
                        notify=r.get("notify", []),
                        timestamp=ts,
                    )
                    session.intermediate_rounds.append(ir)

            # IKE_AUTH
            auth_data = composite_dict.get("IKE_AUTH", {})
            session.initiator_store.authentication = auth_data.get("initiator_auth") or auth_data.get("initiator")
            session.responder_store.authentication = auth_data.get("responder_auth") or auth_data.get("responder")
            session.initiator_store.traffic_selectors = auth_data.get("traffic_selectors", {}).get("initiator", [])
            session.responder_store.traffic_selectors = auth_data.get("traffic_selectors", {}).get("responder", [])

            child_props = auth_data.get("child_sa_proposals", [])
            if not child_props and "child_sa" in auth_data:
                child_props = auth_data["child_sa"].get("proposals", [])
            if child_props:
                session.initiator_store.child_sa_proposals = child_props
                session.responder_store.child_sa_proposals = child_props
                self._register_child_spis(session, child_props)

            # ESP Data Plane Telemetry
            dp_data = composite_dict.get("data_plane", {})
            if dp_data:
                dp_spi = _normalize_spi(dp_data.get("spi"))
                if dp_spi:
                    session.data_plane.spi = dp_spi
                    session.child_sa_spis.add(dp_spi)
                    with self._global_lock:
                        self.init_spi_by_child_spi[dp_spi] = session.initiator_spi
                session.data_plane.packet_count = int(dp_data.get("packet_count", 0))
                session.data_plane.byte_count = int(dp_data.get("byte_count", 0))
                session.data_plane.seq_numbers = list(dp_data.get("seq_numbers", []))
                session.data_plane.last_seq = int(dp_data.get("last_seq", 0))
                session.data_plane.is_natt = bool(dp_data.get("is_natt", False))

            # Auth metadata
            if "auth_metadata" in composite_dict:
                session.auth_metadata = composite_dict["auth_metadata"]

            # Mark state completed
            session.state = SessionLifecycleState.HANDSHAKE_COMPLETED
            session.completed_at = float(common.get("timestamps", {}).get("last_seen") or time.time())

        return session

    def process_ike_packet(self, pkt_dict: dict[str, Any]) -> SessionState | None:
        """Ingest a parsed IKEv2 packet metadata dictionary."""
        common = pkt_dict.get("common", {})
        init_spi = _normalize_spi(common.get("initiator_spi"))
        resp_spi = _normalize_spi(common.get("responder_spi"))
        is_response = bool(common.get("is_response", False))
        exchange_type = common.get("exchange_type") or pkt_dict.get("exchange_type")
        message_id = common.get("message_id")
        ts = float(common.get("timestamp") or time.time())

        # Resolve or initialize session
        session: SessionState | None = None

        with self._global_lock:
            if init_spi:
                if init_spi not in self.sessions_by_init_spi:
                    session = SessionState(initiator_spi=init_spi, created_at=ts)
                    self.sessions_by_init_spi[init_spi] = session
                else:
                    session = self.sessions_by_init_spi[init_spi]
            elif resp_spi and resp_spi in self.init_spi_by_resp_spi:
                mapped_init = self.init_spi_by_resp_spi[resp_spi]
                session = self.sessions_by_init_spi.get(mapped_init)

            if session is None:
                return None

            # Index responder SPI as soon as it appears
            if resp_spi:
                if session.responder_spi is None:
                    session.responder_spi = resp_spi
                if resp_spi not in self.init_spi_by_resp_spi:
                    self.init_spi_by_resp_spi[resp_spi] = session.initiator_spi

        # Mutate session under its instance lock
        with session.lock:
            # 1. Update common endpoint metadata
            for k in ("src_ip", "dst_ip", "src_port", "dst_port", "ike_version"):
                if k in common and common[k] is not None:
                    session.common[k] = common[k]

            # 2. Merge notifications across all exchanges into deduplicated session pool
            self._merge_notifications(session, pkt_dict)

            # 3. Directional routing
            target_store = (
                session.responder_store if is_response else session.initiator_store
            )

            # 4. Exchange-specific state transitions
            canonical_to_emit: dict[str, Any] | None = None

            if exchange_type in (34, "IKE_SA_INIT"):
                init_data = pkt_dict.get("IKE_SA_INIT", {})
                target_store.sa_init_proposals = init_data.get("proposals", [])
                target_store.key_exchange = init_data.get("key_exchange")
                if is_response:
                    session.state = SessionLifecycleState.INIT_RESPONDED
                else:
                    session.state = SessionLifecycleState.INITIATED

            elif exchange_type in (38, 43, "IKE_INTERMEDIATE"):
                inter_data = pkt_dict.get("IKE_INTERMEDIATE", {})
                round_num = (len(session.intermediate_rounds) // 2) + 1
                ir = IntermediateRound(
                    round_number=round_num,
                    message_id=message_id if message_id is not None else 0,
                    direction="response" if is_response else "request",
                    key_exchange=inter_data.get("key_exchange"),
                    proposals=inter_data.get("proposals", []),
                    notify=inter_data.get("notify", []),
                    timestamp=ts,
                )
                session.intermediate_rounds.append(ir)
                session.state = SessionLifecycleState.INTERMEDIATE_IN_PROGRESS

            elif exchange_type in (35, "IKE_AUTH"):
                auth_data = pkt_dict.get("IKE_AUTH", {})
                target_store.authentication = auth_data.get("authentication")
                target_store.certificate = auth_data.get("certificate")
                target_store.certificates = auth_data.get("certificates", [])
                target_store.traffic_selectors = auth_data.get("traffic_selectors", {})

                # Register negotiated Child SA SPIs
                child_props = auth_data.get("child_sa", {}).get("proposals", [])
                if child_props:
                    target_store.child_sa_proposals = child_props
                    self._register_child_spis(session, child_props)

                if not is_response:
                    session.state = SessionLifecycleState.AUTH_REQUESTED
                else:
                    # ── Handshake Completion Trigger ───────────────────
                    session.state = SessionLifecycleState.HANDSHAKE_COMPLETED
                    session.completed_at = ts
                    canonical_to_emit = self._build_canonical_dict_locked(session)

            elif exchange_type in (36, "CREATE_CHILD_SA"):
                child_data = pkt_dict.get("CREATE_CHILD_SA", {})
                props = child_data.get("proposals", [])
                if props:
                    self._register_child_spis(session, props)
                event = LifecycleEvent(
                    timestamp=ts,
                    exchange_type=exchange_type,
                    message_id=message_id,
                    direction="response" if is_response else "request",
                    event_type="REKEY",
                    details=child_data,
                )
                session.lifecycle_events.append(event)
                if session.is_handshake_complete():
                    session.state = SessionLifecycleState.REKEYED

            elif exchange_type in (37, "INFORMATIONAL"):
                info_data = pkt_dict.get("INFORMATIONAL", {})
                deletes = info_data.get("delete", [])
                event_type = "DELETE" if deletes else "DPD_KEEPALIVE"
                event = LifecycleEvent(
                    timestamp=ts,
                    exchange_type=exchange_type,
                    message_id=message_id,
                    direction="response" if is_response else "request",
                    event_type=event_type,
                    details=info_data,
                )
                session.lifecycle_events.append(event)
                if deletes:
                    session.state = SessionLifecycleState.TERMINATED

            else:
                event = LifecycleEvent(
                    timestamp=ts,
                    exchange_type=exchange_type,
                    message_id=message_id,
                    direction="response" if is_response else "request",
                    event_type="CUSTOM",
                    details=pkt_dict,
                )
                session.lifecycle_events.append(event)

        # Trigger callbacks outside session lock to avoid deadlocks
        if canonical_to_emit is not None:
            for cb in self._handshake_callbacks:
                try:
                    cb(session, canonical_to_emit)
                except Exception:
                    pass

        return session

    def process_esp_packet(self, esp_dict: dict[str, Any]) -> SessionState | None:
        """Ingest a parsed ESP / NAT-T data-plane packet metadata dictionary."""
        spi_val = esp_dict.get("spi") or esp_dict.get("spi_hex")
        spi = _normalize_spi(spi_val)
        seq_num = int(esp_dict.get("seq_num", 0))
        wire_bytes = int(esp_dict.get("wire_bytes", 0))
        is_natt = bool(esp_dict.get("is_natt", False))
        ts = float(esp_dict.get("timestamp") or time.time())

        session: SessionState | None = None
        with self._global_lock:
            if spi and spi in self.init_spi_by_child_spi:
                mapped_init = self.init_spi_by_child_spi[spi]
                session = self.sessions_by_init_spi.get(mapped_init)

        if session is not None:
            with session.lock:
                session.data_plane.record_packet(seq_num, wire_bytes, is_natt, ts)
                session.data_plane.spi = spi
            return session

        return None

    # ═══════════════════════════════════════════════════════════════════════════
    #  Canonical Composite Session Dictionary (Downstream Handoff)
    # ═══════════════════════════════════════════════════════════════════════════

    def get_canonical_session_dict(self, initiator_spi: str) -> dict[str, Any]:
        """Construct the canonical composite dictionary for vector and compliance engines."""
        norm_init = _normalize_spi(initiator_spi)
        if not norm_init:
            raise KeyError(f"Invalid initiator SPI: {initiator_spi}")

        with self._global_lock:
            session = self.sessions_by_init_spi.get(norm_init)
            if not session:
                raise KeyError(f"Session with initiator_spi '{initiator_spi}' not found")

        with session.lock:
            return self._build_canonical_dict_locked(session)

    def _build_canonical_dict_locked(self, session: SessionState) -> dict[str, Any]:
        """Internal builder called under session.lock."""
        # 1. Common Metadata
        common = {
            "plane": "control",
            "ike_version": session.common.get("ike_version", 2),
            "src_ip": session.common.get("src_ip", "0.0.0.0"),
            "dst_ip": session.common.get("dst_ip", "0.0.0.0"),
            "src_port": session.common.get("src_port", 500),
            "dst_port": session.common.get("dst_port", 500),
            "initiator_spi": session.initiator_spi,
            "responder_spi": session.responder_spi or "0x0000000000000000",
            "completed": session.is_handshake_complete(),
            "duration_ms": session.get_duration_ms(),
        }

        # 2. Chosen / Negotiated Proposals for IKE_SA_INIT
        # Responder proposal is authoritative; fall back to initiator proposals
        sa_init_proposals = (
            session.responder_store.sa_init_proposals
            if session.responder_store.sa_init_proposals
            else session.initiator_store.sa_init_proposals
        )
        sa_init_ke = (
            session.responder_store.key_exchange
            or session.initiator_store.key_exchange
        )

        ike_sa_init = {
            "exchange": "IKE_SA_INIT",
            "proposals": sa_init_proposals,
            "key_exchange": sa_init_ke,
            "initiator_proposals": session.initiator_store.sa_init_proposals,
            "responder_proposal": session.responder_store.sa_init_proposals,
        }

        # 3. Intermediate rounds summary (RFC 9370 Multi-KE)
        intermediate = {
            "exchange": "IKE_INTERMEDIATE",
            "round_count": len(session.intermediate_rounds) // 2,
            "rounds": [
                {
                    "round_number": r.round_number,
                    "message_id": r.message_id,
                    "direction": r.direction,
                    "key_exchange": r.key_exchange,
                    "notify": r.notify,
                }
                for r in session.intermediate_rounds
            ],
        }

        # 4. Authentication & Child SA (IKE_AUTH)
        chosen_auth = (
            session.responder_store.authentication
            if session.responder_store.authentication
            else session.initiator_store.authentication
        ) or {"present": False, "auth_type": None, "data": None}

        chosen_cert = (
            session.responder_store.certificate
            if session.responder_store.certificate
            else session.initiator_store.certificate
        ) or {"present": False}

        all_certs = []
        if session.initiator_store.certificates:
            all_certs.extend(session.initiator_store.certificates)
        elif session.initiator_store.certificate:
            all_certs.append(session.initiator_store.certificate)

        if session.responder_store.certificates:
            all_certs.extend(session.responder_store.certificates)
        elif session.responder_store.certificate:
            all_certs.append(session.responder_store.certificate)

        child_proposals = (
            session.responder_store.child_sa_proposals
            if session.responder_store.child_sa_proposals
            else session.initiator_store.child_sa_proposals
        )

        # Determine IPsec SA Mode (RFC 7296 §1.3.1 & §3.10.1)
        # Notification 16391 is USE_TRANSPORT_MODE. If present -> TRANSPORT, else default TUNNEL.
        is_transport_mode = 16391 in session.notify_types
        ipsec_mode = "TRANSPORT" if is_transport_mode else "TUNNEL"
        if session.auth_metadata and isinstance(session.auth_metadata, dict):
            daemon_mode = session.auth_metadata.get("mode") or session.auth_metadata.get("ipsec_mode")
            if isinstance(daemon_mode, str) and daemon_mode.strip():
                ipsec_mode = daemon_mode.strip().upper()
                is_transport_mode = (ipsec_mode == "TRANSPORT")

        ike_auth = {
            "exchange": "IKE_AUTH",
            "authentication": chosen_auth,
            "certificate": chosen_cert,
            "certificates": all_certs,
            "child_sa": {
                "present": len(child_proposals) > 0,
                "mode": ipsec_mode,
                "is_transport_mode": is_transport_mode,
                "proposals": child_proposals,
            },
            "traffic_selectors": {
                "initiator": session.initiator_store.traffic_selectors,
                "responder": session.responder_store.traffic_selectors,
            },
            "initiator_auth": session.initiator_store.authentication,
            "responder_auth": session.responder_store.authentication,
        }
        if session.auth_metadata:
            ike_auth["auth_metadata"] = session.auth_metadata
            if "initiator" in session.auth_metadata and not ike_auth.get("initiator"):
                ike_auth["initiator"] = session.auth_metadata["initiator"]
            if "responder" in session.auth_metadata and not ike_auth.get("responder"):
                ike_auth["responder"] = session.auth_metadata["responder"]

        # 5. Notifications Pool
        notify = {
            "present": len(session.notify_types) > 0,
            "notify_types": sorted(list(session.notify_types)),
            "messages": session.notify_messages,
        }

        # 6. ESP Data Plane Telemetry
        data_plane = {
            "spi": session.data_plane.spi,
            "packet_count": session.data_plane.packet_count,
            "byte_count": session.data_plane.byte_count,
            "seq_numbers": list(session.data_plane.seq_numbers),
            "last_seq": session.data_plane.last_seq,
            "is_natt": session.data_plane.is_natt,
            "last_seen": session.data_plane.last_seen,
        }

        canon: dict[str, Any] = {
            "session_id": session.initiator_spi,
            "ipsec_mode": ipsec_mode,
            "common": common,
            "IKE_SA_INIT": ike_sa_init,
            "IKE_INTERMEDIATE": intermediate,
            "IKE_AUTH": ike_auth,
            "notify": notify,
            "data_plane": data_plane,
            "lifecycle_events": [
                {
                    "timestamp": ev.timestamp,
                    "exchange_type": ev.exchange_type,
                    "message_id": ev.message_id,
                    "direction": ev.direction,
                    "event_type": ev.event_type,
                    "details": ev.details,
                }
                for ev in session.lifecycle_events
            ],
        }
        if session.auth_metadata:
            canon["auth_metadata"] = session.auth_metadata
        return canon

    def attach_daemon_credentials(
        self, initiator_spi: str, auth_metadata: dict[str, Any]
    ) -> bool:
        """Inject out-of-band X.509 certificates and authentication metadata from daemon."""
        session = self.get_session(initiator_spi)
        if not session:
            return False
        with session.lock:
            session.auth_metadata = auth_metadata
            if isinstance(auth_metadata, dict):
                init_auth = auth_metadata.get("initiator")
                if init_auth and not session.initiator_store.authentication:
                    session.initiator_store.authentication = init_auth
                resp_auth = auth_metadata.get("responder")
                if resp_auth and not session.responder_store.authentication:
                    session.responder_store.authentication = resp_auth
        return True

    # ═══════════════════════════════════════════════════════════════════════════
    #  Downstream Engine Integrations
    # ═══════════════════════════════════════════════════════════════════════════

    def build_crypto_vector(self, initiator_spi: str) -> list[float]:
        """Produce the 19-dimensional cryptographic vector using vector_engine."""
        canonical = self.get_canonical_session_dict(initiator_spi)
        from vector_engine.vectorEngine import build_vector
        return build_vector(canonical)

    def evaluate_compliance(
        self, initiator_spi: str, replay_window_size: int = 64
    ) -> Any:
        """Run full 12-category RFC evaluation using rfc_engine."""
        canonical = self.get_canonical_session_dict(initiator_spi)
        from rfc_engine.rfcRuleEngine import RfcRuleEngine
        engine = RfcRuleEngine(replay_window_size=replay_window_size)
        return engine.evaluate(canonical, telemetry_dict=canonical.get("data_plane"))

    def classify_posture(self, initiator_spi: str) -> dict[str, Any]:
        """Compute cosine similarity classifications against policy anchors."""
        vec = self.build_crypto_vector(initiator_spi)
        from vector_engine.cosineSimilarity import classify_vector
        return classify_vector(vec)

    def audit_certificates(self, initiator_spi: str) -> Any:
        """Run deep PKI and certificate health audit using cert_engine."""
        canonical = self.get_canonical_session_dict(initiator_spi)
        from cert_engine.certHealthEngine import evaluate_auth_health
        target_auth = canonical.get("auth_metadata") or canonical.get("IKE_AUTH", {})
        return evaluate_auth_health(target_auth)

    def export_session_report(
        self,
        initiator_spi: str,
        output_dir: str | Path = "output",
        flow_verdict: Any | None = None,
    ) -> dict[str, Path]:
        """Execute all downstream analytical engines and persist intermediate JSON reports."""
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        canonical = self.get_canonical_session_dict(initiator_spi)
        rfc_report = self.evaluate_compliance(initiator_spi)
        from vector_engine.vectorEngine import DIMENSION_NAMES, build_vector
        vector_19d = build_vector(canonical)
        posture = self.classify_posture(initiator_spi)
        cert_report = self.audit_certificates(initiator_spi)

        # 1. Canonical Session JSON
        canon_file = out_path / "intermediate_canonical_session.json"
        with open(canon_file, "w", encoding="utf-8") as f:
            json.dump(canonical, f, indent=2, default=str)

        # 2. RFC Compliance Report JSON
        rfc_dict = rfc_report.to_dict() if hasattr(rfc_report, "to_dict") else rfc_report
        rfc_file = out_path / "rfc_compliance_report.json"
        with open(rfc_file, "w", encoding="utf-8") as f:
            json.dump(rfc_dict, f, indent=2, default=str)

        # 3. Crypto Vector Posture JSON
        vector_dict = {
            "vector_19d": vector_19d,
            "dimension_names": list(DIMENSION_NAMES),
            "best_match": posture.get("best_match"),
            "display_name": posture.get("display_name"),
            "best_score": posture.get("best_score"),
            "best_distance": posture.get("best_distance"),
            "rankings": posture.get("rankings", []),
        }
        vec_file = out_path / "crypto_vector_posture.json"
        with open(vec_file, "w", encoding="utf-8") as f:
            json.dump(vector_dict, f, indent=2, default=str)

        # 4. Certificate Health Report JSON
        cert_dict = cert_report.to_dict() if hasattr(cert_report, "to_dict") else cert_report
        cert_file = out_path / "certificate_health_report.json"
        with open(cert_file, "w", encoding="utf-8") as f:
            json.dump(cert_dict, f, indent=2, default=str)

        # 5. Traffic Flow Report JSON
        flow_dict: dict[str, Any] | None = None
        if flow_verdict is not None and hasattr(flow_verdict, "features"):
            flow_dict = {
                "flow_key": list(flow_verdict.flow_key),
                "verdict": flow_verdict.verdict,
                "trigger_type": flow_verdict.trigger_type,
                "features": flow_verdict.features,
                "packet_count": flow_verdict.packet_count,
                "duration_seconds": flow_verdict.duration_seconds,
            }
        elif canonical.get("data_plane", {}).get("packet_count", 0) > 0:
            dp = canonical["data_plane"]
            flow_dict = {
                "flow_key": [
                    canonical.get("common", {}).get("endpoints", {}).get("initiator_ip", "0.0.0.0"),
                    canonical.get("common", {}).get("endpoints", {}).get("responder_ip", "0.0.0.0"),
                ],
                "verdict": None,
                "trigger_type": "DATA_PLANE_TELEMETRY",
                "features": {
                    "total_packets": float(dp.get("packet_count", 0)),
                    "total_bytes": float(dp.get("byte_count", 0)),
                    "mean_packet_size": float(dp.get("byte_count", 0) / max(1, dp.get("packet_count", 1))),
                    "flow_duration_seconds": max(0.0, float(canonical.get("common", {}).get("timestamps", {}).get("handshake_duration_ms", 0.0)) / 1000.0),
                    "packets_per_second": 0.0,
                },
                "packet_count": dp.get("packet_count", 0),
                "duration_seconds": 0.0,
            }

        flow_file = out_path / "traffic_flow_report.json"
        if flow_dict:
            with open(flow_file, "w", encoding="utf-8") as f:
                json.dump(flow_dict, f, indent=2, default=str)

        # 6. Unified RAG Payload JSON (invoking RAG exporter)
        from pipeline.ragExporter import export_from_memory
        export_from_memory(
            canonical_dict=canonical,
            rfc_report_dict=rfc_dict,
            vector_posture_dict=vector_dict,
            cert_report_dict=cert_dict,
            flow_report_dict=flow_dict,
            output_dir=out_path,
        )

        persisted = {
            "canonical_session": canon_file,
            "rfc_compliance": rfc_file,
            "vector_posture": vec_file,
            "cert_health": cert_file,
            "unified_rag_payload": out_path / "unified_rag_payload.json",
        }
        if flow_dict:
            persisted["traffic_flow"] = flow_file
        return persisted

    # ═══════════════════════════════════════════════════════════════════════════
    #  State Query & Lifecycle Utilities
    # ═══════════════════════════════════════════════════════════════════════════

    def get_session(self, spi: str) -> SessionState | None:
        """Retrieve a session by either its initiator_spi or responder_spi."""
        norm = _normalize_spi(spi)
        if not norm:
            return None
        with self._global_lock:
            if norm in self.sessions_by_init_spi:
                return self.sessions_by_init_spi[norm]
            if norm in self.init_spi_by_resp_spi:
                init_norm = self.init_spi_by_resp_spi[norm]
                return self.sessions_by_init_spi.get(init_norm)
            if norm in self.init_spi_by_child_spi:
                init_norm = self.init_spi_by_child_spi[norm]
                return self.sessions_by_init_spi.get(init_norm)
        return None

    def get_active_sessions(self) -> list[SessionState]:
        """Return a snapshot list of all tracked in-memory sessions."""
        with self._global_lock:
            return list(self.sessions_by_init_spi.values())

    def clear(self) -> None:
        """Purge all in-memory tables and indexes."""
        with self._global_lock:
            self.sessions_by_init_spi.clear()
            self.init_spi_by_resp_spi.clear()
            self.init_spi_by_child_spi.clear()

    # ═══════════════════════════════════════════════════════════════════════════
    #  Private Helpers
    # ═══════════════════════════════════════════════════════════════════════════

    def _merge_notifications(
        self, session: SessionState, pkt_dict: dict[str, Any]
    ) -> None:
        """Extract and merge all notification payloads into the session pool."""
        notifs: list[dict[str, Any]] = []

        # From top-level notify bucket
        top_notify = pkt_dict.get("notify", {})
        if isinstance(top_notify, dict):
            notifs.extend(top_notify.get("messages", []))

        # From exchange-specific blocks
        for exch_key in ("IKE_SA_INIT", "IKE_AUTH", "IKE_INTERMEDIATE", "CREATE_CHILD_SA", "INFORMATIONAL"):
            exch_dict = pkt_dict.get(exch_key, {})
            if isinstance(exch_dict, dict) and "notify" in exch_dict:
                val = exch_dict["notify"]
                if isinstance(val, list):
                    notifs.extend(val)

        for n in notifs:
            if isinstance(n, dict):
                ntype = n.get("type")
                if ntype is not None:
                    try:
                        session.notify_types.add(int(ntype))
                    except (ValueError, TypeError):
                        pass
                session.notify_messages.append(n)

    def _register_child_spis(
        self, session: SessionState, proposals: list[dict[str, Any]]
    ) -> None:
        """Extract Child SA SPIs and record them in the global child SPI index."""
        for prop in proposals:
            spi_raw = prop.get("spi")
            spi_norm = _normalize_spi(spi_raw)
            if spi_norm:
                session.child_sa_spis.add(spi_norm)
                with self._global_lock:
                    self.init_spi_by_child_spi[spi_norm] = session.initiator_spi
