"""
pipeline/integratedPipeline.py — End-to-End Integrated IPsec / IKEv2 Pipeline.

Orchestrates packet capture/ingestion, middle-layer session correlation state machine,
analytical & compliance engines (19-D vector, RFC 12-category compliance, X.509 PKI health,
statistical flow telemetry), intermediate JSON persistence, and RAG data packaging.
"""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path
from typing import Any, Callable

# Ensure repository root is on sys.path
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from cert_engine.daemonCertIngest import ingest_from_directory
from flow_engine import FlowEngine, FlowVerdict, MLModelAdapter
from packet_extractor.metadataExtractor import (
    extract_esp_metadata,
    extract_ikeV2_metadata,
)
from pipeline.ragExporter import export_from_memory, export_rag_data
from session_aggregator.sessionAggregator import SessionAggregator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("pipeline.integrated")


class IntegratedPipeline:
    """The central coordinator unifying capture, session correlation, analytics, and RAG export."""

    def __init__(
        self,
        output_dir: str | Path = "output",
        ml_model: Any | None = None,
        auto_export_on_complete: bool = True,
        verbose: bool = False,
    ) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.auto_export_on_complete = auto_export_on_complete
        self.verbose = verbose

        # 1. State Correlation Engine
        self.aggregator = SessionAggregator()

        # 2. ML Traffic Flow Engine & Pluggable Adapter
        self.ml_adapter = MLModelAdapter(
            model=ml_model,
            model_name="pluggable_traffic_model",
        )
        self.flow_engine = FlowEngine(
            window_size=200,
            stride=25,
            idle_timeout=5.0,
            min_packets=10,
            verbose=verbose,
        )

        # 3. Cache of latest flow verdicts per flow key
        self.latest_flow_verdicts: dict[tuple[str, str], FlowVerdict] = {}

    def ingest_ike_packet(self, ike_meta: dict[str, Any] | None) -> str | None:
        """Ingest parsed IKEv2 metadata into state machine and trigger analytics on completion."""
        if not ike_meta:
            return None

        session = self.aggregator.ingest_packet(ike_meta)
        if not session:
            return None

        init_spi = session.initiator_spi
        if session.is_handshake_complete() and self.auto_export_on_complete:
            logger.info("Handshake complete for session %s. Exporting reports...", init_spi)
            self.export_session_reports(init_spi)

        return init_spi

    def ingest_esp_packet(self, esp_meta: dict[str, Any] | None) -> list[FlowVerdict]:
        """Ingest parsed ESP data-plane packet into state machine and flow engine."""
        if not esp_meta:
            return []

        # Correlate sequence numbers & replay windows with session state
        self.aggregator.ingest_packet(esp_meta)

        # Pass packet to flow engine for sliding-window statistical analysis
        verdicts = self.flow_engine.process_packet(esp_meta, model=self.ml_adapter)
        for v in verdicts:
            self.latest_flow_verdicts[v.flow_key] = v
            if self.verbose:
                logger.info(
                    "Flow %s triggered %s: verdict=%s (pkts=%d)",
                    v.flow_key,
                    v.trigger_type,
                    v.verdict,
                    v.packet_count,
                )

        return verdicts

    def attach_daemon_credentials(
        self, initiator_spi: str, auth_metadata: dict[str, Any]
    ) -> bool:
        """Inject out-of-band certificate credentials into the session."""
        success = self.aggregator.attach_daemon_credentials(initiator_spi, auth_metadata)
        if success:
            logger.info("Attached daemon credentials to session %s", initiator_spi)
        else:
            logger.warning("Session %s not found for credential attachment", initiator_spi)
        return success

    def ingest_daemon_credentials_from_path(
        self,
        initiator_spi: str,
        cert_dir: str | Path,
        identity_value: str = "gateway.example.com",
    ) -> bool:
        """Scan local directory for X.509 certs and attach them to the session."""
        try:
            auth_meta = ingest_from_directory(
                dir_path=cert_dir,
                identity_value=identity_value,
            )
            return self.attach_daemon_credentials(initiator_spi, auth_meta)
        except Exception as e:
            logger.error("Failed to ingest certificates from %s: %s", cert_dir, e)
            return False

    def export_session_reports(
        self, initiator_spi: str, custom_output_dir: Path | None = None
    ) -> dict[str, Path]:
        """Run all analytical engines and persist intermediate JSONs and unified RAG payload."""
        out_dir = custom_output_dir or (self.output_dir / "sessions" / initiator_spi)
        out_dir.mkdir(parents=True, exist_ok=True)

        session = self.aggregator.get_session(initiator_spi)
        flow_verdict: FlowVerdict | None = None
        if session and session.common:
            endpoints = session.common.get("endpoints", {})
            src = endpoints.get("initiator_ip")
            dst = endpoints.get("responder_ip")
            if src and dst:
                key = tuple(sorted([str(src), str(dst)]))
                flow_verdict = self.latest_flow_verdicts.get(key)

        # Delegate persistence to aggregator helper
        persisted = self.aggregator.export_session_report(
            initiator_spi=initiator_spi,
            output_dir=out_dir,
            flow_verdict=flow_verdict,
        )

        # Also mirror files to top-level output directory for convenience
        top_persisted = self.aggregator.export_session_report(
            initiator_spi=initiator_spi,
            output_dir=self.output_dir,
            flow_verdict=flow_verdict,
        )

        logger.info(
            "Persisted %d analytical report files for session %s to %s",
            len(top_persisted),
            initiator_spi,
            self.output_dir,
        )
        return top_persisted

    def process_session_dict(
        self,
        session_dict: dict[str, Any],
        auth_metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Convenience method to execute the full pipeline against a pre-assembled session dict."""
        session = self.aggregator.ingest_packet(session_dict)
        if not session:
            raise ValueError("Failed to ingest session_dict into SessionAggregator.")

        init_spi = session.initiator_spi
        if auth_metadata:
            self.attach_daemon_credentials(init_spi, auth_metadata)

        persisted = self.export_session_reports(init_spi)
        rag_payload = export_rag_data(self.output_dir, session_id=init_spi)

        return {
            "session_id": init_spi,
            "persisted_files": {k: str(v) for k, v in persisted.items()},
            "rag_payload": rag_payload,
        }

    def process_pcap(self, pcap_path: str | Path) -> list[str]:
        """Process an offline PCAP capture file through control and data plane extractors."""
        path = Path(pcap_path)
        if not path.exists():
            raise FileNotFoundError(f"PCAP file not found: {path}")

        logger.info("Processing PCAP capture: %s", path)
        completed_sessions: list[str] = []

        # 1. Scapy pass for ESP data plane
        try:
            from scapy.all import rdpcap
            scapy_pkts = rdpcap(str(path))
            logger.info("Loaded %d packets via Scapy. Extracting ESP metadata...", len(scapy_pkts))
            for pkt in scapy_pkts:
                esp_meta = extract_esp_metadata(pkt)
                if esp_meta:
                    self.ingest_esp_packet(esp_meta)
        except Exception as e:
            logger.warning("Scapy PCAP pass encountered an issue: %s", e)

        # 2. PyShark pass for IKEv2 control plane
        try:
            import pyshark
            cap = pyshark.FileCapture(
                str(path),
                display_filter="isakmp",
                use_json=True,
                include_raw=True,
            )
            logger.info("Extracting IKEv2 control packets via PyShark...")
            for pkt in cap:
                ike_meta = extract_ikeV2_metadata(pkt)
                if ike_meta:
                    init_spi = self.ingest_ike_packet(ike_meta)
                    if init_spi and init_spi not in completed_sessions:
                        completed_sessions.append(init_spi)
            cap.close()
        except Exception as e:
            logger.warning("PyShark PCAP pass encountered an issue: %s", e)

        return completed_sessions
