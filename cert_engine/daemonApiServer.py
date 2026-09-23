"""
daemonApiServer.py — REST API & Daemon Webhook Server for Out-of-Band Ingestion.

Implements the HTTP webhook pattern defined in docs/daemon_api_integration.md §4:
  - POST /api/v1/sessions/<initiator_spi>/credentials : Ingests JSON credentials/certificates
  - GET  /api/v1/sessions/<initiator_spi>            : Retrieves canonical session and compliance verdict
  - POST /api/v1/pcap                                : Ingests and processes an offline PCAP file
  - GET  /health                                     : Returns daemon connectivity & pipeline health

Built on Python standard library http.server for zero-dependency deployment, with optional
threading server for non-blocking embedded execution.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from pipeline.integratedPipeline import IntegratedPipeline
from cert_engine.daemonCertIngest import ingest_from_vici

logger = logging.getLogger("daemon.api_server")


class DaemonApiHandler(BaseHTTPRequestHandler):
    """HTTP Request handler for daemon webhooks and pipeline REST queries."""

    pipeline: IntegratedPipeline | None = None
    vici_socket_path: str | None = None

    def _send_json_response(self, status: int, data: dict[str, Any]):
        body = json.dumps(data, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        """Handle GET requests."""
        if self.path in ("/health", "/api/v1/health"):
            vici_status = "unknown"
            try:
                vici_data = ingest_from_vici(self.vici_socket_path) if self.vici_socket_path else ingest_from_vici()
                vici_status = "connected" if vici_data.get("source") == "vici_socket" and "error" not in vici_data else "disconnected"
            except Exception:
                vici_status = "disconnected"

            active_sessions = len(self.pipeline.aggregator.sessions_by_init_spi) if self.pipeline else 0
            self._send_json_response(HTTPStatus.OK, {
                "status": "healthy",
                "vici_daemon": vici_status,
                "active_sessions_count": active_sessions,
            })
            return

        m_session = re.match(r"^/api/v1/sessions/(0x[0-9a-fA-F]+|[0-9a-fA-F]+)$", self.path)
        if m_session:
            spi = m_session.group(1)
            if not spi.startswith("0x"):
                spi = f"0x{spi}"
            if not self.pipeline:
                self._send_json_response(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "Pipeline not initialized"})
                return

            try:
                canon = self.pipeline.aggregator.get_canonical_session_dict(spi)
                rfc = self.pipeline.aggregator.evaluate_compliance(spi)
                rfc_dict = rfc.to_dict() if hasattr(rfc, "to_dict") else rfc
                self._send_json_response(HTTPStatus.OK, {
                    "session_id": spi,
                    "canonical_session": canon,
                    "rfc_compliance": rfc_dict,
                })
            except KeyError:
                self._send_json_response(HTTPStatus.NOT_FOUND, {"error": f"Session {spi} not found"})
            return

        self._send_json_response(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found"})

    def do_POST(self):
        """Handle POST requests for credential injection or PCAP processing."""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length <= 0:
            self._send_json_response(HTTPStatus.BAD_REQUEST, {"error": "Missing request body"})
            return

        try:
            raw_body = self.rfile.read(content_length)
            payload = json.loads(raw_body.decode("utf-8"))
        except Exception as e:
            self._send_json_response(HTTPStatus.BAD_REQUEST, {"error": f"Invalid JSON payload: {e}"})
            return

        m_cred = re.match(r"^/api/v1/sessions/(0x[0-9a-fA-F]+|[0-9a-fA-F]+)/credentials$", self.path)
        if m_cred:
            spi = m_cred.group(1)
            if not spi.startswith("0x"):
                spi = f"0x{spi}"

            if not self.pipeline:
                self._send_json_response(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "Pipeline not initialized"})
                return

            success = self.pipeline.attach_daemon_credentials(spi, payload)
            if success:
                self.pipeline.export_session_reports(spi)
                self._send_json_response(HTTPStatus.OK, {
                    "status": "attached",
                    "session_id": spi,
                    "message": "Credentials attached and reports refreshed successfully."
                })
            else:
                self._send_json_response(HTTPStatus.NOT_FOUND, {
                    "status": "error",
                    "error": f"Session {spi} not found in pipeline state machine."
                })
            return

        if self.path in ("/api/v1/pcap", "/api/v1/process_pcap"):
            pcap_path = payload.get("pcap_path")
            if not pcap_path or not Path(pcap_path).is_file():
                self._send_json_response(HTTPStatus.BAD_REQUEST, {"error": f"PCAP file not found: {pcap_path}"})
                return

            auth_meta = payload.get("auth_metadata")
            try:
                sessions = self.pipeline.process_pcap(pcap_path, auth_metadata=auth_meta)
                self._send_json_response(HTTPStatus.OK, {
                    "status": "success",
                    "pcap_path": pcap_path,
                    "completed_sessions": sessions,
                })
            except Exception as e:
                self._send_json_response(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(e)})
            return

        self._send_json_response(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found"})

    def log_message(self, format, *args):
        logger.debug("%s - - [%s] %s", self.address_string(), self.log_date_time_string(), format % args)


class DaemonApiServer:
    """Lightweight wrapper to manage ThreadingHTTPServer lifecycle."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        pipeline: IntegratedPipeline | None = None,
        vici_socket_path: str | None = None,
    ):
        self.host = host
        self.port = port
        self.pipeline = pipeline or IntegratedPipeline(output_dir="output")
        self.vici_socket_path = vici_socket_path

        class Handler(DaemonApiHandler):
            pass

        Handler.pipeline = self.pipeline
        Handler.vici_socket_path = self.vici_socket_path
        self._handler_class = Handler
        self.server = ThreadingHTTPServer((self.host, self.port), self._handler_class)
        self._thread: threading.Thread | None = None

    def start_background(self) -> None:
        """Launch server in a non-blocking daemon thread."""
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()
        logger.info("Daemon API server listening at http://%s:%d", self.host, self.port)

    def stop(self) -> None:
        """Shut down server and release socket."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            logger.info("Daemon API server stopped.")


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    parser = argparse.ArgumentParser(description="SIH-160 Daemon API & Webhook Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", "-p", type=int, default=8080, help="Bind port (default: 8080)")
    parser.add_argument("--output", "-o", default="output", help="Pipeline output directory")
    parser.add_argument("--vici", default="/var/run/charon.vici", help="Path to strongSwan VICI socket")
    args = parser.parse_args()

    pipeline = IntegratedPipeline(output_dir=args.output)
    server = DaemonApiServer(host=args.host, port=args.port, pipeline=pipeline, vici_socket_path=args.vici)
    print(f"[*] Starting Daemon API Server on http://{args.host}:{args.port}...")
    try:
        server.server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping server...")
        server.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
