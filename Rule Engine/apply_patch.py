import re
from pathlib import Path

# 1. Patch sessionAggregator.py
sa_path = Path("/workspace/session_aggregator/sessionAggregator.py")
if sa_path.exists():
    content = sa_path.read_text(encoding="utf-8")

    # Patch attach_daemon_credentials
    old_attach_regex = r"def attach_daemon_credentials\(.*?return True"
    new_attach = '''def attach_daemon_credentials(
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
                if init_auth:
                    auth_type = init_auth.get("auth_type") or init_auth.get("auth_method", 14)
                    session.initiator_store.authentication = {
                        "present": True,
                        "auth_type": auth_type,
                        "signature_algorithm": "ECDSA",
                        "data": None,
                        "identity": init_auth.get("identity"),
                    }
                    certs = init_auth.get("certificates", [])
                    if certs:
                        session.initiator_store.certificate = dict(certs[0], present=True)
                        session.initiator_store.certificates = certs

                resp_auth = auth_metadata.get("responder")
                if resp_auth:
                    auth_type = resp_auth.get("auth_type") or resp_auth.get("auth_method", 14)
                    session.responder_store.authentication = {
                        "present": True,
                        "auth_type": auth_type,
                        "signature_algorithm": "ECDSA",
                        "data": None,
                        "identity": resp_auth.get("identity"),
                    }
                    certs = resp_auth.get("certificates", [])
                    if certs:
                        session.responder_store.certificate = dict(certs[0], present=True)
                        session.responder_store.certificates = certs
        return True'''
    content = re.sub(old_attach_regex, new_attach, content, flags=re.DOTALL)

    # Patch _build_canonical_dict_locked auth fallback
    old_auth_block = '''        chosen_auth = (
            session.responder_store.authentication
            if session.responder_store.authentication
            else session.initiator_store.authentication
        ) or {"present": False, "auth_type": None, "data": None}

        chosen_cert = (
            session.responder_store.certificate
            if session.responder_store.certificate
            else session.initiator_store.certificate
        ) or {"present": False}'''

    new_auth_block = '''        chosen_auth = (
            session.responder_store.authentication
            if (session.responder_store.authentication and session.responder_store.authentication.get("present"))
            else session.initiator_store.authentication
        )
        if not chosen_auth or not chosen_auth.get("present"):
            if session.auth_metadata and isinstance(session.auth_metadata, dict):
                meta_p = session.auth_metadata.get("responder") or session.auth_metadata.get("initiator")
                if meta_p:
                    chosen_auth = {
                        "present": True,
                        "auth_type": meta_p.get("auth_type") or meta_p.get("auth_method", 14),
                        "signature_algorithm": "ECDSA",
                        "data": None,
                        "identity": meta_p.get("identity"),
                    }
            if not chosen_auth:
                chosen_auth = {"present": False, "auth_type": None, "data": None}

        chosen_cert = (
            session.responder_store.certificate
            if (session.responder_store.certificate and session.responder_store.certificate.get("present"))
            else session.initiator_store.certificate
        )
        if not chosen_cert or not chosen_cert.get("present"):
            if session.auth_metadata and isinstance(session.auth_metadata, dict):
                meta_p = session.auth_metadata.get("responder") or session.auth_metadata.get("initiator")
                if meta_p and meta_p.get("certificates"):
                    chosen_cert = dict(meta_p["certificates"][0], present=True)
            if not chosen_cert:
                chosen_cert = {"present": False}'''
    content = content.replace(old_auth_block, new_auth_block)

    sa_path.write_text(content, encoding="utf-8")
    print("[✔] sessionAggregator.py successfully patched")

# 2. Patch vectorEngine.py for sig_bits cert_key_len fallback
ve_path = Path("/workspace/vector_engine/vectorEngine.py")
if ve_path.exists():
    vcontent = ve_path.read_text(encoding="utf-8")
    old_sig_bits = '''    sig_bits = (
        IKEV2_SIG_ALGO_KEY_BITS.get(sig_pqc_id)
        or IKEV2_AUTH_KEY_BITS.get(auth_type, 0)
    )'''
    new_sig_bits = '''    sig_bits = (
        IKEV2_SIG_ALGO_KEY_BITS.get(sig_pqc_id)
        or IKEV2_AUTH_KEY_BITS.get(auth_type, 0)
        or session.get("IKE_AUTH", {}).get("certificate", {}).get("cert_key_len", 0)
    )'''
    if old_sig_bits in vcontent:
        vcontent = vcontent.replace(old_sig_bits, new_sig_bits)
        ve_path.write_text(vcontent, encoding="utf-8")
        print("[✔] vectorEngine.py successfully patched")
    else:
        print("[!] vectorEngine.py pattern already updated or not found")

# 3. Patch integratedPipeline.py to auto-ingest /certs on handshake complete
ip_path = Path("/workspace/pipeline/integratedPipeline.py")
if ip_path.exists():
    icontent = ip_path.read_text(encoding="utf-8")
    old_ingest_complete = '''        if session.is_handshake_complete() and self.auto_export_on_complete:
            logger.info("Handshake complete for session %s. Exporting reports...", init_spi)'''
    new_ingest_complete = '''        if session.is_handshake_complete() and self.auto_export_on_complete:
            if Path("/certs").is_dir():
                self.ingest_daemon_credentials_from_path(init_spi, "/certs", identity_value="sun.enterprise.net")
            logger.info("Handshake complete for session %s. Exporting reports...", init_spi)'''
    if old_ingest_complete in icontent:
        icontent = icontent.replace(old_ingest_complete, new_ingest_complete)
        ip_path.write_text(icontent, encoding="utf-8")
        print("[✔] integratedPipeline.py successfully patched")
    else:
        print("[!] integratedPipeline.py pattern already updated or not found")
