# IPsec Daemon API Integration Guide

This guide explains how to connect your IPsec VPN Daemon (**strongSwan** or **Libreswan**) to the SIH-160 compliance and traffic analysis pipeline.

---

## 1. Why Daemon Ingestion is Needed

In standard IKEv2 (RFC 7296 §3.8), the `IKE_AUTH` exchange encrypts certificate payloads (`CERT`, `AUTH`, `IDi`, `IDr`) inside Payload 46 (`Encrypted and Authenticated Payload - SK`).
Passive network sniffing (PyShark / Wireshark) on the wire cannot inspect raw X.509 certificate chains without having access to dynamic session keys.

To perform high-assurance X.509 PKI auditing (CNSA 2.0 quantum resistance, certificate validity periods, expiration countdowns, SAN matching, and CA constraints), the pipeline ingests certificate and credential metadata directly from the VPN daemon out-of-band.

---

## 2. Integration Methods

The pipeline provides two out-of-band ingestion paths implemented in [`cert_engine/daemonCertIngest.py`](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/cert_engine/daemonCertIngest.py) and exposed via [`IntegratedPipeline`](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/pipeline/integratedPipeline.py):

### Method A: Local Certificate Directory Scanning (Windows / Linux / Development)

Reads certificate files (`.pem`, `.crt`, `.cer`, `.der`) directly from your daemon's certificate storage directory (e.g. `/etc/swanctl/x509/`, `/etc/ipsec.d/certs/`, or any local folder).

#### Python API:
```python
from pipeline.integratedPipeline import IntegratedPipeline

pipeline = IntegratedPipeline(output_dir="output")

# Scans directory and attaches certificates to active session
pipeline.ingest_daemon_credentials_from_path(
    initiator_spi="0x1122334455667788",
    cert_dir="path/to/daemon/certs",
    identity_value="gateway.example.com"
)
```

### Method B: strongSwan VICI UNIX Domain Socket (Linux Production)

Directly communicates with strongSwan's charon daemon over the VICI protocol (`/var/run/charon.vici`).

#### Installation:
```bash
pip install vici
```

#### Python API:
```python
from cert_engine.daemonCertIngest import ingest_from_vici
from pipeline.integratedPipeline import IntegratedPipeline

# Ingest active certificates directly from charon
auth_metadata = ingest_from_vici(socket_path="/var/run/charon.vici")

# Attach to the session in the pipeline
pipeline = IntegratedPipeline(output_dir="output")
pipeline.attach_daemon_credentials(
    initiator_spi="0x1122334455667788",
    auth_metadata=auth_metadata
)
```

---

## 3. Data Contract: What the Daemon Must Provide

The daemon ingestion module produces a normalized `auth_metadata` dictionary with the following schema:

```json
{
  "source": "daemon_api",
  "daemon_type": "strongswan",
  "initiator": {
    "identity": {
      "type": 2,
      "value": "client.example.com"
    },
    "auth_method": 14,
    "certificates": [
      {
        "encoding": 4,
        "type": "end_entity",
        "subject": "CN=client.example.com, O=Acme Corp",
        "issuer": "CN=Acme Intermediate CA, O=Acme Corp",
        "cert_key_type_oid": "1.3.6.1.4.1.2.267.12.8.7",
        "cert_key_len": 2560,
        "cert_sig_algo_oid": "1.3.6.1.4.1.2.267.12.8.7",
        "not_before": 1700000000.0,
        "not_after": 1731550000.0,
        "is_ca": false,
        "san": ["client.example.com"],
        "key_usage": ["digitalSignature"]
      }
    ]
  },
  "responder": {
    "identity": {
      "type": 2,
      "value": "gateway.example.com"
    },
    "auth_method": 14,
    "certificates": [ ... ]
  }
}
```

### Key Field Descriptions:
- **`auth_method`**: IANA Auth Method ID (`14` = Digital Signature RFC 7427, `1` = RSA Digital Signature, `2` = Shared Key).
- **`encoding`**: Certificate encoding (`4` = X.509 Certificate - Signature).
- **`cert_key_type_oid`**: Public key algorithm OID (e.g., `1.3.6.1.4.1.2.267.12.8.7` for ML-DSA-87, `1.2.840.10045.2.1` for EC).
- **`cert_key_len`**: Public key bit length (e.g., `2560` for ML-DSA-87, `384` for ECDSA P-384, `2048` for RSA).
- **`not_before` / `not_after`**: Unix timestamps (seconds since epoch) for certificate validity window.
- **`san`**: List of Subject Alternative Names (DNS names or IP addresses) matched against the peer's IKE identity.

---

## 4. REST API / Custom Daemon Hook (Placeholder Interface)

If your IPsec gateway exposes a REST API, webhook, or management daemon (e.g. via FastAPI or Flask), you can push credentials to the pipeline using this lightweight webhook pattern:

```python
from flask import Flask, request, jsonify
from pipeline.integratedPipeline import IntegratedPipeline

app = Flask(__name__)
pipeline = IntegratedPipeline(output_dir="output")

@app.route("/api/v1/sessions/<initiator_spi>/credentials", methods=["POST"])
def receive_credentials(initiator_spi):
    """Webhook invoked by the IPsec gateway upon successful tunnel negotiation."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON payload"}), 400

    # Attach credentials directly to the in-memory session
    success = pipeline.attach_daemon_credentials(initiator_spi, data)
    if success:
        return jsonify({"status": "attached", "session_id": initiator_spi}), 200
    else:
        return jsonify({"error": "Session not found"}), 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
```

---

## 5. Security & Privacy Safeguards
- **Private keys are NEVER required or accepted.**
- The pipeline exclusively audits public X.509 certificates and handshake parameters.
- If any private key string is accidentally present, [`pipeline/ragExporter.py`](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/pipeline/ragExporter.py) automatically strips and replaces it with `[REDACTED_SENSITIVE_KEY_MATERIAL]`.
