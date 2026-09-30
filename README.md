<div align="center">

# 🛡️ PACKET PAKAD (IPsec Sentinel)
### Autonomous IPsec VPN Protocol Analyzer, RFC Compliance Auditor & Post-Quantum Cryptographic Testbed
*Engineered for Smart India Hackathon Problem Statement 26160 (SIH-160) — National Technical Research Organisation (NTRO)*

[![Docker](https://img.shields.io/badge/Docker-Compose_v2-2496ED?style=for-the-badge&logo=docker&logoColor=white)](file:///c:/ipsec-testbed/docker-compose.yml)
[![strongSwan](https://img.shields.io/badge/strongSwan-6.0.2_PQC_Native-00599C?style=for-the-badge)](file:///c:/ipsec-testbed/Dockerfile)
[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)](file:///c:/ipsec-testbed/requirements.txt)
[![Next.js](https://img.shields.io/badge/Next.js-14_App_Router-000000?style=for-the-badge&logo=next.js&logoColor=white)](file:///c:/ipsec-testbed/frontend)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?style=for-the-badge&logo=fastapi&logoColor=white)](file:///c:/ipsec-testbed/backend/server.py)
[![Tests](https://img.shields.io/badge/Test_Suite-77%2F77_Passing-success?style=for-the-badge)](file:///c:/ipsec-testbed/Rule%20Engine/tests)
[![PQC Ready](https://img.shields.io/badge/PQC-ML--KEM_|_FrodoKEM-orange?style=for-the-badge)](file:///c:/ipsec-testbed/testbed_generator.py)

---

**Packet Pakad (IPsec Sentinel)** is a sovereign- and enterprise-grade cybersecurity workstation and testbed framework designed for deep packet dissection, deterministic RFC compliance auditing, out-of-band X.509 PKI health verification, 19-dimensional cryptographic posture classification, and machine learning-powered side-channel analysis of encrypted ESP traffic.

</div>

---

## 📑 Table of Contents

- [Executive Summary](#-executive-summary)
- [System Architecture](#-system-architecture)
- [Core Engines & Capabilities](#-core-engines--capabilities)
  - [1. Deterministic RFC Compliance Engine](#1-deterministic-rfc-compliance-engine-rfc_engine)
  - [2. Dedicated PKI & Certificate Health Engine](#2-dedicated-pki--certificate-health-engine-cert_engine)
  - [3. 19-Dimensional Cryptographic Vector Engine](#3-19-dimensional-cryptographic-vector-engine-vector_engine)
  - [4. Encrypted ESP Traffic ML Classification](#4-encrypted-esp-traffic-ml-classification-flow_engine)
  - [5. Native Post-Quantum Cryptography (PQC) Testbed](#5-native-post-quantum-cryptography-pqc-testbed)
  - [6. Threat Matrix & Evidence-Grounded RAG Payloads](#6-threat-matrix--evidence-grounded-rag-payloads)
- [Repository Structure](#-repository-structure)
- [Quick Start Guide](#-quick-start-guide)
  - [Prerequisites](#prerequisites)
  - [Option A: One-Click End-to-End Launcher (`run_all.bat`)](#option-a-one-click-end-to-end-launcher-run_allbat)
  - [Option B: Interactive Web Workstation (`start_webapp.bat`)](#option-b-interactive-web-workstation-start_webappbat)
  - [Option C: Headless / Docker-Only Pipeline (`start_testbed.bat`)](#option-c-headless--docker-only-pipeline-start_testbedbat)
  - [Option D: Running Automated Test Suites (77/77 Passing)](#option-d-running-automated-test-suites-7777-passing)
- [Web Workstation Routes & Capabilities](#-web-workstation-routes--capabilities)
- [REST API Reference](#-rest-api-reference)
- [Cryptographic Policy Anchors](#-cryptographic-policy-anchors)
- [Verification & Troubleshooting](#-verification--troubleshooting)
- [License & Acknowledgements](#-license--acknowledgements)

---

## 🌟 Executive Summary

Modern Virtual Private Networks (VPNs) based on IPsec (IKEv1/IKEv2, ESP, and AH) form the security perimeter for defense establishments, banking backbones, and critical national infrastructure. However, security analysts face critical challenges:
1. **Encrypted Handshake Payloads**: Under standard IKEv2 (RFC 7296 §3.8), the `IKE_AUTH` exchange encrypts certificate payloads (`CERT`, `AUTH`, `IDi`, `IDr`). Passive wire sniffers cannot evaluate certificate validity without session keys.
2. **Harvest-Now-Decrypt-Later (HNDL)**: Adversaries passively store classical Diffie-Hellman handshakes to decrypt them once cryptographically relevant quantum computers (CRQCs) arrive.
3. **Encrypted Data-Plane Blind Spots**: While payload data in ESP tunnels is encrypted, packet lengths, burst cadence, inter-arrival times (IAT), and directional throughput leak metadata that can identify traffic types (e.g., video streaming vs. large file exfiltration).
4. **Implementation Deviations**: Subtle non-compliance with RFCs (e.g., weak pseudo-random functions, omitted ESN, disabled anti-replay windows) degrades defense posture.

**Packet Pakad** solves these challenges by combining:
- A **dual-gateway containerized strongSwan 6.0.2 environment** with native Post-Quantum (FIPS 203 ML-KEM and FrodoKEM) support.
- A **sidecar network analyzer** attached directly to the gateway's network namespace (`container:gw-hq`) for zero-loss wire interception.
- An **out-of-band daemon credential ingestion layer** (via strongSwan VICI API and certificate scrapers) that resolves the `IKE_AUTH` encryption paradox.
- A **mathematical 19-D vector engine** calculating cosine distance against sovereign security baselines (CNSA 2.0, NIST PQC Transitional, RFC 8247, and Deprecated).
- An **unsupervised statistical ESP flow engine** extracting 25 wire features across sliding windows to classify encrypted flows without decryption.
- A **Next.js 14 cyber workstation dashboard** paired with a **FastAPI backend**.

---

## 🏗️ System Architecture

The following diagram illustrates the network topology, container isolation, data extraction paths, and multi-tier analytical pipeline:

```
                                   +-------------------------------------------------------------+
                                   |                     DOCKER BRIDGE NETWORK                   |
                                   |                   ipsec-wan (172.28.0.0/16)                 |
                                   +------------------------------+------------------------------+
                                                                  |
                                       +--------------------------+--------------------------+
                                       |                                                     |
                 +---------------------+---------------------+         +---------------------+---------------------+
                 |           CONTAINER: gw-hq                |         |          CONTAINER: gw-branch             |
                 |             (172.28.0.2)                  |         |              (172.28.0.3)                 |
                 |  - strongSwan 6.0.2 (Charon Daemon)       |  IPsec  |  - strongSwan 6.0.2 (Charon Daemon)       |
                 |  - Native "ml" PQC Plugin (ML-KEM, Frodo) | <=====> |  - Native "ml" PQC Plugin (ML-KEM, Frodo) |
                 |  - Swanctl VICI Interface                 | Tunnel  |  - Swanctl VICI Interface                 |
                 |  - Shared /captures & /certs mount        | (ESP)   |  - Shared /certs mount                    |
                 +---------------------+---------------------+         +-------------------------------------------+
                                       |
                 (network_mode: "container:gw-hq")
                 Zero-copy Promiscuous Sniffing
                                       |
                 +---------------------+---------------------+
                 |       CONTAINER: ipsec-analyzer           |
                 |  - Debian 12 / Python 3.11 Runtime        |
                 |  - Scapy + PyShark / tshark Interceptor   |
                 |  - Live Sniffer (sniffer.py)              |
                 +---------------------+---------------------+
                                       |
                   Wire Intercepts     |     Out-of-band VICI / Cert Scraping
                  (IKEv2 & ESP Meta)   |    (daemon_credential_exporter.py)
                                       v                               v
+-----------------------------------------------------------------------------------------------------------------------+
|                                             ANALYTICAL ENGINE PIPELINE                                                |
|                                            (c:\ipsec-testbed\Rule Engine)                                             |
|                                                                                                                       |
|  +--------------------+  +--------------------+  +--------------------+  +--------------------+  +-----------------+  |
|  |    rfc_engine      |  |    cert_engine     |  |   vector_engine    |  |    flow_engine     |  |packet_extractor |  |
|  | - RFC 7296 / 4303  |  | - X.509 PKI Health |  | - 19-D Wire Vector |  | - 200-Pkt Window   |  | - Pure-wire     |  |
|  | - RFC 8247 / 8221  |  | - 30-Day Expiry Warn| | - Cosine Similarity|  | - 25 Features     |  |   IKEv2 & ESP   |  |
|  | - 64-Pkt Anti-Replay| | - CNSA 2.0 / NIST  |  | - Policy Anchors   |  | - Traffic ML Model |  |   Dissector     |  |
|  | - ESN Rollover Chk |  | - SAN Matching     |  | - Distance Ratings |  | - Burst Detection  |  |                 |  |
|  +--------------------+  +--------------------+  +--------------------+  +--------------------+  +-----------------+  |
|                                                           |                                                           |
|                                  Generates Structured JSON Assessment Telemetry                                       |
|                  (rfc_compliance_report.json, certificate_health_report.json, crypto_vector_posture.json,              |
|                               traffic_flow_report.json, unified_rag_payload.json)                                     |
+-----------------------------------------------------------+-----------------------------------------------------------+
                                                            |
                                                            v
+-----------------------------------------------------------------------------------------------------------------------+
|                                          FASTAPI BACKEND & ORCHESTRATOR                                               |
|                                              (Port 8000 / backend/)                                                   |
|                                                                                                                       |
|  - Testbed Configuration & Deployment Engine (orchestrator.py)                                                        |
|  - Session Reconstruction & Aggregation Layer (data_loader.py)                                                        |
|  - REST Endpoints for Score, Sessions, Compliance, Posture, Traffic Classification & Threat Matrix                    |
+-----------------------------------------------------------+-----------------------------------------------------------+
                                                            |
                                                            v
+-----------------------------------------------------------------------------------------------------------------------+
|                                           NEXT.JS 14 SECURITY WORKSTATION                                             |
|                                              (Port 3001 / frontend/)                                                  |
|                                                                                                                       |
|  - Obsidian Dark Theme (#0B0C0D) & Burnt Amber Accents (#C47A52)                                                      |
|  - Real-Time Tunnel Topology, Animated Packet Artery, IKE Negotiation Timelines, 19-D Radar & Threat Matrix           |
+-----------------------------------------------------------------------------------------------------------------------+
```

---

## 🔬 Core Engines & Capabilities

### 1. Deterministic RFC Compliance Engine (`rfc_engine/`)
The compliance engine inspects raw wire handshakes and live telemetry against 24+ strict RFC state rules:
- **RFC 7296**: IKEv2 protocol specifications, exchange state ordering (`IKE_SA_INIT` → `IKE_AUTH` → `CREATE_CHILD_SA`), SPI assignment uniqueness, message ID synchronization, and cookie/anti-DoS enforcement.
- **RFC 4303 & RFC 8221**: IPsec ESP data-plane compliance, verification of AEAD vs. legacy CBC/HMAC, and anti-replay integrity.
- **64-Packet Anti-Replay Window**: Implements an active bitmask-based sliding window tracking duplicate, delayed, and replayed packets in real-time.
- **Extended Sequence Number (ESN) Verification**: Checks for 64-bit sequence counters to prevent silent wrap-around vulnerability under 10Gbps+ line-rate traffic.
- **RFC 9370 & RFC 9242**: Audits multiple post-quantum key exchanges within `IKE_INTERMEDIATE` rounds.

### 2. Dedicated PKI & Certificate Health Engine (`cert_engine/`)
Solves the out-of-band certificate inspection challenge:
- **Out-of-Band Ingestion**: Interfaces with strongSwan over the VICI socket (`/var/run/charon.vici`) or scans daemon credential stores to reconstruct X.509 metadata.
- **Validity & Expiration Monitoring**: Real-time audit of certificate validity windows with automatic 30-day early expiration alerts.
- **Subject Alternative Name (SAN) Matching**: Enforces strict identity verification against local/remote configuration identifiers (`id = sun.enterprise.net`).
- **Hierarchy & CA Constraints**: Validates Basic Constraints (`cA=True/False`), path length constraints, and critical Key Usage extensions.
- **Sovereign Rating**: Classifies certificates against CNSA 2.0 (Commercial National Security Algorithm Suite 4096-bit+ RSA / ECP-384 / Ed448 / ML-DSA), NIST SP 800-52r2, and legacy deprecation rules.

### 3. 19-Dimensional Cryptographic Vector Engine (`vector_engine/`)
Translates cryptographic negotiation parameters into a normalized vector $\vec{V} \in [0.0, 1.0]^{19}$ covering:
- **Cipher Suite Bit Strength** (AES-GCM-256 vs. ChaCha20 vs. 3DES)
- **Integrity & PRF Algorithms** (SHA-384, SHA-256 vs. MD5/SHA-1)
- **Diffie-Hellman / KEM Security Strength** (ECP-384, Curve25519, MODP-3072, vs. MODP-1024)
- **Post-Quantum Key Exchange Ranks** (ML-KEM-512, ML-KEM-768, ML-KEM-1024, FrodoKEM-976)
- **Authentication Credentials & Signatures** (ECDSA-384, Ed25519 vs. PSK)

The engine calculates mathematical **Cosine Similarity** against authoritative baseline anchors:
$$\text{Similarity}(\vec{u}, \vec{v}) = \frac{\vec{u} \cdot \vec{v}}{\|\vec{u}\|_2 \|\vec{v}\|_2}$$

| Baseline Policy Anchor | Mathematical Vector Target | Compliance Meaning |
| :--- | :--- | :--- |
| **CNSA 2.0 Anchor** | Full PQC & Top Classical Suite | Sovereign military & intelligence-grade posture |
| **NIST PQC Transitional** | Hybrid Classical (X25519/ECP) + ML-KEM | Optimal transitional protection against HNDL |
| **RFC 8247 Classical** | Modern Classical (AES-GCM, DH-19, PRF-SHA2) | Secure against classical adversaries |
| **NIST Deprecated Anchor** | 3DES, MD5, SHA-1, DH Group 2 | Vulnerable to immediate compromise |

### 4. Encrypted ESP Traffic ML Classification (`flow_engine/`)
Enables deep visibility into encrypted tunnels without compromising confidentiality:
- **Sliding-Window Feature Extraction**: Employs a stateful packet buffer (window size = 200 packets, stride = 25 packets) to compute **25 statistical flow metrics**.
- **Metrics Computed**: Packet length variance, inter-arrival time (mean, min, max, standard deviation / jitter), forward-to-backward packet ratios, forward-to-backward byte ratios, and peak burst cadence.
- **Side-Channel Burst Detection**: Detects periodic frame-rate cadences (such as 33.3ms for 30 FPS video streams) and distinguishes interactive voice/video traffic from bulk data exfiltration.

### 5. Native Post-Quantum Cryptography (PQC) Testbed
The environment builds strongSwan 6.0.2 from source on Alpine Linux, compiling the native **`ml`** plugin:
- No external wrapper libraries (`liboqs`) required; native implementation of **FIPS 203 ML-KEM** (Kyber).
- Supports Hybrid Key Exchange: combines classical ECDH (Curve25519 or ECP-384) with quantum-safe KEMs (ML-KEM-512, ML-KEM-768, ML-KEM-1024, FrodoKEM-976).
- Testbed CLI and Web UI allow one-click toggling of hybrid suites, rekeying, and packet capture generation.

### 6. Threat Matrix & Evidence-Grounded RAG Payloads
- **5x5 Forensic Threat Matrix**: Maps vulnerabilities into an interactive Likelihood vs. Impact grid (Weak PRF, Omitted Anti-Replay, Quantum Vulnerability, Expiring Credentials).
- **Unified RAG Payload (`unified_rag_payload.json`)**: Emits structured JSON containing full protocol session context, raw packet telemetry, RFC violation summaries, and remediation advice designed for LLM-assisted SOC analysis.

---

## 📁 Repository Structure

```
c:\ipsec-testbed/
├── Dockerfile                      # strongSwan 6.0.2 builder with native ML-KEM PQC plugin
├── Dockerfile.analyzer             # Analyzer container (Python 3.11, tshark, Scapy, PyShark, scikit-learn)
├── docker-compose.yml              # Multi-container orchestration (gw-hq, gw-branch, ipsec-analyzer)
├── requirements.txt                # Root Python dependencies (textual, rich)
├── run_all.bat                     # Single-click automated orchestrator (Docker -> swanctl -> sniffer -> CLI)
├── start_testbed.bat               # Headless strongSwan testbed launcher and tunnel bootstrapper
├── start_webapp.bat                # Unified launcher for Next.js WebApp (port 3001) & FastAPI (port 8000)
├── testbed_generator.py            # Interactive CLI testbed orchestrator & traffic generator
├── daemon_credential_exporter.py   # Out-of-band strongSwan VICI credential & SA telemetry scraper
├── sniffer.py                      # Root sniffer launcher proxying to Rule Engine
├── hq/
│   └── swanctl.conf                # Gateway HQ strongSwan configuration & PQC proposals
├── branch/
│   └── swanctl.conf                # Gateway Branch strongSwan configuration & PQC proposals
├── certs/                          # X.509 PKI credentials (CA, HQ sunCert, Branch moonCert, PKCS#8 keys)
├── captures/                       # Live and synthetic PCAP captures storage
├── assessment_output/              # Output directory for pipeline JSON reports
│   ├── rfc_compliance_report.json
│   ├── certificate_health_report.json
│   ├── crypto_vector_posture.json
│   ├── traffic_flow_report.json
│   └── unified_rag_payload.json
├── backend/                        # FastAPI REST Server & Orchestration Bridge
│   ├── server.py                   # FastAPI application running on http://localhost:8000
│   ├── orchestrator.py             # Docker, swanctl, and automated pipeline execution controller
│   └── data_loader.py              # Telemetry ingestion, session reconstruction, and RAG compilation
├── frontend/                       # Next.js 14 Cybersecurity Dashboard
│   ├── src/
│   │   ├── app/                    # Next.js App Router (Dashboard, Testbed, Sessions, Compliance, etc.)
│   │   ├── components/             # Reusable UI widgets (Radar charts, gauges, packet arteries)
│   │   ├── lib/api/                # Decoupled frontend API clients talking to FastAPI
│   │   └── types/                  # Strict TypeScript definitions for all telemetry models
│   ├── package.json
│   └── tailwind.config.js
└── Rule Engine/                    # Core Python Rule Engine & Analytical Pipeline
    ├── rfc_engine/                 # RFC 7296 / 4303 state audits & 64-packet sliding window
    ├── cert_engine/                # X.509 PKI health auditor & daemon VICI connector
    ├── vector_engine/              # 19-D mathematical vector space & cosine similarity
    ├── flow_engine/                # Sliding-window ESP flow accumulator & 25-feature ML extractor
    ├── packet_extractor/           # Pure-wire IKEv2 / ESP packet dissector
    ├── pipeline/                   # Unified integrated pipeline orchestrator
    ├── tests/                      # 77 automated test suites (100% passing)
    └── docs/                       # Detailed integration guides and API specs
```

---

## 🚀 Quick Start Guide

### Prerequisites
1. **Operating System**: Windows 10/11 (with PowerShell / Command Prompt), or Linux/macOS with Docker.
2. **Docker Desktop**: Version 4.20+ with Docker Compose V2 enabled. Ensure WSL 2 backend is active on Windows.
3. **Python**: Python 3.11+ installed and added to `PATH`.
4. **Node.js**: Node.js 18+ and `npm` installed.

---

### Option A: One-Click End-to-End Launcher (`run_all.bat`)
The fastest way to spin up the entire testbed, configure tunnels, start the live sniffer, and generate traffic:

```cmd
cd c:\ipsec-testbed
run_all.bat
```

**What this automated script executes:**
1. Starts the Docker containers (`gw-hq`, `gw-branch`, and `ipsec-analyzer`) in detached mode.
2. Waits for strongSwan daemons to report healthy via `swanctl --stats`.
3. Loads all configurations and X.509 certificates into both gateways via `swanctl --load-all`.
4. Spawns the **IPsec Real-Time Sniffer** in a dedicated window attached to `eth0`.
5. Launches the interactive **Testbed Generator CLI** in a dedicated window for scenario selection.

---

### Option B: Interactive Web Workstation (`start_webapp.bat`)
To use the modern web-based cyber dashboard and control testbeds via UI:

```cmd
cd c:\ipsec-testbed
start_webapp.bat
```

- **Frontend Dashboard**: Open your browser at [http://localhost:3001](http://localhost:3001)
- **Backend API Docs**: Swagger UI available at [http://localhost:8000/docs](http://localhost:8000/docs)

From the web interface:
- Navigate to **Testbed Generator** (`/testbed`) to select crypto suites (PQC Hybrid ML-KEM, Classical AES-GCM, etc.), choose traffic models, and click **Deploy Testbed & Trigger Traffic**.
- View live packet feeds in **Packet Capture** (`/capture`).
- Inspect reconstructed sessions and cryptographic handshakes in **Session Explorer** (`/sessions`).
- Examine compliance violations in **RFC Compliance** (`/analysis/compliance`).

---

### Option C: Headless / Docker-Only Pipeline (`start_testbed.bat`)
If you only need to verify the IPsec tunnel connectivity and inspect Child SAs from the terminal:

```cmd
cd c:\ipsec-testbed
start_testbed.bat
```

Once established, run manual diagnostics:
```bash
# Verify active security associations on HQ gateway
docker exec gw-hq swanctl --list-sas

# Send ICMP echo traffic across the encrypted tunnel
docker exec -it gw-hq ping -c 10 172.28.0.3

# Ingest active credentials out-of-band
python daemon_credential_exporter.py
```

---

### Option D: Running Automated Test Suites (77/77 Passing)
The analytical engine includes 6 comprehensive unit and integration test suites:

```powershell
cd "c:\ipsec-testbed\Rule Engine"
python tests/test_rfcRuleEngine.py
python tests/test_certHealthEngine.py
python tests/test_vectorEngine.py
python tests/test_cosineSimilarity.py
python tests/test_flowEngine.py
python tests/test_daemonCertIngest.py
```

**Test Coverage Summary:**
- `test_rfcRuleEngine.py`: 12 tests validating RFC 7296 state logic, anti-replay sliding windows, and sequence number rollovers.
- `test_certHealthEngine.py`: 12 tests validating X.509 expiration countdowns, SAN validation, CA constraints, and CNSA 2.0 evaluation.
- `test_vectorEngine.py`: 36 tests validating 19-D numerical vector bounds, weighting, and transform mappings.
- `test_cosineSimilarity.py`: 6 tests validating mathematical distance against sovereign policy anchors.
- `test_flowEngine.py`: 7 tests validating 200-packet sliding windows, stride steps, and 25-feature extraction.
- `test_daemonCertIngest.py`: 4 tests validating out-of-band certificate extraction, PEM parsing, and session attachment.

---

## 🖥️ Web Workstation Routes & Capabilities

| Route | Title | Core Functions |
|---|---|---|
| `/` | **Security Overview Dashboard** | System security score (0–100), active tunnel topology with live particle animation, pipeline health, and high-level telemetry widgets. |
| `/testbed` | **Testbed Lab Controller** | Web-based controls for IKE version, encryption, DH/KEM groups (ML-KEM-768/1024, ECP-384), traffic generators, and real-time step-by-step deployment logs. |
| `/capture` | **Packet Ingestion & Dissector** | Promiscuous bitstream stream, interactive packet artery visualizer, raw hex payload viewer, and protocol dissect tree. |
| `/sessions` | **Session Explorer** | Searchable directory of captured IKEv1/IKEv2 sessions, SPI pairs, gateway endpoints, and security tags. |
| `/sessions/[id]` | **Session Telemetry & Timeline** | Interactive 4-step negotiation timeline (`IKE_SA_INIT` → `IKE_AUTH` → `CREATE_CHILD_SA` → `INFORMATIONAL`), negotiated transforms, SA parameters, and RAG payload. |
| `/analysis/compliance` | **RFC Compliance Matrix** | Deterministic breakdown of 24+ RFC rules with pass/fail badges, violated clauses, and suggested remediations. |
| `/analysis/crypto` | **19-D Cryptographic Radar** | Interactive radar chart of the 19-dimensional vector, policy similarity percentages (CNSA 2.0 vs. PQC vs. Classical), and algorithm bit strengths. |
| `/analysis/traffic` | **Traffic Intelligence & ML** | Encrypted ESP burst cadence graphs, 33.3ms video I-frame detection, ML classification probabilities, and metadata leakage warnings. |
| `/threats` | **5x5 Forensic Threat Matrix** | Visual Likelihood vs. Impact matrix plotting security anomalies with actionable mitigation cards. |
| `/reports` | **Reports Dossier** | CISO Executive Summary and Technical Protocol Dossier with PDF printing and JSON export. |
| `/dataset` | **Ground Truth Benchmarks** | NTRO benchmark dataset metrics: 250,000 samples, train/val/test splits, and confusion accuracy tables. |
| `/settings` | **System Settings** | FastAPI endpoint URLs, anomaly thresholds, and baseline profile configurations. |

---

## 🔌 REST API Reference

The FastAPI service running on port 8000 provides endpoints consumed by both the Next.js frontend and automated scripts:

### Testbed Management
- `GET /api/v1/testbed/status`: Returns current Docker container states and strongSwan daemon health.
- `GET /api/v1/testbed/logs`: Streams terminal execution logs from the backend orchestrator ring buffer.
- `POST /api/v1/testbed/deploy`: Configures `swanctl.conf`, regenerates keys if needed, restarts Child SAs, and launches traffic.
- `POST /api/v1/testbed/traffic`: Injects synthetic burst traffic (Video, Voice, Web, Bulk).

### Telemetry & Analysis
- `GET /api/v1/analysis/score`: Returns computed system security score, posture level, and summary metrics.
- `GET /api/v1/analysis/compliance`: Returns list of deterministic RFC compliance findings with remediation guidance.
- `GET /api/v1/analysis/crypto`: Returns 19-D vector parameters, transform bit strengths, and similarity percentages.
- `GET /api/v1/analysis/traffic`: Returns 25 flow features and ML model classification distribution.
- `GET /api/v1/analysis/threats`: Returns categorized threat findings formatted for the 5x5 matrix.
- `GET /api/v1/sessions`: Returns list of all reconstructed IPsec sessions.
- `GET /api/v1/sessions/{session_id}`: Returns deep session telemetry, negotiation timeline, and SPI pairs.
- `GET /api/v1/reports/rag-payload`: Returns full `unified_rag_payload.json` for LLM consumption.

---

## 🛡️ Cryptographic Policy Anchors

The 19-dimensional vector engine evaluates handshakes against four standardized reference anchors:

| Parameter Dimension | Index | CNSA 2.0 Sovereign | NIST PQC Transitional | RFC 8247 Classical | NIST SP 800-131A Deprecated |
|---|:---:|:---:|:---:|:---:|:---:|
| **IKE Encryption Algorithm** | $d_0$ | AES-256-GCM (1.0) | AES-256-GCM (1.0) | AES-128/256-GCM (0.8) | 3DES / DES (0.1) |
| **IKE PRF Algorithm** | $d_1$ | PRF-HMAC-SHA384 (1.0) | PRF-HMAC-SHA384 (1.0) | PRF-HMAC-SHA256 (0.8) | MD5 / SHA-1 (0.1) |
| **IKE Integrity Algorithm** | $d_2$ | AEAD / SHA-384 (1.0) | AEAD / SHA-256 (0.9) | SHA-256 (0.8) | MD5 (0.0) |
| **Classical DH Group** | $d_3$ | ECP-384 (Group 20) | Curve25519 (Group 31) | ECP-256 (Group 19) | MODP-1024 (Group 2) |
| **Primary Quantum KEM** | $d_4$ | ML-KEM-1024 (1.0) | ML-KEM-768 (0.9) | None (0.0) | None (0.0) |
| **Secondary Quantum KEM**| $d_5$ | FrodoKEM-976 (0.9) | None (0.0) | None (0.0) | None (0.0) |
| **ESP Encryption Suite** | $d_6$ | AES-256-GCM (1.0) | AES-256-GCM (1.0) | AES-128-GCM (0.8) | 3DES-CBC (0.1) |
| **Extended Seq Numbers** | $d_7$ | ESN Enabled (1.0) | ESN Enabled (1.0) | ESN Enabled (1.0) | Disabled (0.0) |
| **Authentication Credential** | $d_8$ | ECDSA-384 / ML-DSA | ECDSA-256 / Ed25519 | RSA-3072 | PSK / RSA-1024 |

---

## 🔍 Verification & Troubleshooting

### 1. strongSwan Daemon Initialization Timeout
If `run_all.bat` or `start_testbed.bat` reports that `gw-hq` or `gw-branch` timed out:
```cmd
# Inspect container logs
docker compose logs gw-hq
docker compose logs gw-branch

# Verify Docker daemon has sufficient memory (> 2GB allocated in WSL 2)
```

### 2. Promiscuous Sniffing & Linux Capabilities
The sniffer container requires direct raw network interception:
- The analyzer container runs with `network_mode: "container:gw-hq"`, sharing `gw-hq`'s network stack directly.
- Both `gw-hq` and `ipsec-analyzer` must have `NET_ADMIN` and `NET_RAW` Linux capabilities enabled (configured by default in `docker-compose.yml`).

### 3. Port Conflicts
- Ensure ports `8000` (FastAPI) and `3001` (Next.js) are not occupied by existing processes.
- UDP ports `500` (IKE) and `4500` (NAT-Traversal) are internal to the `ipsec-wan` Docker bridge network and do not conflict with host OS VPN services.

---

## 📜 License & Acknowledgements

This project was developed for **Smart India Hackathon (SIH) Problem Statement 26160 (SIH-160)** sponsored by the **National Technical Research Organisation (NTRO)**.

- **strongSwan Project**: For the robust, standards-compliant IPsec implementation and native PQC ML-KEM plugins.
- **Scapy & PyShark**: For packet dissection and pcap stream extraction.
- **Next.js & Tailwind CSS**: For the modern user interface framework.
