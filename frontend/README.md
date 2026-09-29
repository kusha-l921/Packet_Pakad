# IPSEC SENTINEL
### AI-Powered IPsec VPN Protocol Analyzer & Security Assessment Framework
*Based on Smart India Hackathon Problem Statement 26160 — National Technical Research Organisation (NTRO)*

---

## 1. Overview
**IPsec Sentinel** is an enterprise- and sovereign-grade cybersecurity workstation engineered for deep dissection, deterministic compliance auditing, and ML-driven side-channel analysis of IPsec (IKEv1/IKEv2, ESP, AH) virtual private networks.

Unlike generic dashboards, IPsec Sentinel is built specifically for network protocol analysts, security researchers, and SOC/SIEM investigators. It pairs deterministic state-machine RFC verification with unsupervised temporal ML models and evidence-grounded RAG synthesis.

---

## 2. Visual Identity & Design System
- **Obsidian Dark Surface**: `#0B0C0D` (Canvas), `#101214` (Deep Panels), `#17191C` (Elevated Cards), `#1D2024` (Secondary Inputs), `#2A2D31` (Hairline Borders)
- **Warm Bone Text**: `#E8E3D8` (Primary Headings & Code), `#9B9D9A` (Secondary Telemetry)
- **Primary Security Accent (Oxidized Copper / Burnt Amber)**: `#C47A52` (Active Tunnels, Key Timeline States, Brand Indicators)
- **Secondary Security Accent (Muted Mint)**: `#8FB8A8` (Verified RFC Compliance, Posture Passed Statuses, Online Indicators)
- **Semantic Indicators**: Critical `#E05A5A`, Warning `#D7A84D`, Informational `#7E9BB8`
- **Design Ratio**: 70% Enterprise Security Workstation • 20% Network Protocol Analyzer • 10% Terminal Aesthetic

---

## 3. Technology Stack
- **Framework**: Next.js 14 (App Router)
- **Language**: TypeScript (Strict typing, 0 lint/compile errors)
- **Styling**: Tailwind CSS with custom theme tokens & JetBrains Mono / Inter typography
- **Motion & Interactions**: Framer Motion 11
- **Icons**: Lucide React
- **Backend Bridge**: Asynchronous Frontend API abstraction layer ready for FastAPI integration

---

## 4. Application Routes

| Route | Title | Description |
|---|---|---|
| `/` | **Security Overview Dashboard** | Animated score (82/100), segmented posture gauges, live animated IPsec tunnel with moving packets, pipeline status, session table. |
| `/testbed` | **IPsec Testbed Generator** | Laboratory controls (IKEv1/v2, Tunnel/Transport, AES-GCM, DH19/31, PFS, IPv4/IPv6, Traffic generation) with live profile visualizer and deployment stages. |
| `/capture` | **Packet Capture & Ingestion** | Promiscuous bitstream stream, interactive packet artery (●────●), packet dissector with hex preview, and live terminal logs. |
| `/sessions` | **Session Explorer** | Filterable, searchable table of reconstructed IKEv1/IKEv2 sessions, SPI pairs, and status badges. |
| `/sessions/[id]` | **Detailed Session Analysis** | Technical session header, animated IKE negotiation timeline (IKE_SA_INIT → IKE_AUTH → CREATE_CHILD_SA → INFORMATIONAL), cryptographic parameters, SA telemetry, and RAG synthesis. |
| `/analysis/compliance` | **RFC Compliance** | 24-rule deterministic state machine (RFC 7296, RFC 4303, RFC 8221, NTRO baseline) with expandable evidence and remediation. |
| `/analysis/crypto` | **Cryptographic Posture** | Observed crypto suite, normalized vector table, and Profile Similarity Analysis (Modern Classical 92%, Legacy 21%, PQC Transitional 48%). |
| `/analysis/traffic` | **Traffic Intelligence** | Encrypted traffic burst cadence chart (33.3ms I-frame detection), ML classification (Video 91.4%, Web 5.2%), multi-model anomaly detection, and metadata side-channel analysis. |
| `/threats` | **Threat Matrix** | Plotted Likelihood vs. Impact 5x5 matrix with expandable forensic findings feed. |
| `/reports` | **Reports Dossier** | CISO Executive Report and Technical Protocol Dossier with simulated PDF generation and JSON export. |
| `/dataset` | **Ground Truth Dataset** | NTRO benchmark dataset metrics: 250,000 samples, train/val/test splits, protocol class distributions, and confusion accuracy. |
| `/settings` | **System Settings** | FastAPI endpoint adapter configuration, anomaly decision thresholds, and sovereign compliance baselines. |

---

## 5. API Abstraction & Backend Contract

The frontend is decoupled from the backend via modular API services located in `src/lib/api/`:
- `client.ts`: Base client, simulated network latency, and `API_BASE_URL` (`http://localhost:8000/api/v1`).
- `analysis.ts`: Fetches `SecurityScore`, `ComplianceFinding[]`, `ThreatFinding[]`, `CryptoProfile`, and `TrafficClassification`.
- `sessions.ts`: Queries session lists and individual session telemetry by ID.
- `testbed.ts`: Submits synthetic testbed parameters and streams deployment stages.
- `reports.ts`: Generates Executive & Technical dossiers and exports JSON.

### FastAPI Integration Blueprint
To connect the live Python backend, update `NEXT_PUBLIC_API_URL` in your `.env.local` or Settings page. The TypeScript interfaces in `src/types/index.ts` map directly to Pydantic models in FastAPI:
```python
# Expected FastAPI endpoint shapes:
# GET  /api/v1/analysis/score        -> SecurityScore
# GET  /api/v1/sessions              -> List[Session]
# GET  /api/v1/sessions/{id}         -> Session
# POST /api/v1/testbed/deploy        -> TestbedDeploymentResponse
# POST /api/v1/capture/upload        -> PCAPIngestionResponse
# GET  /api/v1/analysis/compliance   -> List[ComplianceFinding]
# GET  /api/v1/analysis/traffic      -> TrafficClassification
```

---

## 6. How to Run Locally

```bash
# Ensure Node 18+ is available in PATH
npm run dev

# Or run the optimized production bundle
npm run build
npm run start
```
The application will be accessible at: `http://localhost:3001`
