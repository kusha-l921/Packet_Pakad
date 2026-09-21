# Codebase Directory & File Overview

A modular guide explaining each package and file in this repository.

---

## 1. `rfc_engine/` — RFC Compliance & Rule Engine

Evaluates unified IKEv2 handshake session parameters and runtime data-plane telemetry against RFC specifications:
* **[rfcRuleEngine.py](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/rfc_engine/rfcRuleEngine.py)**: Main orchestrator combining handshake control-plane auditing and runtime ESP anti-replay telemetry.
* **[rfcControlPlane.py](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/rfc_engine/rfcControlPlane.py)**: Audits session parameters across Categories 1–12 (ciphers, DH groups, PRFs, integrity, ESN, Child SA proposals).
* **[rfcRuntimeTelemetry.py](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/rfc_engine/rfcRuntimeTelemetry.py)**: RFC 4303 64-packet sliding window anti-replay detector and 64-bit sequence number rollover checker.
* **[rfcEngineModels.py](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/rfc_engine/rfcEngineModels.py)**: Dataclasses & enums (`EngineReport`, `RuleEvaluationResult`, `SecurityPosture`, `PqcClassification`).
* **[rfcRegistries.py](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/rfc_engine/rfcRegistries.py)**: Authoritative algorithm registry lookup tables based on IANA and RFC 8247 / RFC 8221.

---

## 2. `cert_engine/` — Dedicated PKI & Certificate Health

Dedicated engine for auditing X.509 (Encoding 4) certificate health, chains, and out-of-band daemon API ingestion:
* **[certHealthEngine.py](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/cert_engine/certHealthEngine.py)**: Audits validity windows, expiration (30-day early warnings), CA hierarchy flags, SAN identity matching, and rates credentials against CNSA 2.0, NIST, and RFC 8247 with hardcoded remediation advice.
* **[daemonCertIngest.py](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/cert_engine/daemonCertIngest.py)**: Out-of-band connector. Ingests credentials from strongSwan VICI API (`/var/run/charon.vici`), local `.pem`/`.crt`/`.der` files, or certificate directories, normalizes them into `auth_metadata`, and runs health audits.

---

## 3. `vector_engine/` — 19-D Vector Engine & Cosine Similarity

Converts IKEv2 session parameters into normalized numerical vectors and classifies cryptographic postures:
* **[vectorEngine.py](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/vector_engine/vectorEngine.py)**: 19-dimensional ($D=19$) pure-wire vector engine mapping session crypto parameters to floats in `[0.0, 1.0]`.
* **[baseVectors.py](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/vector_engine/baseVectors.py)**: Reference 19-D policy anchor vectors (`CNSA2_VECTOR`, `NIST_PQC_TRANSITIONAL_VECTOR`, `RFC8247_CLASSICAL_VECTOR`, `NIST_SP800_131A_DEPRECATED_VECTOR`).
* **[cosineSimilarity.py](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/vector_engine/cosineSimilarity.py)**: Measures cosine similarity between session vectors and reference policy anchors.
* **[ikeV2scores.py](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/vector_engine/ikeV2scores.py)**: Score tables ($0.0$ to $1.0$) for IKEv2 algorithms (KEMs, ciphers, PRFs, hashes, PQC signatures).
* **[ikeV2Lookups.py](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/vector_engine/ikeV2Lookups.py)**: Maps algorithm IDs to symmetric security bit strengths (112, 128, 192, 256 bits) and AEAD cipher sets.
* **[ikeV2IDs.py](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/vector_engine/ikeV2IDs.py)**: IANA IKEv2 parameter IDs (payloads, transforms, exchanges, notifications).
* **[ikeV1scores.py](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/vector_engine/ikeV1scores.py)** & **[ikeV1IDs.py](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/vector_engine/ikeV1IDs.py)**: Legacy IKEv1 constants and score tables.

---

## 4. `flow_engine/` — Machine Learning ESP Flow Engine

Real-time statistical traffic feature extraction and machine learning classification for encrypted ESP tunnels:
* **[FlowEngine.py](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/flow_engine/FlowEngine.py)**: Stateful ESP flow dispatcher managing per-flow sliding windows, stride advancement, and timeout triggers.
* **[FlowRecord.py](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/flow_engine/FlowRecord.py)**: Sliding-window packet buffer (window=200, stride=25) computing 25 statistical traffic features (IAT mean/std, packet size mean/std, byte ratios).

---

## 5. `packet_extractor/` — Wire Packet Dissection

Extracts normalized metadata from live network captures and PCAP files:
* **[metadataExtractor.py](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/packet_extractor/metadataExtractor.py)**: De-congested pure-wire dissector for IKEv2 and ESP network packets (proposals, transforms, key exchange, traffic selectors, delete, notifications, and ESP sequence numbers).

---

## 6. `tests/` — Automated Test Suites

All 6 test suites organized under a single directory with 77 tests (100% pass rate):
* **[test_rfcRuleEngine.py](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/tests/test_rfcRuleEngine.py)**: 12 tests for RFC compliance rules, streaming anti-replay sliding window, sequence rollover, and auth integration.
* **[test_certHealthEngine.py](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/tests/test_certHealthEngine.py)**: 12 tests for validity windows, 30-day early warnings, CA hierarchy flags, SAN matching, and CNSA 2.0 ratings.
* **[test_vectorEngine.py](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/tests/test_vectorEngine.py)**: 36 tests for the 19-D vector engine, dimensions, bounds, and policy anchor mapping.
* **[test_cosineSimilarity.py](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/tests/test_cosineSimilarity.py)**: 6 tests for cosine similarity math and policy classification.
* **[test_flowEngine.py](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/tests/test_flowEngine.py)**: 7 tests for real-time ESP flow aggregation, window buffering, and dispatcher coordination.
* **[test_daemonCertIngest.py](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/tests/test_daemonCertIngest.py)**: 4 tests for daemon certificate ingestion (PEM/DER parsing, peer metadata builder, directory scanning, and session attachment).

---

## 7. `docs/` — Documentation & Integration Guides

* **[integration.md](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/docs/integration.md)**: Developer integration guide with API signatures, schemas, daemon integration, and examples.
* **[FILE_OVERVIEW.md](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/docs/FILE_OVERVIEW.md)**: This document.

---

## 8. Root Facades (Backward Compatibility)

Thin re-export shims at the project root ensure existing scripts and automation importing directly from root continue to work with zero breaking changes:
* `rfcRuleEngine.py`, `certHealthEngine.py`, `daemonCertIngest.py`, `vectorEngine.py`, `baseVectors.py`, `cosineSimilarity.py`, `FlowEngine.py`, `FlowRecord.py`, `metadataExtractor.py`.
