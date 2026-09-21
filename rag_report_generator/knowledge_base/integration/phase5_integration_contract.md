---
document_id: phase5_integration_contract
title: Phase 5 Unified Integration Schema and Contract
category: integration
section: Phase 5 Integration Contract
source: knowledge_base/integration/phase5_integration_contract.md
version: "1.0"
topic: phase5_contract
authority: project_phase5_spec
project_specific: true
keywords:
  - Phase 5
  - integration schema
  - unified analysis result
  - analysis metadata
  - capture summary
  - IPsec analysis
  - flows
  - prediction
  - model uncertainty
  - behavioral analysis
  - security assessment
  - explainability
---

# Phase 5 Unified Integration Schema and Contract

## Role of Phase 5 in the Person 2 Architecture

Phase 5 represents the culmination of the Person 2 processing pipeline. It aggregates the outputs of all preceding phases (Phase 1 protocol detection, Phase 2 feature extraction, Phase 3 category resemblance classification, Phase 3.5 provenance evaluation, and Phase 4 behavioral risk scoring) into a single, standardized, integration-compatible JSON analysis result.

This structured result serves as the factual foundation consumed by downstream consumers, including Person 3 visualization dashboards and the Part 2 RAG automated report generation subsystem.

## Schema Components of the Unified Analysis Result

The Phase 5 output adheres to the following structural sections:

1. **`analysis_metadata`**:
   * Execution timestamps, engine version, schema versions (`FEATURE_SCHEMA_VERSION = "1.0"`, `INTEGRATION_SCHEMA_VERSION = "1.0"`), and run parameters.
2. **`capture_summary`**:
   * Total packets processed, total byte volume, start/end timestamps, duration, packet loss counters, and transport protocol breakdown (TCP, UDP, ICMP).
3. **`ipsec_analysis`**:
   * Detection status of IPsec protocols: ESP (protocol 50), AH (protocol 51), IKE (UDP 500), and NAT-T (UDP 4500).
   * Active domain validation status (`VERIFIED IPSEC` vs. `TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED`).
   * Enforcement state of the `allow_unverified_domain` override flag.
4. **`flows`**:
   * Full inventory of bidirectional flows identified by 5-tuple, with the exact 25 deterministic Phase 2 features populated for each flow.
5. **`prediction`**:
   * Estimated traffic-category resemblance probabilities across `web`, `video`, `voip`, `file_transfer`, and `interactive`.
6. **`model_uncertainty`**:
   * Prediction entropy, margin metrics, and assigned confidence tier (`HIGH`, `MEDIUM`, or `LOW`).
7. **`behavioral_analysis`**:
   * List of triggered Phase 4 indicators (out of the 6 canonical indicators) and their individual point values.
8. **`security_assessment`**:
   * Final aggregate risk score (0–100) and corresponding risk severity tier (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
9. **`explainability`**:
   * Plain-text rationales and feature contributions explaining why specific indicators triggered and why the model assigned the given category.

## Decoupling Principle for RAG (Part 1 vs. Part 2)

* **Part 1 Boundary**: The RAG subsystem in Part 1 is purely responsible for indexing and retrieving trusted explanatory knowledge. It does not call Phase 5 or modify its data structures.
* **Part 2 Handoff**: In Part 2, the report generator will feed factual data from Phase 5 JSON into the deterministic query builder, retrieve grounded evidence from Part 1, and assemble synthesized reports.
