---
document_id: technical_limitations
title: Technical Limitations and Sound Analytical Boundaries
category: limitations
section: Technical Limitations
source: knowledge_base/limitations/technical_limitations.md
version: "1.0"
topic: analytical_boundaries
authority: project_system_spec
project_specific: true
keywords:
  - limitations
  - non-overclaiming
  - boundaries
  - statistical resemblance
  - behavioral risk
  - domain validation
  - evaluation caveats
---

# Technical Limitations and Sound Analytical Boundaries

## Overview and Non-Overclaiming Mandate

To maintain scientific integrity and operational credibility, the Person 2 network traffic analysis engine and its accompanying RAG reporting subsystem adhere strictly to sound analytical boundaries. Automated systems must avoid claiming conclusions that are not mathematically or empirically supported by observable data.

Downstream report generators must enforce the following six core limitations:

---

## 1. Category Resemblance Is Not Application Identification

* **Principle**: The Phase 3 machine learning classifier computes mathematical proximity to statistical traffic profiles (`web`, `video`, `voip`, `file_transfer`, `interactive`) using 25 flow features.
* **Boundary**: This is **not** application identification. A flow classified as `web` does not guarantee HTTP/HTTPS; a flow classified as `video` does not confirm YouTube; a flow classified as `voip` does not confirm Skype.
* **Prohibition**: Reports must never state that an application protocol has been definitively identified solely from statistical resemblance scores.

---

## 2. Behavioral Indicators Do Not Confirm Malicious Activity

* **Principle**: The six Phase 4 behavioral indicators (`UNUSUAL_HIGH_UPLOAD_VOLUME`, `UNUSUAL_HIGH_PACKET_RATE`, `UNUSUAL_BURST_ACTIVITY`, `LONG_LIVED_HIGH_VOLUME_FLOW`, `PERIODIC_LOW_VOLUME_ACTIVITY`, `STRONG_DIRECTIONAL_ASYMMETRY`) capture observable physical transmission properties.
* **Boundary**: High packet rates, heavy uploads, or directional asymmetries occur routinely in benign operational contexts (e.g., system updates, cloud backups, media streaming, benchmark testing).
* **Prohibition**: An indicator or elevated risk score must **never** be cited as conclusive proof of an attack, malware infection, unauthorized intrusion, or malicious intent without external corroborating evidence.

---

## 3. Unverified IPsec Inference Is Not IPsec-Domain Validated

* **Principle**: Traffic protected by IPsec ESP exhibits distinct framing overhead, packet padding, and encapsulation dynamics.
* **Boundary**: Running a classifier on `TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED` traffic via the `allow_unverified_domain` override produces experimental outputs prone to domain-shift errors.
* **Prohibition**: Reports must never represent unverified IPsec inference as validated IPsec-domain analysis.

---

## 4. Dataset Diversity Governs Evaluation Validity

* **Principle**: A machine learning model's reported benchmark metrics reflect the specific conditions of its training and test captures.
* **Boundary**: Models evaluated on homogeneous or synthetic captures may overfit to environmental artifacts (host configurations, specific MTU settings, background clock jitter).
* **Prohibition**: Benchmark scores must not be generalized to diverse production networks without multi-environment validation.

---

## 5. WITHIN_CAPTURE_HOLDOUT Is Not Unseen-Capture Validation

* **Principle**: `WITHIN_CAPTURE_HOLDOUT` splits test data from the same recording session as training data.
* **Boundary**: Temporal and host correlations leak across the split, inflating perceived performance metrics. Only `GROUP_ISOLATED` partitions demonstrate true unseen-capture generalization.
* **Prohibition**: Evaluators must never describe `WITHIN_CAPTURE_HOLDOUT` or `OVERALL_MIXED_EVALUATION` as proof of unseen-capture robustness.

---

## 6. Model Uncertainty Does Not Equal Behavioral Risk

* **Principle**: Model uncertainty reflects classifier confidence across categories; behavioral risk reflects physical traffic anomalies.
* **Boundary**: Model uncertainty contributes **0 points** to behavioral risk scoring. High model confidence can coexist with CRITICAL risk, and LOW classification confidence frequently accompanies completely benign LOW-risk flows.
* **Prohibition**: Reports must never conflate classification uncertainty with security risk or threat probability.
