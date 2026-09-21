---
document_id: ipsec_domain_validation
title: IPsec Domain Validation Policy and Safety Controls
category: integration
section: IPsec Domain Validation
source: knowledge_base/integration/ipsec_domain_validation.md
version: "1.0"
topic: ipsec_domain_validation
authority: project_integration_spec
project_specific: true
keywords:
  - IPsec domain validation
  - VERIFIED IPSEC
  - TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED
  - allow_unverified_domain
  - domain shift
  - safety policy
---

# IPsec Domain Validation Policy and Safety Controls

## The IPsec Domain Adaptation Problem

Encrypted IPsec traffic introduces structural modifications to packet dynamics compared to cleartext traffic:
* **Protocol Overhead**: ESP headers, initialization vectors, padding, and ICVs add fixed byte overhead to every packet, altering packet length distributions.
* **Traffic Aggregation**: Tunnel mode multiplexes multiple diverse inner host communications into a single aggregate outer tunnel flow, creating composite statistical behaviors.
* **Timing Perturbations**: Hardware crypto offloading or software cryptographic processing queues can introduce timing shifts.

Consequently, a machine learning classifier trained exclusively on cleartext or non-IPsec captures cannot be assumed to perform reliably on IPsec traffic without domain-specific validation.

## Domain Policy Classifications

The Person 2 engine strictly enforces the following domain statuses:

### 1. VERIFIED IPSEC
* **Definition**: The model has been empirically evaluated, tested, and validated against genuine, verified IPsec network captures representing the target deployment environment.
* **Operational Implication**: ML inference is formally authorized on IPsec flows. Predictions and confidence estimates reflect verified domain performance.

### 2. TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED
* **Definition**: The flow feature extraction pipeline successfully processes the packet stream and extracts the 25 statistical features (the data is technically compatible with the model input schema), but the classifier has **not** undergone empirical validation on IPsec traffic.
* **Operational Implication**: Domain validity is unconfirmed. Running inference across an unverified domain risks severe domain-shift errors, miscalibration, and false confidence.

### 3. `allow_unverified_domain` (Configuration Override)
* **Definition**: An explicit, opt-in administrative configuration flag that permits experimental or diagnostic model inference on `TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED` traffic.
* **Operational Implication**: When enabled, inference proceeds, but the engine annotates all resulting predictions with an explicit unverified domain caveat.

## Project Safety and Compliance Policy

The project documentation establishes a strict governance rule:

> **Unverified IPsec inference must never be represented as IPsec-domain-validated inference.**

### Enforcement Mechanics
1. **Safe Default (Blocked Inference)**:
   By default, when the engine identifies IPsec traffic (ESP, AH, or NAT-T) and the active model holds `TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED` status, ML classification is **suppressed / blocked**. The engine reports the technical compatibility while refusing to produce speculative category predictions.
2. **Explicit Override Required**:
   Inference on unverified IPsec traffic is strictly gated behind the `allow_unverified_domain=True` configuration flag.
3. **Auditable Reporting**:
   When the override is utilized, downstream reports must prominently display that the output is experimental and lacks empirical domain verification.
