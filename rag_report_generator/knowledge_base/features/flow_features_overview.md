---
document_id: flow_features_overview
title: Phase 2 Statistical Flow Features Overview
category: feature
section: Flow Features Overview
source: knowledge_base/features/flow_features_overview.md
version: "1.0"
topic: statistical_flow_analysis
authority: project_phase2_spec
project_specific: true
keywords:
  - Phase 2
  - flow features
  - statistical features
  - bidirectional flow
  - forward direction
  - backward direction
---

# Phase 2 Statistical Flow Features Overview

## Concept and Philosophy of Phase 2 Feature Extraction

In modern secure network environments, payload encryption (such as IPsec ESP, TLS 1.3, and WireGuard) prevents conventional inspection of packet payload bytes. The Person 2 network security engine circumvents this limitation in **Phase 2** by extracting **exactly 25 deterministic statistical flow features** from bidirectional network conversations.

These features capture behavioral and temporal properties of network traffic without inspecting payload contents. They rely solely on:
1. Individual packet arrival timestamps
2. Packet total lengths in bytes
3. Directionality of each transmission relative to flow initiation

## Bidirectional Flow Architecture

A network flow is defined by the standard 5-tuple:
`[Source IP, Destination IP, Source Port, Destination Port, Transport Protocol]`

The engine tracks flows bidirectionally:
* **Forward Direction**: Packets traveling from the flow initiator (the client that sent the initial packet or handshake) toward the responder.
* **Backward Direction**: Packets traveling from the responder back toward the initiator.

Separating forward and backward properties enables the engine to quantify transmission asymmetry, client-server volume disparities, and response latency patterns.

## Deterministic Computation

All 25 features are computed deterministically from observed packet metadata:
* No probabilistic estimation or lossy approximations are used in feature calculation.
* Given identical PCAP packet inputs, the Phase 2 feature extraction pipeline produces bit-exact identical numerical values.
* The extracted vector serves as the standardized input for Phase 3 category resemblance classification and Phase 4 behavioral risk evaluation.

## Important Interpretation Boundary

While statistical flow features provide rich behavioral signatures, **features measure transmission mechanics, not malicious intent**. An extreme value in packet rate or directional byte ratio reflects observable physical transmission dynamics; it does not in itself constitute evidence of an attack, malware activity, or unauthorized intrusion.
