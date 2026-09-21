---
document_id: traffic_category_resemblance
title: Phase 3 Traffic-Category Resemblance Classification
category: classification
section: Traffic Category Resemblance
source: knowledge_base/classification/traffic_category_resemblance.md
version: "1.0"
topic: traffic_classification
authority: project_phase3_spec
project_specific: true
keywords:
  - Phase 3
  - traffic categories
  - category resemblance
  - web
  - video
  - voip
  - file_transfer
  - interactive
  - statistical resemblance
---

# Phase 3 Traffic-Category Resemblance Classification

## Traffic Category Resemblance Concept

The Person 2 Phase 3 engine employs a lightweight, CPU-friendly machine learning model to evaluate network flows. The objective of this model is **traffic-category resemblance estimation**:

> The classifier estimates mathematical resemblance to known statistical traffic categories based strictly on the 25 Phase 2 flow features.

The model evaluates feature distributions (packet sizing, pacing, duration, and directional balance) against statistical profiles learned during training to assign probability scores across five predefined categories.

## The Five Traffic Categories

The model recognizes five canonical traffic categories:

### 1. `web`
* **Statistical Profile**: Moderate packet sizes with request-response alternation, variable inter-arrival times, and moderate byte ratios.
* **Resemblance Meaning**: Flow dynamics align with conversational hypertext transactions, API polling, or multi-asset web browsing.

### 2. `video`
* **Statistical Profile**: Consistently large packet sizes near MTU in the download/inbound direction, elevated throughput, and steady packet chunk bursts.
* **Resemblance Meaning**: Flow dynamics align with chunked media buffer delivery, video-on-demand playback, or real-time video streaming.

### 3. `voip`
* **Statistical Profile**: Small, highly uniform packet sizes with near-constant inter-arrival times (low timing variance) and balanced bidirectional packet exchange.
* **Resemblance Meaning**: Flow dynamics align with periodic audio codec packetization, real-time voice, or low-latency telemetry pacing.

### 4. `file_transfer`
* **Statistical Profile**: Sustained large packet sizes, continuous high throughput, elevated duration, and pronounced directional asymmetry toward the receiving peer.
* **Resemblance Meaning**: Flow dynamics align with bulk data transportation, archive downloads, or large-scale document transfers.

### 5. `interactive`
* **Statistical Profile**: Small packet sizes, sporadic human-paced inter-arrival times (elevated timing standard deviation), and immediate low-volume acknowledgments.
* **Resemblance Meaning**: Flow dynamics align with keystroke-driven interactive shells (e.g., SSH, Telnet), chat messaging, or sporadic control sessions.

## Mandatory Non-Overclaiming Boundary: Resemblance vs. Application Identification

The RAG subsystem and all downstream reports must strictly preserve the following analytical boundary:

1. **Not Guaranteed Application Identification**:
   * A classification of `web` does **not** guarantee the application is HTTP or HTTPS.
   * A classification of `video` does **not** prove YouTube, Netflix, or Vimeo streaming.
   * A classification of `voip` does **not** prove Skype, Zoom, or SIP calling.
   * A classification of `file_transfer` does **not** prove FTP, SCP, or BitTorrent.
2. **Encrypted Payload Opacity**:
   Because the underlying payload may be encrypted under IPsec ESP or TLS, deep application signatures cannot be validated. The classifier outputs statistical resemblance to behavioral profiles, not deterministic application decodes.
