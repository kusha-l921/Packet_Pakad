---
document_id: behavioral_risk_indicators
title: Phase 4 Behavioral Risk Indicators
category: behavioral_indicator
section: Behavioral Risk Indicators
source: knowledge_base/behavioral/risk_indicators.md
version: "1.0"
topic: behavioral_indicators
authority: project_phase4_spec
project_specific: true
keywords:
  - Phase 4
  - behavioral indicators
  - UNUSUAL_HIGH_UPLOAD_VOLUME
  - UNUSUAL_HIGH_PACKET_RATE
  - UNUSUAL_BURST_ACTIVITY
  - LONG_LIVED_HIGH_VOLUME_FLOW
  - PERIODIC_LOW_VOLUME_ACTIVITY
  - STRONG_DIRECTIONAL_ASYMMETRY
  - risk points
---

# Phase 4 Behavioral Risk Indicators

The Person 2 Phase 4 engine evaluates network flows against exactly six deterministic behavioral risk indicators. Each indicator represents an observable physical pattern in flow metrics, assigns a deterministic point contribution, and enforces strict interpretative boundaries.

---

## UNUSUAL_HIGH_UPLOAD_VOLUME

Human-readable Name:
Unusual High Upload Volume

Description:
The observed flow exhibits an exceptionally large volume of outbound data transmitted from the initiator to the responder, exceeding the configured baseline upload threshold.

Observable Behavior:
Triggered when the forward byte count (`forward_bytes`) surpasses the high-volume upload threshold (typically accompanied by high `forward_byte_ratio`).

Risk Contribution:
25 points.

Intended Interpretation:
The flow demonstrates concentrated, high-volume outbound data transmission characteristic of bulk transfers, large document syncs, or continuous data push.

Does Not Prove:
This indicator does not independently prove unauthorized data exfiltration, information theft, sensitive document leakage, or malicious egress activity. Legitimate cloud backups, software publishing, and video uploads routinely trigger this pattern.

---

## UNUSUAL_HIGH_PACKET_RATE

Human-readable Name:
Unusual High Packet Rate

Description:
The observed flow exhibits a packet rate above the configured behavioral rate threshold, indicating rapid and dense packet transmission over its active duration.

Observable Behavior:
Triggered when `packets_per_second` exceeds the configured rate ceiling, reflecting high packet frequency across the flow duration.

Risk Contribution:
20 points.

Intended Interpretation:
The flow demonstrates unusually rapid packet transmission cadence, indicating time-sensitive streaming, network performance benchmarking, or intensive signaling.

Does Not Prove:
This indicator does not independently confirm an attack, malware, denial-of-service (DoS) flooding, port scanning, intrusion, or malicious intent. High packet rates occur naturally during video conferencing, gaming, and legitimate network benchmarking.

---

## UNUSUAL_BURST_ACTIVITY

Human-readable Name:
Unusual Burst Activity

Description:
The observed flow exhibits a sudden, highly concentrated spike in packet transmissions within a short temporal window compared to its overall average pacing.

Observable Behavior:
Triggered when `maximum_packets_in_one_second` exceeds the burst ceiling or displays a marked ratio discrepancy relative to the flow's average packet rate.

Risk Contribution:
15 points.

Intended Interpretation:
The flow experiences abrupt bursts of network activity, where large numbers of packets are flushed simultaneously into the network queue.

Does Not Prove:
This indicator does not prove an attack burst, automated brute-force attempts, exploit delivery spikes, or anomalous compromise. Standard TCP slow-start dynamics, video keyframe transmissions, and application batch flushes frequently exhibit burstiness.

---

## LONG_LIVED_HIGH_VOLUME_FLOW

Human-readable Name:
Long Lived High Volume Flow

Description:
The observed flow maintains both an extended temporal duration and a sustained, high aggregate byte volume across its lifecycle.

Observable Behavior:
Triggered when `flow_duration_seconds` exceeds the persistent connection threshold concurrently with `total_bytes` exceeding the bulk data volume threshold.

Risk Contribution:
15 points.

Intended Interpretation:
The flow represents a persistent, high-throughput communication channel operating continuously between endpoints.

Does Not Prove:
This indicator does not prove data tunneling, covert VPN usage, command-and-control (C2) persistence, or unauthorized data staging. Enterprise database replication, legitimate VPN tunnels, continuous audio/video streaming, and operating system updates exhibit this exact profile.

---

## PERIODIC_LOW_VOLUME_ACTIVITY

Human-readable Name:
Periodic Low Volume Activity

Description:
The observed flow exhibits highly regular, rhythmic packet transmissions characterized by small packet volumes and minimal timing variation between events.

Observable Behavior:
Triggered when `total_packets` is moderate, `total_bytes` is low, and `standard_deviation_inter_arrival_time` is close to zero, reflecting consistent, periodic inter-packet intervals.

Risk Contribution:
10 points.

Intended Interpretation:
The flow demonstrates automated, machine-driven, periodic communication cadence rather than human-generated interactive traffic.

Does Not Prove:
This indicator does not prove malware beaconing, C2 polling, Trojan heartbeats, or covert exfiltration channels. Benign network NTP synchronization, routing protocol hello packets, cloud monitoring agent health checks, and WebSocket keepalives regularly operate on strict periodic schedules.

---

## STRONG_DIRECTIONAL_ASYMMETRY

Human-readable Name:
Strong Directional Asymmetry

Description:
The observed flow displays extreme directional imbalance in byte transfer, where almost all traffic is concentrated in one direction with negligible return data.

Observable Behavior:
Triggered when `forward_byte_ratio` is near 1.0 (or conversely near 0.0 with `backward_byte_ratio` near 1.0), indicating that one endpoint transmits nearly all payload bytes while the other only returns bare acknowledgments.

Risk Contribution:
10 points.

Intended Interpretation:
The flow displays a one-sided data movement profile, separating the pure data sender from the pure data receiver.

Does Not Prove:
This indicator does not prove unauthorized data extraction or protocol manipulation. Unidirectional byte flow is standard in client-server architecture: web file downloads, media content delivery, and sensor telemetry ingestion are inherently strongly asymmetric.
