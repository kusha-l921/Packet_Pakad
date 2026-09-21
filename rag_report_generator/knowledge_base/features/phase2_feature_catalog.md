---
document_id: phase2_feature_catalog
title: Phase 2 25-Feature Deterministic Flow Schema Catalog
category: feature
section: Phase 2 Feature Catalog
source: knowledge_base/features/phase2_feature_catalog.md
version: "1.0"
topic: feature_catalog
authority: project_phase2_spec
project_specific: true
keywords:
  - Phase 2
  - 25 features
  - total_packets
  - forward_packets
  - backward_packets
  - total_bytes
  - forward_bytes
  - backward_bytes
  - minimum_packet_size
  - maximum_packet_size
  - mean_packet_size
  - standard_deviation_packet_size
  - median_packet_size
  - forward_mean_packet_size
  - backward_mean_packet_size
  - flow_duration_seconds
  - packets_per_second
  - bytes_per_second
  - mean_inter_arrival_time
  - minimum_inter_arrival_time
  - maximum_inter_arrival_time
  - standard_deviation_inter_arrival_time
  - forward_packet_ratio
  - backward_packet_ratio
  - forward_byte_ratio
  - backward_byte_ratio
  - maximum_packets_in_one_second
---

# Phase 2 25-Feature Deterministic Flow Schema Catalog

The Person 2 Phase 2 engine extracts exactly 25 deterministic statistical flow features. Each feature is defined below in full technical detail.

---

## total_packets

Meaning:
The total count of all network packets observed in both forward and backward directions throughout the lifetime of the flow.

Measures:
Overall packet volume.

Unit:
Packets (integer).

Relevance:
Distinguishes short ephemeral transactions (e.g., DNS queries, TLS handshakes) from high-volume streaming sessions, bulk file transfers, or long-lived connections.

Limitation:
A large packet count indicates high activity volume but does not indicate malicious intent or protocol misuse.

---

## forward_packets

Meaning:
The total number of packets transmitted in the forward direction (from the flow initiator toward the responder).

Measures:
Initiator-transmitted packet count.

Unit:
Packets (integer).

Relevance:
Quantifies client-side activity, request volume, or outbound transmission load.

Limitation:
Elevated forward packet count alone does not establish port scanning, command flooding, or abnormal client behavior.

---

## backward_packets

Meaning:
The total number of packets transmitted in the backward direction (from the flow responder back toward the initiator).

Measures:
Responder-transmitted packet count.

Unit:
Packets (integer).

Relevance:
Measures server-side response volume, download pacing, and bidirectional handshake completion. A value of zero indicates a unidirectional or unanswered flow.

Limitation:
A lack of backward packets can result from benign firewall packet filtering, packet capture vantage point limitations, or UDP simplex flows, rather than attack reconnaissance.

---

## total_bytes

Meaning:
The aggregate sum of all packet lengths in bytes across both directions of the flow.

Measures:
Total data transfer volume.

Unit:
Bytes (integer).

Relevance:
Critical for bandwidth accounting and categorizing flows into lightweight transactional exchanges versus bulk data movements.

Limitation:
Total byte volume reflects transmission size only; large volume is typical for benign media streaming and system backups.

---

## forward_bytes

Meaning:
The total volume of data in bytes transmitted in the forward direction (initiator to responder).

Measures:
Outbound / client-side data transfer volume.

Unit:
Bytes (integer).

Relevance:
Key metric for identifying upload volume, client data submission, and outbound payload transfer.

Limitation:
High forward byte volume is common in legitimate cloud uploads, backups, and file sharing; it does not independently prove data exfiltration.

---

## backward_bytes

Meaning:
The total volume of data in bytes transmitted in the backward direction (responder to initiator).

Measures:
Inbound / server-side data transfer volume.

Unit:
Bytes (integer).

Relevance:
Indicates download volume, web response sizing, and data retrieval magnitude.

Limitation:
Substantial download volume does not indicate unauthorized data retrieval or malicious command-and-control payload delivery.

---

## minimum_packet_size

Meaning:
The smallest individual packet length in bytes observed in the flow.

Measures:
Lower bound of packet length distribution.

Unit:
Bytes (integer).

Relevance:
Reflects bare protocol headers, TCP control segments (e.g., pure ACKs, SYNs, FINs), or small keepalive heartbeats.

Limitation:
Small minimum packet size is ubiquitous in all TCP/IP communications due to standard connection setup and acknowledgment packets.

---

## maximum_packet_size

Meaning:
The largest individual packet length in bytes observed in the flow.

Measures:
Upper bound of packet length distribution.

Unit:
Bytes (integer).

Relevance:
Indicates whether the flow reaches standard Maximum Transmission Unit (MTU) boundaries (e.g., 1500 bytes for standard Ethernet, or lower due to IPsec tunnel overhead).

Limitation:
Reaching the MTU limit is standard for legitimate bulk transfers and media streams; it does not indicate malicious fragmentation or buffer attacks.

---

## mean_packet_size

Meaning:
The arithmetic average of packet lengths across all observed packets in the flow.

Measures:
Central tendency of packet sizing.

Unit:
Bytes (floating-point).

Relevance:
Characterizes whether a flow is dominated by small control/interactive messaging (e.g., telnet, SSH typing, DNS) or large bulk data segments.

Limitation:
Average packet size varies widely across legitimate applications; intermediate values frequently occur in mixed traffic.

---

## standard_deviation_packet_size

Meaning:
The standard deviation of packet lengths across the flow.

Measures:
Variability and dispersion of packet sizes.

Unit:
Bytes (floating-point).

Relevance:
Distinguishes flows with uniform packet sizes (e.g., constant-bitrate audio with near-zero deviation) from multimodal distributions (e.g., HTTP with small requests and maximum-sized data segments).

Limitation:
High variability is standard for interactive web browsing and complex application protocols; it does not indicate obfuscation or malicious encapsulation.

---

## median_packet_size

Meaning:
The 50th percentile packet size in bytes across all packets in the flow.

Measures:
Robust central tendency unaffected by extreme packet outliers.

Unit:
Bytes (floating-point).

Relevance:
Provides a stable metric for the dominant packet size when a flow contains a few unrepresentative large or small control segments.

Limitation:
Cannot capture bimodal distributions on its own without considering variance or minimum/maximum bounds.

---

## forward_mean_packet_size

Meaning:
The arithmetic mean packet size of all packets transmitted in the forward direction.

Measures:
Average size of client/initiator transmissions.

Unit:
Bytes (floating-point).

Relevance:
Differentiates between client requests sending small command queries versus client requests uploading bulk data segments.

Limitation:
A large forward mean packet size merely reflects large payload generation by the client; it does not establish unauthorized transfer.

---

## backward_mean_packet_size

Meaning:
The arithmetic mean packet size of all packets transmitted in the backward direction.

Measures:
Average size of server/responder transmissions.

Unit:
Bytes (floating-point).

Relevance:
Characterizes responder delivery behavior, such as file downloads or full-frame video streaming versus short status responses.

Limitation:
A small backward mean packet size can occur legitimately when a server only returns brief acknowledgments or error codes.

---

## flow_duration_seconds

Meaning:
The total time elapsed from the timestamp of the first observed packet to the timestamp of the last observed packet in the flow.

Measures:
Temporal lifespan of the flow.

Unit:
Seconds (floating-point).

Relevance:
Distinguishes transient connections from persistent, long-lived sessions (e.g., VPN tunnels, database connections, streaming sessions).

Limitation:
Long duration alone does not signify unauthorized persistence, beaconing, or covert channels.

---

## packets_per_second

Meaning:
The overall packet rate of the flow, calculated as `total_packets / flow_duration_seconds` (or assigned to total packets if duration is zero).

Measures:
Packet transmission frequency / rate.

Unit:
Packets per second (floating-point).

Relevance:
High values indicate high-throughput pipelines, streaming bursts, or rapid signaling; very low values indicate idle or sporadic communication.

Limitation:
Elevated packet rates occur naturally during network speed tests, video conferences, and file transfers; high rate does not prove a Denial of Service (DoS) attack.

---

## bytes_per_second

Meaning:
The overall data throughput of the flow, calculated as `total_bytes / flow_duration_seconds` (or assigned to total bytes if duration is zero).

Measures:
Data transfer bandwidth consumption.

Unit:
Bytes per second (floating-point).

Relevance:
Indicates bandwidth intensity and communication speed across the connection.

Limitation:
High throughput is normal in modern high-speed broadband connections and enterprise networks; it does not indicate malicious data exfiltration.

---

## mean_inter_arrival_time

Meaning:
The arithmetic mean of time intervals between consecutive packets in the flow.

Measures:
Average packet spacing / transmission cadence.

Unit:
Seconds (floating-point).

Relevance:
Identifies whether transmissions occur in rapid succession or are separated by long idle periods.

Limitation:
Network buffering, scheduling jitter, and transit queuing can distort packet spacing independently of endpoint intent.

---

## minimum_inter_arrival_time

Meaning:
The shortest observed time interval between two consecutive packets in the flow.

Measures:
Burst packet spacing lower bound.

Unit:
Seconds (floating-point).

Relevance:
Near-zero inter-arrival times signify back-to-back packet transmission bursts within hardware interface limits.

Limitation:
Microsecond or sub-microsecond intervals are ubiquitous on gigabit and 10-gigabit network links due to NIC offloading (TSO/GSO).

---

## maximum_inter_arrival_time

Meaning:
The longest observed time interval between two consecutive packets in the flow.

Measures:
Maximum idle time / pause duration within the flow.

Unit:
Seconds (floating-point).

Relevance:
Detects long pauses, connection stalls, or periodic heartbeat intervals in persistent sessions.

Limitation:
Application think-time or keepalive timeouts legitimately produce extended maximum inter-arrival times.

---

## standard_deviation_inter_arrival_time

Meaning:
The standard deviation of inter-arrival times between consecutive packets.

Measures:
Consistency and regularity of packet timing intervals.

Unit:
Seconds (floating-point).

Relevance:
Low standard deviation indicates highly regular, periodic pacing (e.g., automated polling or VoIP codecs); high standard deviation indicates bursty, irregular user-driven traffic.

Limitation:
Network jitter introduced by intermediate routers can artificially inflate timing variation.

---

## forward_packet_ratio

Meaning:
The proportion of total flow packets that were transmitted in the forward direction: `forward_packets / total_packets`.

Measures:
Directional distribution of packet counts.

Unit:
Dimensionless ratio in the range `[0.0, 1.0]`.

Relevance:
Identifies directional asymmetry in packet counts. In standard TCP flows, receiver ACK generation typically balances packet ratios around 0.5 to 0.7.

Limitation:
Asymmetric packet ratios can result from delayed ACKs or asymmetric routing where return packets follow an alternate path.

---

## backward_packet_ratio

Meaning:
The proportion of total flow packets that were transmitted in the backward direction: `backward_packets / total_packets`.

Measures:
Directional distribution of responder packet counts.

Unit:
Dimensionless ratio in the range `[0.0, 1.0]`.

Relevance:
Measures responder packet dominance. Satisfies `forward_packet_ratio + backward_packet_ratio = 1.0` for any non-empty flow.

Limitation:
Low backward packet ratio does not confirm an unacknowledged flooding attack without deeper transport-state analysis.

---

## forward_byte_ratio

Meaning:
The proportion of total flow bytes transmitted in the forward direction: `forward_bytes / total_bytes`.

Measures:
Directional byte distribution.

Unit:
Dimensionless ratio in the range `[0.0, 1.0]`.

Relevance:
A high value indicates traffic is strongly weighted toward the forward direction (e.g., client upload or data submission).

Limitation:
Directional asymmetry alone does not establish malicious behavior. Legitimate cloud uploads, file backups, and video streaming uploads routinely produce high forward byte ratios.

---

## backward_byte_ratio

Meaning:
The proportion of total flow bytes transmitted in the backward direction: `backward_bytes / total_bytes`.

Measures:
Directional distribution of responder byte volume.

Unit:
Dimensionless ratio in the range `[0.0, 1.0]`.

Relevance:
High values indicate download-heavy workloads (e.g., web page asset fetching, video streaming, file downloading).

Limitation:
Asymmetry toward the backward direction is standard for consumer Internet browsing and does not signify malicious payload delivery.

---

## maximum_packets_in_one_second

Meaning:
The highest number of packets observed within any single rolling one-second time window across the flow duration.

Measures:
Peak short-term packet burst intensity.

Unit:
Packets (integer).

Relevance:
Identifies sudden transmission bursts, instantaneous congestion spikes, or bursty media streaming chunking.

Limitation:
Burst activity is characteristic of TCP slow-start window doubling and application buffer flushes; it does not independently prove an attack burst.
