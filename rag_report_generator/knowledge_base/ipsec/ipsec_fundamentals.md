---
document_id: ipsec_fundamentals
title: IPsec Architecture and Traffic Interpretation
category: ipsec
section: IPsec Fundamentals
source: knowledge_base/ipsec/ipsec_fundamentals.md
version: "1.0"
topic: ipsec_architecture
authority: project_domain_spec
project_specific: true
keywords:
  - IPsec
  - tunnel mode
  - transport mode
  - Security Association
  - SPI
  - encrypted traffic
---

# IPsec Architecture and Traffic Interpretation

## IPsec Overview

Internet Protocol Security (IPsec) is an open-standard suite of protocols developed by the Internet Engineering Task Force (IETF) to secure communication across Internet Protocol (IP) networks. IPsec operates at the Network Layer (Layer 3) of the OSI model. By securing IP packets directly at the network layer, IPsec provides protocol-transparent cryptographic security to all upper-layer transport protocols (TCP, UDP, ICMP) and applications without requiring application-level modifications.

IPsec provides four fundamental security services:
1. **Confidentiality**: Encrypting packet payloads using symmetric ciphers (e.g., AES-GCM, AES-CBC) to prevent unauthorized inspection.
2. **Data Integrity**: Cryptographically verifying that packet contents have not been altered or tampered with in transit.
3. **Data Origin Authentication**: Confirming that packets originate from the legitimate and claimed sender identity.
4. **Anti-Replay Protection**: Utilizing monotonically incrementing sequence numbers to detect and reject retransmitted duplicate packets.

## Modes of Operation: Transport Mode vs. Tunnel Mode

IPsec operates in two distinct encapsulation modes, each serving specific network topologies:

### Transport Mode
In Transport Mode, IPsec secures only the upper-layer payload (e.g., TCP or UDP segment) while preserving the original IP packet header:
* The original IP source and destination addresses remain exposed and intact in the packet header.
* The security protocol header (ESP or AH) is inserted immediately after the original IP header and before the transport layer payload.
* Transport Mode is predominantly utilized for host-to-host or end-to-end communication where both endpoints implement IPsec directly.

### Tunnel Mode
In Tunnel Mode, IPsec encapsulates the entire original IP packet (both header and payload) within a brand new outer IP packet:
* The original IP packet becomes the encrypted inner payload.
* A new outer IP header is prepended, specifying the security gateway endpoints (e.g., VPN concentrators or routers) as outer source and destination IP addresses.
* Tunnel Mode is standard for gateway-to-gateway (site-to-site VPN) and host-to-gateway (remote access VPN) deployments.
* Inner routing topologies and private IP address allocations are hidden from intermediate transit networks.

## Security Associations (SA) and SPI

A Security Association (SA) is a simplex (unidirectional) logical connection that defines the exact cryptographic parameters agreed upon between two IPsec communication endpoints. 

Key attributes of a Security Association include:
* **Security Parameter Index (SPI)**: A 32-bit identifier carried in the ESP or AH header that allows the receiving entity to select the correct SA from its Security Association Database (SAD).
* **Cryptographic Algorithms**: Specific symmetric encryption ciphers, hashing algorithms, and key lengths negotiated for the session.
* **Cryptographic Keys**: Active encryption and authentication keys generated during the key exchange phase.
* **Sequence Number Counter**: A 32-bit or extended 64-bit counter tracking transmitted packets to enforce anti-replay verification.

Because SAs are unidirectional, a bidirectional secure session requires a minimum of two Security Associations—one inbound and one outbound.

## Encrypted Traffic Interpretation and Payload Opacity

A central premise of this project is the disciplined interpretation of encrypted IPsec traffic:

### Payload Opacity
Once IPsec encryption (ESP) is applied, the packet payload is cryptographically opaque. Deep Packet Inspection (DPI), payload string matching, cleartext signature detection, and application header parsing are mathematically precluded. 

### Statistical Flow Analysis
Because payload inspection is impossible, network traffic characterization for IPsec must be conducted strictly using observable packet and flow metadata:
* Packet timestamps and inter-arrival intervals
* Packet byte lengths and size distributions
* Directional transfer volume and packet ratios
* Temporal burstiness and flow duration

### Sound Analytical Boundaries
Statistical flow features reveal transmission patterns (e.g., steady-state bulk data movement versus bursty transactional messaging), but they do not disclose cleartext payload contents. Traffic classification on IPsec flows estimates resemblance to known statistical profiles rather than confirming application identity.
