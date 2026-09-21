---
document_id: esp_ah_protocols
title: ESP and AH Protocols in IPsec
category: ipsec
section: ESP and AH Protocols
source: knowledge_base/ipsec/esp_ah_protocols.md
version: "1.0"
topic: ipsec_protocols
authority: project_domain_spec
project_specific: true
keywords:
  - ESP
  - Encapsulating Security Payload
  - AH
  - Authentication Header
  - Protocol 50
  - Protocol 51
  - integrity
  - encryption
---

# ESP and AH Protocols in IPsec

## Encapsulating Security Payload (ESP)

The Encapsulating Security Payload (ESP) protocol is assigned IP protocol number **50**. ESP provides a comprehensive suite of security services for IP traffic, including confidentiality (encryption), data origin authentication, connectionless data integrity, and anti-replay protection.

### Structure of ESP
ESP encapsulates the protected payload data with both a header and a trailer:
1. **ESP Header**:
   * **Security Parameter Index (SPI)**: A 32-bit field identifying the specific Security Association at the receiving peer.
   * **Sequence Number**: A 32-bit counter incremented with every packet sent, protecting against replay attacks.
2. **ESP Payload Data**: The encrypted transport-layer segment (Transport Mode) or complete inner IP packet (Tunnel Mode).
3. **ESP Trailer**:
   * **Padding**: 0 to 255 bytes added to satisfy cipher block size requirements and align fields on 4-byte boundaries.
   * **Pad Length**: 1 byte specifying the number of padding bytes preceding it.
   * **Next Header**: 1 byte identifying the protocol type of the encapsulated payload (e.g., protocol 6 for TCP, 17 for UDP, or 4 for IPv4 in Tunnel Mode).
4. **ESP ICV (Integrity Check Value)**: An optional cryptographic message authentication code computed over the ESP header, payload, and trailer to verify data integrity.

### Operational Characteristics of ESP
* ESP is the standard choice for secure virtual private networks (VPNs) because it provides cryptographic confidentiality.
* In the project's Phase 1 detection, IP packets with IP header protocol field equal to 50 are identified as ESP traffic.

## Authentication Header (AH)

The Authentication Header (AH) protocol is assigned IP protocol number **51**. AH is designed to provide connectionless data integrity, data origin authentication, and optional anti-replay protection for IP packets, but it provides **no confidentiality (no encryption)**.

### Structure of AH
AH consists of a 24-byte or larger header inserted into the IP packet:
* **Next Header**: 8 bits specifying the payload protocol that follows AH.
* **Payload Length**: 8 bits defining the length of the AH header in 32-bit words, minus 2.
* **Reserved**: 16 bits reserved for future use.
* **Security Parameter Index (SPI)**: 32 bits identifying the receiving SA.
* **Sequence Number**: 32 bits providing anti-replay protection.
* **Integrity Check Value (ICV)**: Variable-length cryptographic digest computed across the entire packet, including selected IP header fields.

### The NAT Incompatibility of AH
AH cryptographically verifies the integrity of the IP header fields that are considered immutable in transit (such as source IP, destination IP, and version). 

When an IP packet passes through a Network Address Translation (NAT) or Port Address Translation (PAT) router:
* The NAT device alters the source or destination IP address.
* Because the IP header is included in the AH ICV computation, any modification by NAT immediately invalidates the ICV at the receiving endpoint.
* As a consequence, **AH cannot traverse NAT devices** and will fail cryptographic verification. This fundamental limitation has led modern deployments to prefer ESP with NAT-Traversal.

## ESP vs. AH Comparison

| Attribute | ESP (Protocol 50) | AH (Protocol 51) |
| :--- | :--- | :--- |
| **Confidentiality / Encryption** | Yes (AES-GCM, AES-CBC, ChaCha20) | No (Payload transmitted in cleartext) |
| **Data Integrity** | Yes (via ESP ICV / AEAD) | Yes (via AH ICV) |
| **Data Origin Authentication** | Yes | Yes |
| **Anti-Replay Protection** | Yes | Yes |
| **IP Header Coverage** | Only in Tunnel Mode (inner IP) | Covers outer IP header (mutable fields zeroed) |
| **NAT Traversal Compatibility** | Compatible (via UDP 4500 NAT-T) | Strictly incompatible with NAT |
| **Project Phase 1 Identification**| Protocol 50 packet detection | Protocol 51 packet detection |
