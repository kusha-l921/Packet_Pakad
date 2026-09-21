---
document_id: ike_nat_traversal
title: IKE and NAT-Traversal Protocols
category: ipsec
section: IKE and NAT Traversal
source: knowledge_base/ipsec/ike_nat_traversal.md
version: "1.0"
topic: ike_natt
authority: project_domain_spec
project_specific: true
keywords:
  - IKE
  - IKEv1
  - IKEv2
  - NAT-T
  - UDP 500
  - UDP 4500
  - key exchange
  - SA negotiation
---

# IKE and NAT-Traversal Protocols

## Internet Key Exchange (IKE) Overview

Internet Key Exchange (IKE) is the control-plane protocol used to dynamically authenticate communicating IPsec peers, negotiate cryptographic security associations (SAs), and establish shared session keys. IKE operates over **UDP port 500**.

Without an automated key management protocol like IKE, IPsec endpoints would require manual configuration of encryption ciphers, integrity algorithms, and symmetric cryptographic keys (Manual Keying), which scales poorly and lacks Perfect Forward Secrecy (PFS).

## IKE Versions: IKEv1 vs. IKEv2

The IETF standardized two major generations of the IKE protocol:

### IKEv1 (RFC 2409)
IKEv1 negotiates security in a distinct two-phase process:
1. **Phase 1 (ISAKMP SA)**: Establishes a secure, authenticated communications channel between peers. Can run in:
   * *Main Mode*: 6-packet exchange that conceals peer identities behind encryption.
   * *Aggressive Mode*: 3-packet exchange that provides faster negotiation but transmits peer identity in the clear.
2. **Phase 2 (Quick Mode)**: 3-packet exchange operating inside the protection of Phase 1 to negotiate the child IPsec SAs (ESP or AH) that will carry actual data traffic.

### IKEv2 (RFC 7296)
IKEv2 provides a significantly streamlined, resilient, and modern key exchange framework:
* **Fewer Packet Exchanges**: Replaces the multi-phase model with standard exchanges:
  * `IKE_SA_INIT`: 2 packets negotiating cryptographic parameters and performing Diffie-Hellman key derivation.
  * `IKE_AUTH`: 2 packets authenticating identities and creating the first Child SA.
  * `CREATE_CHILD_SA`: Used for rekeying and generating additional Child SAs.
* **Built-in NAT Detection**: Natively includes NAT detection mechanisms without requiring custom vendor extensions.
* **Mobility and Multihoming (MOBIKE)**: Allows IPsec endpoints to change IP addresses (e.g., migrating between Wi-Fi and mobile networks) without terminating the VPN tunnel.
* **Enhanced Resilience**: Native protection against denial-of-service (DoS) attacks via stateless cookie verification.

## NAT Traversal (NAT-T) and UDP Port 4500

Network Address Translation (NAT) presents substantial obstacles to raw IPsec ESP traffic because ESP is a transport-less network-layer protocol:
* ESP (IP protocol 50) does not contain TCP/UDP port numbers.
* Port Address Translation (PAT) devices require port numbers to multiplex multiple internal hosts onto a single public IP address.
* When plain ESP packets transit a PAT router, the router cannot properly map inbound packets to the originating internal host.

### NAT-T Encapsulation Mechanism
NAT-Traversal solves this problem by encapsulating raw ESP packets inside standard UDP datagrams:
1. **Detection**: During the IKE exchange (UDP port 500), peers send NAT-Discovery payloads (hashes of IP addresses and ports). If a discrepancy is detected between the transmitted and received hashes, a NAT gateway is identified on the path.
2. **Port Floating**: Once NAT is detected, the peers float the IKE negotiation and subsequent data traffic from UDP port 500 to **UDP port 4500**.
3. **UDP Encapsulation of ESP**:
   * ESP packets are wrapped inside a standard UDP header with destination port 4500.
   * Because the outer header is standard UDP, PAT routers can inspect and rewrite the UDP source port, maintaining translation mappings in their state tables.
   * A 4-byte "Non-ESP Marker" (zeros) is placed before the IKE header on port 4500 to distinguish IKE management packets from encapsulated ESP packets.

### Phase 1 Detection in the Project
The Person 2 Phase 1 network analysis engine specifically detects:
* **IKE Control Traffic**: UDP packets on destination or source port 500.
* **NAT-T Encapsulated Traffic**: UDP packets on destination or source port 4500.
* **Raw ESP Traffic**: Packets with IPv4/IPv6 Next Header equal to 50.
* **Raw AH Traffic**: Packets with IPv4/IPv6 Next Header equal to 51.
