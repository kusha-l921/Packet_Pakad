"""
packet_extractor — Wire Packet Dissector for IKEv2 & ESP.

Extracts normalized handshake proposals, transforms, key exchanges, traffic selectors,
and ESP sequence numbers from live packets or PCAP captures.
"""

from __future__ import annotations

from .metadataExtractor import (
    extract_esp_metadata,
    extract_ikeV1_metadata,
    extract_ikeV2_metadata,
    parse_ikev2_cert_payload,
    parse_x509_certificate,
)

# Alias
extract_esp_packet_metadata = extract_esp_metadata

__all__ = [
    "extract_ikeV2_metadata",
    "extract_ikeV1_metadata",
    "extract_esp_metadata",
    "extract_esp_packet_metadata",
    "parse_ikev2_cert_payload",
    "parse_x509_certificate",
]
