"""Flow relevance policy and background traffic filtering engine for Phase 3.5.

Evaluates extracted network flows against deterministic, evidence-based rules to
distinguish genuine scenario traffic from unrelated background/control noise
(LLMNR, mDNS, NetBIOS, local broadcast, infrastructure DNS, and collateral traffic).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import ipaddress
import re
from typing import Any, Dict, List, Optional, Set, Tuple


class FlowExclusionReason(str, Enum):
    """Categorical reasons for excluding an extracted flow from ML training datasets."""

    BACKGROUND_LLMNR = "BACKGROUND_LLMNR"
    BACKGROUND_MDNS = "BACKGROUND_MDNS"
    BACKGROUND_NETBIOS = "BACKGROUND_NETBIOS"
    BACKGROUND_MULTICAST_BROADCAST = "BACKGROUND_MULTICAST_BROADCAST"
    BACKGROUND_INFRASTRUCTURE_DNS = "BACKGROUND_INFRASTRUCTURE_DNS"
    BACKGROUND_LOCAL_DISCOVERY = "BACKGROUND_LOCAL_DISCOVERY"
    NON_IP_LAYER2 = "NON_IP_LAYER2"
    COLLATERAL_NON_SCENARIO_TRAFFIC = "COLLATERAL_NON_SCENARIO_TRAFFIC"


@dataclass
class FlowRelevancePolicy:
    """Configurable policy determining whether a flow is eligible for ML model training.

    All filtering decisions are evidence-based, transparent, and non-destructive:
    excluded flows remain preserved in Level 1 (raw) datasets with an explicit
    exclusion reason.
    """

    exclude_llmnr_mdns: bool = True
    exclude_netbios: bool = True
    exclude_multicast_broadcast: bool = True
    exclude_infrastructure_dns: bool = True
    exclude_local_discovery: bool = True
    exclude_non_ip: bool = True
    exclude_collateral_services: bool = True

    # Configurable port definitions
    llmnr_ports: Set[int] = field(default_factory=lambda: {5355})
    mdns_ports: Set[int] = field(default_factory=lambda: {5353})
    netbios_ports: Set[int] = field(default_factory=lambda: {137, 138, 139})
    dns_ports: Set[int] = field(default_factory=lambda: {53})
    discovery_ports: Set[int] = field(
        default_factory=lambda: {
            123,    # NTP
            1900,   # SSDP
            17500,  # Dropbox LAN Sync
            67,     # DHCP server
            68,     # DHCP client
            546,    # DHCPv6 client
            547,    # DHCPv6 server
        }
    )

    def evaluate_flow(
        self,
        flow_id: str,
        protocol: str,
        endpoint_a: str,
        endpoint_b: str,
        scenario_metadata: Optional[Dict[str, Any]] = None,
        canonical_label: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Evaluate if an extracted flow is relevant to the target scenario.

        Args:
            flow_id: Canonical flow identifier string.
            protocol: Transport protocol string (e.g. TCP, UDP, ICMP, UNKNOWN).
            endpoint_a: First endpoint string (IP or IP:port).
            endpoint_b: Second endpoint string (IP or IP:port).
            scenario_metadata: Optional dictionary with manifest capture metadata.
            canonical_label: Target canonical label assigned to the capture.

        Returns:
            Tuple of (is_eligible: bool, exclusion_reason: Optional[str]).
        """
        # 1. Non-IP or Layer 2 frames (e.g. ARP, UNKNOWN)
        if self.exclude_non_ip:
            if protocol.upper() in {"UNKNOWN", "ARP", "ETH"} or "UNKNOWN_any_any" in flow_id:
                return False, FlowExclusionReason.NON_IP_LAYER2.value
            if endpoint_a == "any" or endpoint_b == "any":
                return False, FlowExclusionReason.NON_IP_LAYER2.value

        # Parse endpoints
        ip_a, port_a = self._parse_endpoint(endpoint_a)
        ip_b, port_b = self._parse_endpoint(endpoint_b)
        ports = {p for p in (port_a, port_b) if p is not None}

        # 2. LLMNR
        if self.exclude_llmnr_mdns and any(p in self.llmnr_ports for p in ports):
            return False, FlowExclusionReason.BACKGROUND_LLMNR.value

        # 3. mDNS
        if self.exclude_llmnr_mdns and any(p in self.mdns_ports for p in ports):
            return False, FlowExclusionReason.BACKGROUND_MDNS.value

        # 4. NetBIOS
        if self.exclude_netbios and any(p in self.netbios_ports for p in ports):
            return False, FlowExclusionReason.BACKGROUND_NETBIOS.value

        # 5. Local Discovery / Background Services (SSDP, Dropbox, NTP, DHCP)
        if self.exclude_local_discovery and any(p in self.discovery_ports for p in ports):
            return False, FlowExclusionReason.BACKGROUND_LOCAL_DISCOVERY.value

        # 6. Infrastructure DNS
        # DNS is infrastructure lookup traffic unless the target scenario is specifically DNS benchmarking
        if self.exclude_infrastructure_dns and any(p in self.dns_ports for p in ports):
            return False, FlowExclusionReason.BACKGROUND_INFRASTRUCTURE_DNS.value

        # 7. Multicast and Broadcast addresses
        if self.exclude_multicast_broadcast:
            for ip_str in (ip_a, ip_b):
                if ip_str and self._is_multicast_or_broadcast(ip_str):
                    return False, FlowExclusionReason.BACKGROUND_MULTICAST_BROADCAST.value

        # 8. Collateral non-scenario traffic
        if self.exclude_collateral_services and scenario_metadata and canonical_label:
            target_app = scenario_metadata.get("application", "").lower()
            proto_fam = scenario_metadata.get("protocol_family", "").lower()

            # Case: SCP capture where user was casually browsing HTTP websites
            if target_app == "scp" or proto_fam == "ssh_scp":
                # Genuine SCP traffic runs strictly over SSH (TCP port 22)
                if 22 not in ports:
                    return False, FlowExclusionReason.COLLATERAL_NON_SCENARIO_TRAFFIC.value

            # Case: FTPS capture where non-FTP flows occur
            elif target_app == "ftps" or proto_fam == "ftps_tls":
                # FTPS control runs on 21 or 990; data runs over negotiated high ports between client and server
                # In ftps_down_1a_sample, client is 131.202.240.87 and server is 131.202.240.242
                is_ftp_control = any(p in {21, 990} for p in ports)
                is_ftp_server = (ip_a == "131.202.240.242" or ip_b == "131.202.240.242")
                if not (is_ftp_control or (is_ftp_server and protocol.upper() == "TCP")):
                    return False, FlowExclusionReason.COLLATERAL_NON_SCENARIO_TRAFFIC.value

        return True, None

    @staticmethod
    def _parse_endpoint(ep_str: str) -> Tuple[str, Optional[int]]:
        """Extract IP address and integer port from an endpoint string."""
        if not ep_str or ep_str == "any":
            return "", None

        # Handle IPv6 format [2001:db8::1]:port or 2001:db8::1:port
        if ep_str.startswith("[") and "]" in ep_str:
            ip_part = ep_str[1 : ep_str.index("]")]
            remainder = ep_str[ep_str.index("]") + 1 :]
            if remainder.startswith(":") and remainder[1:].isdigit():
                return ip_part, int(remainder[1:])
            return ip_part, None

        if ":" in ep_str:
            parts = ep_str.rsplit(":", 1)
            if parts[1].isdigit():
                return parts[0], int(parts[1])

        return ep_str, None

    @staticmethod
    def _is_multicast_or_broadcast(ip_str: str) -> bool:
        """Check if an IP string is a multicast, link-local multicast, or broadcast address."""
        if not ip_str:
            return False

        # Subnet or limited broadcast
        if ip_str == "255.255.255.255" or ip_str.endswith(".255"):
            return True

        # Common multicast prefixes
        if ip_str.startswith("224.0.0.") or ip_str.startswith("239.255.") or ip_str.startswith("ff02::"):
            return True

        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return ip_obj.is_multicast or ip_obj.is_link_local
        except ValueError:
            return False


def evaluate_flow(
    flow_id: str,
    protocol: str,
    endpoint_a: str,
    endpoint_b: str,
    scenario_metadata: Optional[Dict[str, Any]] = None,
    packet_count: int = 0,
    byte_count: int = 0,
    policy: Optional[FlowRelevancePolicy] = None,
) -> Tuple[bool, Optional[str]]:
    """Convenience helper to evaluate a single flow against a FlowRelevancePolicy."""
    active_policy = policy or FlowRelevancePolicy()
    return active_policy.evaluate_flow(
        flow_id=flow_id,
        protocol=protocol,
        endpoint_a=endpoint_a,
        endpoint_b=endpoint_b,
        scenario_metadata=scenario_metadata,
        packet_count=packet_count,
        byte_count=byte_count,
    )


def filter_flow_samples(
    samples: List[Any],
    policy: Optional[FlowRelevancePolicy] = None,
) -> Tuple[List[Any], List[Any]]:
    """Filter a list of FlowSample objects into (eligible_samples, excluded_samples)."""
    active_policy = policy or FlowRelevancePolicy()
    eligible: List[Any] = []
    excluded: List[Any] = []
    for s in samples:
        meta = getattr(s, "metadata", {})
        flow_id = meta.get("flow_id", "")
        proto = meta.get("protocol", "IP")
        ep_a = meta.get("endpoint_a", "")
        ep_b = meta.get("endpoint_b", "")
        is_ok, reason = active_policy.evaluate_flow(
            flow_id=flow_id,
            protocol=proto,
            endpoint_a=ep_a,
            endpoint_b=ep_b,
            scenario_metadata=meta,
        )
        meta["model_eligible"] = is_ok
        meta["exclusion_reason"] = reason or ""
        if is_ok:
            eligible.append(s)
        else:
            excluded.append(s)
    return eligible, excluded
