"""
metadataExtractor.py — Control-plane (IKEv1/v2) metadata via PyShark,
                        data-plane (ESP/NAT-T) metadata via Scapy.

PyShark approach:
  - Header fields (IPs, ports, SPIs, exchange type, flags, message ID) read
    from PyShark's isakmp layer attributes.
  - Nested payload structures (SA → Proposal → Transform, Notify, CERT, AUTH,
    TSi/TSr, ID, KE, Nonce, Hash, Sig, Delete) are parsed from the raw UDP
    payload bytes because PyShark flattens repeated fields and loses the
    hierarchical relationship between proposals and their transforms.

ESP/NAT-T parsing remains Scapy-based (unchanged).
"""

# ─── Scapy: kept ONLY for ESP data-plane ──────────────────────────────────
from scapy.all import IP, IPv6, UDP, Raw

# ─── IKEv1 lookup tables ──────────────────────────────────────────────────
from ikeV1IDs import (
    ISAKMP_IDENTIFICATION_TYPES,
    IKEV1_CERTIFICATE_ENCODINGS,
    IKEV1_NOTIFY_ERROR_TYPES,
    IKEV1_NOTIFY_STATUS_TYPES,
    ISAKMP_NOTIFY_STATUS_TYPES,
)

import struct
import socket


# ─── Constants ─────────────────────────────────────────────────────────────

TRANSFORM_TYPE_MAP_IKEV2 = {
    1: "encryption",
    2: "prf",
    3: "integrity",
    4: "dh_group",
    5: "extended_sequence_numbers",
    6: "additional_key_exchange_1",    
    7: "additional_key_exchange_2", 
    8: "additional_key_exchange_3", 
    9: "additional_key_exchange_4", 
    10: "additional_key_exchange_5",    
    11: "additional_key_exchange_6",    
    12: "additional_key_exchange_7"     
}
IKEV1_ATTR_TYPES = {
    1: "encryption",
    2: "hash",
    3: "auth_method",
    4: "group_description",
    5: "group_type",
    6: "life_type",
    7: "life_duration",
    8: "prf",
    11: "encapsulation_mode",
    14: "key_length"
}

IKEV1_IPSEC_ATTR_TYPES = {
    1: "life_type",
    2: "life_duration",
    3: "group_description",
    4: "encapsulation_mode",
    5: "auth_method",
    6: "key_length",
}

ISAKMP_EXCHANGE_TYPES = {
    1: "Base Mode",
    2: "Main Mode",
    3: "Authentication Only",
    4: "Aggressive Mode",
    5: "Informational",
    32: "Quick Mode",
    33: "New Group Mode",
}

IKEV1_ATTR_NAME_NORMALIZE = {
    "encryption": "encryption",
    "hash": "hash",
    "authentication": "auth_method",
    "auth_method": "auth_method",
    "groupdesc": "group_description",
    "group_description": "group_description",
    "grouptype": "group_type",
    "group_type": "group_type",
    "lifetype": "life_type",
    "life_type": "life_type",
    "lifeduration": "life_duration",
    "life_duration": "life_duration",
    "prf": "prf",
    "encapsulationmode": "encapsulation_mode",
    "encapsulation_mode": "encapsulation_mode",
    "keylength": "key_length",
    "key_length": "key_length",
    "authenticationalgorithm": "hash",
    "authentication_algorithm": "hash",
}


# ─── Utility helpers ──────────────────────────────────────────────────────

def _format_hex_or_bytes(val):
    if val is None:
        return None
    if isinstance(val, bytes):
        return f"0x{val.hex()}" if len(val) > 0 else None
    if isinstance(val, int):
        return hex(val)
    return str(val)


def _get_ikev1_notify_name(msg_type):
    if msg_type is None:
        return None
    if msg_type in IKEV1_NOTIFY_ERROR_TYPES:
        return IKEV1_NOTIFY_ERROR_TYPES[msg_type]
    if msg_type in IKEV1_NOTIFY_STATUS_TYPES:
        return IKEV1_NOTIFY_STATUS_TYPES[msg_type]
    if msg_type in ISAKMP_NOTIFY_STATUS_TYPES:
        return ISAKMP_NOTIFY_STATUS_TYPES[msg_type]
    return str(msg_type)


def _colon_hex_to_bytes(hex_str):
    """Convert PyShark colon-delimited hex 'ab:cd:ef' → bytes b'\\xab\\xcd\\xef'."""
    if hex_str is None:
        return None
    return bytes.fromhex(hex_str.replace(":", ""))


def _colon_hex_to_hex_str(hex_str):
    """Convert 'ab:cd:ef' → '0xabcdef'."""
    if hex_str is None:
        return None
    raw = hex_str.replace(":", "")
    if not raw:
        return None
    return f"0x{raw}"


def _safe_int(val, default=None):
    """Safely convert a PyShark field value to int."""
    if val is None:
        return default
    try:
        s = str(val).strip()
        if s.startswith("0x") or s.startswith("0X"):
            return int(s, 16)
        return int(s)
    except (ValueError, TypeError):
        return default


# ═══════════════════════════════════════════════════════════════════════════
#  RAW BINARY PARSERS — IKEv2 payloads from UDP payload bytes
# ═══════════════════════════════════════════════════════════════════════════

def _parse_ikev2_from_raw(raw_bytes, exchange_type):
    """Parse IKEv2 payloads from raw bytes (after the 28-byte IKEv2 header).
    
    Returns lists of parsed payloads organised by type.
    """
    # IKEv2 header is 28 bytes
    if len(raw_bytes) < 28:
        return {}

    next_payload = raw_bytes[16]
    offset = 28  # skip the 28-byte IKEv2 header

    proposals = []
    notify_list = []
    auth_info = None
    cert_info = None
    tsi_list = []
    tsr_list = []

    while next_payload != 0 and offset < len(raw_bytes):
        if offset + 4 > len(raw_bytes):
            break

        np_next = raw_bytes[offset]
        payload_len = struct.unpack("!H", raw_bytes[offset + 2 : offset + 4])[0]
        if payload_len < 4:
            break
        payload_data = raw_bytes[offset + 4 : offset + payload_len]
        payload_all = raw_bytes[offset : offset + payload_len]

        if next_payload == 33:  # SA
            proposals.extend(_parse_ikev2_sa_payload(payload_data, exchange_type))
        elif next_payload == 41:  # Notify
            notify_list.append(_parse_ikev2_notify_payload(payload_data))
        elif next_payload == 39:  # AUTH
            auth_info = _parse_ikev2_auth_payload(payload_data)
        elif next_payload == 37:  # CERT
            cert_info = _parse_ikev2_cert_payload(payload_data)
        elif next_payload == 44:  # TSi
            tsi_list.extend(_parse_ikev2_ts_payload(payload_data))
        elif next_payload == 45:  # TSr
            tsr_list.extend(_parse_ikev2_ts_payload(payload_data))

        next_payload = np_next
        offset += payload_len

    return {
        "proposals": proposals,
        "notify": notify_list,
        "auth": auth_info,
        "cert": cert_info,
        "tsi": tsi_list,
        "tsr": tsr_list,
    }


def _parse_ikev2_sa_payload(data, exchange_type):
    """Parse SA payload data (after generic payload header) into proposals."""
    proposals = []
    offset = 0

    while offset < len(data):
        if offset + 8 > len(data):
            break

        # Proposal sub-structure:
        # 0: next proposal (0 or 2)
        # 1: reserved
        # 2-3: proposal length
        # 4: proposal number
        # 5: protocol ID
        # 6: SPI size
        # 7: num transforms
        prop_len = struct.unpack("!H", data[offset + 2 : offset + 4])[0]
        prop_num = data[offset + 4]
        proto_id = data[offset + 5]
        spi_size = data[offset + 6]
        num_transforms = data[offset + 7]

        spi_val = None
        transform_offset = offset + 8
        if spi_size > 0:
            spi_bytes = data[offset + 8 : offset + 8 + spi_size]
            spi_val = _format_hex_or_bytes(spi_bytes) if exchange_type in (35, "IKE_AUTH") else None
            transform_offset = offset + 8 + spi_size

        transforms = {
            "encryption": [], "prf": [], "integrity": [], "dh_group": [],
            "extended_sequence_numbers": [],
            "additional_key_exchange_1": [], "additional_key_exchange_2": [],
            "additional_key_exchange_3": [], "additional_key_exchange_4": [],
            "additional_key_exchange_5": [], "additional_key_exchange_6": [],
            "additional_key_exchange_7": [],
            "key_wrap": [], "group_controller_authentication": []
        }

        t_offset = transform_offset
        for _ in range(num_transforms):
            if t_offset + 8 > offset + prop_len:
                break
            # Transform header: 
            # 0: next transform (0 or 3)
            # 1: reserved
            # 2-3: transform length
            # 4: transform type
            # 5: reserved
            # 6-7: transform ID
            t_len = struct.unpack("!H", data[t_offset + 2 : t_offset + 4])[0]
            t_type = data[t_offset + 4]
            t_id = struct.unpack("!H", data[t_offset + 6 : t_offset + 8])[0]

            # Parse transform attributes for key_length
            key_length = None
            attr_offset = t_offset + 8
            while attr_offset + 4 <= t_offset + t_len:
                attr_header = struct.unpack("!HH", data[attr_offset : attr_offset + 4])
                attr_type_raw = attr_header[0]
                is_tv = bool(attr_type_raw & 0x8000)
                attr_type = attr_type_raw & 0x7FFF
                if is_tv:
                    attr_val = attr_header[1]
                    if attr_type == 14:  # Key Length
                        key_length = attr_val
                    attr_offset += 4
                else:
                    attr_len = attr_header[1]
                    attr_offset += 4 + attr_len

            t_type_name = TRANSFORM_TYPE_MAP_IKEV2.get(t_type)
            if t_type_name and t_type_name in transforms:
                transforms[t_type_name].append({
                    "id": t_id,
                    "length": key_length,
                })

            t_offset += t_len

        proposals.append({
            "proposal_num": prop_num,
            "protocol_id": proto_id,
            "spi": spi_val,
            "transforms": transforms,
        })

        offset += prop_len

    return proposals


def _parse_ikev2_notify_payload(data):
    """Parse Notify payload data."""
    if len(data) < 4:
        return {}
    proto_id = data[0]
    spi_size = data[1]
    notify_type = struct.unpack("!H", data[2:4])[0]
    
    spi = None
    if spi_size > 0 and len(data) >= 4 + spi_size:
        spi_bytes = data[4:4 + spi_size]
        spi = _format_hex_or_bytes(spi_bytes)
    
    notify_data = None
    data_start = 4 + spi_size
    if data_start < len(data):
        notify_data = _format_hex_or_bytes(data[data_start:])

    return {
        "type": notify_type,
        "protocol_id": proto_id,
        "spi_size": spi_size,
        "spi": spi,
        "data": notify_data,
    }


def _parse_ikev2_auth_payload(data):
    """Parse AUTH payload data."""
    if len(data) < 4:
        return None
    auth_method = data[0]
    auth_data = data[4:] if len(data) > 4 else data[1:]
    return {
        "auth_type": auth_method,
        "data": _format_hex_or_bytes(auth_data) if auth_data else None,
    }


def _parse_ikev2_cert_payload(data):
    """Parse CERT payload data."""
    if len(data) < 1:
        return None
    encoding = data[0]
    cert_data = data[1:] if len(data) > 1 else None
    return {
        "encoding": encoding,
        "data": _format_hex_or_bytes(cert_data),
    }


def _parse_ikev2_ts_payload(data):
    """Parse Traffic Selector payload data."""
    selectors = []
    if len(data) < 4:
        return selectors
    num_ts = data[0]
    offset = 4  # skip num_ts + 3 reserved bytes

    for _ in range(num_ts):
        if offset + 8 > len(data):
            break
        ts_type = data[offset]
        ip_proto = data[offset + 1]
        selector_len = struct.unpack("!H", data[offset + 2 : offset + 4])[0]
        start_port = struct.unpack("!H", data[offset + 4 : offset + 6])[0]
        end_port = struct.unpack("!H", data[offset + 6 : offset + 8])[0]

        start_addr = None
        end_addr = None
        if ts_type == 7 and selector_len >= 16:  # TS_IPV4_ADDR_RANGE
            start_addr = socket.inet_ntoa(data[offset + 8 : offset + 12])
            end_addr = socket.inet_ntoa(data[offset + 12 : offset + 16])
        elif ts_type == 8 and selector_len >= 40:  # TS_IPV6_ADDR_RANGE
            start_addr = socket.inet_ntop(socket.AF_INET6, data[offset + 8 : offset + 24])
            end_addr = socket.inet_ntop(socket.AF_INET6, data[offset + 24 : offset + 40])

        selectors.append({
            "type": ts_type,
            "ip_protocol": ip_proto,
            "start_port": start_port,
            "end_port": end_port,
            "start_address": start_addr,
            "end_address": end_addr,
        })

        offset += selector_len

    return selectors


# ═══════════════════════════════════════════════════════════════════════════
#  RAW BINARY PARSERS — IKEv1 payloads from UDP payload bytes
# ═══════════════════════════════════════════════════════════════════════════

def _parse_ikev1_payloads_from_raw(raw_bytes):
    """Walk IKEv1 payload chain from raw ISAKMP bytes.
    
    Returns a list of (payload_type, payload_data_bytes) tuples in order.
    """
    if len(raw_bytes) < 28:
        return []

    next_payload = raw_bytes[16]
    offset = 28

    payloads = []
    while next_payload != 0 and offset + 4 <= len(raw_bytes):
        np_next = raw_bytes[offset]
        reserved = raw_bytes[offset + 1]
        payload_len = struct.unpack("!H", raw_bytes[offset + 2 : offset + 4])[0]
        if payload_len < 4:
            break

        payload_data = raw_bytes[offset + 4 : offset + payload_len]
        payloads.append((next_payload, payload_data, raw_bytes[offset : offset + payload_len]))

        next_payload = np_next
        offset += payload_len

    return payloads


def _parse_ikev1_sa_proposals(data):
    """Parse IKEv1 SA payload → list of proposal dicts."""
    # SA payload data: DOI(4) + Situation(4) + proposals...
    if len(data) < 8:
        return []

    proposals = []
    offset = 8  # skip DOI + Situation

    while offset + 8 <= len(data):
        np_next = data[offset]
        prop_len = struct.unpack("!H", data[offset + 2 : offset + 4])[0]
        if prop_len < 8:
            break

        prop_num = data[offset + 4]
        proto_id = data[offset + 5]
        spi_size = data[offset + 6]
        num_transforms = data[offset + 7]

        spi_val = None
        trans_start = offset + 8
        if spi_size > 0 and trans_start + spi_size <= offset + prop_len:
            spi_bytes = data[trans_start : trans_start + spi_size]
            spi_val = _format_hex_or_bytes(spi_bytes)
            trans_start += spi_size

        transforms_dict = {
            "encryption": [], "hash": [], "auth_method": [],
            "group_description": [], "group_type": [],
            "life_type": [], "life_duration": [],
            "prf": [], "encapsulation_mode": [], "key_length": [],
        }

        t_offset = trans_start
        for _ in range(num_transforms):
            if t_offset + 8 > offset + prop_len:
                break

            t_len = struct.unpack("!H", data[t_offset + 2 : t_offset + 4])[0]
            if t_len < 8:
                break

            # Parse transform attributes
            attr_offset = t_offset + 8
            while attr_offset + 4 <= t_offset + t_len:
                attr_header = struct.unpack("!HH", data[attr_offset : attr_offset + 4])
                attr_type_raw = attr_header[0]
                is_tv = bool(attr_type_raw & 0x8000)
                attr_type = attr_type_raw & 0x7FFF

                if is_tv:
                    attr_val = attr_header[1]
                    attr_offset += 4
                else:
                    attr_val_len = attr_header[1]
                    if attr_val_len <= 4 and attr_offset + 4 + attr_val_len <= t_offset + t_len:
                        raw_val = data[attr_offset + 4 : attr_offset + 4 + attr_val_len]
                        attr_val = int.from_bytes(raw_val, "big") if raw_val else 0
                    else:
                        attr_val = _format_hex_or_bytes(
                            data[attr_offset + 4 : attr_offset + 4 + attr_val_len]
                        ) if attr_offset + 4 + attr_val_len <= t_offset + t_len else None
                    attr_offset += 4 + attr_val_len

                attr_map = IKEV1_IPSEC_ATTR_TYPES if proto_id in (2, 3, 4) else IKEV1_ATTR_TYPES
                attr_name = attr_map.get(attr_type)
                if not attr_name:
                    norm_key = str(attr_type).lower().replace(" ", "_")
                    attr_name = IKEV1_ATTR_NAME_NORMALIZE.get(norm_key, norm_key)

                if attr_name not in transforms_dict:
                    transforms_dict[attr_name] = []
                transforms_dict[attr_name].append({"value": attr_val})

            t_offset += t_len

        proposals.append({
            "proposal_num": prop_num,
            "protocol_id": proto_id,
            "spi": spi_val,
            "transforms": transforms_dict,
        })

        offset += prop_len

    return proposals


def _parse_ikev1_identification(id_data):
    """Parse IKEv1 ID payload raw data → (type_name, formatted_data, details)."""
    if id_data is None or len(id_data) < 4:
        return None, None, {}

    id_type = id_data[0]
    proto_id = id_data[1]
    port = struct.unpack("!H", id_data[2:4])[0]
    raw_data = id_data[4:]

    id_type_name = ISAKMP_IDENTIFICATION_TYPES.get(id_type, str(id_type) if id_type is not None else None)

    formatted_data = None
    addr_info = {}

    if isinstance(raw_data, bytes) and len(raw_data) > 0:
        if id_type == 1 and len(raw_data) == 4:
            try:
                formatted_data = socket.inet_ntoa(raw_data)
                addr_info["start_address"] = formatted_data
                addr_info["end_address"] = formatted_data
            except Exception:
                formatted_data = f"0x{raw_data.hex()}"
        elif id_type == 4 and len(raw_data) == 8:
            try:
                subnet_ip = socket.inet_ntoa(raw_data[:4])
                subnet_mask = socket.inet_ntoa(raw_data[4:8])
                formatted_data = f"{subnet_ip}/{subnet_mask}"
                addr_info["start_address"] = subnet_ip
                addr_info["end_address"] = subnet_mask
            except Exception:
                formatted_data = f"0x{raw_data.hex()}"
        elif id_type == 7 and len(raw_data) == 8:
            try:
                start_ip = socket.inet_ntoa(raw_data[:4])
                end_ip = socket.inet_ntoa(raw_data[4:8])
                formatted_data = f"{start_ip}-{end_ip}"
                addr_info["start_address"] = start_ip
                addr_info["end_address"] = end_ip
            except Exception:
                formatted_data = f"0x{raw_data.hex()}"
        elif id_type == 5 and len(raw_data) == 16:
            try:
                formatted_data = socket.inet_ntop(socket.AF_INET6, raw_data)
                addr_info["start_address"] = formatted_data
                addr_info["end_address"] = formatted_data
            except Exception:
                formatted_data = f"0x{raw_data.hex()}"
        elif id_type in (2, 3):
            try:
                formatted_data = raw_data.decode("utf-8")
            except Exception:
                formatted_data = f"0x{raw_data.hex()}"
        else:
            formatted_data = f"0x{raw_data.hex()}"

    details = {
        "type": id_type_name,
        "ip_protocol": proto_id,
        "port": port,
        "data": formatted_data,
    }
    details.update(addr_info)
    return id_type_name, formatted_data, details


# ═══════════════════════════════════════════════════════════════════════════
#  PYSHARK HELPER — read fields from a PyShark packet
# ═══════════════════════════════════════════════════════════════════════════

def _pyshark_get_raw_udp_payload(pkt):
    """Extract the raw UDP payload bytes from a PyShark packet.
    
    This is the IKE/ISAKMP data starting from the initiator SPI.
    """
    try:
        # PyShark exposes the UDP payload as hex in udp.payload
        raw_hex = pkt.udp.payload.replace(":", "")
        return bytes.fromhex(raw_hex)
    except (AttributeError, ValueError):
        return None


# ═══════════════════════════════════════════════════════════════════════════
#  IKEv2 METADATA EXTRACTOR — PyShark-based
# ═══════════════════════════════════════════════════════════════════════════

def extract_ikeV2_metadata(pkt):
    """Extract IKEv2 metadata from a PyShark packet.
    
    Output schema is identical to the original Scapy-based implementation.
    """
    if not hasattr(pkt, 'isakmp'):
        return None

    ike = pkt.isakmp

    # Check it's IKEv2 (major version 2)
    try:
        major_ver = _safe_int(ike.mjver)
        if major_ver is not None and major_ver != 2:
            return None
    except AttributeError:
        # If we can't determine version, try to proceed
        pass

    exchangeType = _safe_int(ike.exchangetype)

    # Get IPs
    src_ip = None
    dst_ip = None
    try:
        src_ip = str(pkt.ip.src)
        dst_ip = str(pkt.ip.dst)
    except AttributeError:
        try:
            src_ip = str(pkt.ipv6.src)
            dst_ip = str(pkt.ipv6.dst)
        except AttributeError:
            pass

    # Get ports
    src_port = None
    dst_port = None
    try:
        src_port = _safe_int(pkt.udp.srcport)
        dst_port = _safe_int(pkt.udp.dstport)
    except AttributeError:
        pass

    # SPIs
    init_spi = _colon_hex_to_hex_str(getattr(ike, 'ispi', None))
    resp_spi = _colon_hex_to_hex_str(getattr(ike, 'rspi', None))

    # Flags
    flags_int = _safe_int(getattr(ike, 'flags', '0x00'), 0)
    is_response = bool(flags_int & 0x20)

    # Message ID
    message_id = _safe_int(getattr(ike, 'messageid', None))

    # Timestamp
    try:
        timestamp = float(pkt.sniff_timestamp)
    except (AttributeError, ValueError, TypeError):
        timestamp = 0.0

    overall_metadata = {
        "exchange_type": exchangeType,
    }

    common_metadata = {
        "plane": "control",
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "initiator_spi": init_spi,
        "responder_spi": resp_spi,
        "exchange_type": exchangeType,
        "is_response": is_response,
        "message_id": message_id,
    }

    overall_metadata["common"] = common_metadata

    # ── Parse payloads from raw bytes ──────────────────────────────────
    raw_bytes = _pyshark_get_raw_udp_payload(pkt)
    if raw_bytes is None or len(raw_bytes) < 28:
        return overall_metadata

    parsed = _parse_ikev2_from_raw(raw_bytes, exchangeType)

    # ── Build exchange-specific metadata ──────────────────────────────
    if exchangeType in (34, "IKE_SA_INIT"):
        ike_sa_init_metadata = {
            "exchange": "IKE_SA_INIT",
            "proposals": parsed["proposals"],
        }
        overall_metadata["IKE_SA_INIT"] = ike_sa_init_metadata

    elif exchangeType in (35, "IKE_AUTH"):
        auth_info = parsed.get("auth")
        cert_info = parsed.get("cert")

        ike_auth_metadata = {
            "exchange": "IKE_AUTH",
            "authentication": {
                "present": auth_info is not None,
                "auth_type": auth_info["auth_type"] if auth_info else None,
                "signature_algorithm": None,
                "signature_hash_algorithm": None,
                "data": auth_info["data"] if auth_info else None,
            },
            "certificate": {
                "present": cert_info is not None,
                "encoding": cert_info["encoding"] if cert_info else None,
                "data": cert_info["data"] if cert_info else None,
            },
            "child_sa": {
                "present": len(parsed["proposals"]) > 0,
                "proposals": parsed["proposals"],
            },
            "traffic_selectors": {
                "initiator": parsed.get("tsi", []),
                "responder": parsed.get("tsr", []),
            },
        }
        overall_metadata["IKE_AUTH"] = ike_auth_metadata

    # ── Notify metadata ───────────────────────────────────────────────
    notify_messages = parsed.get("notify", [])
    if notify_messages:
        notify_metadata = {
            "present": True,
            "notify_types": [n.get("type") for n in notify_messages],
            "messages": notify_messages,
        }
        overall_metadata["notify"] = notify_metadata

    return overall_metadata


# ═══════════════════════════════════════════════════════════════════════════
#  IKEv1 METADATA EXTRACTOR — PyShark-based
# ═══════════════════════════════════════════════════════════════════════════

def extract_ikeV1_metadata(pkt):
    """Extract IKEv1 metadata from a PyShark packet.
    
    Output schema is identical to the original Scapy-based implementation.
    """
    if not hasattr(pkt, 'isakmp'):
        return None

    ike = pkt.isakmp

    # Check it's IKEv1 (major version 1)
    try:
        major_ver = _safe_int(ike.mjver)
        if major_ver is not None and major_ver != 1:
            return None
    except AttributeError:
        pass

    # IPs
    src_ip = None
    dst_ip = None
    try:
        src_ip = str(pkt.ip.src)
        dst_ip = str(pkt.ip.dst)
    except AttributeError:
        try:
            src_ip = str(pkt.ipv6.src)
            dst_ip = str(pkt.ipv6.dst)
        except AttributeError:
            pass

    # Ports
    src_port = None
    dst_port = None
    try:
        src_port = _safe_int(pkt.udp.srcport)
        dst_port = _safe_int(pkt.udp.dstport)
    except AttributeError:
        pass

    # Cookies
    init_cookie = _colon_hex_to_hex_str(getattr(ike, 'ispi', None))
    resp_cookie = _colon_hex_to_hex_str(getattr(ike, 'rspi', None))

    # Exchange type
    exch_type_num = _safe_int(ike.exchangetype)
    exchange_type = ISAKMP_EXCHANGE_TYPES.get(
        exch_type_num, str(exch_type_num) if exch_type_num is not None else None
    )

    # Flags & is_response
    flags_int = _safe_int(getattr(ike, 'flags', '0x00'), 0)
    resp_cookie_bytes = _colon_hex_to_bytes(getattr(ike, 'rspi', None))
    if not resp_cookie_bytes or resp_cookie_bytes == b"\x00" * 8:
        is_response = False
    else:
        is_response = bool(flags_int & 0x20)

    # Message ID
    message_id = _safe_int(getattr(ike, 'messageid', None))

    # Timestamp
    try:
        timestamp = float(pkt.sniff_timestamp)
    except (AttributeError, ValueError, TypeError):
        timestamp = 0.0

    overall_metadata = {}

    common_metadata = {
        "plane": "control",
        "ike_version": 1,
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "initiator_cookie": init_cookie,
        "responder_cookie": resp_cookie,
        "exchange_type": exchange_type,
        "exchange_type_id": exch_type_num,
        "is_response": is_response,
        "message_id": message_id,
    }

    overall_metadata["common"] = common_metadata

    # ── Exchange-specific metadata skeletons ──────────────────────────

    main_mode_metadata = {
        "exchange": "MAIN_MODE",
        "security_association": {"present": False, "proposals": []},
        "key_exchange": {"present": False, "group": None, "value": None},
        "nonce": {"present": False, "value": None},
        "identification": {"present": False, "type": None, "data": None},
        "authentication": {"present": False, "method": None, "data": None},
        "certificate": {"present": False, "encoding": None, "data": None},
    }

    aggressive_mode_metadata = {
        "exchange": "AGGRESSIVE_MODE",
        "security_association": {"present": False, "proposals": []},
        "key_exchange": {"present": False, "group": None, "value": None},
        "nonce": {"present": False, "value": None},
        "identification": {"present": False, "type": None, "data": None},
        "authentication": {"present": False, "method": None, "data": None},
        "certificate": {"present": False, "encoding": None, "data": None},
    }

    quick_mode_metadata = {
        "exchange": "QUICK_MODE",
        "security_association": {"present": False, "proposals": []},
        "nonce": {"present": False, "value": None},
        "key_exchange": {"present": False, "group": None, "value": None},
        "traffic_selectors": {"initiator": [], "responder": []},
    }

    informational_metadata = {
        "exchange": "INFORMATIONAL",
        "delete": [],
        "notify": [],
    }

    new_group_mode_metadata = {
        "exchange": "NEW_GROUP_MODE",
        "security_association": {"present": False, "proposals": []},
        "key_exchange": {"present": False, "group": None, "value": None},
        "nonce": {"present": False, "value": None},
    }

    notify_metadata = {
        "present": False,
        "notify_types": [],
        "messages": [],
    }

    if exchange_type == "Main Mode":
        active = main_mode_metadata
    elif exchange_type == "Aggressive Mode":
        active = aggressive_mode_metadata
    elif exchange_type == "Quick Mode":
        active = quick_mode_metadata
    elif exchange_type == "Informational":
        active = informational_metadata
    elif exchange_type == "New Group Mode":
        active = new_group_mode_metadata
    else:
        fallback_name = str(exchange_type).upper().replace(" ", "_") if exchange_type else "UNKNOWN"
        active = {
            "exchange": fallback_name,
            "security_association": {"present": False, "proposals": []},
        }

    # ── Parse payloads from raw bytes ──────────────────────────────────
    raw_bytes = _pyshark_get_raw_udp_payload(pkt)
    if raw_bytes is None or len(raw_bytes) < 28:
        # Store exchange metadata and return
        _store_ikev1_exchange(overall_metadata, exchange_type, active,
                             main_mode_metadata, aggressive_mode_metadata,
                             quick_mode_metadata, informational_metadata,
                             new_group_mode_metadata, notify_metadata)
        return overall_metadata

    payloads = _parse_ikev1_payloads_from_raw(raw_bytes)

    for payload_type, payload_data, full_payload in payloads:
        if payload_type == 1:  # SA
            proposals = _parse_ikev1_sa_proposals(payload_data)
            if "security_association" in active:
                active["security_association"]["present"] = True
                active["security_association"]["proposals"].extend(proposals)

        elif payload_type == 4:  # KE
            ke_val = _format_hex_or_bytes(payload_data)
            if "key_exchange" in active:
                active["key_exchange"]["present"] = True
                active["key_exchange"]["value"] = ke_val

        elif payload_type == 10:  # Nonce
            nonce_val = _format_hex_or_bytes(payload_data)
            if "nonce" in active:
                active["nonce"]["present"] = True
                active["nonce"]["value"] = nonce_val

        elif payload_type == 5:  # ID
            id_type_name, formatted_data, ts_details = _parse_ikev1_identification(payload_data)
            if "traffic_selectors" in active:
                if len(active["traffic_selectors"]["initiator"]) == 0:
                    active["traffic_selectors"]["initiator"].append(ts_details)
                else:
                    active["traffic_selectors"]["responder"].append(ts_details)
            elif "identification" in active:
                active["identification"]["present"] = True
                active["identification"]["type"] = id_type_name
                active["identification"]["data"] = formatted_data

        elif payload_type == 8:  # Hash
            hash_val = _format_hex_or_bytes(payload_data)
            if "authentication" in active:
                active["authentication"]["present"] = True
                active["authentication"]["method"] = "pre-shared key"
                active["authentication"]["data"] = hash_val

        elif payload_type == 9:  # Signature
            sig_val = _format_hex_or_bytes(payload_data)
            if "authentication" in active:
                active["authentication"]["present"] = True
                active["authentication"]["method"] = "signature"
                active["authentication"]["data"] = sig_val

        elif payload_type == 11:  # Notify
            if len(payload_data) >= 8:
                doi = struct.unpack("!I", payload_data[0:4])[0]
                proto_id = payload_data[4]
                spi_size = payload_data[5]
                notify_type = struct.unpack("!H", payload_data[6:8])[0]

                spi_start = 8
                spi_bytes = payload_data[spi_start : spi_start + spi_size] if spi_size > 0 else None
                spi_str = _format_hex_or_bytes(spi_bytes)

                data_start = spi_start + spi_size
                data_bytes = payload_data[data_start:] if data_start < len(payload_data) else None
                data_str = _format_hex_or_bytes(data_bytes)

                notify_metadata["present"] = True
                notify_metadata["notify_types"].append(notify_type)

                notify_entry = {
                    "type": notify_type,
                    "type_name": _get_ikev1_notify_name(notify_type),
                    "protocol_id": proto_id,
                    "spi_size": spi_size,
                    "spi": spi_str,
                    "data": data_str,
                }
                notify_metadata["messages"].append(notify_entry)

                if "notify" in active and isinstance(active["notify"], list):
                    active["notify"].append(notify_entry)

        elif payload_type == 12:  # Delete
            if len(payload_data) >= 8:
                doi = struct.unpack("!I", payload_data[0:4])[0]
                proto_id = payload_data[4]
                spi_size = payload_data[5]
                spi_count = struct.unpack("!H", payload_data[6:8])[0]

                spis_list = []
                spi_offset = 8
                for _ in range(spi_count):
                    if spi_offset + spi_size <= len(payload_data):
                        spi_bytes = payload_data[spi_offset : spi_offset + spi_size]
                        spis_list.append(_format_hex_or_bytes(spi_bytes))
                        spi_offset += spi_size

                delete_entry = {
                    "protocol_id": proto_id,
                    "spi_size": spi_size,
                    "spi_count": spi_count,
                    "spis": spis_list,
                }
                if "delete" in active and isinstance(active["delete"], list):
                    active["delete"].append(delete_entry)

        elif payload_type == 6:  # Certificate
            if len(payload_data) >= 1:
                cert_encoding = payload_data[0]
                cert_encoding_name = IKEV1_CERTIFICATE_ENCODINGS.get(cert_encoding, cert_encoding)
                cert_data = _format_hex_or_bytes(payload_data[1:]) if len(payload_data) > 1 else None

                if "certificate" in active:
                    active["certificate"]["present"] = True
                    active["certificate"]["encoding"] = cert_encoding_name
                    active["certificate"]["data"] = cert_data

    # ── Store results ─────────────────────────────────────────────────
    _store_ikev1_exchange(overall_metadata, exchange_type, active,
                         main_mode_metadata, aggressive_mode_metadata,
                         quick_mode_metadata, informational_metadata,
                         new_group_mode_metadata, notify_metadata)

    return overall_metadata


def _store_ikev1_exchange(overall_metadata, exchange_type, active,
                          main_mode, aggressive_mode, quick_mode,
                          informational, new_group_mode, notify_metadata):
    """Store IKEv1 exchange-specific metadata in overall_metadata."""
    if exchange_type == "Main Mode":
        overall_metadata["MAIN_MODE"] = main_mode
    elif exchange_type == "Aggressive Mode":
        overall_metadata["AGGRESSIVE_MODE"] = aggressive_mode
    elif exchange_type == "Quick Mode":
        overall_metadata["QUICK_MODE"] = quick_mode
    elif exchange_type == "Informational":
        overall_metadata["INFORMATIONAL"] = informational
    elif exchange_type == "New Group Mode":
        overall_metadata["NEW_GROUP_MODE"] = new_group_mode
    else:
        fallback_key = str(exchange_type).upper().replace(" ", "_") if exchange_type else "UNKNOWN"
        overall_metadata[fallback_key] = active

    if notify_metadata["present"]:
        overall_metadata["notify"] = notify_metadata


# ═══════════════════════════════════════════════════════════════════════════
#  ESP METADATA EXTRACTOR — Scapy-based (UNCHANGED)
# ═══════════════════════════════════════════════════════════════════════════

def extract_esp_metadata(pkt):
    src_ip = pkt[IP].src if pkt.haslayer(IP) else (pkt[IPv6].src if pkt.haslayer(IPv6) else None)
    dst_ip = pkt[IP].dst if pkt.haslayer(IP) else (pkt[IPv6].dst if pkt.haslayer(IPv6) else None)

    if not src_ip or not dst_ip:
        return None

    spi = None
    seq_num = None

    # Case A: Native ESP (IP Protocol 50)
    if (pkt.haslayer(IP) and pkt[IP].proto == 50) or (pkt.haslayer(IPv6) and pkt[IPv6].nh == 50):
        layer_payload = bytes(pkt[IP].payload) if pkt.haslayer(IP) else bytes(pkt[IPv6].payload)
        if len(layer_payload) >= 8:
            # First 4 bytes: SPI | Next 4 bytes: Sequence Number
            spi = int.from_bytes(layer_payload[0:4], byteorder="big")
            seq_num = int.from_bytes(layer_payload[4:8], byteorder="big")

    # Case B: NAT-T Encapsulated ESP (UDP 4500)
    elif pkt.haslayer(UDP) and (pkt[UDP].sport == 4500 or pkt[UDP].dport == 4500):
        if pkt.haslayer(Raw):
            raw_data = pkt[Raw].load
            # If the first 4 bytes are NOT all zeroes, it's ESP data (not IKE)
            if len(raw_data) >= 8 and raw_data[0:4] != b'\x00\x00\x00\x00':
                spi = int.from_bytes(raw_data[0:4], byteorder="big")
                seq_num = int.from_bytes(raw_data[4:8], byteorder="big")

    if spi is None:
        return None

    return {
        "plane": "data",
        "timestamp": float(pkt.time),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "spi": hex(spi),
        "seq_num": seq_num,
        "wire_bytes": len(pkt)
    }

""" Each certificate blueprint is diff so its possible to not get signature algo and signature hash from it for all types look on to it"""