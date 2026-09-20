import struct
import socket

# ─── Scapy: kept ONLY for ESP data-plane ──────────────────────────────────
from scapy.all import IP, IPv6, UDP, Raw

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


# ─── Utility helpers ──────────────────────────────────────────────────────

def _format_hex_or_bytes(val):
    if val is None:
        return None
    if isinstance(val, bytes):
        return f"0x{val.hex()}" if len(val) > 0 else None
    if isinstance(val, int):
        return hex(val)
    return str(val)


def _colon_hex_to_bytes(hex_str):
    """Convert PyShark colon-delimited hex 'ab:cd:ef' -> bytes b'\\xab\\xcd\\xef'."""
    if hex_str is None:
        return None
    return bytes.fromhex(str(hex_str).replace(":", ""))


def _colon_hex_to_hex_str(hex_str):
    """Convert 'ab:cd:ef' -> '0xabcdef'."""
    if hex_str is None:
        return None
    raw = str(hex_str).replace(":", "")
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
    
    Returns a dictionary of parsed payloads organized by type.
    """
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
    ke_info = None
    delete_list = []
    is_encrypted = False
    encrypted_next_payload = None

    while next_payload != 0 and offset < len(raw_bytes):
        if offset + 4 > len(raw_bytes):
            break

        np_next = raw_bytes[offset]
        payload_len = struct.unpack("!H", raw_bytes[offset + 2 : offset + 4])[0]
        if payload_len < 4:
            break
        payload_data = raw_bytes[offset + 4 : offset + payload_len]

        if next_payload == 33:  # SA
            proposals.extend(_parse_ikev2_sa_payload(payload_data, exchange_type))
        elif next_payload == 34:  # Key Exchange (KE)
            ke_info = _parse_ikev2_ke_payload(payload_data)
        elif next_payload == 37:  # CERT
            cert_info = _parse_ikev2_cert_payload(payload_data)
        elif next_payload == 39:  # AUTH
            auth_info = _parse_ikev2_auth_payload(payload_data)
        elif next_payload == 41:  # Notify
            notify_list.append(_parse_ikev2_notify_payload(payload_data))
        elif next_payload == 42:  # Delete
            del_item = _parse_ikev2_delete_payload(payload_data)
            if del_item:
                delete_list.append(del_item)
        elif next_payload == 44:  # TSi
            tsi_list.extend(_parse_ikev2_ts_payload(payload_data))
        elif next_payload == 45:  # TSr
            tsr_list.extend(_parse_ikev2_ts_payload(payload_data))
        elif next_payload == 46:  # Encrypted and Authenticated (SK)
            is_encrypted = True
            encrypted_next_payload = np_next
            # The remainder of the packet payload is encrypted ciphertext
            break

        next_payload = np_next
        offset += payload_len

    return {
        "proposals": proposals,
        "key_exchange": ke_info,
        "notify": notify_list,
        "delete": delete_list,
        "auth": auth_info,
        "cert": cert_info,
        "tsi": tsi_list,
        "tsr": tsr_list,
        "is_encrypted": is_encrypted,
        "encrypted_next_payload": encrypted_next_payload,
    }


def _parse_ikev2_ke_payload(data):
    """Parse Key Exchange payload (RFC 7296 Section 3.4)."""
    if len(data) < 4:
        return None
    group_id = struct.unpack("!H", data[0:2])[0]
    # data[2:4] is RESERVED (2 bytes)
    ke_data = data[4:]
    return {
        "group_id": group_id,
        "key_data_len": len(ke_data),
        "key_data": _format_hex_or_bytes(ke_data),
    }


def _parse_ikev2_delete_payload(data):
    """Parse Delete payload (RFC 7296 Section 3.11)."""
    if len(data) < 4:
        return None
    proto_id = data[0]
    spi_size = data[1]
    spi_count = struct.unpack("!H", data[2:4])[0]

    spis = []
    spi_offset = 4
    for _ in range(spi_count):
        if spi_offset + spi_size <= len(data):
            spi_bytes = data[spi_offset : spi_offset + spi_size]
            spis.append(_format_hex_or_bytes(spi_bytes))
            spi_offset += spi_size
        else:
            break

    return {
        "protocol_id": proto_id,
        "spi_size": spi_size,
        "spi_count": spi_count,
        "spis": spis,
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
            if proto_id in (2, 3) or exchange_type in (35, "IKE_AUTH"):
                spi_val = _format_hex_or_bytes(spi_bytes)
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
    """Parse CERT payload data (RFC 7296 Section 3.6)."""
    if len(data) < 1:
        return None
    encoding = data[0]
    cert_data = data[1:] if len(data) > 1 else None

    cert_key_type_oid = None
    cert_key_len = None
    cert_sig_algo_oid = None

    if encoding == 4 and cert_data:
        try:
            import cryptography.x509 as x509
            parsed_cert = x509.load_der_x509_certificate(cert_data)

            # Public key algorithm OID
            if hasattr(parsed_cert, "public_key_algorithm_oid"):
                cert_key_type_oid = str(parsed_cert.public_key_algorithm_oid.dotted_string)

            # Signature algorithm OID
            if hasattr(parsed_cert, "signature_algorithm_oid"):
                cert_sig_algo_oid = str(parsed_cert.signature_algorithm_oid.dotted_string)

            # Public key length in bits
            pub_key = parsed_cert.public_key()
            if hasattr(pub_key, "key_size"):
                cert_key_len = int(pub_key.key_size)
            elif hasattr(pub_key, "curve") and hasattr(pub_key.curve, "key_size"):
                cert_key_len = int(pub_key.curve.key_size)
            elif hasattr(pub_key, "public_bytes_raw"):
                cert_key_len = len(pub_key.public_bytes_raw()) * 8
        except Exception:
            cert_key_type_oid = None
            cert_key_len = None
            cert_sig_algo_oid = None

    return {
        "encoding": encoding,
        "data": _format_hex_or_bytes(cert_data),
        "cert_key_type_oid": cert_key_type_oid,
        "cert_key_len": cert_key_len,
        "cert_sig_algo_oid": cert_sig_algo_oid,
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
#  PYSHARK HELPER — read fields from a PyShark packet
# ═══════════════════════════════════════════════════════════════════════════

def _pyshark_get_raw_udp_payload(pkt):
    """Extract the raw UDP payload bytes from a PyShark packet.
    
    This is the IKE/ISAKMP data starting from the initiator SPI.
    """
    try:
        # PyShark exposes the UDP payload as hex in udp.payload
        raw_hex = str(pkt.udp.payload).replace(":", "")
        return bytes.fromhex(raw_hex)
    except (AttributeError, ValueError):
        return None


# ═══════════════════════════════════════════════════════════════════════════
#  IKEv2 METADATA EXTRACTOR — PyShark-based
# ═══════════════════════════════════════════════════════════════════════════

def extract_ikeV2_metadata(pkt):
    """Extract IKEv2 metadata from a PyShark packet."""
    if not hasattr(pkt, 'isakmp'):
        return None

    ike = pkt.isakmp

    # Check it's IKEv2 (major version 2)
    try:
        major_ver = _safe_int(ike.mjver)
        if major_ver is not None and major_ver != 2:
            return None
    except AttributeError:
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

    # ── Parse payloads from raw bytes ──────────────────────────────────
    raw_bytes = _pyshark_get_raw_udp_payload(pkt)
    parsed = _parse_ikev2_from_raw(raw_bytes, exchangeType) if (raw_bytes and len(raw_bytes) >= 28) else {}

    is_encrypted = parsed.get("is_encrypted", False)
    encrypted_next_payload = parsed.get("encrypted_next_payload")

    overall_metadata = {
        "exchange_type": exchangeType,
        "is_encrypted": is_encrypted,
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
        "is_encrypted": is_encrypted,
    }
    if encrypted_next_payload is not None:
        common_metadata["encrypted_next_payload"] = encrypted_next_payload

    overall_metadata["common"] = common_metadata

    if not parsed:
        return overall_metadata

    # ── Build exchange-specific metadata ──────────────────────────────
    if exchangeType in (34, "IKE_SA_INIT"):
        ike_sa_init_metadata = {
            "exchange": "IKE_SA_INIT",
            "proposals": parsed.get("proposals", []),
            "key_exchange": parsed.get("key_exchange"),
            "notify": parsed.get("notify", []),
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
                "cert_key_type_oid": cert_info.get("cert_key_type_oid") if cert_info else None,
                "cert_key_len": cert_info.get("cert_key_len") if cert_info else None,
                "cert_sig_algo_oid": cert_info.get("cert_sig_algo_oid") if cert_info else None,
            },
            "child_sa": {
                "present": len(parsed.get("proposals", [])) > 0,
                "proposals": parsed.get("proposals", []),
            },
            "traffic_selectors": {
                "initiator": parsed.get("tsi", []),
                "responder": parsed.get("tsr", []),
            },
        }
        overall_metadata["IKE_AUTH"] = ike_auth_metadata

    elif exchangeType in (36, "CREATE_CHILD_SA"):
        create_child_sa_metadata = {
            "exchange": "CREATE_CHILD_SA",
            "proposals": parsed.get("proposals", []),
            "key_exchange": parsed.get("key_exchange"),
            "traffic_selectors": {
                "initiator": parsed.get("tsi", []),
                "responder": parsed.get("tsr", []),
            },
            "notify": parsed.get("notify", []),
        }
        overall_metadata["CREATE_CHILD_SA"] = create_child_sa_metadata

    elif exchangeType in (37, "INFORMATIONAL"):
        informational_metadata = {
            "exchange": "INFORMATIONAL",
            "delete": parsed.get("delete", []),
            "notify": parsed.get("notify", []),
        }
        overall_metadata["INFORMATIONAL"] = informational_metadata

    elif exchangeType in (38, 43, "IKE_INTERMEDIATE"):
        ike_intermediate_metadata = {
            "exchange": "IKE_INTERMEDIATE",
            "proposals": parsed.get("proposals", []),
            "key_exchange": parsed.get("key_exchange"),
            "notify": parsed.get("notify", []),
        }
        overall_metadata["IKE_INTERMEDIATE"] = ike_intermediate_metadata

    else:
        fallback_name = str(exchangeType).upper().replace(" ", "_") if exchangeType else "UNKNOWN"
        overall_metadata[fallback_name] = {
            "exchange": fallback_name,
            "proposals": parsed.get("proposals", []),
            "key_exchange": parsed.get("key_exchange"),
            "delete": parsed.get("delete", []),
            "notify": parsed.get("notify", []),
        }

    # ── Notify metadata (top-level bucket) ────────────────────────────
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
#  IKEv1 STUB — (Removed as requested)
# ═══════════════════════════════════════════════════════════════════════════

def extract_ikeV1_metadata(pkt):
    """IKEv1 metadata extraction has been removed from this module."""
    raise NotImplementedError("IKEv1 extraction is currently removed from metadataExtractor.py")


# ═══════════════════════════════════════════════════════════════════════════
#  ESP METADATA EXTRACTOR — Scapy-based
# ═══════════════════════════════════════════════════════════════════════════

def extract_esp_metadata(pkt):
    """Extract ESP / NAT-T metadata from a Scapy packet."""
    src_ip = pkt[IP].src if pkt.haslayer(IP) else (pkt[IPv6].src if pkt.haslayer(IPv6) else None)
    dst_ip = pkt[IP].dst if pkt.haslayer(IP) else (pkt[IPv6].dst if pkt.haslayer(IPv6) else None)

    if not src_ip or not dst_ip:
        return None

    spi = None
    seq_num = None
    src_port = None
    dst_port = None
    is_natt = False

    # Case A: Native ESP (IP Protocol 50)
    if (pkt.haslayer(IP) and pkt[IP].proto == 50) or (pkt.haslayer(IPv6) and pkt[IPv6].nh == 50):
        layer_payload = bytes(pkt[IP].payload) if pkt.haslayer(IP) else bytes(pkt[IPv6].payload)
        if len(layer_payload) >= 8:
            # First 4 bytes: SPI | Next 4 bytes: Sequence Number
            spi = int.from_bytes(layer_payload[0:4], byteorder="big")
            seq_num = int.from_bytes(layer_payload[4:8], byteorder="big")
            src_port = None
            dst_port = None
            is_natt = False

    # Case B: NAT-T Encapsulated ESP (UDP 4500)
    elif pkt.haslayer(UDP) and (pkt[UDP].sport == 4500 or pkt[UDP].dport == 4500):
        if pkt.haslayer(Raw):
            raw_data = pkt[Raw].load
            # If the first 4 bytes are NOT all zeroes, it's ESP data (not IKE)
            if len(raw_data) >= 8 and raw_data[0:4] != b'\x00\x00\x00\x00':
                spi = int.from_bytes(raw_data[0:4], byteorder="big")
                seq_num = int.from_bytes(raw_data[4:8], byteorder="big")
                src_port = int(pkt[UDP].sport)
                dst_port = int(pkt[UDP].dport)
                is_natt = True

    if spi is None:
        return None

    return {
        "plane": "data",
        "timestamp": float(pkt.time),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "is_natt": is_natt,
        "spi": hex(spi),
        "seq_num": seq_num,
        "wire_bytes": len(pkt),
    }