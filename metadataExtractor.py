from scapy.all import IP, IPv6, UDP, Raw
from scapy.contrib.ikev2 import (
    IKEv2,
    IKEv2_SA,
    IKEv2_Proposal,
    IKEv2_Transform,
    IKEv2_Notify,
    IKEv2_CERT,
    IKEv2_AUTH,
    IKEv2_TSi,
    IKEv2_TSr, 
)
from scapy.layers.isakmp import (
    ISAKMP,
    ISAKMP_payload,
    ISAKMP_payload_SA,
    ISAKMP_payload_Proposal,
    ISAKMP_payload_Transform,
    ISAKMP_payload_KE,
    ISAKMP_payload_ID,
    ISAKMP_payload_Hash,
    ISAKMP_payload_SIG,
    ISAKMP_payload_Nonce,
    ISAKMP_payload_Notify,
    ISAKMP_payload_Delete,
    ISAKMP_payload_VendorID,
)
from ikeV1IDs import (
    ISAKMP_IDENTIFICATION_TYPES,
    IKEV1_CERTIFICATE_ENCODINGS,
    IKEV1_NOTIFY_ERROR_TYPES,
    IKEV1_NOTIFY_STATUS_TYPES,
    ISAKMP_NOTIFY_STATUS_TYPES,
)
import socket


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


def _parse_ikev1_identification(id_payload):
    if id_payload is None:
        return None, None, {}

    id_type = getattr(id_payload, "IDtype", None)
    id_type_name = ISAKMP_IDENTIFICATION_TYPES.get(id_type, str(id_type) if id_type is not None else None)
    raw_data = getattr(id_payload, "IdentData", None)
    proto_id = getattr(id_payload, "ProtoID", None)
    port = getattr(id_payload, "Port", None)

    formatted_data = None
    addr_info = {}

    if isinstance(raw_data, bytes):
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
    elif isinstance(raw_data, str):
        formatted_data = raw_data
        if id_type == 1:
            addr_info["start_address"] = formatted_data
            addr_info["end_address"] = formatted_data
    elif raw_data is not None:
        formatted_data = str(raw_data)

    details = {
        "type": id_type_name,
        "ip_protocol": proto_id,
        "port": port,
        "data": formatted_data,
    }
    details.update(addr_info)
    return id_type_name, formatted_data, details


def extract_ikeV2_metadata(pkt):
    """ check tsi and tsr problem later"""
    if not pkt.haslayer(IKEv2):
        return None

    ike = pkt[IKEv2]
    exchangeType = getattr(ike, "exch_type", None)

    if exchangeType is None:
        exchangeType = getattr(ike, "exchange_type", None)

    has_udp = pkt.haslayer(UDP)
    overall_metadata = {
        "exchange_type": exchangeType
    }

    common_metadata = {
        "plane": "control",
        "timestamp": float(pkt.time),

        "src_ip": pkt[IP].src if pkt.haslayer(IP) else pkt[IPv6].src,
        "dst_ip": pkt[IP].dst if pkt.haslayer(IP) else pkt[IPv6].dst,

        "src_port": pkt[UDP].sport if pkt.haslayer(UDP) else None,
        "dst_port": pkt[UDP].dport if pkt.haslayer(UDP) else None,

        "initiator_spi": _format_hex_or_bytes(getattr(ike, "init_SPI", None)),
        "responder_spi": _format_hex_or_bytes(getattr(ike, "resp_SPI", None)),

        "exchange_type": exchangeType,
        "is_response": bool(getattr(ike, "flags", 0) & 0x20),
        "message_id": getattr(ike, "id", None),
    }

    ike_sa_init_metadata = {
        "exchange": "IKE_SA_INIT",
        "proposals": [],
    }

    ike_auth_metadata = {
        "exchange": "IKE_AUTH",

        "authentication": {
            "present": False,
            "auth_type": None,
            "signature_algorithm": None,
            "signature_hash_algorithm": None,
            "data": None
        },

        "certificate": {
            "present": False,
            "encoding": None,
            "data": None,
        },

        "child_sa": {
            "present": False,
            "proposals": [],
        },

        "traffic_selectors": {
            "initiator": [],
            "responder": [],
        },
    }

    informational_metadata = {
        "exchange": "INFORMATIONAL",
        "delete": [],
        "configuration": [],
    }

    notify_metadata = {
        "present": False,
        "notify_types": [],
        "messages": []
    }

    overall_metadata["common"] = common_metadata

    payload = ike.payload
    while payload:
        if isinstance(payload, IKEv2_Notify):
            notify_metadata["notify_types"].append(payload.type)

            notify_metadata["present"] = True

            notify_data = getattr(payload, "notify", None)
            notify_metadata["messages"].append({
                "type": getattr(payload, "type", None),
                "protocol_id": getattr(payload, "proto", None),
                "spi_size": getattr(payload, "SPIsize", getattr(payload, "spi_size", None)),
                "spi": _format_hex_or_bytes(getattr(payload, "SPI", getattr(payload, "spi", None))),
                "data": _format_hex_or_bytes(notify_data) if notify_data else None,
            })
        
        elif isinstance(payload, IKEv2_AUTH):

            ike_auth_metadata["authentication"]["present"] = True

            ike_auth_metadata["authentication"]["auth_type"] = getattr(
                payload,
                "auth_type",
                getattr(payload, "auth_method", getattr(payload, "method", None))
            )
            raw_auth_load = getattr(payload, "load", None)
            ike_auth_metadata["authentication"]["data"] = _format_hex_or_bytes(raw_auth_load)

            ike_auth_metadata["authentication"]["signature_algorithm"] = None

            ike_auth_metadata["authentication"]["signature_hash_algorithm"] = None

        elif isinstance(payload, IKEv2_CERT):
            certificate = ike_auth_metadata["certificate"]

            certificate["present"] = True
            certificate["encoding"] = getattr(
                payload,
                "cert_encoding",
                getattr(payload, "encoding", None),
            )
            certificate["data"] = _format_hex_or_bytes(getattr(
                payload,
                "cert_data",
                getattr(payload, "data", None),
            ))



        elif isinstance(payload, IKEv2_SA):
            prop = getattr(payload, "prop", None)
            while prop and isinstance(prop, IKEv2_Proposal):
                proposal_dict = {
                    "proposal_num": prop.proposal,
                    "protocol_id": prop.proto,
                    "spi": getattr(prop, "spi", None) if exchangeType == "IKE_AUTH" else None,
                   "transforms": {
                        "encryption": [],
                        "prf": [],
                        "integrity": [],
                        "dh_group": [],
                        "extended_sequence_numbers": [],
                        "additional_key_exchange_1": [],
                        "additional_key_exchange_2": [],
                        "additional_key_exchange_3": [],
                        "additional_key_exchange_4": [],
                        "additional_key_exchange_5": [],
                        "additional_key_exchange_6": [],
                        "additional_key_exchange_7": [],
                        "key_wrap": [],
                        "group_controller_authentication": []
                    }

                }
                
                trans = getattr(prop, "trans", None)

                
                
                while trans and isinstance(trans, IKEv2_Transform):
                    t_type_name = TRANSFORM_TYPE_MAP_IKEV2.get(trans.transform_type)

                    if t_type_name:
                        proposal_dict["transforms"][t_type_name].append({
                            "id": trans.transform_id,
                            "length": getattr(trans, "key_length", None)
                        })

                    trans = getattr(trans, "payload", None)

                if exchangeType in (34, "IKE_SA_INIT"):
                    ike_sa_init_metadata["proposals"].append(proposal_dict)

                elif exchangeType in (35, "IKE_AUTH"):
                    ike_auth_metadata["child_sa"]["present"] = True
                    ike_auth_metadata["child_sa"]["proposals"].append(proposal_dict)


                prop = getattr(prop, "payload", None)
        

        elif exchangeType in (35, "IKE_AUTH") and isinstance(payload, IKEv2_TSi):
            ts = payload

            while ts and isinstance(ts, IKEv2_TSi):
                ike_auth_metadata["traffic_selectors"]["initiator"].append({
                    "type": getattr(ts, "ts_type", None),
                    "ip_protocol": getattr(ts, "ip_proto", None),
                    "start_port": getattr(ts, "startport", None),
                    "end_port": getattr(ts, "endport", None),
                    "start_address": getattr(ts, "startaddr", None),
                    "end_address": getattr(ts, "endaddr", None),
                })

                ts = getattr(ts, "payload", None)

        elif exchangeType in (35, "IKE_AUTH") and isinstance(payload, IKEv2_TSr):
            ts = payload

            while ts and isinstance(ts, IKEv2_TSr):
                ike_auth_metadata["traffic_selectors"]["responder"].append({
                    "type": getattr(ts, "ts_type", None),
                    "ip_protocol": getattr(ts, "ip_proto", None),
                    "start_port": getattr(ts, "startport", None),
                    "end_port": getattr(ts, "endport", None),
                    "start_address": getattr(ts, "startaddr", None),
                    "end_address": getattr(ts, "endaddr", None),
                })

                ts = getattr(ts, "payload", None)

        payload = getattr(payload, "payload", None)
    
    if exchangeType in (34, "IKE_SA_INIT"):
        overall_metadata["IKE_SA_INIT"] = ike_sa_init_metadata

    elif exchangeType in (35, "IKE_AUTH"):
        overall_metadata["IKE_AUTH"] = ike_auth_metadata

    if notify_metadata["present"]:
        overall_metadata["notify"] = notify_metadata
        
    return overall_metadata


def extract_ikeV1_metadata(pkt):
    if not pkt.haslayer(ISAKMP):
        return None

    ike = pkt[ISAKMP]

    src_ip = pkt[IP].src if pkt.haslayer(IP) else (pkt[IPv6].src if pkt.haslayer(IPv6) else None)
    dst_ip = pkt[IP].dst if pkt.haslayer(IP) else (pkt[IPv6].dst if pkt.haslayer(IPv6) else None)

    has_udp = pkt.haslayer(UDP)
    src_port = pkt[UDP].sport if has_udp else None
    dst_port = pkt[UDP].dport if has_udp else None

    raw_init_cookie = getattr(ike, "init_cookie", None)
    raw_resp_cookie = getattr(ike, "resp_cookie", None)

    init_cookie = _format_hex_or_bytes(raw_init_cookie)
    resp_cookie = _format_hex_or_bytes(raw_resp_cookie)

    exch_type_num = getattr(ike, "exch_type", None)
    exchange_type = ISAKMP_EXCHANGE_TYPES.get(exch_type_num, str(exch_type_num) if exch_type_num is not None else None)

    flags = getattr(ike, "flags", 0)
    flags_int = int(flags) if flags is not None else 0
    # In IKEv1, if responder cookie is zero/empty, this is an initial request (not a response).
    # Standard IKEv1 ISAKMP header flags do not have an R-bit, but 0x20 is used in some test/vendor setups.
    if not raw_resp_cookie or raw_resp_cookie == b"\x00" * 8:
        is_response = False
    else:
        is_response = bool(flags_int & 0x20)

    message_id = getattr(ike, "id", None)

    overall_metadata = {}

    common_metadata = {
        "plane": "control",
        "ike_version": 1,
        "timestamp": float(pkt.time),

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

    main_mode_metadata = {
        "exchange": "MAIN_MODE",
        "security_association": {
            "present": False,
            "proposals": [],
        },
        "key_exchange": {
            "present": False,
            "group": None,
            "value": None,
        },
        "nonce": {
            "present": False,
            "value": None,
        },
        "identification": {
            "present": False,
            "type": None,
            "data": None,
        },
        "authentication": {
            "present": False,
            "method": None,
            "data": None,
        },
        "certificate": {
            "present": False,
            "encoding": None,
            "data": None,
        },
    }

    aggressive_mode_metadata = {
        "exchange": "AGGRESSIVE_MODE",
        "security_association": {
            "present": False,
            "proposals": [],
        },
        "key_exchange": {
            "present": False,
            "group": None,
            "value": None,
        },
        "nonce": {
            "present": False,
            "value": None,
        },
        "identification": {
            "present": False,
            "type": None,
            "data": None,
        },
        "authentication": {
            "present": False,
            "method": None,
            "data": None,
        },
        "certificate": {
            "present": False,
            "encoding": None,
            "data": None,
        },
    }

    quick_mode_metadata = {
        "exchange": "QUICK_MODE",
        "security_association": {
            "present": False,
            "proposals": [],
        },
        "nonce": {
            "present": False,
            "value": None,
        },
        "key_exchange": {
            "present": False,
            "group": None,
            "value": None,
        },
        "traffic_selectors": {
            "initiator": [],
            "responder": [],
        },
    }

    informational_metadata = {
        "exchange": "INFORMATIONAL",
        "delete": [],
        "notify": [],
    }

    new_group_mode_metadata = {
        "exchange": "NEW_GROUP_MODE",
        "security_association": {
            "present": False,
            "proposals": [],
        },
        "key_exchange": {
            "present": False,
            "group": None,
            "value": None,
        },
        "nonce": {
            "present": False,
            "value": None,
        },
    }

    notify_metadata = {
        "present": False,
        "notify_types": [],
        "messages": [],
    }

    overall_metadata["common"] = common_metadata

    if exchange_type == "Main Mode":
        active_exchange_metadata = main_mode_metadata
    elif exchange_type == "Aggressive Mode":
        active_exchange_metadata = aggressive_mode_metadata
    elif exchange_type == "Quick Mode":
        active_exchange_metadata = quick_mode_metadata
    elif exchange_type == "Informational":
        active_exchange_metadata = informational_metadata
    elif exchange_type == "New Group Mode":
        active_exchange_metadata = new_group_mode_metadata
    else:
        fallback_exchange_name = str(exchange_type).upper().replace(" ", "_") if exchange_type else "UNKNOWN"
        active_exchange_metadata = {
            "exchange": fallback_exchange_name,
            "security_association": {
                "present": False,
                "proposals": [],
            },
        }

    payload = ike.payload
    current_np = getattr(ike, "next_payload", None)

    while payload:
        next_np = getattr(payload, "next_payload", None)

        if isinstance(payload, ISAKMP_payload_SA):
            prop = getattr(payload, "prop", None)
            while prop and isinstance(prop, ISAKMP_payload_Proposal):
                raw_spi = getattr(prop, "spi", getattr(prop, "SPI", None))
                spi_val = _format_hex_or_bytes(raw_spi)

                proposal_dict = {
                    "proposal_num": getattr(prop, "proposal", None),
                    "protocol_id": getattr(prop, "proto", None),
                    "spi": spi_val,
                    "transforms": {
                        "encryption": [],
                        "hash": [],
                        "auth_method": [],
                        "group_description": [],
                        "group_type": [],
                        "life_type": [],
                        "life_duration": [],
                        "prf": [],
                        "encapsulation_mode": [],
                        "key_length": [],
                    }
                }

                transformer = getattr(prop, "trans", None)
                while transformer and isinstance(transformer, ISAKMP_payload_Transform):
                    raw_attributes = getattr(transformer, "transforms", [])
                    for attr_key, attr_val in raw_attributes:
                        attr_name = IKEV1_ATTR_TYPES.get(attr_key)
                        if not attr_name:
                            norm_key = str(attr_key).lower().replace(" ", "_")
                            attr_name = IKEV1_ATTR_NAME_NORMALIZE.get(norm_key, norm_key)

                        if attr_name not in proposal_dict["transforms"]:
                            proposal_dict["transforms"][attr_name] = []

                        proposal_dict["transforms"][attr_name].append({
                            "value": attr_val
                        })

                    transformer = getattr(transformer, "payload", None)

                if "security_association" in active_exchange_metadata:
                    active_exchange_metadata["security_association"]["present"] = True
                    active_exchange_metadata["security_association"]["proposals"].append(proposal_dict)

                prop = getattr(prop, "payload", None)

        elif isinstance(payload, ISAKMP_payload_KE):
            ke_val = _format_hex_or_bytes(getattr(payload, "ke", None))
            if "key_exchange" in active_exchange_metadata:
                active_exchange_metadata["key_exchange"]["present"] = True
                active_exchange_metadata["key_exchange"]["value"] = ke_val

        elif isinstance(payload, ISAKMP_payload_Nonce):
            nonce_val = _format_hex_or_bytes(getattr(payload, "nonce", None))
            if "nonce" in active_exchange_metadata:
                active_exchange_metadata["nonce"]["present"] = True
                active_exchange_metadata["nonce"]["value"] = nonce_val

        elif isinstance(payload, ISAKMP_payload_ID):
            id_type_name, formatted_data, ts_details = _parse_ikev1_identification(payload)
            if "traffic_selectors" in active_exchange_metadata:
                # In Quick Mode: First ID is initiator client ID (IDci), second is responder client ID (IDcr)
                if len(active_exchange_metadata["traffic_selectors"]["initiator"]) == 0:
                    active_exchange_metadata["traffic_selectors"]["initiator"].append(ts_details)
                else:
                    active_exchange_metadata["traffic_selectors"]["responder"].append(ts_details)
            elif "identification" in active_exchange_metadata:
                active_exchange_metadata["identification"]["present"] = True
                active_exchange_metadata["identification"]["type"] = id_type_name
                active_exchange_metadata["identification"]["data"] = formatted_data

        elif isinstance(payload, ISAKMP_payload_Hash):
            hash_val = _format_hex_or_bytes(getattr(payload, "hash", None))
            if "authentication" in active_exchange_metadata:
                active_exchange_metadata["authentication"]["present"] = True
                active_exchange_metadata["authentication"]["method"] = "pre-shared key"
                active_exchange_metadata["authentication"]["data"] = hash_val

        elif isinstance(payload, ISAKMP_payload_SIG):
            sig_val = _format_hex_or_bytes(getattr(payload, "sig", None))
            if "authentication" in active_exchange_metadata:
                active_exchange_metadata["authentication"]["present"] = True
                active_exchange_metadata["authentication"]["method"] = "signature"
                active_exchange_metadata["authentication"]["data"] = sig_val

        elif isinstance(payload, ISAKMP_payload_Notify):
            notify_type = getattr(payload, "notify_msg_type", None)
            notify_metadata["present"] = True
            notify_metadata["notify_types"].append(notify_type)

            spi_str = _format_hex_or_bytes(getattr(payload, "SPI", None))
            data_str = _format_hex_or_bytes(getattr(payload, "notify_data", None))

            notify_entry = {
                "type": notify_type,
                "type_name": _get_ikev1_notify_name(notify_type),
                "protocol_id": getattr(payload, "proto", None),
                "spi_size": getattr(payload, "SPIsize", None),
                "spi": spi_str,
                "data": data_str,
            }
            notify_metadata["messages"].append(notify_entry)

            if "notify" in active_exchange_metadata and isinstance(active_exchange_metadata["notify"], list):
                active_exchange_metadata["notify"].append(notify_entry)

        elif isinstance(payload, ISAKMP_payload_Delete):
            raw_spis = getattr(payload, "SPIs", [])
            spis_list = [_format_hex_or_bytes(s) for s in raw_spis] if raw_spis else []

            delete_entry = {
                "protocol_id": getattr(payload, "proto", None),
                "spi_size": getattr(payload, "SPIsize", None),
                "spi_count": getattr(payload, "SPIcount", None),
                "spis": spis_list,
            }
            if "delete" in active_exchange_metadata and isinstance(active_exchange_metadata["delete"], list):
                active_exchange_metadata["delete"].append(delete_entry)

        else:
            # Handle Certificate payload (Scapy parses type 6 as generic ISAKMP_payload or custom class)
            is_cert = (payload.__class__.__name__ == "ISAKMP_payload_CERT") or (
                isinstance(payload, ISAKMP_payload) and current_np == 6
            )
            if is_cert and "certificate" in active_exchange_metadata:
                load = getattr(payload, "load", b"")
                cert_encoding = getattr(payload, "cert_encoding", getattr(payload, "encoding", None))
                cert_data = getattr(payload, "cert_data", getattr(payload, "data", None))

                if cert_encoding is None and len(load) >= 1:
                    enc_num = load[0]
                    cert_encoding = IKEV1_CERTIFICATE_ENCODINGS.get(enc_num, enc_num)
                    cert_data = _format_hex_or_bytes(load[1:]) if len(load) > 1 else None
                else:
                    if isinstance(cert_encoding, int):
                        cert_encoding = IKEV1_CERTIFICATE_ENCODINGS.get(cert_encoding, cert_encoding)
                    cert_data = _format_hex_or_bytes(cert_data)

                active_exchange_metadata["certificate"]["present"] = True
                active_exchange_metadata["certificate"]["encoding"] = cert_encoding
                active_exchange_metadata["certificate"]["data"] = cert_data

        current_np = next_np
        payload = getattr(payload, "payload", None)

    if exchange_type == "Main Mode":
        overall_metadata["MAIN_MODE"] = main_mode_metadata
    elif exchange_type == "Aggressive Mode":
        overall_metadata["AGGRESSIVE_MODE"] = aggressive_mode_metadata
    elif exchange_type == "Quick Mode":
        overall_metadata["QUICK_MODE"] = quick_mode_metadata
    elif exchange_type == "Informational":
        overall_metadata["INFORMATIONAL"] = informational_metadata
    elif exchange_type == "New Group Mode":
        overall_metadata["NEW_GROUP_MODE"] = new_group_mode_metadata
    else:
        fallback_key = str(exchange_type).upper().replace(" ", "_") if exchange_type else "UNKNOWN"
        overall_metadata[fallback_key] = active_exchange_metadata

    if notify_metadata["present"]:
        overall_metadata["notify"] = notify_metadata

    return overall_metadata


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