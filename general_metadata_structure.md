# General Metadata Structure: IKEv1 & IKEv2 Extractor Schemas

This document defines the general dictionary structure, nesting hierarchy, and field data types returned by `extract_ikeV1_metadata(pkt)` and `extract_ikeV2_metadata(pkt)` in [`metadataExtractor.py`](file:///c:/Users/Cat/Desktop/SIH-160/metadataExtractor.py).

---

## 1. High-Level Architectural Tree

### IKEv1 Metadata Architecture
```
overall_metadata (dict)
├── common (dict)
│   ├── plane: "control"
│   ├── ike_version: 1
│   ├── timestamp: float
│   ├── src_ip: str | null
│   ├── dst_ip: str | null
│   ├── src_port: int | null
│   ├── dst_port: int | null
│   ├── initiator_cookie: str ("0x...") | null
│   ├── responder_cookie: str ("0x...") | null
│   ├── exchange_type: str ("Main Mode", "Quick Mode", etc.)
│   ├── exchange_type_id: int | null
│   ├── is_response: bool
│   └── message_id: int | null
│
├── MAIN_MODE / AGGRESSIVE_MODE (dict - depending on exchange)
│   ├── exchange: "MAIN_MODE" | "AGGRESSIVE_MODE"
│   ├── security_association (dict)
│   │   ├── present: bool
│   │   └── proposals: list[ProposalDict]
│   │       └── ProposalDict
│   │           ├── proposal_num: int
│   │           ├── protocol_id: int
│   │           ├── spi: str ("0x...") | null
│   │           └── transforms: dict[attr_name -> list[{"value": ...}]]
│   ├── key_exchange (dict)
│   │   ├── present: bool
│   │   ├── group: null
│   │   └── value: str ("0x...") | null
│   ├── nonce (dict)
│   │   ├── present: bool
│   │   └── value: str ("0x...") | null
│   ├── identification (dict)
│   │   ├── present: bool
│   │   ├── type: str | int | null
│   │   └── data: str | null
│   ├── authentication (dict)
│   │   ├── present: bool
│   │   ├── method: str ("pre-shared key", "signature") | null
│   │   └── data: str ("0x...") | null
│   └── certificate (dict)
│       ├── present: bool
│       ├── encoding: str | int | null
│       └── data: str ("0x...") | null
│
├── QUICK_MODE (dict - when exchange_type is "Quick Mode")
│   ├── exchange: "QUICK_MODE"
│   ├── security_association (dict)
│   │   ├── present: bool
│   │   └── proposals: list[ProposalDict]
│   ├── nonce (dict)
│   │   ├── present: bool
│   │   └── value: str ("0x...") | null
│   ├── key_exchange (dict)
│   │   ├── present: bool
│   │   ├── group: null
│   │   └── value: str ("0x...") | null
│   └── traffic_selectors (dict)
│       ├── initiator: list[SelectorDict]
│       └── responder: list[SelectorDict]
│           └── SelectorDict
│               ├── type: str | int | null
│               ├── ip_protocol: int | null
│               ├── port: int | null
│               ├── data: str | null
│               ├── start_address: str | null (optional)
│               └── end_address: str | null (optional)
│
├── INFORMATIONAL (dict - when exchange_type is "Informational")
│   ├── exchange: "INFORMATIONAL"
│   ├── delete: list[DeleteDict]
│   │   └── DeleteDict
│   │       ├── protocol_id: int | null
│   │       ├── spi_size: int | null
│   │       ├── spi_count: int | null
│   │       └── spis: list[str ("0x...")]
│   └── notify: list[NotifyDict]
│
└── notify (dict - present ONLY if notify payloads exist in packet)
    ├── present: bool
    ├── notify_types: list[int]
    └── messages: list[NotifyDict]
        └── NotifyDict
            ├── type: int | null
            ├── type_name: str | null
            ├── protocol_id: int | null
            ├── spi_size: int | null
            ├── spi: str ("0x...") | null
            └── data: str ("0x...") | null
```

---

### IKEv2 Metadata Architecture
```
overall_metadata (dict)
├── common (dict)
│   ├── plane: "control"
│   ├── timestamp: float
│   ├── src_ip: str | null
│   ├── dst_ip: str | null
│   ├── src_port: int | null
│   ├── dst_port: int | null
│   ├── initiator_spi: str ("0x...")
│   ├── responder_spi: str ("0x...")
│   ├── exchange_type: int | null
│   ├── is_response: bool
│   └── message_id: int | null
│
├── IKE_SA_INIT (dict - when exchange_type is "IKE_SA_INIT")
│   ├── exchange: "IKE_SA_INIT"
│   └── proposals: list[ProposalDict]
│       └── ProposalDict
│           ├── proposal_num: int
│           ├── protocol_id: int
│           ├── spi: null
│           └── transforms: dict[transform_type_name -> list[{"id": int, "length": int | null}]]
│               ├── encryption: list[TransformEntry]
│               ├── prf: list[TransformEntry]
│               ├── integrity: list[TransformEntry]
│               ├── dh_group: list[TransformEntry]
│               ├── extended_sequence_numbers: list[TransformEntry]
│               ├── additional_key_exchange_1: list[TransformEntry]
│               └── ... (additional_key_exchange_2..7, key_wrap, etc.)
│
├── IKE_AUTH (dict - when exchange_type is "IKE_AUTH")
│   ├── exchange: "IKE_AUTH"
│   ├── authentication (dict)
│   │   ├── present: bool
│   │   ├── auth_type: int | str | null
│   │   ├── signature_algorithm: null
│   │   └── signature_hash_algorithm: null
│   ├── certificate (dict)
│   │   ├── present: bool
│   │   ├── encoding: int | str | null
│   │   └── data: str ("0x...") | bytes | null
│   ├── child_sa (dict)
│   │   ├── present: bool
│   │   └── proposals: list[ProposalDict]
│   │       └── ProposalDict (spi: str ("0x..."))
│   └── traffic_selectors (dict)
│       ├── initiator: list[TSDict]
│       └── responder: list[TSDict]
│           └── TSDict
│               ├── type: int | null
│               ├── ip_protocol: int | null
│               ├── start_port: int | null
│               ├── end_port: int | null
│               ├── start_address: str | null
│               └── end_address: str | null
│
├── INFORMATIONAL (dict - when exchange_type is "INFORMATIONAL")
│   ├── exchange: "INFORMATIONAL"
│   ├── delete: list
│   └── configuration: list
│
└── notify (dict - present ONLY if notify payloads exist in packet)
    ├── present: bool
    ├── notify_types: list[int]
    └── messages: list[NotifyDict]
        └── NotifyDict
            ├── type: int | null
            ├── protocol_id: int | null
            ├── spi_size: int | null
            └── spi: str | bytes | null
```

---

## 2. General Schema Skeletons

### 2.1 Complete IKEv1 Schema Skeleton

```python
{
    "common": {
        "plane": "control",                   # str: always "control"
        "ike_version": 1,                     # int: always 1
        "timestamp": float,                   # float: epoch time in seconds
        "src_ip": str,                        # str: source IPv4 or IPv6 address
        "dst_ip": str,                        # str: destination IPv4 or IPv6 address
        "src_port": int | None,               # int or null: source UDP port
        "dst_port": int | None,               # int or null: destination UDP port
        "initiator_cookie": str | None,       # str: "0x..." 8-byte hex string
        "responder_cookie": str | None,       # str: "0x..." 8-byte hex string (or 0x0000000000000000)
        "exchange_type": str,                 # str: "Main Mode", "Aggressive Mode", "Quick Mode", etc.
        "exchange_type_id": int | None,       # int: raw numeric exchange type (e.g. 2, 4, 32, 5)
        "is_response": bool,                  # bool: false if initial request, or derived from flags
        "message_id": int | None,             # int: ISAKMP message ID (0 for Phase 1, non-zero for Phase 2)
    },

    # --- Exactly ONE of the following exchange keys is included per packet ---

    # Case A: Main Mode or Aggressive Mode
    "MAIN_MODE": {                            # or "AGGRESSIVE_MODE"
        "exchange": str,                      # "MAIN_MODE" or "AGGRESSIVE_MODE"
        "security_association": {
            "present": bool,                  # True if SA payload was present in this packet
            "proposals": [
                {
                    "proposal_num": int,      # 1-indexed proposal number
                    "protocol_id": int,       # 1 for ISAKMP, 3 for IPsec ESP, etc.
                    "spi": str | None,        # SPI hex string (usually null for Phase 1)
                    "transforms": {
                        "encryption": [{"value": str | int}],
                        "hash": [{"value": str | int}],
                        "auth_method": [{"value": str | int}],
                        "group_description": [{"value": str | int}],
                        "group_type": [{"value": str | int}],
                        "life_type": [{"value": str | int}],
                        "life_duration": [{"value": int}],
                        "prf": [{"value": str | int}],
                        "encapsulation_mode": [{"value": str | int}],
                        "key_length": [{"value": int}],
                        # Any additional/vendor attribute types preserved here:
                        # "<attr_name>": [{"value": ...}]
                    }
                }
            ]
        },
        "key_exchange": {
            "present": bool,                  # True if KE payload was present
            "group": None,                    # Group is negotiated in SA transforms, not in wire KE header
            "value": str | None               # "0x..." hex-encoded DH public value
        },
        "nonce": {
            "present": bool,                  # True if Nonce payload was present
            "value": str | None               # "0x..." hex-encoded nonce bytes
        },
        "identification": {
            "present": bool,                  # True if ID payload was present
            "type": str | int | None,         # "ID_IPV4_ADDR", "ID_FQDN", "ID_USER_FQDN", etc.
            "data": str | None                # Human-readable IP, subnet, FQDN, or "0x..." hex
        },
        "authentication": {
            "present": bool,                  # True if Hash or Signature payload was present
            "method": str | None,             # "pre-shared key" or "signature"
            "data": str | None                # "0x..." hex-encoded hash or signature bytes
        },
        "certificate": {
            "present": bool,                  # True if Certificate payload was present
            "encoding": str | int | None,     # "X.509 Certificate - Signature", "None", etc.
            "data": str | None                # "0x..." hex-encoded certificate DER bytes
        }
    },

    # Case B: Quick Mode (Phase 2)
    "QUICK_MODE": {
        "exchange": "QUICK_MODE",
        "security_association": {
            "present": bool,
            "proposals": [
                {
                    "proposal_num": int,
                    "protocol_id": int,       # 3 (IPSEC_ESP) or 2 (IPSEC_AH)
                    "spi": str | None,        # "0x..." 4-byte SPI allocated for the Child SA
                    "transforms": {
                        "encapsulation_mode": [{"value": str | int}], # "Tunnel" or "Transport"
                        "hash": [{"value": str | int}],               # "HMAC-SHA", "HMAC-MD5", etc.
                        "life_type": [{"value": str | int}],
                        "life_duration": [{"value": int}],
                        # ... other transform attributes
                    }
                }
            ]
        },
        "nonce": {
            "present": bool,
            "value": str | None
        },
        "key_exchange": {
            "present": bool,                  # True if PFS (Perfect Forward Secrecy) KE payload included
            "group": None,
            "value": str | None
        },
        "traffic_selectors": {
            "initiator": [                    # Derived from client initiator ID (IDci)
                {
                    "type": str | None,       # "ID_IPV4_ADDR_SUBNET", "ID_IPV4_ADDR", etc.
                    "ip_protocol": int,       # IP protocol (0=any, 6=TCP, 17=UDP)
                    "port": int,              # Port (0=any)
                    "data": str,              # e.g. "192.168.10.0/255.255.255.0"
                    "start_address": str,     # e.g. "192.168.10.0"
                    "end_address": str        # e.g. "255.255.255.0" (subnet mask)
                }
            ],
            "responder": [                    # Derived from client responder ID (IDcr)
                {
                    "type": str | None,
                    "ip_protocol": int,
                    "port": int,
                    "data": str,
                    "start_address": str,
                    "end_address": str
                }
            ]
        }
    },

    # Case C: Informational
    "INFORMATIONAL": {
        "exchange": "INFORMATIONAL",
        "delete": [
            {
                "protocol_id": int,           # Protocol being deleted (1=ISAKMP, 3=ESP)
                "spi_size": int,              # SPI size in bytes (4 or 8)
                "spi_count": int,             # Number of SPIs
                "spis": [str]                 # ["0x...", "0x..."] list of hex SPIs
            }
        ],
        "notify": [
            {
                "type": int,                  # IANA Notify message type number
                "type_name": str,             # e.g. "INITIAL-CONTACT", "RESPONDER-LIFETIME"
                "protocol_id": int,
                "spi_size": int,
                "spi": str | None,
                "data": str | None            # Hex notify data payload
            }
        ]
    },

    # --- Optional top-level notification bucket (present if notify payloads exist) ---
    "notify": {
        "present": bool,                      # True if any Notify payload found
        "notify_types": [int],                # List of numeric notification types
        "messages": [
            {
                "type": int,
                "type_name": str,
                "protocol_id": int,
                "spi_size": int,
                "spi": str | None,
                "data": str | None
            }
        ]
    }
}
```

---

### 2.2 Complete IKEv2 Schema Skeleton

```python
{
    "common": {
        "plane": "control",                   # str: always "control"
        "timestamp": float,                   # float: epoch time in seconds
        "src_ip": str,                        # str: source IPv4 or IPv6
        "dst_ip": str,                        # str: destination IPv4 or IPv6
        "src_port": int | None,               # int or null: source UDP port
        "dst_port": int | None,               # int or null: destination UDP port
        "initiator_spi": str,                 # str: "0x..." 8-byte hex string
        "responder_spi": str,                 # str: "0x..." 8-byte hex string
        "exchange_type": int | None,          # int: 34 (IKE_SA_INIT), 35 (IKE_AUTH), 37 (INFORMATIONAL)
        "is_response": bool,                  # bool: True if R-bit (0x20) set in flags
        "message_id": int | None,             # int: sequence number of the exchange
    },

    # --- Exactly ONE of the following exchange keys is included per packet ---

    # Case A: IKE_SA_INIT
    "IKE_SA_INIT": {
        "exchange": "IKE_SA_INIT",
        "proposals": [
            {
                "proposal_num": int,          # Proposal number (1-indexed)
                "protocol_id": int,           # 1 for IKE
                "spi": None,                  # null during initial SA negotiation
                "transforms": {
                    # In IKEv2, keys are transform type names; values are lists of {id, length}
                    "encryption": [{"id": int, "length": int | None}],
                    "prf": [{"id": int, "length": int | None}],
                    "integrity": [{"id": int, "length": int | None}],
                    "dh_group": [{"id": int, "length": int | None}],
                    "extended_sequence_numbers": [{"id": int, "length": int | None}],
                    "additional_key_exchange_1": [{"id": int, "length": int | None}],
                    "additional_key_exchange_2": [{"id": int, "length": int | None}],
                    "additional_key_exchange_3": [{"id": int, "length": int | None}],
                    "additional_key_exchange_4": [{"id": int, "length": int | None}],
                    "additional_key_exchange_5": [{"id": int, "length": int | None}],
                    "additional_key_exchange_6": [{"id": int, "length": int | None}],
                    "additional_key_exchange_7": [{"id": int, "length": int | None}],
                    "key_wrap": [{"id": int, "length": int | None}],
                    "group_controller_authentication": [{"id": int, "length": int | None}]
                }
            }
        ]
    },

    # Case B: IKE_AUTH
    "IKE_AUTH": {
        "exchange": "IKE_AUTH",
        "authentication": {
            "present": bool,
            "auth_type": int | str | None,    # Authentication method (1=RSA, 2=Shared Key, etc.)
            "signature_algorithm": None,
            "signature_hash_algorithm": None
        },
        "certificate": {
            "present": bool,
            "encoding": int | str | None,     # Certificate encoding type
            "data": str | bytes | None        # Raw or hex-encoded certificate
        },
        "child_sa": {
            "present": bool,
            "proposals": [
                {
                    "proposal_num": int,
                    "protocol_id": int,       # 3 for ESP, 2 for AH
                    "spi": str,               # "0x..." Child SA SPI
                    "transforms": {
                        "encryption": [{"id": int, "length": int | None}],
                        "integrity": [{"id": int, "length": int | None}],
                        "extended_sequence_numbers": [{"id": int, "length": int | None}],
                        # ... other transform types
                    }
                }
            ]
        },
        "traffic_selectors": {
            "initiator": [                    # Derived from TSi payloads
                {
                    "type": int | None,       # TS Type (7=TS_IPV4_ADDR_RANGE, 8=TS_IPV6_ADDR_RANGE)
                    "ip_protocol": int | None,# Protocol (0=any)
                    "start_port": int | None, # Port range start (0)
                    "end_port": int | None,   # Port range end (65535)
                    "start_address": str,     # Start IP address
                    "end_address": str        # End IP address
                }
            ],
            "responder": [                    # Derived from TSr payloads
                {
                    "type": int | None,
                    "ip_protocol": int | None,
                    "start_port": int | None,
                    "end_port": int | None,
                    "start_address": str,
                    "end_address": str
                }
            ]
        }
    },

    # Case C: INFORMATIONAL
    "INFORMATIONAL": {
        "exchange": "INFORMATIONAL",
        "delete": list,                       # List of delete records
        "configuration": list                 # List of CP (Configuration Payload) records
    },

    # --- Optional top-level notification bucket ---
    "notify": {
        "present": bool,
        "notify_types": [int],
        "messages": [
            {
                "type": int | None,           # Notify message type
                "protocol_id": int | None,
                "spi_size": int | None,
                "spi": str | bytes | None
            }
        ]
    }
}
```

---

## 3. Key Structural Differences

| Dimension | IKEv1 Structure | IKEv2 Structure |
| :--- | :--- | :--- |
| **Transforms Mapping** | Attribute-Value based: `{"<attr_name>": [{"value": ...}]}` | Type-ID based: `{"<type_name>": [{"id": ..., "length": ...}]}` |
| **Phase 2 / Child SA** | Negotiated in a dedicated exchange container (`QUICK_MODE`) | Negotiated within `IKE_AUTH` under `child_sa`, or subsequently in `CREATE_CHILD_SA` |
| **Traffic Selectors** | Derived from $ID_{ci}$ (Client Initiator) and $ID_{cr}$ (Client Responder) ID payloads | Derived from native `TSi` (Traffic Selector Initiator) and `TSr` (Traffic Selector Responder) payloads |
| **Cookies / SPIs** | Named `initiator_cookie` and `responder_cookie` (8 bytes) | Named `initiator_spi` and `responder_spi` (8 bytes) |
| **Exchange Keys** | `"MAIN_MODE"`, `"AGGRESSIVE_MODE"`, `"QUICK_MODE"`, `"INFORMATIONAL"` | `"IKE_SA_INIT"`, `"IKE_AUTH"`, `"INFORMATIONAL"` |
