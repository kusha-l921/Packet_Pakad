# RFC Health & Compliance Rule Engine — Integration Guide

This guide explains how to integrate and call the **RFC-Based Health and Compliance Rule Engine** for IPsec and IKEv2.

---

## 1. Quick Start: What Function to Call

The primary entry point is the `RfcRuleEngine` class (`rfcRuleEngine.py`), which provides three core methods:

1. **`evaluate(session_dict, telemetry_dict=None)`** — Full evaluation of handshake session and/or batch telemetry.
2. **`process_esp_packet(packet_dict, session_dict=None)`** — Real-time evaluation of a single ESP packet (live packet streaming).
3. **`reset_telemetry_windows(spi=None)`** — Reset sliding window state for an SPI or all SPIs (e.g. on rekey).

```python
from rfcRuleEngine import RfcRuleEngine

# 1. Instantiate the engine (optional: configure anti-replay window size, default=64)
engine = RfcRuleEngine(replay_window_size=64)

# 2. Call evaluate() with your session dict (and optional telemetry dict)
report = engine.evaluate(session_dict, telemetry_dict=None)

# 3. Access decoupled results
print("Overall Status:", report.overall_rfc_status.value)      # PASS, FAIL, WARNING, NOT_VERIFIABLE
print("PQC Status:", report.pqc_classification.value)          # NONE, PQC_KEM, PPK, PQC_SIG, COMPOSITE
print("Hybrid Status:", report.hybrid_classification.value)    # HYBRID, NOT_HYBRID, NOT_VERIFIABLE
print("Security Posture:", report.cryptographic_posture.value) # STRONG, ACCEPTABLE, WEAK, BROKEN
```

---

## 2. API Signatures & Input Parameters

### Method 1: `evaluate(...)`
```python
def evaluate(
    self,
    session_dict: dict[str, Any],
    telemetry_dict: dict[str, Any] | None = None
) -> EngineReport:
```

### Method 2: `process_esp_packet(...)`
```python
def process_esp_packet(
    self,
    packet_dict: dict[str, Any],
    session_dict: dict[str, Any] | None = None
) -> list[RuleEvaluationResult]:
```

### Method 3: `reset_telemetry_windows(...)`
```python
def reset_telemetry_windows(
    self,
    spi: str | None = None
) -> None:
```

### Parameter 1: `session_dict` (Part 1: Post-Handshake Control Plane)

The unified handshake session dictionary produced by `metadataExtractor.extract_ikeV2_metadata()` or merged via `merge_session_metadata(*dicts)`.

#### Structure / Keys Expected:
```python
session_dict = {
    # ── Header & Plane Metadata ──────────────────────────────────────
    "common": {
        "ike_version": 2,          # 2 for IKEv2 (1 flags RFC 9395 deprecation)
        "src_ip": "192.168.1.1",
        "dst_ip": "192.168.1.2",
        "src_port": 500,           # 500 (native) or 4500 (NAT-T)
        "dst_port": 500,
        "message_id": 0,           # Optional: validates sequential ordering
    },

    # ── IKE_SA_INIT (Exchange 34) ───────────────────────────────────
    "IKE_SA_INIT": {
        "exchange": "IKE_SA_INIT",
        "proposals": [{
            "proposal_num": 1,
            "protocol_id": 1,      # 1 = IKE
            "transforms": {
                "encryption": [{"id": 20, "length": 256}],   # e.g., AES-GCM-256 (ID 20) or AES-CBC (ID 12)
                "prf":        [{"id": 6}],                    # e.g., HMAC-SHA2-384 (ID 6) or HMAC-SHA2-256 (ID 5)
                "integrity":  [{"id": 0}],                    # ID 0 (NONE) for AEAD; ID 12 for non-AEAD
                "dh_group":   [{"id": 20}],                   # e.g., P-384 (ID 20), Curve25519 (ID 31), MODP-2048 (ID 14)
                "extended_sequence_numbers": [{"id": 1}],     # 1 = ESN enabled, 0 = 32-bit
                "additional_key_exchange_1": [{"id": 37}],    # Optional: RFC 9370 Multi-KE (e.g., ML-KEM-1024)
            },
        }],
        "key_exchange": {
            "group_id": 20,
            "key_data_len": 96,
        },
    },

    # ── IKE_AUTH (Exchange 35) ──────────────────────────────────────
    "IKE_AUTH": {
        "exchange": "IKE_AUTH",
        "authentication": {
            "present": True,
            "auth_type": 14,       # 14 = Digital Signature (RFC 7427), 2 = PSK, 9/10/11 = ECDSA
            "data": "0x...",
        },
        "certificate": {           # Optional for PSK
            "present": True,
            "encoding": 4,         # X.509 Certificate - Signature
            "cert_key_type_oid": "2.16.840.1.101.3.4.3.19",  # e.g., ML-DSA-87 or 1.2.840.10045.2.1
            "cert_key_len": 2592,
            "cert_sig_algo_oid": "2.16.840.1.101.3.4.3.19",
        },
        "child_sa": {
            "present": True,
            "proposals": [{
                "proposal_num": 1,
                "protocol_id": 3,  # 3 = ESP
                "transforms": {
                    "encryption": [{"id": 20, "length": 256}],
                    "integrity":  [{"id": 0}],
                    "dh_group":   [{"id": 20}],
                    "extended_sequence_numbers": [{"id": 1}],
                },
            }],
        },
        "traffic_selectors": {
            "initiator": [{"start_address": "10.0.0.0", "end_address": "10.0.0.255"}],
            "responder": [{"start_address": "10.1.0.0", "end_address": "10.1.0.255"}],
        },
    },

    # ── Consolidated Notifications ─────────────────────────────────
    "notify": {
        "present": True,
        "notify_types": [16440, 16443],  # 16440 = Multi-KE, 16443 = Signature Hash Algos, 16435 = USE_PPK
        "messages": [],
    },
}
```

---

### Parameter 2: `telemetry_dict` (Part 2: Runtime Telemetry — Optional)

Passed over periodic sliding windows or trace completion. If omitted or passed as `None`, Part 2 rules evaluate safely to `NOT_VERIFIABLE` without false positives or false failures.

#### Structure / Keys Expected:
```python
telemetry_dict = {
    "data_plane": {
        "spi": "0xaabbccdd",
        "is_natt": False,          # True if UDP-encapsulated (port 4500)
        "src_ip": "192.168.1.1",
        "dst_ip": "192.168.1.2",
        "src_port": None,          # 4500 if NAT-T
        "dst_port": None,
        "esn": True,               # Optional: True if ESN negotiated, False for 32-bit
        "packets": [               # List of observed ESP packet records
            {"seq_num": 1, "wire_bytes": 128, "timestamp": 100.001},
            {"seq_num": 2, "wire_bytes": 128, "timestamp": 100.002},
            {"seq_num": 3, "wire_bytes": 256, "timestamp": 100.003},
            # ...
        ],
    }
}
```

> [!NOTE]
> `telemetry_dict` can also be passed directly as a flat dictionary with `{"packets": [...], "spi": ...}` or embedded inside `session_dict["data_plane"]`. The engine automatically inspects both locations.

---

## 3. Output: The `EngineReport` Object

Calling `engine.evaluate(...)` returns an `EngineReport` dataclass with decoupled fields:

| Field | Type / Enum | Values | Description |
| :--- | :--- | :--- | :--- |
| `overall_rfc_status` | `RuleStatus` | `PASS`, `FAIL`, `WARNING`, `NOT_VERIFIABLE` | Overall Boolean / Requirement compliance |
| `protocol_compliance` | `RuleStatus` | `PASS`, `FAIL`, `WARNING`, `NOT_VERIFIABLE` | Category 1 (IKEv2 protocol compliance) |
| `cryptographic_compliance` | `RuleStatus` | `PASS`, `FAIL`, `WARNING`, `NOT_VERIFIABLE` | Categories 2–6 (ENCR, PRF, INTEG, DH) |
| `ipsec_esp_compliance` | `RuleStatus` | `PASS`, `FAIL`, `WARNING`, `NOT_VERIFIABLE` | Categories 8, 10, 12 (ESP, Replay, SPD) |
| `authentication_compliance` | `RuleStatus` | `PASS`, `FAIL`, `WARNING`, `NOT_VERIFIABLE` | Category 7 (Auth, Certs, Signatures) |
| `cryptographic_posture` | `SecurityPosture` | `STRONG`, `ACCEPTABLE`, `WEAK`, `BROKEN` | Classical cryptographic security tier |
| `pqc_classification` | `PqcClassification` | `NONE`, `PQC_KEM`, `PPK`, `PQC_SIG`, `COMPOSITE` | Post-quantum readiness classification |
| `hybrid_classification` | `HybridClassification` | `HYBRID`, `NOT_HYBRID`, `NOT_VERIFIABLE` | Cryptographic mechanism binding |
| `critical_failures` | `list[RuleEvaluationResult]` | List of critical failed rules | Any `MUST` violation or `MUST NOT` breach |
| `warnings` | `list[RuleEvaluationResult]` | List of warning rules | Any `SHOULD NOT` or deprecated usage |
| `passed_rules` | `list[RuleEvaluationResult]` | List of passed rules | Satisfied RFC requirements |
| `not_verifiable_rules` | `list[RuleEvaluationResult]` | List of unverified rules | Missing required trace/telemetry inputs |
| `not_applicable_rules` | `list[RuleEvaluationResult]` | List of N/A rules | Rules not applicable to negotiated mode |
| `all_results` | `list[RuleEvaluationResult]` | Complete list of all evaluated rules | Every rule evaluation result |
| `category_summaries` | `dict[str, CategoryComplianceSummary]` | Per-category summaries | Granular category pass/fail/warn counts |

### `RuleEvaluationResult` Schema

Each item in `critical_failures`, `warnings`, `passed_rules`, etc. is a `RuleEvaluationResult` object with:

```python
@dataclass
class RuleEvaluationResult:
    rule_id: str                   # e.g., "IKE-PROTO-VER-001", "ESP-REPLAY-DUP-001"
    rfc: str                       # e.g., "RFC 7296", "RFC 8247", "RFC 4303"
    section: str                   # e.g., "§3.1", "§2.1", "§3.4.3"
    category: str                  # e.g., "IKEv2 Protocol Compliance", "Anti-Replay / ESN"
    condition: str                 # Human-readable rule condition being evaluated
    requirement_level: str         # "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", "MAY"
    applicable_context: str        # "HANDSHAKE", "RUNTIME", "COMMON"
    status: RuleStatus             # PASS, FAIL, WARNING, NOT_VERIFIABLE, NOT_APPLICABLE
    severity: Severity             # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    reason: str                    # Detailed diagnostic rationale citing RFC requirements
    observed_value: Any            # What was found in the input packet/session
    expected_requirement: str      # What RFC normative text dictates
    spec_source: str               # "PUBLISHED RFC", "IANA REGISTRY", "FIPS STANDARD"
```

---

## 4. Integration Code Examples

### Example 1: Evaluating a Completed Handshake Session (Control-Plane Only)

```python
from rfcRuleEngine import RfcRuleEngine

# Instantiate engine
engine = RfcRuleEngine()

# Handshake session metadata
session = {
    "common": {"ike_version": 2, "src_port": 500, "dst_port": 500},
    "IKE_SA_INIT": {
        "proposals": [{
            "proposal_num": 1,
            "transforms": {
                "encryption": [{"id": 20, "length": 256}],  # AES-GCM-256
                "prf":        [{"id": 6}],                   # SHA-384
                "integrity":  [{"id": 0}],                   # NONE (valid for AEAD)
                "dh_group":   [{"id": 20}],                  # P-384
                "extended_sequence_numbers": [{"id": 1}],
                "additional_key_exchange_1": [{"id": 37}],   # ML-KEM-1024
            },
        }],
        "key_exchange": {"group_id": 20, "key_data_len": 96},
    },
    "IKE_AUTH": {
        "authentication": {"present": True, "auth_type": 14},
        "certificate": {
            "present": True,
            "cert_key_type_oid": "2.16.840.1.101.3.4.3.19",  # ML-DSA-87
            "cert_key_len": 2592,
            "cert_sig_algo_oid": "2.16.840.1.101.3.4.3.19",
        },
        "child_sa": {
            "present": True,
            "proposals": [{
                "transforms": {
                    "encryption": [{"id": 20, "length": 256}],
                    "integrity":  [{"id": 0}],
                    "dh_group":   [{"id": 37}],
                }
            }]
        },
    },
    "notify": {
        "present": True,
        "notify_types": [16440, 16443],
        "messages": [],
    },
}

# Run evaluation
report = engine.evaluate(session)

# Export as dictionary or formatted text report
report_dict = report.to_dict()
report_text = report.to_text_report()

print(report_text)
```

---

### Example 2: Continuous Runtime Telemetry (ESP Sliding Window)

```python
from rfcRuleEngine import RfcRuleEngine

engine = RfcRuleEngine(replay_window_size=128)

# Telemetry sliding window of observed packets
telemetry = {
    "data_plane": {
        "spi": "0x12345678",
        "is_natt": True,
        "src_port": 4500,
        "dst_port": 4500,
        "esn": True,
        "packets": [
            {"seq_num": 100, "wire_bytes": 140, "timestamp": 12.01},
            {"seq_num": 101, "wire_bytes": 140, "timestamp": 12.02},
            {"seq_num": 102, "wire_bytes": 140, "timestamp": 12.03},
            {"seq_num": 101, "wire_bytes": 140, "timestamp": 12.04},  # Replay!
        ],
    }
}

# Evaluate telemetry (can be run with or without handshake session)
report = engine.evaluate({}, telemetry_dict=telemetry)

if report.critical_failures:
    print("Security Violations Detected:")
    for failure in report.critical_failures:
        print(f"[{failure.severity.value}] {failure.rule_id}: {failure.reason}")
```

---

### Example 3: Pipeline Integration with `metadataExtractor.py` and `vectorEngine.py`

```python
from metadataExtractor import extract_ikeV2_metadata, extract_esp_metadata
from vectorEngine import merge_session_metadata
from rfcRuleEngine import RfcRuleEngine

# 1. Parse packets from PyShark or PCAP
session_packets = []
# for pkt in pyshark_capture:
#     meta = extract_ikeV2_metadata(pkt)
#     if meta: session_packets.append(meta)

# 2. Merge multi-packet handshake
session_dict = merge_session_metadata(*session_packets)

# 3. Evaluate compliance
engine = RfcRuleEngine()
report = engine.evaluate(session_dict)

# 4. Integrate into database, logging, or alerting
if report.overall_rfc_status.value == "FAIL":
    # Trigger alert for non-compliant VPN negotiation
    pass
```

---

### Example 4: Streaming ESP Packets One by One (Real-Time Live Capture)

Yes! You can feed ESP packets **one by one** directly as they arrive from Scapy, PyShark, or a socket stream using `engine.process_esp_packet(packet_dict)`:

```python
from scapy.all import sniff
from metadataExtractor import extract_esp_metadata
from rfcRuleEngine import RfcRuleEngine

# 1. Instantiate the engine (the sliding window persists across calls)
engine = RfcRuleEngine(replay_window_size=64)

# Optional: pass the previously evaluated handshake session dict
# so the engine knows if ESN or specific Traffic Selectors were negotiated
handshake_session = session_dict  # or None

def on_packet_received(pkt):
    # 2. Extract ESP packet metadata using metadataExtractor
    esp_meta = extract_esp_metadata(pkt)
    if not esp_meta:
        return

    # 3. Feed the single packet to the engine
    findings = engine.process_esp_packet(esp_meta, session_dict=handshake_session)

    # 4. Check findings for this specific packet
    for r in findings:
        if r.status.value == "FAIL":
            print(f"🚨 [CRITICAL ALERT] {r.rule_id} violated on packet seq={esp_meta['seq_num']}: {r.reason}")
        elif r.status.value == "WARNING":
            print(f"⚠️ [WARNING] {r.rule_id}: {r.reason}")

# Example: Sniff live ESP traffic and evaluate each packet on the fly
# sniff(filter="ip proto 50 or udp port 4500", prn=on_packet_received)
```

#### What `process_esp_packet()` checks per packet:
1. **Anti-Replay Sliding Window (RFC 4303 §3.4.3)**:
   - Immediately detects **duplicate sequence numbers** (`ESP-REPLAY-DUP-001`, `CRITICAL`).
   - Immediately detects **packets falling behind the sliding window trailing edge** (`ESP-REPLAY-WINDOW-001`, `HIGH`).
   - Advances the window right edge when higher sequence numbers arrive.
2. **Sequence Number Rollover (RFC 4303 §3.3.3)**:
   - Detects if 32-bit sequence number wraps or approaches $2^{32}-1$ without ESN.
3. **Encapsulation & Ports (RFC 3948)**:
   - Validates UDP 4500 NAT-T mapping or Protocol 50 native ESP.
4. **SPD Traffic Selector Bounds (RFC 4301 §4.4.1)**:
   - Validates inner headers against negotiated TS (if inner headers are available).

#### Resetting Sliding Windows on Rekeying or SA Expiration:

When an SA is rekeyed or torn down, reset its replay window to restart sequence tracking fresh:

```python
# Reset window for a specific Child SA SPI:
engine.reset_telemetry_windows(spi="0x12345678")

# Or reset all active telemetry windows:
engine.reset_telemetry_windows()
```


