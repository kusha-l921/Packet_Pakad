# Person 3 Integration Contract & Public API Reference

## 1. Overview: What Person 3 Receives

Person 3 (Dashboard, Incident Reporting, and Security Visualization layer) receives **one stable, unified JSON dictionary** representing the complete end-to-end analysis of a network capture (`.pcap` or `.pcapng`).

The entire 5-phase engine is callable via **one public entry point**:

```python
from person2_engine import analyze_capture_complete

result = analyze_capture_complete("capture.pcap")
```

The returned object (`UnifiedCaptureResult`) provides `.to_dict()` and `.to_json()` methods conforming to:

```python
INTEGRATION_SCHEMA_VERSION = "1.0"
```

Person 3 does **not** need to call internal modules, stitch together packet records, or manage machine learning inference pipelines.

---

## 2. Python Quickstart Example

```python
from pathlib import Path
from person2_engine import analyze_capture_complete, validate_integration_result

# 1. Execute full 5-phase analysis
capture_file = Path("captures/session_01.pcap")
unified_result = analyze_capture_complete(
    file_path=capture_file,
    output_json="output/unified_session_01.json", # optional
    allow_unverified_domain=True,                # enables inference for unverified IPsec encapsulation
)

# 2. Access high-level capture data
data = unified_result.to_dict()
print(f"Schema Version:       {data['integration_schema_version']}")
print(f"Total Flows:          {data['capture_summary']['total_flows']}")
print(f"Overall Risk Tier:    {data['capture_summary']['overall_risk_level']} (Score: {data['capture_summary']['overall_risk_score']}/100)")
print(f"IPsec Detected:       {data['ipsec_analysis']['ipsec_detected']}")

# 3. Iterate over individual flows
for flow in data["flows"]:
    fid = flow["flow_id"]
    cat = flow["prediction"]["traffic_category"]
    conf = flow["prediction"]["confidence"]
    risk = flow["security_assessment"]["risk_level"]
    score = flow["security_assessment"]["risk_score"]
    
    # Check model uncertainty independently from behavioral risk
    is_uncertain = flow["model_uncertainty"]["present"]
    
    print(f"Flow {fid}: Category={cat} ({conf:.1%}), Behavioral Risk={risk} ({score}/100), Model Uncertainty={is_uncertain}")
```

---

## 3. Main Top-Level Sections

The unified integration schema contains four top-level sections:

```json
{
  "integration_schema_version": "1.0",
  "analysis_metadata": {},
  "capture_summary": {},
  "ipsec_analysis": {},
  "flows": []
}
```

### A. `analysis_metadata`
Technical capture metadata and execution status:
* `file_name`: Basename of the capture file.
* `file_path`: Absolute path on the filesystem.
* `file_type`: Format detected (e.g. `"pcap"`, `"pcapng"`).
* `total_packets`: Total number of packets processed from the capture.
* `readable`: Boolean indicating whether packets were successfully parsed.
* `analysis_status`: `"SUCCESS"` or `"FAILED"`.
* `errors`: List of fatal execution errors (empty on success).
* `warnings`: List of non-fatal operational notices.
* `model_information`: Active ML model ID, version, and IPsec domain validation status.

### B. `capture_summary`
Aggregated overview across all flows in the capture:
* `total_flows`: Number of bidirectional flows extracted.
* `overall_risk_score`: Percentile-blended capture risk score (`0` to `100`).
* `overall_risk_level`: Qualitative risk tier (`"LOW"`, `"MEDIUM"`, `"HIGH"`, `"CRITICAL"`).
* `risk_distribution`: Count of flows per risk tier (e.g. `{"LOW": 12, "MEDIUM": 2, "HIGH": 1, "CRITICAL": 0}`).
* `traffic_distribution`: Count of flows per predicted category (e.g. `{"web": 10, "video": 3, "file_transfer": 2}`).
* `average_confidence`: Mean classification confidence across all flows (`0.0` to `1.0`).
* `top_indicators`: List of the top 5 most frequently triggered behavioral risk indicators.

### C. `ipsec_analysis`
Tunnel protocol and cryptographic encapsulation findings:
* `ipsec_detected`: Boolean indicating presence of IPsec traffic.
* `esp_detected`: Boolean indicating ESP (Encapsulating Security Payload, IP protocol 50).
* `esp_packets`: Total count of ESP packets observed.
* `ah_detected`: Boolean indicating AH (Authentication Header, IP protocol 51).
* `ah_packets`: Total count of AH packets observed.
* `ike_related_traffic_detected`: Boolean indicating IKE exchange (UDP 500).
* `ike_version`: Detected IKE version (`"1"`, `"2"`, or `null`).
* `nat_traversal_related_traffic_detected`: Boolean indicating NAT-T encapsulation (UDP 4500).

### D. `flows`
Ordered list of detailed flow objects.

---

## 4. Per-Flow Information

Each item in `flows` contains:

```json
{
  "flow_id": "TCP_192.168.1.10:54321_93.184.216.34:80",
  "flow_metadata": {
    "flow_id": "TCP_192.168.1.10:54321_93.184.216.34:80",
    "ip_version": 4,
    "protocol": "TCP",
    "endpoint_a": "192.168.1.10:54321",
    "endpoint_b": "93.184.216.34:80",
    "first_timestamp": 1789108303.4719,
    "last_timestamp": 1789108303.4719,
    "is_ipsec_related": false,
    "esp_detected": false,
    "ah_detected": false,
    "ike_related": false,
    "nat_t_related": false
  },
  "features": {
    "total_packets": 10.0,
    "forward_packets": 6.0,
    "backward_packets": 4.0,
    "total_bytes": 1500.0,
    "forward_bytes": 900.0,
    "backward_bytes": 600.0,
    "minimum_packet_size": 54.0,
    "maximum_packet_size": 500.0,
    "mean_packet_size": 150.0,
    "standard_deviation_packet_size": 120.5,
    "median_packet_size": 100.0,
    "forward_mean_packet_size": 150.0,
    "backward_mean_packet_size": 150.0,
    "flow_duration_seconds": 2.5,
    "packets_per_second": 4.0,
    "bytes_per_second": 600.0,
    "mean_inter_arrival_time": 0.25,
    "minimum_inter_arrival_time": 0.01,
    "maximum_inter_arrival_time": 0.50,
    "standard_deviation_inter_arrival_time": 0.12,
    "forward_packet_ratio": 0.6,
    "backward_packet_ratio": 0.4,
    "forward_byte_ratio": 0.6,
    "backward_byte_ratio": 0.4,
    "maximum_packets_in_one_second": 5.0
  },
  "prediction": {
    "traffic_category": "web",
    "confidence": 0.88,
    "confidence_level": "HIGH",
    "prediction_status": "HIGH_CONFIDENCE",
    "probabilities": {
      "web": 0.88,
      "video": 0.05,
      "voip": 0.04,
      "file_transfer": 0.02,
      "interactive": 0.01
    },
    "model_name": "random_forest_v1",
    "model_version": "1.0"
  },
  "model_uncertainty": {
    "present": false,
    "flags": []
  },
  "behavior": {
    "traffic_pattern": "Standard Web/Interactive Session",
    "observations": [
      "MODERATE_PACKET_RATE"
    ],
    "metrics_summary": {
      "total_packets": 10,
      "total_bytes": 1500,
      "duration_seconds": 2.5,
      "packets_per_second": 4.0,
      "bytes_per_second": 600.0,
      "forward_byte_ratio": 0.6,
      "backward_byte_ratio": 0.4,
      "max_packets_one_second": 5
    }
  },
  "security_assessment": {
    "risk_score": 0,
    "risk_level": "LOW",
    "indicators": [],
    "score_contributions": []
  },
  "explainability": {
    "important_features": [
      {"feature_name": "mean_packet_size", "importance": 0.35},
      {"feature_name": "bytes_per_second", "importance": 0.22}
    ],
    "summary": "Flow statistically resembles 'web' traffic with high confidence (88.0%). Observable behavior aligns with 'Standard Web/Interactive Session', transferring 1,500 bytes across 10 packets over 2.50 seconds. No elevated behavioral risk indicators were observed. The flow is evaluated at LOW behavioral risk (score: 0/100)."
  },
  "summary": "Flow statistically resembles 'web' traffic with high confidence (88.0%). Observable behavior aligns with 'Standard Web/Interactive Session', transferring 1,500 bytes across 10 packets over 2.50 seconds. No elevated behavioral risk indicators were observed. The flow is evaluated at LOW behavioral risk (score: 0/100)."
}
```

---

## 5. Critical UI Display Rule: Model Uncertainty vs. Behavioral Risk

> [!IMPORTANT]
> **Person 3 UI Cardinal Rule**:
> The UI must display **MODEL UNCERTAINTY** in a dedicated, visually separate container from **BEHAVIORAL RISK**.
>
> **The UI must NEVER visually or mathematically combine them.**

### Recommended UI Layout
```text
┌───────────────────────────────────────────────────────────────────┐
│ FLOW: 192.168.1.10:54321 <───> 93.184.216.34:80 (TCP)             │
├─────────────────────────────────┬─────────────────────────────────┤
│ BEHAVIORAL SECURITY RISK        │ MODEL CLASSIFICATION & CONFIDENCE│
│ Status: LOW (Score: 20/100)     │ Category: Web                   │
│ Indicators:                     │ Model Confidence: 42% (LOW)     │
│  - UNUSUAL_HIGH_PACKET_RATE     │                                 │
│                                 │ Model Uncertainty: PRESENT      │
│ Note: Evaluated strictly from   │ Reason: Traffic profile does    │
│ observable traffic behavior.    │ not strongly match training set.│
│                                 │ (0 risk points contributed)     │
└─────────────────────────────────┴─────────────────────────────────┘
```

A operator must never be led to believe that "Low ML Confidence = High Security Threat".

---

## 6. Recommended Terminology vs. Prohibited Language

Because this system analyzes statistical traffic shapes without decrypting payloads, use cautious, evidence-backed terminology:

### Recommended Wording
* "Observable anomalous pattern"
* "Behavioral risk indicator"
* "Potential anomaly requiring review"
* "Traffic category statistical resemblance"
* "Classification model uncertainty"
* "Elevated outbound transfer volume"

### Prohibited Wording
* ❌ **Do NOT say**: "Cyber attack detected"
* ❌ **Do NOT say**: "Malicious traffic confirmed"
* ❌ **Do NOT say**: "Intrusion identified"
* ❌ **Do NOT say**: "Compromised host"
* ❌ **Do NOT say**: "Attacker identified"

All risk scores and levels reflect **heuristic behavioral deviations**, not confirmed security breaches.

---

## 7. Optional and Informational Fields

* **`model_uncertainty`**:
  - Optional informational field.
  - Does **not** add points to `risk_score`.
  - Does **not** alter `risk_level`.
  - Existing or minimal consumers that do not need uncertainty reporting can safely ignore this field without affecting behavioral risk calculation.
* **`explainability`**:
  - Informational feature weights and narrative summary.
  - Ideal for tooltip / drawer inspection views in Person 3 dashboards.

---

## 8. IPsec Domain Validation Status & Dashboard Rules

The dashboard must explicitly distinguish between verified and unverified IPsec domain classifications:

### A. Verified IPsec Model (`ipsec_validation == "verified_ipsec"`)
- The model was trained and evaluated on labeled IPsec traffic (e.g. future Person 1 StrongSwan data).
- The prediction may be displayed as an IPsec-domain-validated classification.

### B. Unverified IPsec Model (`ipsec_validation == "unverified"`)
- **Blocked Mode** (`allow_unverified_domain=False` default):
  - Model inference is not executed on IPsec traffic.
  - `traffic_category`: `"unclassified"`, `confidence`: `0.0`, `prediction_status`: `"TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED"`.
  - Dashboard display: "Inference Blocked (Unverified IPsec Domain)".
- **Override Mode** (`allow_unverified_domain=True`):
  - Model inference is executed, but `prediction_status` remains `"TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED"`.
  - Dashboard display: Must render a prominent badge: `[UNVERIFIED IPSEC DOMAIN]`.
  - **Cardinal Rule**: The dashboard must never silently present a high-confidence prediction (e.g., "VoIP, 99.9% confidence") from an unverified model as though it were a validated IPsec classification.

---

## 9. Evaluation Validity & Capture Diversity Definitions

For incident reporting, model provenance panels, and metric displays:

* **`GROUP_ISOLATED`**:
  Training and test flows come from strictly disjoint capture groups. Supports evaluation on unseen capture groups. No cross-capture leakage exists for classes evaluated under this mode.
* **`WITHIN_CAPTURE_HOLDOUT`**:
  Training and test flows originate from the same capture group because independent capture diversity is unavailable in the dataset. Does **not** represent unseen-capture validation.
* **`OVERALL_MIXED_EVALUATION`**:
  Combines results from different evaluation modes across the dataset. It must **not** be presented as fully unseen-capture or zero-leakage evaluation for every class.
