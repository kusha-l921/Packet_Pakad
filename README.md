# Network Security and Encrypted Traffic Analysis Engine

Part of the Network Security and AI Traffic Analysis pipeline (`person2_engine`).

---

## 1. What Phase 1 Does

Phase 1 provides a robust, fail-safe ingestion and layer-inspection foundation for raw network captures:

- **File Validation**: Validates file existence, format extensions (`.pcap`, `.pcapng`), 0-byte detection, read permissions, and header magic numbers without crashing.
- **Safe Packet Parsing**: Stream-reads packets via Scapy (`PcapReader` and `PcapNgReader`), handling malformed or truncated packets cleanly.
- **Layer & Protocol Identification**: Identifies and counts occurrences of:
  - Layer 2: Ethernet
  - Layer 3: IPv4, IPv6
  - Layer 4: TCP, UDP, ICMP, ICMPv6, and Other protocols (e.g. ESP, AH, GRE)
- **Dedicated IPsec & IKE Detection**:
  - Direct observation of native ESP (IP protocol 50) and AH (IP protocol 51).
  - Port-based identification of IKE (UDP 500) and NAT-Traversal (UDP 4500).
  - Inspection of NAT-T non-ESP markers (`0x00000000`) for encapsulated IKE vs encapsulated ESP.
  - Strict ISAKMP header decoding: distinguishes `"IKEv1"`, `"IKEv2"`, or `"Unknown"` without guessing.
- **Packet Statistics**: Calculates minimum, maximum, and average packet sizes across the capture.
- **Structured Machine-Readable Output**: Produces standardized dictionary and JSON conforming to the contract schema for downstream phases.
- **Public Python API & CLI**: Exposes `analyze_capture(file_path)` and a standalone `main.py` command-line utility.

---

## 2. What Phase 2 Adds

Phase 2 builds upon Phase 1 by aggregating packet records into **bidirectional network flows** and extracting numerical statistical features for machine learning:

1. **Bidirectional Flow Construction**:
   - Canonicalizes endpoints so client $\rightarrow$ server and server $\rightarrow$ client packets belong to the identical flow.
   - Handles TCP, UDP, ESP, AH, ICMP, and ICMPv6 traffic cleanly.
   - Non-port protocols (ESP, AH, ICMP) group by IP endpoints without requiring transport ports.
2. **Directional Conventions ("Forward" vs. "Backward")**:
   - The direction of the **first observed packet** of a flow defines `FORWARD`.
   - Packets traveling in the reverse direction are classified as `BACKWARD`.
   - *Note*: "Forward" strictly means the first observed transmission direction in the capture, and does not falsely presuppose client-to-server roles.
3. **Deterministic 25-Feature Schema (v1.0)**:
   - Extracts 25 numerical features covering flow sizes, packet sizes, durations, rates, inter-arrival times, directional ratios, and temporal burstiness.
   - Pinned in [docs/feature_schema.md](file:///home/illoir/Desktop/sih/docs/feature_schema.md).
4. **Feature Validation & Sanitization**:
   - Guards against `NaN`, `Infinity`, negative counts, and invalid ratios.
   - Ensures safe defaults for single-packet and zero-duration flows (no division-by-zero).
5. **ML-Ready Vectorization**:
   - Exposes `flow_features_to_vector(flow_result)` to generate a deterministic list of 25 floats suitable for training and inference in Phase 3.
6. **Additive Public API**:
   - Adds `analyze_capture_with_features(file_path)` without altering Phase 1's `analyze_capture(file_path)`.

---

## 3. What Phase 3 Adds (Real PCAP Training & ML Intelligence)

Phase 3 introduces a **real, lightweight machine learning intelligence, training, evaluation, and inference layer** that consumes the stable Phase 2 25-feature schema (`1.0`) and performs verifiable classification:

1. **Derived from Real Network PCAPs**:
   - Primary real-world dataset derived from UNB/CIC ISCXVPN2016 encrypted traffic captures across 5 aligned classes: `web`, `streaming` (with alias `video`), `voip`, `file_transfer`, and `interactive`.
   - The synthetic dataset (`synthetic_flows_test_fixture.csv`) is preserved solely as an automated testing and smoke-test fixture.
2. **Reusable Dataset Adapter & Manifest Architecture**:
   - Declarative manifest ingestion (`PcapDatasetManifest`) decouples raw PCAP ingestion from ML training.
   - Future Person 1 StrongSwan/IPsec PCAP captures can be ingested and retrained without changing the model architecture or feature extraction pipeline.
3. **Single Source of Truth Feature Extraction**:
   - PCAP files flow through the existing Phase 1 packet analysis and Phase 2 flow extraction to generate exactly the 25 canonical numerical features.
4. **Group-Aware Splitting & Honest Capture-Diversity Evaluation**:
   - Holds out entire capture sessions/files for multi-group classes (zero cross-capture leakage under `GROUP_ISOLATED` splitting).
   - Classes without sufficient independent capture diversity use `WITHIN_CAPTURE_HOLDOUT` and are explicitly identified as such.
   - Evaluation validity depends on capture diversity; the overall experiment (`OVERALL_MIXED_EVALUATION`) is not interpreted as fully unseen-capture validation for every class.
   - Preprocessing (`StandardScaler`) is fitted strictly on the training partition.
5. **Lightweight CPU-Friendly Model Pipeline**:
   - Evaluates 4 candidate classifiers: Random Forest, Gradient Boosting, Extra Trees, and Logistic Regression.
   - No GPU or deep learning dependencies required; fast CPU-friendly training and inference (< 0.01 ms / flow).
6. **Strict Scientific Model Selection**:
   - Selects models deterministically based on held-out Macro F1 and latency.
   - Transparent, honest metrics reporting without artificial inflation.
7. **Real-World Inference on Captures**:
   - `analyze_capture_with_predictions(file_path)` performs complete Phase 1 packet analysis, Phase 2 flow extraction, and Phase 3 model inference with explainability and domain status warnings.

---

## 4. What Phase 4 Adds (AI Security Assessment & Behavioral Risk Analysis)

Phase 4 introduces an **AI Security Assessment, Behavioral Indicator Engine, and Explainability Layer** that transforms raw numerical features (Phase 2) and machine learning predictions (Phase 3) into an explainable, structured security evaluation:

1. **Behavioral Analysis Engine**: Evaluates deterministic statistical properties of encrypted flows to generate transparent behavioral profiles (e.g. Asymmetric Outbound Transfer, High-Throughput Streaming, Bursty Exchange).
2. **Explainable Security Indicators**: Triggers 7 evidence-based risk indicators (`UNUSUAL_HIGH_UPLOAD_VOLUME`, `UNUSUAL_HIGH_PACKET_RATE`, `UNUSUAL_BURST_ACTIVITY`, `LONG_LIVED_HIGH_VOLUME_FLOW`, `PERIODIC_LOW_VOLUME_ACTIVITY`, `LOW_CLASSIFICATION_CONFIDENCE`, `STRONG_DIRECTIONAL_ASYMMETRY`).
3. **Calibrated Additive Risk Scoring**: Computes transparent risk scores ($0 \le S \le 100$) and deterministic risk tiers (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
4. **Intelligent Capture Aggregation**: Uses a percentile-blend aggregation ($0.70 \times P_{90} + 0.30 \times \mu$) ensuring outlier critical flows are not diluted away.
5. **Integration-Ready JSON Contract**: Serializes complete security evaluations for Person 3's frontend dashboard, reporting systems, and scoring pipelines.

> **System Capability & Limitation Statement**:
> The current Phase 4 security assessment is an explainable behavioral and heuristic risk analysis system. It identifies statistically unusual traffic characteristics and configurable risk indicators without decrypting payloads. It does not independently confirm that a flow represents a cyber attack, malicious activity, or an intrusion. Risk indicators should be interpreted in the context of the deployment environment and expected baseline traffic.

---

## 5. Important Non-Goals

In accordance with strict modular pipeline boundaries:
- DO NOT train deep neural networks, Transformers, BERT, or ET-BERT.
- DO NOT require a GPU or heavy deep learning runtime.
- DO NOT fabricate predictions or claim zero-shot IPsec accuracy without empirical evaluation.
- DO NOT claim confirmed attack or intrusion detection verdicts without payload decryption.
- DO NOT alter Phase 1, Phase 2, or Phase 3 public contracts or feature schemas.

---

## 5. Installation & Setup

```bash
# Navigate to repository root
cd /home/illoir/Desktop/sih

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies (scapy, scikit-learn, joblib, numpy, pytest)
pip install -r requirements.txt
```

---

## 6. How to Run the CLI

### Phase 1 Mode (Packet Analysis)
```bash
python main.py sample_data/basic_traffic.pcap
python main.py sample_data/basic_traffic.pcap --output output/analysis.json
```

### Phase 2 Mode (Flow Detection & Feature Extraction)
```bash
python main.py sample_data/basic_traffic.pcap --features
python main.py sample_data/basic_traffic.pcap --features --output output/flows.json
python main.py sample_data/basic_traffic.pcap --features --json-only
```

### Phase 3 Mode (Real PCAP Extraction, Validation, Training, & Evaluation)
```bash
# Extract 25 canonical features from real PCAPs via manifest
python main.py --extract-manifest --manifest datasets/manifests/iscxvpn2016_manifest.json

# Validate dataset against the 25-feature Phase 2 schema contract
python main.py datasets/processed/iscxvpn2016_flows.csv --validate-dataset

# Train candidate models, compare them, and save the best model
python main.py --train --dataset datasets/processed/iscxvpn2016_flows.csv

# Evaluate candidates on real flows and print per-class metrics
python main.py --evaluate --dataset datasets/processed/iscxvpn2016_flows.csv

# List registered models and IPsec domain verification status
python main.py --model-info
```

### Phase 3 Mode (Model Inference on Captures)
```bash
# Predict on capture (reports domain warning if model is unverified for IPsec)
python main.py datasets/raw/iscxvpn2016/streaming/vpn_netflix_sample.pcap --predict

# Allow inference with unverified domain models
python main.py datasets/raw/iscxvpn2016/streaming/vpn_netflix_sample.pcap --predict --allow-unverified-domain

# Save complete Phase 3 JSON output
python main.py capture.pcap --predict --allow-unverified-domain --output output/predictions.json
```

---

## 7. How to Access Predictions from Python

```python
from person2_engine import (
    analyze_capture,
    analyze_capture_with_features,
    analyze_capture_with_predictions,
)

# Phase 3: Additive inference layer
result = analyze_capture_with_predictions(
    "sample_data/basic_traffic.pcap",
    allow_unverified_domain=True,
)

print(f"Total flows:      {result.prediction_summary.total_flows}")
print(f"Successful:       {result.prediction_summary.predictions_successful}")

for flow_pred in result.predictions:
    if flow_pred.prediction:
        print(f"Flow prediction: {flow_pred.prediction.label} ({flow_pred.prediction.confidence:.2%})")
        print(f"Top features:    {flow_pred.feature_importance}")
```

---

## 8. How to Run Tests

All unit, integration, and regression tests across Phase 1, Phase 2, and Phase 3 run via `pytest`:

```bash
pytest -v tests/
```

---

## 9. Documentation References

- **Phase 2 Feature Schema Specification**: [docs/feature_schema.md](file:///home/illoir/Desktop/sih/docs/feature_schema.md)
- **Phase 3 Dataset Contract Specification**: [docs/dataset_contract.md](file:///home/illoir/Desktop/sih/docs/dataset_contract.md)
- **Phase 3 Model Contract Specification**: [docs/model_contract.md](file:///home/illoir/Desktop/sih/docs/model_contract.md)
- **Phase 3 Training Workflow Guide**: [docs/training_workflow.md](file:///home/illoir/Desktop/sih/docs/training_workflow.md)
- **Phase 3 Usage Guide**: [docs/phase3_usage.md](file:///home/illoir/Desktop/sih/docs/phase3_usage.md)


