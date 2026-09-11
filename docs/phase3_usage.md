# Phase 3 Usage Guide: Real PCAP ML Intelligence, Training, Evaluation & Inference

## Overview

Phase 3 builds a real, lightweight machine learning intelligence layer atop the stable Phase 1 packet parser and Phase 2 bidirectional flow builder (25-feature schema `1.0`).

Its primary design principles:
* **Derived from Real PCAP Data**: The primary dataset is extracted directly from genuine network captures (UNB/CIC ISCXVPN2016) via Phase 1 and Phase 2. The synthetic dataset is strictly a test fixture.
* **Reusable Manifest Architecture**: Any raw PCAP dataset can be ingested via a declarative JSON/CSV manifest, guaranteeing 100% architectural compatibility when Person 1 delivers future StrongSwan/IPsec PCAPs.
* **Real Trained Weights**: Inference uses genuinely fitted estimators (Gradient Boosting, Random Forest, Logistic Regression, etc.) serialized via `joblib`.
* **Zero GPU / CPU-Friendly**: High-speed training (< 1s) and fast per-flow inference (< 0.01ms) without deep learning or heavy GPU dependencies.
* **Explainability**: Feature importances are extracted directly from trained estimators and attached to predictions.
* **Domain Honesty**: Models trained on proxy OpenVPN datasets are tagged as `unverified` for IPsec until Person 1's StrongSwan ground truth is evaluated.

---

## 1. CLI Commands & Quick Reference

### 1.1 Manifest-Based PCAP Flow Extraction
Extract canonical 25-feature flow samples directly from real PCAPs defined in a manifest:
```bash
# Ingest ISCXVPN2016 real captures using Phase 1 & Phase 2 single source of truth
python main.py --extract-manifest --manifest datasets/manifests/iscxvpn2016_manifest.json -o datasets/processed/iscxvpn2016_flows.csv
```

### 1.2 Dataset Validation
Validate any CSV dataset against the Phase 2 25-feature schema contract:
```bash
python main.py datasets/processed/iscxvpn2016_flows.csv --validate-dataset
```

### 1.3 Training Candidate Models
Train and compare the 4 candidate models (Random Forest, Gradient Boosting, Extra Trees, Logistic Regression) with group-aware splitting on held-out capture sessions, select the optimal model by Macro F1 and latency, and persist the artifacts:
```bash
# Train on default processed real PCAP dataset
python main.py --train

# Train on a custom or future Person 1 IPsec dataset
python main.py --train --dataset datasets/processed/person1_ipsec_flows.csv --model-id ipsec_strongswan_v1
```

### 1.4 Evaluating Models
Evaluate models on real flows and print detailed per-class precision, recall, F1, and confusion matrices:
```bash
python main.py --evaluate --dataset datasets/processed/iscxvpn2016_flows.csv
```

### 1.5 Inspecting Registered Models
List all models registered in `models/registry/` and `models/metadata/`:
```bash
python main.py --model-info
```

### 1.6 Real Inference on a Capture
Run full Phase 1 packet analysis, Phase 2 flow feature extraction, and Phase 3 model inference:
```bash
# Real inference on a PCAP capture with domain override
python main.py datasets/raw/iscxvpn2016/streaming/vpn_netflix_sample.pcap --predict --allow-unverified-domain

# Output structured JSON
python main.py capture.pcap --predict --allow-unverified-domain --output output/predictions.json

# Pure JSON to stdout
python main.py capture.pcap --predict --allow-unverified-domain --json-only
```

---

## 2. Programmatic Python API

### 2.1 Manifest PCAP Ingestion Pipeline
```python
from pathlib import Path
from person2_engine.src.pcap_dataset_adapter import extract_flows_from_manifest

# Extract 25 canonical features using Phase 1 & Phase 2
dataset = extract_flows_from_manifest(
    manifest=Path("datasets/manifests/iscxvpn2016_manifest.json"),
    output_csv_path=Path("datasets/processed/iscxvpn2016_flows.csv"),
)
print(f"Extracted {len(dataset)} flows across classes: {dataset.get_classes()}")
```

### 2.2 Training Pipeline
```python
from person2_engine.src.dataset_adapter import load_csv_dataset
from person2_engine.src.model_trainer import train_candidate_models
from person2_engine.src.model_evaluator import evaluate_all_candidates
from person2_engine.src.model_selector import compare_candidates, select_best_candidate, save_trained_model_and_metadata

# 1. Load real PCAP dataset with capture groups
ds = load_csv_dataset("datasets/processed/iscxvpn2016_flows.csv")

# 2. Train candidates (group-aware capture splitting, zero intra-capture leakage)
candidates = train_candidate_models(ds, test_size=0.20, random_state=42)

# 3. Evaluate on held-out test partition
evaluations = evaluate_all_candidates(candidates)
print(compare_candidates(evaluations))

# 4. Select best candidate (highest Macro F1)
best_key = select_best_candidate(evaluations)

# 5. Persist weights and metadata contract
save_trained_model_and_metadata(
    candidates[best_key],
    evaluations[best_key],
    dataset_name=ds.metadata.name,
)
```

### 2.3 End-to-End Inference
```python
from person2_engine.src.packet_analyzer import analyze_capture_with_predictions

result = analyze_capture_with_predictions(
    "datasets/raw/iscxvpn2016/streaming/vpn_netflix_sample.pcap",
    model_id="gradient_boosting_traffic_classifier_v1",
    allow_unverified_domain=True,
)

for flow_pred in result.predictions:
    if flow_pred.prediction:
        print(f"Flow {flow_pred.model_info.get('flow_id')}:")
        print(f"  Prediction: {flow_pred.prediction.label} ({flow_pred.prediction.confidence:.2%})")
        print(f"  Top Features: {flow_pred.feature_importance}")
```

---

## 3. Retraining with Person 1 StrongSwan IPsec Data

When Person 1 provides ground-truth labeled StrongSwan PCAPs:
1. Place the PCAP files in `datasets/raw/person1_ipsec/`.
2. Define the entries in `datasets/manifests/person1_ipsec_manifest.json` following `datasets/manifests/person1_ipsec_manifest_template.json`.
3. Run manifest extraction to generate canonical features:
   ```bash
   python main.py --extract-manifest --manifest datasets/manifests/person1_ipsec_manifest.json -o datasets/processed/person1_ipsec_flows.csv
   ```
4. Train and select updated models:
   ```bash
   python main.py --train --dataset datasets/processed/person1_ipsec_flows.csv --model-id ipsec_strongswan_v1
   ```
5. All downstream APIs remain identical; the model artifacts are 100% interchangeable.
