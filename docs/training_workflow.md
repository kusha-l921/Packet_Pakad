# Phase 3 Training and Retraining Workflow

## 1. Overview

Phase 3 implements a fully reproducible, lightweight CPU-friendly machine learning training pipeline for tabular encrypted flow features. It avoids deep learning, GPU requirements, or opaque feature embeddings, focusing on fast, explainable, and verifiable classifiers operating strictly on the 25 canonical Phase 2 features.

---

## 2. End-to-End Pipeline Stages

```text
[Raw PCAPs + Manifest]
           ↓
 1. PCAP Feature Extraction (extract_flows_from_manifest)
           ↓
 2. Schema Validation (validate_csv_dataset)
           ↓
 3. Dataset Ingestion (load_csv_dataset with capture_group)
           ↓
 4. Label Normalization (LabelMapper -> 5 canonical categories)
           ↓
 5. Group-Aware Split & Preprocessing (prepare_train_test_split):
    - Multi-capture classes held out by entire capture group (GROUP_ISOLATED, zero cross-capture leakage)
    - Single-capture classes held out within capture (WITHIN_CAPTURE_HOLDOUT, explicit diversity limitation)
    - StandardScaler fit strictly on X_train, applied to X_test
           ↓
 6. Training of 4 Lightweight Tabular Candidates:
    - Random Forest (100 trees, max_depth=12)
    - Gradient Boosting (100 estimators, max_depth=4)
    - Extra Trees (100 trees, max_depth=12)
    - Logistic Regression (l2 regularized linear baseline)
           ↓
 7. Multi-Metric Evaluation on Held-Out Test Groups (evaluate_all_candidates):
    - Macro F1, Macro Recall, Macro Precision, Accuracy, Confusion Matrix, Latency
           ↓
 8. Candidate Comparison & Selection (select_best_candidate via Macro F1 + Latency)
           ↓
 9. Persistence of Weights (.joblib) & Metadata Contract (.json)
           ↓
 10. Automatic Discovery by ModelRegistry
```

---

## 3. Real PCAP Candidate Comparison & Selection

Trained and evaluated on real PCAP flows (`datasets/processed/iscxvpn2016_flows.csv`, 1,142 flows across 20 distinct capture sessions):

```text
=====================================================================================
   PHASE 3: CANDIDATE MODEL COMPARISON SUMMARY (REAL PCAP DATASET)
=====================================================================================
Model Key              Accuracy   Macro F1   Weighted F1   Train (s)   Latency (ms)
-------------------------------------------------------------------------------------
random_forest          0.1982     0.2739     0.1179        0.097       0.039       
gradient_boosting      0.1750     0.3942     0.0690        0.809       0.007       
extra_trees            0.2000     0.2613     0.1159        0.109       0.040       
logistic_regression    0.1500     0.3485     0.0509        0.017       0.002       
=====================================================================================
```

### Selected Best Candidate: `gradient_boosting`
- **Macro F1**: 0.3942 (highest across all 4 candidates)
- **Macro Recall**: 0.7918
- **Inference Latency**: 0.007ms / flow
- **Top Influential Features**:
  1. `minimum_packet_size` (0.2951)
  2. `mean_inter_arrival_time` (0.2489)
  3. `backward_mean_packet_size` (0.1193)
  4. `forward_bytes` (0.0988)
  5. `maximum_packet_size` (0.0650)

> [!NOTE]
> **Scientific Integrity & Honest Metrics**:
> Unlike the synthetic benchmark fixture (which produced artificially inflated ~98-100% scores on simulated distributions), evaluation on real held-out PCAP captures reflects true generalization difficulty across heterogeneous real-world network sessions. Real captures show realistic inter-capture variance and honest per-class metrics.

---

## 4. Retraining Workflow for Future Person 1 StrongSwan IPsec Data

When Person 1 provides StrongSwan/IPsec PCAP captures, the retraining workflow requires zero architectural changes:

```text
Person 1 StrongSwan PCAPs
           ↓
Populate datasets/manifests/person1_ipsec_manifest.json
           ↓
Run PCAP Extraction:
python main.py --extract-manifest \
  --manifest datasets/manifests/person1_ipsec_manifest.json \
  -o datasets/processed/person1_ipsec_flows.csv
           ↓
Retrain Lightweight Candidate Models:
python main.py --train \
  --dataset datasets/processed/person1_ipsec_flows.csv \
  --model-id ipsec_strongswan_v1
           ↓
Models automatically evaluate, select best, and persist to:
- models/trained/ipsec_strongswan_v1.joblib
- models/metadata/ipsec_strongswan_v1.json
           ↓
Run Verification Inference:
python main.py capture.pcap --predict --model-id ipsec_strongswan_v1
```
