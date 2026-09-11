# Model Contract Specification (Phase 3)

## Overview

Phase 3 introduces a verified model integration and inference layer for the Network Security and IPsec Traffic Analysis Engine. To ensure scientific integrity and prevent false claims, any model integrated into this system must adhere to this strict **Model Contract**.

A model is **never** executed blindly, and heuristics or random predictions are **never** presented as machine learning inference.

---

## 1. The 11-Point Compatibility Criteria

Before any model can be accepted for inference, the `ModelValidator` evaluates the following eleven criteria:

| # | Check Item | Requirement | Failure Outcome |
|---|---|---|---|
| 1 | **Model Artifact Exists** | Model weight or serialized file must physically exist at the declared `artifact_path`. | Rejection (`INCOMPATIBLE`) |
| 2 | **Model Metadata Exists** | Valid `metadata.json` must be present and parseable into `ModelMetadata`. | Rejection (`INCOMPATIBLE`) |
| 3 | **Model Task is Known** | `prediction_task` must match a supported task (e.g., `application_category`, `attack_type`, `vpn_detection`, `encrypted_traffic_category`). | Rejection (`INCOMPATIBLE`) |
| 4 | **Input Type is Known** | `input_type` must be `"flow_features"`. Raw packet models (e.g. byte-sequence models) are rejected for the flow pipeline. | Rejection (`INCOMPATIBLE`) |
| 5 | **Feature Count Matches** | `feature_count` must be exactly 25, matching Phase 2 `FEATURE_SCHEMA_VERSION = "1.0"`. | Rejection (`INCOMPATIBLE`) |
| 6 | **Feature Names Match** | All 25 feature names must be an exact match with the Phase 2 `FEATURE_ORDER` definitions. | Rejection (`INCOMPATIBLE`) |
| 7 | **Feature Order Matches** | The sequential ordering of features must strictly correspond index-for-index with Phase 2. Matching set count without order match is rejected. | Rejection (`INCOMPATIBLE`) |
| 8 | **Feature Schema Version** | Declared `feature_schema_version` must be `"1.0"`. | Rejection (`INCOMPATIBLE`) |
| 9 | **Preprocessing Defined** | `preprocessing.type` must be explicitly defined and supported (`identity`, `standard_scaler`, `min_max_scaler`) with explicit vector parameters. | Rejection (`INCOMPATIBLE`) |
| 10 | **Label Mapping Exists** | `labels` must map every possible output integer index to an explicit, documented class string. | Rejection (`INCOMPATIBLE`) |
| 11 | **Output Format Understood**| Model adapter must yield standard probability distributions and class indices. | Rejection (`INCOMPATIBLE`) |

---

## 2. Phase 2 Feature Schema Contract

The feature vector consumed by Phase 3 consists of exactly 25 ordered numerical features (`FEATURE_SCHEMA_VERSION = "1.0"`):

1. `total_packets` (count)
2. `forward_packets` (count)
3. `backward_packets` (count)
4. `total_bytes` (bytes)
5. `forward_bytes` (bytes)
6. `backward_bytes` (bytes)
7. `minimum_packet_size` (bytes)
8. `maximum_packet_size` (bytes)
9. `mean_packet_size` (bytes)
10. `standard_deviation_packet_size` (bytes)
11. `median_packet_size` (bytes)
12. `forward_mean_packet_size` (bytes)
13. `backward_mean_packet_size` (bytes)
14. `flow_duration_seconds` (seconds)
15. `packets_per_second` (rate)
16. `bytes_per_second` (rate)
17. `mean_inter_arrival_time` (seconds)
18. `minimum_inter_arrival_time` (seconds)
19. `maximum_inter_arrival_time` (seconds)
20. `standard_deviation_inter_arrival_time` (seconds)
21. `forward_packet_ratio` (ratio in [0, 1])
22. `backward_packet_ratio` (ratio in [0, 1])
23. `forward_byte_ratio` (ratio in [0, 1])
24. `backward_byte_ratio` (ratio in [0, 1])
25. `maximum_packets_in_one_second` (count)

---

## 3. Preprocessing Specification

The system refuses to apply undocumented or assumed preprocessing.

Supported preprocessing specifications in `metadata.json`:

### Identity (No transformation)
```json
{
  "type": "identity"
}
```

### Standard Scaler (Z-score normalization)
Requires explicit length-25 arrays for `mean` and `std`:
```json
{
  "type": "standard_scaler",
  "parameters": {
    "mean": [ ... 25 floats ... ],
    "std": [ ... 25 floats ... ]
  }
}
```

### Min-Max Scaler (Range normalization)
Requires explicit length-25 arrays for `min` and `max`:
```json
{
  "type": "min_max_scaler",
  "parameters": {
    "min": [ ... 25 floats ... ],
    "max": [ ... 25 floats ... ]
  }
}
```

If any parameter length does not equal 25 or if standard deviation is zero/negative, the model is rejected.

---

## 4. Model States

The integration layer enforces 4 distinct model operational states:

1. **`READY_FOR_INFERENCE`**:
   - Model passes all 11 technical criteria.
   - Domain validation is verified, OR the caller explicitly provided `--allow-unverified-domain` (with mandatory logged warnings).

2. **`INCOMPATIBLE`**:
   - Model fails one or more technical criteria (e.g. wrong feature count, wrong names, missing parameters, nonexistent file).
   - Inference is strictly blocked.

3. **`MODEL_UNAVAILABLE`**:
   - No model artifact matching the requested task or feature schema is registered.
   - Clean, structured null result is returned. The engine never crashes or hallucinates predictions.

4. **`TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED`**:
   - The model mathematically accepts the 25 features and has valid weights.
   - However, the model was trained on general unencrypted or non-IPsec traffic (e.g. standard TLS/QUIC) and has never been validated against StrongSwan/ESP encapsulated traffic.
   - Inference is withheld by default to prevent misleading security assessments unless overridden.

---

## 5. Technical Compatibility vs. Real IPsec Domain Validation

A critical scientific distinction enforced by this engine:

> **Technical Compatibility** means the model can parse and accept a 25-element vector, apply normalization, and run matrix multiplications without crashing.

> **Domain Validation** means the model has been empirically evaluated against ground-truth IPsec/ESP/IKE traffic and achieves statistically significant, reproducible accuracy under IPsec encapsulation conditions.

Because IPsec encapsulation alters packet padding, MTU fragmentation, ESP overhead, and timing characteristics, models trained on plain TCP/UDP cannot be assumed to generalize to IPsec.
