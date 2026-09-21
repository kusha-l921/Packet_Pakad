---
document_id: model_uncertainty
title: Machine Learning Model Uncertainty and Confidence Tiers
category: classification
section: Model Uncertainty
source: knowledge_base/classification/model_uncertainty.md
version: "1.0"
topic: uncertainty_quantification
authority: project_phase3_spec
project_specific: true
keywords:
  - model uncertainty
  - confidence tiers
  - HIGH confidence
  - MEDIUM confidence
  - LOW confidence
  - LOW_CLASSIFICATION_CONFIDENCE
  - uncertainty vs risk
---

# Machine Learning Model Uncertainty and Confidence Tiers

## Concept of Classification Confidence

In Phase 3 traffic-category resemblance modeling, point predictions are accompanied by uncertainty quantification. Model confidence measures the dispersion and concentration of the model's output probability distribution over the five traffic categories.

When an incoming flow's statistical features closely match the training distribution of a specific category, the model exhibits low prediction entropy (high confidence). When features fall near decision boundaries or diverge from observed training envelopes, prediction entropy increases (low confidence).

## Confidence Tiers

The project defines three explicit confidence tiers:

### HIGH Confidence
* **Definition**: The predicted top category probability is substantially elevated above competing classes (e.g., probability exceeds 0.70 with low prediction entropy).
* **Meaning**: The flow's 25-feature vector strongly aligns with the established statistical signature of the indicated traffic category.

### MEDIUM Confidence
* **Definition**: The predicted top category holds a moderate plurality (e.g., probability between 0.45 and 0.70) with a moderate margin over the second-ranked class.
* **Meaning**: The flow exhibits partial characteristics of the predicted category, but shares noticeable feature overlap with an alternative category.

### LOW Confidence (`LOW_CLASSIFICATION_CONFIDENCE`)
* **Definition**: The probability distribution across categories is dispersed or near-uniform, or the top class probability falls below the confidence cutoff (e.g., < 0.45).
* **Meaning**: The model cannot reliably distinguish between candidate categories based on the extracted feature vector. This indicates out-of-distribution traffic, mixed-behavior connections, or transitional network dynamics.

## Critical Principle: Model Uncertainty Is Not Behavioral Risk

The project enforces an absolute division between model uncertainty and behavioral risk:

```text
Model Uncertainty (Phase 3)
           ≠
Behavioral Risk (Phase 4)
```

| Dimension | Model Uncertainty (Phase 3) | Behavioral Risk (Phase 4) |
| :--- | :--- | :--- |
| **Domain** | Machine learning statistical reliability | Observable physical network anomalies |
| **Measurement** | Output class probability entropy / margin | Sum of deterministic indicator risk points |
| **Output Range** | HIGH, MEDIUM, LOW confidence | LOW (0–24), MEDIUM (25–49), HIGH (50–74), CRITICAL (75–100) |
| **Contribution** | Contributes **0 points** to risk scoring | Directly computes the risk score |
| **Interpretation** | How sure the ML model is about resemblance | How strongly the flow deviates in rate, volume, or pacing |

### Practical Examples
1. **Low Confidence, Zero Risk**: A newly introduced, benign proprietary enterprise synchronization client creates unusual packet size pairings. The ML classifier marks `LOW_CLASSIFICATION_CONFIDENCE` because the pattern matches no known training category. However, since the flow transmits at calm packet rates and low volume, zero behavioral indicators trigger, resulting in a **LOW risk score of 0**.
2. **High Confidence, Critical Risk**: A massive automated data scraping script mimics web browsing packet structures perfectly. The ML model predicts `web` with **HIGH confidence**. However, the script pushes hundreds of megabytes per second in sustained bursts, triggering `UNUSUAL_HIGH_UPLOAD_VOLUME`, `UNUSUAL_HIGH_PACKET_RATE`, and `UNUSUAL_BURST_ACTIVITY`, resulting in a **HIGH or CRITICAL risk score**.
