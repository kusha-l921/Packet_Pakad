# Traffic Analysis ML Model Integration Guide

This guide explains how to integrate your custom Machine Learning (ML) traffic classification model into the SIH-160 IPsec platform.

---

## 1. Architectural Overview

The traffic analysis layer evaluates live or captured **ESP (Encapsulated Security Payload)** data-plane traffic.

```text
Raw ESP / NAT-T Packets
         ↓
FlowEngine.process_packet(esp_meta)
         ↓  (Sliding Window: 200 pkts, Stride: 25 pkts)
FlowRecord.extract_features()
         ↓  (25 Statistical Flow Features)
MLModelAdapter.predict(X) / MLModelAdapter.classify_flow(features)
         ↓
FlowVerdict (Verdict, Confidence, Flow Metrics)
         ↓
output/traffic_flow_report.json  &  unified_rag_payload.json
```

---

## 2. The 25 Extracted Statistical Flow Features

When a sliding window fills (or on flow inactivity timeout), [`FlowRecord.extract_features()`](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/flow_engine/FlowRecord.py) computes an ordered dictionary of **25 statistical flow metrics**:

| Index | Feature Name | Data Type | Description |
| :---: | :--- | :---: | :--- |
| `0` | `total_packets` | `float` | Number of packets in sliding window |
| `1` | `forward_packets` | `float` | Number of outbound packets from initiator |
| `2` | `backward_packets` | `float` | Number of inbound packets from responder |
| `3` | `total_bytes` | `float` | Cumulative payload and wire bytes |
| `4` | `forward_bytes` | `float` | Outbound bytes from initiator |
| `5` | `backward_bytes` | `float` | Inbound bytes from responder |
| `6` | `minimum_packet_size` | `float` | Minimum observed wire packet length (bytes) |
| `7` | `maximum_packet_size` | `float` | Maximum observed wire packet length (bytes) |
| `8` | `mean_packet_size` | `float` | Mean wire packet length (bytes) |
| `9` | `standard_deviation_packet_size` | `float` | Std dev of packet length (bytes) |
| `10` | `median_packet_size` | `float` | Median wire packet length (bytes) |
| `11` | `forward_mean_packet_size` | `float` | Mean packet size in forward direction |
| `12` | `backward_mean_packet_size` | `float` | Mean packet size in backward direction |
| `13` | `flow_duration_seconds` | `float` | Time delta between first and latest packet in window |
| `14` | `packets_per_second` | `float` | Instantaneous packet rate |
| `15` | `bytes_per_second` | `float` | Instantaneous byte throughput |
| `16` | `mean_inter_arrival_time` | `float` | Mean inter-arrival time between packets (seconds) |
| `17` | `minimum_inter_arrival_time` | `float` | Minimum packet inter-arrival time (seconds) |
| `18` | `maximum_inter_arrival_time` | `float` | Maximum packet inter-arrival time (seconds) |
| `19` | `standard_deviation_inter_arrival_time` | `float` | Std dev of inter-arrival time (jitter) |
| `20` | `forward_packet_ratio` | `float` | Ratio of forward packets ($N_{fwd} / N_{tot}$) |
| `21` | `backward_packet_ratio` | `float` | Ratio of backward packets ($N_{bwd} / N_{tot}$) |
| `22` | `forward_byte_ratio` | `float` | Ratio of forward bytes ($B_{fwd} / B_{tot}$) |
| `23` | `backward_byte_ratio` | `float` | Ratio of backward bytes ($B_{bwd} / B_{tot}$) |
| `24` | `maximum_packets_in_one_second` | `float` | Peak 1-second packet count bin |

---

## 3. How to Plug In Your Model

The pipeline uses [`flow_engine/mlAdapter.py`](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/flow_engine/mlAdapter.py), which implements [`TrafficClassifierProtocol`](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/flow_engine/mlAdapter.py).

Any model (Scikit-Learn, XGBoost, LightGBM, PyTorch, or ONNX) can be plugged in directly as long as it exposes a standard `.predict(X)` method:

```python
# Interface Contract
def predict(self, X: list[list[float]]) -> list[Any]:
    ...
```

### Example 1: Loading a Scikit-Learn or XGBoost Model (`.pkl` / `.joblib`)

```python
import joblib
from flow_engine import MLModelAdapter
from pipeline.integratedPipeline import IntegratedPipeline

# 1. Load your pre-trained model
my_classifier = joblib.load("models/ipsec_traffic_classifier.pkl")

# 2. Wrap it in the adapter
ml_adapter = MLModelAdapter(
    model=my_classifier,
    model_name="xgboost_ipsec_classifier_v1"
)

# 3. Instantiate the pipeline with your adapter
pipeline = IntegratedPipeline(
    output_dir="output",
    ml_model=ml_adapter
)
```

### Example 2: Loading an ONNX Runtime Model

```python
import numpy as np
import onnxruntime as ort
from flow_engine import MLModelAdapter
from pipeline.integratedPipeline import IntegratedPipeline

class OnnxTrafficClassifier:
    def __init__(self, model_path: str):
        self.session = ort.InferenceSession(model_path)
        self.input_name = self.session.get_inputs()[0].name
        self.labels = ["BENIGN_IPSEC", "DATA_EXFILTRATION", "C2_BEACONING"]

    def predict(self, X: list[list[float]]) -> list[str]:
        inputs = np.array(X, dtype=np.float32)
        outputs = self.session.run(None, {self.input_name: inputs})[0]
        class_indices = np.argmax(outputs, axis=1)
        return [self.labels[idx] for idx in class_indices]

    def predict_proba(self, X: list[list[float]]) -> list[list[float]]:
        inputs = np.array(X, dtype=np.float32)
        outputs = self.session.run(None, {self.input_name: inputs})[0]
        # Softmax probabilities
        exp = np.exp(outputs - np.max(outputs, axis=1, keepdims=True))
        return (exp / np.sum(exp, axis=1, keepdims=True)).tolist()

# Plug into the pipeline
onnx_model = OnnxTrafficClassifier("models/traffic_model.onnx")
pipeline = IntegratedPipeline(output_dir="output", ml_model=onnx_model)
```

---

## 4. Output Format in Reports

When inference runs, verdicts are saved in [`output/traffic_flow_report.json`](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/output/traffic_flow_report.json) and packaged into [`output/unified_rag_payload.json`](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/output/unified_rag_payload.json):

```json
{
  "flow_key": ["10.0.0.1", "192.168.1.105"],
  "verdict": "BENIGN_IPSEC",
  "trigger_type": "WINDOW_STRIDE",
  "packet_count": 250,
  "duration_seconds": 5.24,
  "features": {
    "total_packets": 250.0,
    "forward_packets": 140.0,
    "backward_packets": 110.0,
    "packets_per_second": 47.7,
    "bytes_per_second": 35300.0,
    ...
  }
}
```

---

## 5. Behavior When No Model is Loaded
If you run the pipeline without supplying an ML model:
- All 25 flow features are still extracted accurately without errors.
- The `verdict` field safely records `null` (or baseline heuristics if `use_ml_fallback=True`).
- No crashes or exceptions occur.
