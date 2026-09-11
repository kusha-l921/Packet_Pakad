# Phase 3 Flow Dataset Contract Specification

## 1. Overview & Architectural Role

Phase 3 introduces a lightweight tabular machine learning intelligence layer that learns from flow records and predicts application categories for network flows extracted by Phase 2.

To guarantee zero feature drift and prevent silent data contamination, all datasets ingested into the pipeline must conform strictly to this **Dataset Contract**.

```text
Raw PCAP Files (ISCXVPN2016 / Future Person 1 StrongSwan)
                  ↓
       Dataset Manifest (JSON / CSV)
                  ↓
   Phase 1 Packet Analysis (Existing Engine)
                  ↓
    Phase 2 Flow Detection (Existing Engine)
                  ↓
Phase 2 Feature Extraction (Existing Engine - Single Source of Truth)
                  ↓
     Exactly 25 Canonical Features (v1.0)
                  ↓
           Feature Validator
                  ↓
      Label Mapper (5 Aligned Classes)
                  ↓
Group-Aware Partitioning (Zero Capture Leakage)
                  ↓
    Model Training, Evaluation, & Persistence
```

---

## 2. Real PCAP Data vs. Synthetic Test Fixture

> [!IMPORTANT]
> **Synthetic Data Notice**:
> The synthetic benchmark dataset (`datasets/synthetic_flows_test_fixture.csv`) is strictly an automated testing fixture and development tool. It is **not** real-world evaluation data, and its performance metrics must not be presented as real-world benchmark results.
>
> All reported model performance and production training are derived from **real PCAP network captures**.

### 2.1 Primary Real-World Dataset: ISCXVPN2016
- **Source**: UNB / Canadian Institute for Cybersecurity (ISCX VPN-nonVPN 2016).
- **Official URL**: [https://www.unb.ca/cic/datasets/vpn.html](https://www.unb.ca/cic/datasets/vpn.html)
- **Nature of Traffic**: Real packet captures containing encrypted sessions across OpenVPN tunnels and non-VPN standard services.
- **Role in Project**: Serves as the primary real-world tabular dataset for training and benchmarking until Person 1's IPsec captures become available.

### 2.2 ISCX OpenVPN vs. Final IPsec Domain Boundary
> [!WARNING]
> **Domain Discrepancy**:
> ISCXVPN2016 captures encapsulate traffic using **OpenVPN (SSL/TLS user-space tunnels)**. OpenVPN traffic is **not mathematically or structurally equivalent** to kernel-level **IPsec (ESP/AH)** encapsulation.
>
> Final IPsec validation and domain verification strictly require **Person 1's StrongSwan/IPsec gateway PCAP captures**.

---

## 3. Five Aligned Application Categories & Label Mapping

The project focuses on five aligned application categories. Raw capture labels from manifests are mapped deterministically via `LabelMapper`:

| ISCX / Source Category | Canonical Project Label | Backward Compatibility Alias | Typical Traffic / Applications |
|---|---|---|---|
| Browsing | `web` | - | HTTPS, HTTP/1.1, HTTP/2, QUIC/HTTP/3, Chromium, Firefox |
| Streaming | `streaming` | `video` | Netflix, YouTube HD, Vimeo, HLS / DASH streaming |
| VoIP | `voip` | - | SIP, RTP, Facebook audio, Skype calls, Discord |
| File Transfer | `file_transfer` | - | FTPS, SCP, SFTP, bulk file downloads / uploads |
| Chat | `interactive` | - | AIM chat, ICQ, SSH terminal, interactive shells |

*Note: Email and P2P are excluded from the primary 5-class experiment.*

---

## 4. Reusable PCAP Dataset Adapter & Manifest Contract

The pipeline does not hard-code paths to ISCX captures. Instead, it uses a decoupled, reusable manifest architecture defined in `person2_engine/src/pcap_dataset_adapter.py`.

### 4.1 Manifest Format (JSON / CSV)
Manifests define the captures to ingest, their expected labels, and capture groups for leakage-free splitting.

Example Manifest Entry:
```json
{
  "scenario_id": "vpn_netflix_sample_01",
  "pcap_path": "datasets/raw/iscxvpn2016/streaming/vpn_netflix_sample.pcap",
  "canonical_label": "streaming",
  "original_label": "VPN_Netflix",
  "source_dataset": "iscxvpn2016",
  "capture_group": "group_netflix_sample",
  "metadata": {
    "tunnel": "openvpn",
    "cipher": "aes-128-cbc",
    "application": "netflix"
  }
}
```

### 4.2 Seamless Person 1 StrongSwan / IPsec Retraining
When Person 1 provides StrongSwan PCAPs:
1. Place raw PCAPs in `datasets/raw/person1_ipsec/`.
2. Populate `datasets/manifests/person1_ipsec_manifest.json` using the provided template (`datasets/manifests/person1_ipsec_manifest_template.json`).
3. Set `source_dataset: "person1_ipsec"`.
4. Run the standard extraction command:
   ```bash
   python main.py --extract-manifest --manifest datasets/manifests/person1_ipsec_manifest.json -o datasets/processed/person1_ipsec_flows.csv
   ```
5. Retrain models without modifying a single line of feature extraction or model code:
   ```bash
   python main.py --train --dataset datasets/processed/person1_ipsec_flows.csv
   ```

---

## 5. Canonical Feature Schema (v1.0)

Every extracted flow record must conform to the 25 canonical features in deterministic order (`FEATURE_ORDER`):

| Index | Feature Name | Description | Constraints |
|---|---|---|---|
| 0 | `total_packets` | Total count of packets across both directions | $\ge 1$, Non-negative integer |
| 1 | `forward_packets` | Packets sent in forward direction | $\ge 0$, Non-negative integer |
| 2 | `backward_packets` | Packets sent in backward direction | $\ge 0$, Non-negative integer |
| 3 | `total_bytes` | Total byte volume across both directions | $\ge 0$, Non-negative integer |
| 4 | `forward_bytes` | Total byte volume in forward direction | $\ge 0$, Non-negative integer |
| 5 | `backward_bytes` | Total byte volume in backward direction | $\ge 0$, Non-negative integer |
| 6 | `minimum_packet_size` | Minimum observed packet length | $\ge 0$, bytes |
| 7 | `maximum_packet_size` | Maximum observed packet length | $\ge 0$, bytes |
| 8 | `mean_packet_size` | Arithmetic mean packet length | $\ge 0$, bytes |
| 9 | `standard_deviation_packet_size` | Standard deviation of packet sizes | $\ge 0$, bytes |
| 10 | `median_packet_size` | 50th percentile packet size | $\ge 0$, bytes |
| 11 | `forward_mean_packet_size` | Mean packet size in forward direction | $\ge 0$, bytes |
| 12 | `backward_mean_packet_size` | Mean packet size in backward direction | $\ge 0$, bytes |
| 13 | `flow_duration_seconds` | Elapsed duration between first and last packet | $\ge 0.0$, seconds |
| 14 | `packets_per_second` | Flow throughput in packets/second | $\ge 0.0$ |
| 15 | `bytes_per_second` | Flow throughput in bytes/second | $\ge 0.0$ |
| 16 | `mean_inter_arrival_time` | Mean time interval between consecutive packets | $\ge 0.0$, seconds |
| 17 | `minimum_inter_arrival_time` | Minimum packet inter-arrival time | $\ge 0.0$, seconds |
| 18 | `maximum_inter_arrival_time` | Maximum packet inter-arrival time | $\ge 0.0$, seconds |
| 19 | `standard_deviation_inter_arrival_time`| Standard deviation of inter-arrival times | $\ge 0.0$, seconds |
| 20 | `forward_packet_ratio` | $\text{forward\_packets} / \text{total\_packets}$ | $[0.0, 1.0]$ |
| 21 | `backward_packet_ratio` | $\text{backward\_packets} / \text{total\_packets}$ | $[0.0, 1.0]$ |
| 22 | `forward_byte_ratio` | $\text{forward\_bytes} / \text{total\_bytes}$ | $[0.0, 1.0]$ |
| 23 | `backward_byte_ratio` | $\text{backward\_bytes} / \text{total\_bytes}$ | $[0.0, 1.0]$ |
| 24 | `maximum_packets_in_one_second` | Peak burst packets in any 1-second window | $\ge 0$, Non-negative integer |

### Mathematical Rules & Invariants
- **Zero NaN/Inf Tolerance**: Any NaN or Infinite value in any feature fails validation immediately.
- **Ratio Boundary Invariants**: Forward and backward ratios must sum to $1.0 \pm 0.01$.

---

## 6. Group-Aware Splitting & Data Leakage Prevention

To prevent intra-capture flow leakage across training and test sets:
1. **Group Assignment**: Each flow is tagged with a `capture_group` identifying the source PCAP file or session.
2. **Partitioning Policy**:
   - For classes with $\ge 2$ capture groups, entire capture groups are held out exclusively in the test set (`GROUP_ISOLATED`). There is **zero capture group overlap** between train and test.
   - For classes with a single capture file, flows are partitioned sequentially/temporally (`WITHIN_CAPTURE_HOLDOUT`) to ensure all 5 classes remain evaluable.
3. **Scaler Fitting**: `StandardScaler` is fitted **strictly on the training partition** ($X_{\text{train}}$) and only applied (transformed) to the test partition ($X_{\text{test}}$). Zero test statistics leak into the training process.

> [!IMPORTANT]
> **Evaluation Validity & Capture Diversity**:
> Evaluation validity depends on capture diversity:
> - **`GROUP_ISOLATED`**: Training and test flows come from different capture groups. Supports evaluation on unseen capture groups. No cross-capture leakage was found for classes evaluated using `GROUP_ISOLATED` splitting.
> - **`WITHIN_CAPTURE_HOLDOUT`**: Training and test flows originate from the same capture group because independent capture diversity is unavailable in the dataset. Classes without sufficient independent capture diversity use `WITHIN_CAPTURE_HOLDOUT` and are explicitly marked as having insufficient independent capture diversity. This does NOT represent unseen-capture validation.
> - **`OVERALL_MIXED_EVALUATION`**: Combines results from different evaluation modes. Therefore, the overall experiment should not be interpreted as fully unseen-capture validation for every class.
