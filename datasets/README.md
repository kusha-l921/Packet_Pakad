# Datasets for Phase 3 ML Intelligence & Training

## Overview

This directory contains real-world PCAP-derived encrypted flow datasets and automated test fixtures adhering strictly to the **Phase 2 25-Feature Schema (`FEATURE_SCHEMA_VERSION = "1.0"`)**.

Per Phase 3 requirements, all primary model training and evaluation is conducted on genuine captured network traffic flows extracted directly from PCAP files using the project's single source of truth: `person2_engine.src.packet_analyzer.analyze_capture_with_features`.

---

## 1. Directory Structure

```text
datasets/
├── manifests/
│   ├── iscxvpn2016_manifest.json         # Manifest cataloging real ISCX captures across 5 categories
│   └── person1_ipsec_manifest_template.json # Contract template for Person 1 StrongSwan PCAPs
├── raw/
│   └── iscxvpn2016/                      # Real PCAP captures organized by application category
│       ├── file_transfer/                # Real FTPS download and SCP file transfer PCAPs
│       ├── interactive/                  # Real OpenVPN AIM & ICQ chat PCAPs (VPN & Non-VPN)
│       ├── streaming/                    # Real OpenVPN Netflix video streaming PCAP
│       ├── voip/                         # Real Facebook Audio VoIP call PCAP
│       └── web/                          # Real HTTP/1.1, HTTP/2, QUIC/HTTP/3, TLS captures
├── processed/
│   └── iscxvpn2016_flows.csv             # 1,142 genuine flows extracted from raw PCAPs via Phase 1 & 2
├── synthetic_flows_test_fixture.csv      # SYNTHETIC test fixture for smoke tests and CI only
├── test_fixture_small.csv                # Lightweight (20 samples) deterministic test fixture
└── generate_benchmark_dataset.py         # Generator for synthetic test fixtures
```

---

## 2. Primary Real-World Dataset (`datasets/processed/iscxvpn2016_flows.csv`)

- **Dataset Origin**: Canadian Institute for Cybersecurity (CIC) / University of New Brunswick (UNB) [ISCX VPN-nonVPN 2016 (ISCXVPN2016)](https://www.unb.ca/cic/datasets/vpn.html) and verified protocol captures.
- **Extraction Mechanism**: All 25 numerical features are extracted directly from raw PCAP files using the project's Phase 1 packet analyzer and Phase 2 flow builder. **No CICFlowMeter/ISCXFlowMeter CSVs are used.**
- **Total Valid Flows**: 1,142 flows.
- **Classes**: 5 aligned canonical application categories:
  - `web`: Web browsing / HTTP / HTTP2 / QUIC / TLS (14 flows)
  - `streaming`: Video streaming / Netflix over OpenVPN (62 flows)
  - `voip`: Real-time voice calls / Facebook Audio (111 flows)
  - `file_transfer`: Bulk data transfers / FTPS & SCP (468 flows)
  - `interactive`: Chat / AIM & ICQ over OpenVPN and Non-VPN TLS (487 flows)
- **Capture Groups**: 20 distinct capture sessions for group-aware train/test splitting to prevent data leakage.

---

## 3. Label Mapping Contract

| Raw Dataset Label / Protocol | Canonical Project Label | Description |
| :--- | :--- | :--- |
| `browsing`, `http`, `https`, `tls` | `web` | Web browsing traffic |
| `streaming`, `video`, `netflix`, `youtube` | `streaming` | Video / audio streaming |
| `voip`, `audio`, `facebook_audio`, `skype` | `voip` | Real-time voice & calls |
| `file_transfer`, `ftps`, `scp`, `sftp` | `file_transfer` | Bulk file download / upload |
| `interactive`, `chat`, `aim`, `icq`, `ssh` | `interactive` | Interactive chat and shell sessions |

---

## 4. Synthetic Data Disclaimer

> [!WARNING]
> `synthetic_flows_test_fixture.csv` and `test_fixture_small.csv` contain **SYNTHETIC** statistical data.
> - They exist **solely** as development fixtures, smoke tests, and automated pipeline validation tools.
> - They must **never** be presented as real-world benchmarks.
> - High accuracy metrics achieved on synthetic data do **not** reflect real-world model performance.
> - Primary model training, evaluation, and reported performance derive 100% from `datasets/processed/iscxvpn2016_flows.csv`.

---

## 5. Domain Honesty & Person 1 StrongSwan Integration

> [!IMPORTANT]
> - **ISCX OpenVPN $\ne$ IPsec ESP/AH**: While ISCXVPN2016 provides genuine encrypted tunnel traffic, it utilizes OpenVPN (SSL/TLS encapsulation), not IPsec ESP (Protocol 50) or IKEv2 (UDP 500/4500).
> - Models trained on ISCX data carry the metadata tag `ipsec_compatibility.level: "unverified"`.
> - **Seamless Person 1 Replacement**: When Person 1 delivers ground-truth StrongSwan PCAPs:
>   1. Place captures into `datasets/raw/person1_ipsec/`.
>   2. Populate `datasets/manifests/person1_ipsec_manifest.json` using the provided template.
>   3. Run `python main.py --extract-manifest --manifest datasets/manifests/person1_ipsec_manifest.json --output datasets/processed/person1_ipsec_flows.csv`.
>   4. Run `python main.py --train --dataset datasets/processed/person1_ipsec_flows.csv`.
>   Zero architectural or feature schema changes are required.
