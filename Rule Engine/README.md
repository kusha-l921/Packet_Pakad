# SIH-160 Rule Engine

A modular Python framework for IKEv2 / IPsec protocol compliance auditing, cryptographic posture classification, X.509 PKI health monitoring, and real-time ESP machine learning traffic classification.

---

## Directory Structure

```
SIH-160 Rule Engine/
├── rfc_engine/          # RFC compliance rule engine, control-plane audits & 64-packet anti-replay
├── cert_engine/         # Dedicated PKI health engine & strongSwan VICI daemon ingestion
├── vector_engine/       # 19-D cryptographic vector engine, cosine similarity & policy anchors
├── flow_engine/         # Sliding-window ESP flow accumulator & ML traffic dispatcher
├── packet_extractor/    # Wire packet dissector for IKEv2 & ESP
├── tests/               # Automated test suites (77/77 tests passing)
└── docs/                # Architecture, API signatures, and file overview guides
```

---

## Running Tests

All 6 test suites can be run with the virtual environment:

```powershell
.\.venv\Scripts\python.exe tests/test_rfcRuleEngine.py
.\.venv\Scripts\python.exe tests/test_certHealthEngine.py
.\.venv\Scripts\python.exe tests/test_vectorEngine.py
.\.venv\Scripts\python.exe tests/test_cosineSimilarity.py
.\.venv\Scripts\python.exe tests/test_flowEngine.py
.\.venv\Scripts\python.exe tests/test_daemonCertIngest.py
```

---

## Documentation

* **[docs/FILE_OVERVIEW.md](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/docs/FILE_OVERVIEW.md)**: Detailed overview of each package and script.
* **[docs/integration.md](file:///c:/Users/Cat/Desktop/SIH-160%20Rule%20Engine/docs/integration.md)**: Complete developer integration guide and API reference.
