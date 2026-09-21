# RAG Report Generator — Subsystem Documentation (Parts 1 & 2)

> **Subsystem**: `rag_report_generator`  
> **Phase**: Part 1 (Knowledge Base Ingestion & Retrieval) & Part 2 (Grounded LLM Context, Structured Report Generation & Multi-Layer Validation)  
> **Target Consumer**: Part 3 (End-to-End CLI & Dashboard Integration)

---

## 1. Executive Summary & Purpose

The `rag_report_generator` is an auditable, zero-hallucination report generation subsystem for the Person 2 network-security traffic analysis project.

### Core Architectural Principle: Two Independent Sources of Truth

```text
┌────────────────────────────────────────────────────────┐
│     SOURCE OF TRUTH #1: OBSERVED ANALYSIS FACTS         │
│               (Phase 5 Unified JSON)                   │
├────────────────────────────────────────────────────────┤
│ • Packet counts, flow counts, duration, total bytes    │
│ • Observed transport & encryption protocols (ESP/AH)   │
│ • IPsec detection flags (ESP, AH, IKE, NAT-T)          │
│ • Classification: predicted category, confidence, tiers│
│ • Phase 4 risk score (0-100), severity tier            │
│ • Active behavioral indicators (out of 6 canonical)    │
│ • Model uncertainty metrics (level, entropy, margin)   │
│ • Active domain validation status & evaluation mode    │
└────────────────────────────────────────────────────────┘
                           +
┌────────────────────────────────────────────────────────┐
│   SOURCE OF TRUTH #2: TRUSTED EXPLANATORY KNOWLEDGE    │
│                 (Part 1 RAG Evidence)                  │
├────────────────────────────────────────────────────────┤
│ • Canonical indicator definitions & risk points        │
│ • Feature meanings & operational interpretations       │
│ • Protocol explanations (ESP payload opacity, AH, IKE) │
│ • Non-malice caveats & indicator limitations           │
│ • Evaluation mode definitions (GROUP_ISOLATED, etc.)   │
│ • Domain validation policies (UNVERIFIED vs VERIFIED)  │
└────────────────────────────────────────────────────────┘
                           │
                           ▼
          Controlled Context & Prompt Template
                           │
                           ▼
             LLM Provider (Mock / Ollama)
                           │
                           ▼
                 Structured Report JSON
                           │
                           ▼
          Deterministic Multi-Layer Validator
        (Schema + Facts + Evidence + Terminology)
                           │
                           ▼
             Deterministic Markdown Renderer
                           │
                           ▼
              report.json  +  report.md
```

### Strict Non-Negotiable Boundaries
1. **Never Invent or Alter Numbers**: Packet counts, flow counts, bytes, durations, risk scores, confidence values, and probabilities are strictly preserved from Source of Truth #1.
2. **Never Recalculate Risk**: The LLM never recalculates or devises alternative risk scores; it only summarizes the deterministic Phase 4 risk score.
3. **Never Invent Indicators**: Only indicators present in Phase 5 JSON are allowed in the report.
4. **Traffic Category Resemblance**: Classification represents statistical feature resemblance, NOT guaranteed application identity.
5. **Domain Policy Enforcement**: Unverified IPsec traffic (`TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED`) must never be described as "IPsec-validated".
6. **Risk vs. Uncertainty Separation**: Model uncertainty (classification confidence dispersion) is strictly decoupled from behavioral risk.
7. **Neutral, Evidence-Grounded Tone**: Prohibits sensationalist phrases like "attack detected", "malware confirmed", "definitely malicious", or "intrusion identified".
8. **Structured JSON First**: Generation targets structured JSON first, undergoes multi-layer validation, and is only then rendered to Markdown deterministically.

---

## 2. Complete Pipeline Architecture

```mermaid
flowchart TD
    subgraph InputLayer [Authoritative Inputs]
        P5[Phase 5 Unified JSON\n(Authoritative Facts)]
        KB[Part 1 Curated Knowledge Base\n(14 Documents, 106 Chunks)]
    end

    subgraph ContextLayer [Context & Query Planning]
        FACTS[extract_analysis_facts\n(Preserves exact numeric precision)]
        PLAN[QueryPlanner\n(Constructs queries only for active concepts)]
        RETR[Part 1 Hybrid Retriever\n(Cosine Vector + Exact Boost + Keyword Overlap)]
        DEDUP[Evidence Deduplication\n(by document_id + section, keeps highest score)]
        CTX[ContextBuilder\n(Facts Block + Evidence Block + Rules Block)]
    end

    subgraph GenerationLayer [Generation Layer]
        PROMPT[PromptTemplate\n(Strict JSON Schema Description)]
        LLM[LLMProvider\n(MockLLMProvider / OllamaProvider)]
        REPAIR[JSONRepair\n(Safe structural cleanup & parsing)]
    end

    subgraph ValidationLayer [Deterministic Multi-Layer Validation]
        SCHEMA_CHK[Schema Completeness Checker]
        FACT_CHK[FactChecker\n(Verifies counts, scores, flags, indicators)]
        EVID_CHK[EvidenceChecker\n(Validates cited evidence IDs exist)]
        TERM_CHK[TerminologyChecker\n(Rejects sensationalism & false IPsec claims)]
    end

    subgraph OutputLayer [Outputs]
        MD_GEN[MarkdownRenderer\n(Deterministic formatting)]
        JSON_OUT[report.json\n(Machine-readable)]
        MD_OUT[report.md\n(Human-readable)]
    end

    P5 --> FACTS
    FACTS --> PLAN
    PLAN --> RETR
    KB --> RETR
    RETR --> DEDUP
    FACTS --> CTX
    DEDUP --> CTX
    CTX --> PROMPT
    PROMPT --> LLM
    LLM --> REPAIR
    REPAIR --> SCHEMA_CHK
    SCHEMA_CHK --> FACT_CHK
    FACT_CHK --> EVID_CHK
    EVID_CHK --> TERM_CHK
    TERM_CHK --> MD_GEN
    TERM_CHK --> JSON_OUT
    MD_GEN --> MD_OUT
```

---

## 3. Directory Structure

```text
rag_report_generator/
├── __init__.py                 # Public API (build_index, retrieve, generate_report, generate_report_from_phase5)
├── __main__.py                 # CLI interface (build, retrieve, generate)
├── README.md                   # Complete architectural documentation
├── knowledge_base/             # 14 curated markdown documents across 7 categories
├── storage/                    # Persisted vector index (chunks_and_vectors.json)
├── src/
│   ├── config.py               # RAGConfig
│   ├── context/
│   │   ├── __init__.py
│   │   ├── facts.py            # extract_analysis_facts
│   │   ├── flow_selector.py    # FlowSelector (deterministic notable flow ranking)
│   │   ├── query_plan.py       # QueryPlanner (constructs queries for active concepts)
│   │   └── context_builder.py  # ContextBuilder (deduplication & prompt assembly)
│   ├── embeddings/             # DeterministicLocalEmbeddingProvider (384-d dense vectors)
│   ├── generation/
│   │   ├── __init__.py
│   │   ├── llm_provider.py     # LLMProvider ABC & MockLLMProvider
│   │   ├── ollama_provider.py  # OllamaProvider (HTTP JSON client for local Ollama)
│   │   ├── prompt_template.py  # PromptTemplate with strict schema instructions
│   │   ├── json_repair.py      # Safe JSON extraction & fence removal
│   │   ├── markdown_renderer.py# Deterministic Markdown renderer
│   │   └── report_generator.py # Pipeline coordinator
│   ├── ingestion/              # DocumentLoader, DocumentNormalizer, SemanticChunker
│   ├── models/
│   │   ├── __init__.py
│   │   ├── chunk.py            # DocumentChunk
│   │   ├── document.py         # Document
│   │   ├── evidence.py         # RetrievedEvidence, RetrievalResult, BuildStats
│   │   ├── facts.py            # AnalysisFacts, CaptureFacts, IPsecFacts, etc.
│   │   ├── report.py           # Report, ReportMetadata, ExecutiveSummary, etc.
│   │   └── report_metadata.py  # ReportConfig, ValidationSummary, GeneratedReport
│   ├── retrieval/              # FlatCosineVectorStore, HybridRetriever, QueryBuilder
│   └── validation/
│       ├── __init__.py
│       ├── fact_checker.py     # Numeric, indicator, protocol, and enum checker
│       ├── evidence_checker.py # Citation existence & auditability checker
│       ├── terminology_checker.py # Tone, non-malice, and domain policy checker
│       └── report_validator.py # Multi-layer validation orchestrator
└── tests/
    ├── fixtures/               # 7 synthetic Phase 5 fixtures
    │   ├── low_risk.json
    │   ├── high_risk.json
    │   ├── medium_risk.json
    │   ├── ipsec_unverified.json
    │   ├── ipsec_verified.json
    │   ├── high_uncertainty.json
    │   └── mixed_indicators.json
    ├── test_facts_extraction.py
    ├── test_flow_selector.py
    ├── test_query_plan.py
    ├── test_context_builder.py
    ├── test_llm_provider.py
    ├── test_validators.py
    ├── test_markdown_renderer.py
    ├── test_report_pipeline.py
    └── test_ollama_integration.py
```

---

## 4. Input Contract

Part 2 accepts two inputs:

### Input A — Phase 5 Unified JSON
Conforms to the project's integration schema:
```json
{
  "analysis_metadata": {
    "engine_version": "2.0.0",
    "feature_schema_version": "1.0",
    "integration_schema_version": "1.0",
    "evaluation_mode": "GROUP_ISOLATED"
  },
  "capture_summary": {
    "total_packets": 1024,
    "total_flows": 12,
    "duration": 35.7,
    "total_bytes": 850000,
    "protocols": { "ESP": 800, "UDP": 224 }
  },
  "ipsec_analysis": {
    "detected": true,
    "esp_detected": true,
    "ah_detected": false,
    "ike_detected": true,
    "nat_t_detected": false,
    "domain_validation_status": "TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED",
    "allow_unverified_domain": false
  },
  "flows": [ ... ],
  "prediction": {
    "predicted_category": "web",
    "confidence": 0.812,
    "confidence_tier": "HIGH",
    "category_probabilities": { "web": 0.812, "video": 0.088, ... }
  },
  "model_uncertainty": {
    "level": "LOW",
    "entropy": 0.35,
    "margin": 0.724
  },
  "behavioral_analysis": {
    "triggered_indicators": ["UNUSUAL_HIGH_PACKET_RATE"],
    "indicator_points": { "UNUSUAL_HIGH_PACKET_RATE": 20 }
  },
  "security_assessment": {
    "risk_score": 20,
    "risk_level": "LOW"
  }
}
```

### Input B — RetrievedEvidence[]
Directly returned by Part 1:
```python
@dataclass
class RetrievedEvidence:
    evidence_id: str         # e.g. "E001"
    document_id: str         # e.g. "behavioral_risk_indicators"
    title: str               # e.g. "Phase 4 Behavioral Risk Indicators"
    category: str            # e.g. "behavioral_indicator"
    section: str             # e.g. "UNUSUAL_HIGH_PACKET_RATE"
    text: str                # Explanatory content
    score: float             # Retrieval relevance score
    source: str              # File path
    metadata: dict           # Metadata dict
```

---

## 5. Authoritative AnalysisFacts Layer

Before prompt construction, `extract_analysis_facts` converts raw Phase 5 JSON into strongly-typed `AnalysisFacts`:
* `CaptureFacts`: packet count, flow count, duration (seconds), total bytes, protocols.
* `IPsecFacts`: detected, esp_detected, ah_detected, ike_detected, nat_t_detected, domain_validation_status, allow_unverified_domain.
* `ClassificationFacts`: predicted_category, confidence (exact float), confidence_tier, category_probabilities, prediction_status.
* `BehavioralFacts`: risk_score (exact integer), risk_level, triggered_indicators (strict list), indicator_points.
* `UncertaintyFacts`: level, entropy, margin, reason.
* `EvaluationFacts`: evaluation_mode, dataset_provenance.
* `selected_flows`: up to `max_flows` (default 5) selected deterministically.

### Deterministic Flow Selection Rules
`FlowSelector` ranks flows according to strict operational criteria:
1. Flows with `CRITICAL` or `HIGH` risk (risk_score >= 50 descending).
2. Number of active behavioral indicators.
3. Total risk score.
4. IPsec protocol involvement (protocol 50/51 or UDP 500/4500).
5. Byte volume descending.

---

## 6. Query Planning & Retrieval Interaction

Part 2 constructs retrieval queries programmatically without prompting an LLM:
* **Indicators**: for each active indicator in `triggered_indicators` -> `"{indicator} meaning"`.
* **Protocols**: if ESP detected -> `"ESP Encapsulating Security Payload meaning"`; if AH -> `"AH Authentication Header meaning"`; if IKE -> `"IKE Internet Key Exchange meaning"`.
* **Domain Status**: if unverified -> `"TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED meaning"`.
* **Evaluation Mode**: `"{evaluation_mode} evaluation mode meaning"`.
* **Classification**: `"{predicted_category} traffic category resemblance classification"`.
* **Uncertainty**: `"model uncertainty versus behavioral risk"`.

### Evidence Deduplication
Passages are deduplicated by `(document_id, section)`, retaining the highest-scoring chunk. The total number of chunks is capped by `config.max_evidence` (default 8).

---

## 7. LLM Provider Abstraction

The report generator does not hard-code model dependencies:
* `LLMProvider` (Abstract Base Class): defines `generate(prompt: str, config: ReportConfig) -> str`.
* `MockLLMProvider`: deterministic, offline-capable provider for test suites and environments without Ollama. Supports mutation modes (`altered_risk_score`, `invented_indicator`, `malformed_json`, etc.) to test validator resilience.
* `OllamaProvider`: communicates with a local Ollama daemon via `POST http://localhost:11434/api/generate` using standard library `urllib` and JSON format enforcement. Gracefully reports errors when the server is unreachable.

---

## 8. Structured Report JSON Schema

The generation layer requests strict JSON conforming to the `Report` schema:

```json
{
  "report_metadata": {
    "report_id": "rep_mock_001",
    "generated_at": "2026-09-21T13:22:21Z",
    "report_schema_version": "1.0",
    "input_schema_version": "1.0",
    "rag_knowledge_base_version": "1.0",
    "llm_provider": "mock",
    "llm_model": "mock-deterministic"
  },
  "executive_summary": "Automated traffic evaluation processed 1024 packets...",
  "capture_overview": {
    "packet_count": 1024,
    "flow_count": 12,
    "duration_seconds": 35.7,
    "total_bytes": 850000,
    "summary_text": "Observed 1024 packets..."
  },
  "ipsec_analysis": {
    "detected": true,
    "esp_detected": true,
    "ah_detected": false,
    "ike_detected": true,
    "nat_t_detected": false,
    "domain_validation_status": "TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED",
    "explanation": "...",
    "evidence_ids": ["E001", "E002"]
  },
  "traffic_classification": {
    "predicted_category": "web",
    "confidence": 0.812,
    "probabilities": { "web": 0.812, ... },
    "resemblance_explanation": "...",
    "evidence_ids": ["E003"]
  },
  "behavioral_analysis": {
    "risk_score": 20,
    "risk_level": "LOW",
    "triggered_indicators": ["UNUSUAL_HIGH_PACKET_RATE"],
    "explanation": "...",
    "non_malice_disclaimer": "Behavioral risk indicators highlight statistical deviations...",
    "evidence_ids": ["E004"]
  },
  "flow_findings": [
    {
      "flow_id": "flow_esp_001",
      "description": "...",
      "risk_score": 20,
      "indicators": ["UNUSUAL_HIGH_PACKET_RATE"]
    }
  ],
  "model_uncertainty": {
    "uncertainty_level": "LOW",
    "explanation": "...",
    "risk_separation_statement": "Model uncertainty is strictly decoupled from behavioral risk.",
    "evidence_ids": ["E005"]
  },
  "limitations": [
    {
      "topic": "Domain Validation",
      "statement": "The traffic was evaluated under TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED...",
      "evidence_ids": ["E006"]
    }
  ],
  "technical_evidence": [
    {
      "evidence_id": "E001",
      "title": "ESP and AH Protocols in IPsec",
      "source": "ipsec/esp_ah_protocols.md",
      "section": "Encapsulating Security Payload (ESP)"
    }
  ],
  "review_areas": ["Investigate activity triggering indicator UNUSUAL_HIGH_PACKET_RATE."],
  "conclusion": "Analysis completed with risk tier LOW..."
}
```

---

## 9. Deterministic Multi-Layer Validation

The `ReportValidator` enforces four independent verification gates:

1. **Schema Completeness**: All 10 required report sections must be present and contain non-empty narrative text.
2. **Fact Consistency (`FactChecker`)**:
   - `packet_count`, `flow_count`, `total_bytes`, `duration_seconds` match `AnalysisFacts`.
   - `risk_score` and `risk_level` match `AnalysisFacts` exactly.
   - `predicted_category` and `confidence` match `AnalysisFacts`.
   - `esp_detected`, `ah_detected`, `ike_detected`, `nat_t_detected`, and `domain_validation_status` match `AnalysisFacts`.
   - **Zero Invented Indicators**: No indicator outside the input is permitted.
3. **Evidence Grounding (`EvidenceChecker`)**:
   - Every cited evidence ID (`E001`, `E002`, etc.) must exist in the retrieved evidence bundle. Hallucinated IDs immediately fail validation.
4. **Terminology & Policy (`TerminologyChecker`)**:
   - Prohibits sensationalist phrases (`"attack detected"`, `"confirmed attack"`, `"definitely malicious"`, `"intrusion identified"`, `"guaranteed application"`).
   - Enforces domain policy: If domain is `UNVERIFIED`, forbids claiming `"IPsec-validated"`.
   - Enforces uncertainty vs. risk separation: Forbids claiming risk score resulted from model uncertainty.
   - Rejects unauthorized scoring systems (`"AI risk: 8/10"`).

---

## 10. Python Public API & Usage

```python
from rag_report_generator import (
    generate_report,
    generate_report_from_phase5,
    ReportConfig,
)

# Option 1: End-to-end convenience pipeline (extracts facts, retrieves evidence, generates report)
result = generate_report_from_phase5(
    analysis_result=phase5_json_dict,
    config=ReportConfig(llm_provider="mock"),
)

if result.status == "SUCCESS":
    print("Report generated successfully!")
    print(result.markdown)
    # Save files
    with open("report.json", "w") as f:
        json.dump(result.report_json, f, indent=2)
    with open("report.md", "w") as f:
        f.write(result.markdown)
else:
    print(f"Generation failed with status: {result.status}")
    print("Errors:", result.validation["errors"])

# Option 2: Direct generation with explicit retrieved evidence
from rag_report_generator import retrieve

evidence = retrieve("UNUSUAL_HIGH_PACKET_RATE meaning", top_k=3).retrieved_evidence
result = generate_report(
    analysis_result=phase5_json_dict,
    retrieved_evidence=evidence,
    config=ReportConfig(llm_provider="mock"),
)
```

---

## 11. Command-Line Interface (CLI)

```bash
# Build knowledge base index
python -m rag_report_generator build

# Retrieve explanatory evidence
python -m rag_report_generator retrieve --query "ESP payload opacity" --top-k 3

# Generate report from Phase 5 JSON using mock LLM (offline)
python -m rag_report_generator generate \
  --input rag_report_generator/tests/fixtures/high_risk.json \
  --output report.md \
  --json-output report.json \
  --provider mock

# Generate report from Phase 5 JSON using local Ollama (when running)
python -m rag_report_generator generate \
  --input rag_report_generator/tests/fixtures/low_risk.json \
  --output report.md \
  --json-output report.json \
  --provider ollama \
  --model llama3.2
```

---

## 12. Synthetic Test Fixtures

Part 2 includes 7 verified synthetic Phase 5 fixtures under `rag_report_generator/tests/fixtures/`:
1. `low_risk.json`: 512 packets, risk score 0 (LOW), category `web` (confidence 0.92), no IPsec.
2. `high_risk.json`: 45,000 packets, risk score 60 (HIGH), 3 indicators, category `file_transfer`, ESP detected under `TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED`.
3. `medium_risk.json`: 2,400 packets, risk score 30 (MEDIUM), 2 indicators, category `interactive`.
4. `ipsec_unverified.json`: 1,024 packets, ESP + IKE detected, domain `TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED`, confidence 0.812.
5. `ipsec_verified.json`: 3,200 packets, ESP detected, domain `VERIFIED_IPSEC`, risk score 0.
6. `high_uncertainty.json`: 1,500 packets, model uncertainty HIGH (entropy 1.85, margin 0.04), category `video` (confidence 0.42).
7. `mixed_indicators.json`: 18,500 packets, risk score 50 (HIGH), 4 distinct behavioral indicators.

---

## 13. Handoff Contract to Part 3

Part 3 will integrate the report generator into the main CLI and Person 3 dashboard.

### Consumption Contract
Part 3 only needs to call:
```python
from rag_report_generator import generate_report_from_phase5, ReportConfig

report_result = generate_report_from_phase5(
    analysis_result=phase5_unified_json,
    config=ReportConfig(
        llm_provider="ollama" if ollama_available else "mock",
        llm_model="llama3.2",
    ),
)
```

And inspect:
* `report_result.status`: `"SUCCESS"`, `"VALIDATION_FAILED"`, `"GENERATION_FAILED"`, or `"INVALID_INPUT"`.
* `report_result.report_json`: Structured report dictionary (consumed by Person 3 dashboard or stored on disk).
* `report_result.markdown`: Rendered GitHub-flavored Markdown text.
* `report_result.validation`: Dictionary containing validation outcome, error messages, and checked rules.
* `report_result.metadata`: Generation runtime, model name, and evidence IDs cited.

Part 3 does NOT need to manage vector indices, chunking, embeddings, prompt templates, or validator internals.
