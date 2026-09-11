"""Automated test suite for Phase 3.5 — Dataset Quality, Label Integrity, and Evaluation Correction.

Tests all 17 requirements specified in Part O:
1. Raw flow provenance preservation.
2. Model-eligible flow generation.
3. Exclusion reason generation.
4. Background traffic detection rules.
5. Configurable filtering rules.
6. Label conflict detection and zero conflicts on eligible dataset.
7. Schema version preservation (FEATURE_SCHEMA_VERSION == "1.0").
8. FEATURE_ORDER preservation (25 features).
9. No synthetic rows entering real training dataset.
10. Group-isolated split verification.
11. Within-capture split labeling.
12. Train/test metadata correctness.
13. No silent row deletion (Level 1 vs Level 2 integrity).
14. Dataset reproducibility.
15. Backward compatibility with Phase 1.
16. Backward compatibility with Phase 2.
17. Backward compatibility with Phase 3 & Phase 4.
"""

from __future__ import annotations

from pathlib import Path
import tempfile
import pytest

from person2_engine.src.feature_schema import FEATURE_ORDER, FEATURE_SCHEMA_VERSION
from person2_engine.src.flow_filter import (
    FlowExclusionReason,
    FlowRelevancePolicy,
    evaluate_flow,
    filter_flow_samples,
)
from person2_engine.src.dataset_sufficiency import (
    DatasetSufficiencyReport,
    EvaluationMode,
    SufficiencyStatus,
    generate_dataset_sufficiency_report,
)
from person2_engine.src.dataset_models import FlowSample, SplitData, TrainingDataset
from person2_engine.src.dataset_adapter import load_csv_dataset
from person2_engine.src.pcap_dataset_adapter import (
    audit_manifest_captures,
    extract_flows_from_manifest,
)
from person2_engine.src.model_trainer import prepare_train_test_split, train_candidate_models
from person2_engine.src.model_evaluator import evaluate_candidate_model
from person2_engine.src.packet_analyzer import (
    analyze_capture,
    analyze_capture_with_features,
    analyze_capture_with_predictions,
)
from person2_engine.src.security_analyzer import analyze_capture_security


MANIFEST_PATH = Path("datasets/manifests/iscxvpn2016_manifest.json")
PROCESSED_DATASET = Path("datasets/processed/iscxvpn2016_flows.csv")
RAW_DATASET = Path("datasets/processed/iscxvpn2016_flows_raw.csv")
TEST_PCAP = Path("sample_data/basic_traffic.pcap")


# 1. Raw flow provenance preservation
def test_raw_flow_provenance_preservation():
    """Verify raw extracted flows retain complete forensic metadata and provenance."""
    assert RAW_DATASET.is_file(), "Raw dataset must exist"
    ds_raw = load_csv_dataset(RAW_DATASET)
    assert len(ds_raw.samples) == 1142, f"Expected 1142 raw flows, got {len(ds_raw.samples)}"

    for s in ds_raw.samples:
        assert "source_capture" in s.metadata
        assert s.sample_id != ""
        assert "model_eligible" in s.metadata
        assert "exclusion_reason" in s.metadata
        assert isinstance(s.metadata["model_eligible"], bool)


# 2. Model-eligible flow generation
def test_model_eligible_flow_generation():
    """Verify Level 2 dataset contains only model-eligible flows passing relevance policy."""
    assert PROCESSED_DATASET.is_file(), "Processed dataset must exist"
    ds_eligible = load_csv_dataset(PROCESSED_DATASET)
    assert len(ds_eligible.samples) == 253, f"Expected 253 eligible flows, got {len(ds_eligible.samples)}"

    for s in ds_eligible.samples:
        assert s.metadata.get("model_eligible", True) is True
        assert s.metadata.get("exclusion_reason", "") == ""


# 3. Exclusion reason generation
def test_exclusion_reason_generation():
    """Verify exclusion reasons match the standardized FlowExclusionReason enum."""
    policy = FlowRelevancePolicy()
    valid_reasons = {e.value for e in FlowExclusionReason}

    # Test LLMNR
    ok, reason = policy.evaluate_flow("f1", "UDP", "192.168.1.10:5355", "224.0.0.252:5355")
    assert not ok
    assert reason == FlowExclusionReason.BACKGROUND_LLMNR.value

    # Test mDNS
    ok, reason = policy.evaluate_flow("f2", "UDP", "192.168.1.10:5353", "224.0.0.251:5353")
    assert not ok
    assert reason == FlowExclusionReason.BACKGROUND_MDNS.value

    # Test NetBIOS
    ok, reason = policy.evaluate_flow("f3", "UDP", "192.168.1.10:137", "192.168.1.255:137")
    assert not ok
    assert reason == FlowExclusionReason.BACKGROUND_NETBIOS.value

    assert reason in valid_reasons


# 4. Background traffic detection rules
def test_background_traffic_detection_rules():
    """Verify all individual background traffic rules filter unwanted flows."""
    policy = FlowRelevancePolicy()

    # Infrastructure DNS
    ok, r = policy.evaluate_flow("dns", "UDP", "192.168.1.5:49152", "8.8.8.8:53")
    assert not ok
    assert r == FlowExclusionReason.BACKGROUND_INFRASTRUCTURE_DNS.value

    # Dropbox LAN sync (port 17500)
    ok, r = policy.evaluate_flow("dropbox", "UDP", "192.168.1.5:17500", "255.255.255.255:17500")
    assert not ok
    assert r == FlowExclusionReason.BACKGROUND_LOCAL_DISCOVERY.value

    # Non-IP / ARP frame
    ok, r = policy.evaluate_flow("arp", "ARP", "00:11:22:33:44:55", "ff:ff:ff:ff:ff:ff")
    assert not ok
    assert r == FlowExclusionReason.NON_IP_LAYER2.value

    # Genuine scenario flow (e.g. FTPS traffic)
    meta = {"source_capture": "ftps_down_1a_sample.pcap", "assigned_label": "file_transfer"}
    ok, r = policy.evaluate_flow("ftps", "TCP", "10.0.0.1:51234", "131.202.240.242:990", scenario_metadata=meta)
    assert ok
    assert r is None


# 5. Configurable filtering rules
def test_configurable_filtering_rules():
    """Verify filtering behavior can be adjusted via policy configuration flags."""
    # When disabled, LLMNR unicast traffic is allowed
    permissive_policy = FlowRelevancePolicy(exclude_llmnr_mdns=False, exclude_multicast_broadcast=False)
    ok, reason = permissive_policy.evaluate_flow("f1", "UDP", "192.168.1.10:5355", "224.0.0.252:5355")
    assert ok
    assert reason is None

    # When enabled, LLMNR traffic is excluded
    strict_policy = FlowRelevancePolicy(exclude_llmnr_mdns=True)
    ok, reason = strict_policy.evaluate_flow("f1", "UDP", "192.168.1.10:5355", "224.0.0.252:5355")
    assert not ok
    assert reason == FlowExclusionReason.BACKGROUND_LLMNR.value


# 6. Label conflict detection and zero conflicts on eligible dataset
def test_label_conflict_detection_and_zero_eligible_conflicts():
    """Verify that cross-label feature conflicts present in raw data are eliminated in model-eligible data."""
    audit_rep = audit_manifest_captures(MANIFEST_PATH)
    assert audit_rep["cross_label_conflicts_raw_count"] >= 1, "Raw dataset should contain cross-label conflicts from LLMNR"
    assert audit_rep["cross_label_conflicts_eligible_count"] == 0, "Model-eligible dataset must have 0 cross-label conflicts"


# 7. Schema version preservation
def test_schema_version_preservation():
    """Verify FEATURE_SCHEMA_VERSION remains exactly 1.0."""
    assert FEATURE_SCHEMA_VERSION == "1.0"
    ds = load_csv_dataset(PROCESSED_DATASET)
    assert ds.feature_schema_version == "1.0"


# 8. FEATURE_ORDER preservation
def test_feature_order_preservation():
    """Verify all 25 features match the exact canonical FEATURE_ORDER."""
    assert len(FEATURE_ORDER) == 25
    ds = load_csv_dataset(PROCESSED_DATASET)
    assert ds.feature_names == list(FEATURE_ORDER)
    for s in ds.samples:
        assert len(s.features) == 25


# 9. No synthetic rows entering real training dataset
def test_no_synthetic_rows_in_real_dataset():
    """Verify all samples in processed real dataset originate from real PCAP files."""
    ds = load_csv_dataset(PROCESSED_DATASET)
    for s in ds.samples:
        src = s.metadata.get("source_dataset", "")
        cap = s.metadata.get("source_capture", "")
        assert "synthetic" not in src.lower()
        assert cap.endswith(".pcap") or cap.endswith(".pcapng")


# 10. Group-isolated split verification
def test_group_isolated_split_verification():
    """Verify that for classes with multiple capture groups, captures are strictly partitioned."""
    ds = load_csv_dataset(PROCESSED_DATASET)
    split, _ = prepare_train_test_split(ds, test_size=0.2, random_state=42)

    # For interactive and web, train and test groups must not intersect
    for c in ["interactive", "web"]:
        train_grps = set(split.groups_train[split.y_train == c])
        test_grps = set(split.groups_test[split.y_test == c])
        overlap = train_grps.intersection(test_grps)
        assert len(overlap) == 0, f"Class '{c}' has capture group overlap in group-isolated mode: {overlap}"


# 11. Within-capture split labeling
def test_within_capture_split_labeling():
    """Verify single-capture classes are explicitly tagged as WITHIN_CAPTURE_HOLDOUT."""
    ds = load_csv_dataset(PROCESSED_DATASET)
    split, _ = prepare_train_test_split(ds, test_size=0.2, random_state=42)

    assert split.per_class_evaluation_modes.get("streaming") == EvaluationMode.WITHIN_CAPTURE_HOLDOUT.value
    assert split.per_class_evaluation_modes.get("voip") == EvaluationMode.WITHIN_CAPTURE_HOLDOUT.value
    assert split.sufficiency_status.get("streaming") == SufficiencyStatus.INSUFFICIENT_CAPTURE_DIVERSITY.value
    assert split.sufficiency_status.get("voip") == SufficiencyStatus.INSUFFICIENT_CAPTURE_DIVERSITY.value


# 12. Train/test metadata correctness
def test_train_test_metadata_correctness():
    """Verify SplitData structure contains complete scientific evaluation metadata."""
    ds = load_csv_dataset(PROCESSED_DATASET)
    split, _ = prepare_train_test_split(ds, test_size=0.2, random_state=42)

    assert split.evaluation_mode == "OVERALL_MIXED_EVALUATION"
    assert "interactive" in split.per_class_evaluation_modes
    assert "streaming" in split.per_class_evaluation_modes
    assert "voip" in split.per_class_evaluation_modes
    assert "web" in split.per_class_evaluation_modes
    assert len(split.X_train) == 200
    assert len(split.X_test) == 53


# 13. No silent row deletion (Level 1 vs Level 2 integrity)
def test_no_silent_row_deletion():
    """Verify all 1142 extracted flows are preserved in Level 1 raw dataset with reasons."""
    ds_raw = load_csv_dataset(RAW_DATASET)
    ds_eligible = load_csv_dataset(PROCESSED_DATASET)

    assert len(ds_raw.samples) == 1142
    assert len(ds_eligible.samples) == 253

    eligible_in_raw = [s for s in ds_raw.samples if s.metadata.get("model_eligible", False)]
    assert len(eligible_in_raw) == 253

    excluded_in_raw = [s for s in ds_raw.samples if not s.metadata.get("model_eligible", True)]
    assert len(excluded_in_raw) == 889
    for s in excluded_in_raw:
        assert s.metadata.get("exclusion_reason") != ""


# 14. Dataset reproducibility
def test_dataset_reproducibility():
    """Verify running manifest extraction multiple times produces deterministic counts and vectors."""
    audit1 = audit_manifest_captures(MANIFEST_PATH)
    audit2 = audit_manifest_captures(MANIFEST_PATH)

    assert audit1["total_raw_flows"] == audit2["total_raw_flows"] == 1142
    assert audit1["total_eligible_flows"] == audit2["total_eligible_flows"] == 253
    assert audit1["total_excluded_flows"] == audit2["total_excluded_flows"] == 889
    assert audit1["cross_label_conflicts_eligible_count"] == audit2["cross_label_conflicts_eligible_count"] == 0


# 15. Backward compatibility with Phase 1
def test_backward_compatibility_phase1():
    """Verify analyze_capture() runs successfully without regression."""
    assert TEST_PCAP.is_file()
    res = analyze_capture(str(TEST_PCAP))
    assert res.status.success is True
    assert res.capture_info.total_packets >= 1


# 16. Backward compatibility with Phase 2
def test_backward_compatibility_phase2():
    """Verify analyze_capture_with_features() extracts valid 25 flow features."""
    assert TEST_PCAP.is_file()
    res = analyze_capture_with_features(str(TEST_PCAP))
    assert res.analysis.status.success is True
    assert len(res.flows) >= 1
    assert res.feature_schema_version == "1.0"
    for f in res.flows:
        assert len(f.features) == 25


# 17. Backward compatibility with Phase 3 & Phase 4
def test_backward_compatibility_phase3_and_phase4():
    """Verify Phase 3 inference and Phase 4 security assessment work seamlessly on new models."""
    assert TEST_PCAP.is_file()
    pred_res = analyze_capture_with_predictions(str(TEST_PCAP), allow_unverified_domain=True)
    assert pred_res.capture_features.analysis.status.success is True
    assert len(pred_res.predictions) >= 1

    sec_res = analyze_capture_security(str(TEST_PCAP), allow_unverified_domain=True)
    assert sec_res.analysis_metadata.get("analysis_status") == "SUCCESS"
    assert sec_res.capture_summary.overall_risk_score >= 0
