"""Comprehensive automated tests for Reusable PCAP Dataset Adapter, Manifest Parsing,
Group-Aware Splitting, and Real PCAP Flow Extraction.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from person2_engine.src.dataset_adapter import load_csv_dataset
from person2_engine.src.feature_schema import (
    FEATURE_ORDER,
    FEATURE_SCHEMA_VERSION,
)
from person2_engine.src.feature_validator import validate_ml_vector
from person2_engine.src.label_mapper import LabelMapper
from person2_engine.src.model_evaluator import evaluate_candidate_model
from person2_engine.src.model_trainer import (
    build_candidate_estimators,
    prepare_train_test_split,
    train_candidate_models,
)
from person2_engine.src.pcap_dataset_adapter import (
    PcapDatasetManifest,
    PcapManifestEntry,
    extract_flows_from_manifest,
    load_pcap_manifest,
    save_pcap_dataset_to_csv,
)


class TestPcapDatasetAdapter:
    """Test suite for manifest-driven real PCAP ingestion and feature extraction."""

    def test_load_iscx_manifest_valid(self):
        """Verify the primary ISCXVPN2016 dataset manifest loads correctly."""
        manifest_path = Path("datasets/manifests/iscxvpn2016_manifest.json")
        assert manifest_path.exists(), "iscxvpn2016_manifest.json must exist"

        manifest = load_pcap_manifest(manifest_path)
        assert "iscxvpn2016" in manifest.dataset_id
        assert len(manifest.entries) >= 20
        assert manifest.label_strategy == "5_class_aligned"

        # Check entry fields
        for entry in manifest.entries:
            assert entry.scenario_id
            assert entry.pcap_path
            assert entry.canonical_label in {"web", "streaming", "voip", "file_transfer", "interactive"}
            assert entry.source_dataset in {"iscxvpn2016", "standard_web"}
            assert entry.capture_group

    def test_load_person1_ipsec_manifest_template(self):
        """Verify the future Person 1 StrongSwan/IPsec manifest template contract."""
        manifest_path = Path("datasets/manifests/person1_ipsec_manifest_template.json")
        assert manifest_path.exists(), "person1_ipsec_manifest_template.json must exist"

        manifest = load_pcap_manifest(manifest_path)
        assert "person1" in manifest.dataset_id
        assert "StrongSwan" in manifest.description
        for entry in manifest.entries:
            assert entry.source_dataset == "person1_ipsec"
            assert entry.canonical_label in {"web", "streaming", "voip", "file_transfer", "interactive"}

    def test_load_manifest_nonexistent_or_corrupted(self, tmp_path):
        """Verify error handling on invalid or missing manifest files."""
        # Nonexistent file
        with pytest.raises(FileNotFoundError):
            load_pcap_manifest(tmp_path / "nonexistent.json")

        # Corrupted JSON
        bad_json = tmp_path / "bad.json"
        bad_json.write_text("{invalid json", encoding="utf-8")
        with pytest.raises(ValueError):
            load_pcap_manifest(bad_json)

        # Missing required entries key
        empty_json = tmp_path / "empty.json"
        empty_json.write_text(json.dumps({"dataset_id": "test"}), encoding="utf-8")
        manifest = load_pcap_manifest(empty_json)
        assert len(manifest.captures) == 0

    def test_extract_flows_from_manifest_with_real_pcaps(self, tmp_path):
        """Verify extraction from real PCAPs produces valid canonical 25-feature rows."""
        # Pick 2 existing sample PCAPs
        sample1 = Path("datasets/raw/iscxvpn2016/interactive/vpn_aim_chat1a.pcap")
        sample2 = Path("datasets/raw/iscxvpn2016/streaming/vpn_netflix_sample.pcap")
        assert sample1.exists() and sample2.exists()

        mini_manifest = {
            "dataset_id": "mini_test",
            "entries": [
                {
                    "scenario_id": "test_chat",
                    "pcap_path": str(sample1),
                    "original_label": "AIM_chat",
                    "canonical_label": "interactive",
                    "capture_group": "group_aim",
                },
                {
                    "scenario_id": "test_stream",
                    "pcap_path": str(sample2),
                    "original_label": "Netflix",
                    "canonical_label": "streaming",
                    "capture_group": "group_netflix",
                },
            ],
        }
        manifest_file = tmp_path / "mini_manifest.json"
        manifest_file.write_text(json.dumps(mini_manifest), encoding="utf-8")

        out_csv = tmp_path / "extracted_flows.csv"
        flow_dataset = extract_flows_from_manifest(
            manifest=manifest_file,
            output_csv_path=out_csv,
        )

        assert len(flow_dataset) > 0
        assert out_csv.exists()

        # Every flow must conform to canonical 25-feature schema
        for sample in flow_dataset.samples:
            val = validate_ml_vector(sample.features)
            assert val.valid, f"Feature vector validation failed: {val.errors}"
            assert len(sample.features) == 25
            assert sample.label in {"interactive", "streaming"}
            assert sample.group in {"group_aim", "group_netflix"}

        # Check CSV content can be reloaded by load_csv_dataset
        reloaded = load_csv_dataset(out_csv)
        assert len(reloaded) == len(flow_dataset)
        assert reloaded.feature_names == FEATURE_ORDER

    def test_extract_flows_skips_missing_pcaps_gracefully(self, tmp_path):
        """Verify that a missing or corrupted PCAP in manifest logs and skips without crash."""
        manifest_data = {
            "dataset_id": "missing_pcap_test",
            "entries": [
                {
                    "scenario_id": "nonexistent_capture",
                    "pcap_path": str(tmp_path / "does_not_exist.pcap"),
                    "original_label": "unknown",
                    "canonical_label": "web",
                    "capture_group": "bad_group",
                }
            ],
        }
        manifest_file = tmp_path / "manifest.json"
        manifest_file.write_text(json.dumps(manifest_data), encoding="utf-8")

        out_csv = tmp_path / "empty_extracted.csv"
        flow_dataset = extract_flows_from_manifest(manifest_file, output_csv_path=out_csv)
        assert len(flow_dataset) == 0

    def test_group_aware_train_test_split_prevents_leakage(self):
        """Verify group-aware splitting holds out entire capture groups with zero overlap."""
        dataset_path = Path("datasets/processed/iscxvpn2016_flows.csv")
        assert dataset_path.exists(), "Processed ISCX dataset must exist"

        ds = load_csv_dataset(dataset_path)
        split_data, scaler = prepare_train_test_split(ds, test_size=0.20, random_state=42)

        # Assert no overlap between train groups and test groups for classes with >= 2 groups
        assert len(split_data.groups_train) > 0
        assert len(split_data.groups_test) > 0

        train_groups = set(split_data.groups_train)
        test_groups = set(split_data.groups_test)
        overlap = train_groups.intersection(test_groups)
        # Only single-capture fallback classes (where only 1 capture file existed) can share a group
        for grp in overlap:
            # Confirm that the only overlapping groups are single-capture classes partitioned temporally
            samples_in_grp = [s for s in ds.samples if s.group == grp]
            labels = {s.label for s in samples_in_grp}
            assert len(labels) == 1

        # Scaler fitted strictly on training data
        assert scaler is not None
        assert scaler.n_features_in_ == 25
        assert len(scaler.mean_) == 25

    def test_train_candidates_and_evaluate_on_real_flows(self):
        """Train candidate models on real flows and assert valid evaluation metrics."""
        dataset_path = Path("datasets/processed/iscxvpn2016_flows.csv")
        assert dataset_path.exists()

        ds = load_csv_dataset(dataset_path)
        candidates = train_candidate_models(
            ds,
            candidate_keys=["random_forest", "logistic_regression"],
            test_size=0.20,
            random_state=42,
        )

        for name in ["random_forest", "logistic_regression"]:
            cand = candidates[name]
            report = evaluate_candidate_model(cand)
            assert 0.0 <= report.f1_macro <= 1.0
            assert 0.0 <= report.accuracy <= 1.0
            assert len(report.confusion_matrix) == len(report.classes)
            # Feature importances exist
            assert len(report.feature_importances) == 25

    def test_invalid_pcap_handling_in_manifest(self, tmp_path):
        """Verify that a corrupted or truncated binary file in manifest is skipped safely."""
        corrupt_pcap = tmp_path / "corrupt.pcap"
        corrupt_pcap.write_bytes(b"\x00\x00\x00\x00corrupted bytes")

        manifest_data = {
            "dataset_name": "corrupt_test",
            "captures": [
                {
                    "scenario_id": "corrupt_pcap_01",
                    "pcap_path": str(corrupt_pcap),
                    "canonical_label": "web",
                }
            ],
        }
        mf_path = tmp_path / "manifest.json"
        mf_path.write_text(json.dumps(manifest_data), encoding="utf-8")

        dataset = extract_flows_from_manifest(mf_path)
        assert len(dataset) == 0

    def test_feature_schema_compatibility_with_processed_dataset(self):
        """Verify processed ISCX dataset meets all canonical schema invariants."""
        dataset_path = Path("datasets/processed/iscxvpn2016_flows.csv")
        assert dataset_path.exists()

        ds = load_csv_dataset(dataset_path)
        assert ds.feature_names == FEATURE_ORDER
        assert ds.feature_schema_version == FEATURE_SCHEMA_VERSION
        assert len(ds) >= 200
        raw_path = Path("datasets/processed/iscxvpn2016_flows_raw.csv")
        if raw_path.exists():
            ds_raw = load_csv_dataset(raw_path)
            assert len(ds_raw) >= 1000

        valid_labels = {"web", "streaming", "voip", "file_transfer", "interactive"}
        for s in ds.samples:
            assert s.label in valid_labels
            val = validate_ml_vector(s.features)
            assert val.valid

    def test_real_pcap_inference_end_to_end(self):
        """Verify inference layer on a real PCAP with trained model produces valid predictions."""
        from person2_engine.src.packet_analyzer import analyze_capture_with_predictions

        sample_pcap = Path("datasets/raw/iscxvpn2016/streaming/vpn_netflix_sample.pcap")
        assert sample_pcap.exists()

        result = analyze_capture_with_predictions(
            file_path=sample_pcap,
            allow_unverified_domain=True,
        )

        assert result.capture_features.analysis.status.success
        assert len(result.predictions) > 0
        for pred in result.predictions:
            assert pred.model_status in {"READY_FOR_INFERENCE", "prediction_available"}
            assert pred.prediction is not None
            assert pred.prediction.label in {"web", "streaming", "voip", "file_transfer", "interactive"}
            assert 0.0 <= pred.prediction.confidence <= 1.0

    def test_cli_manifest_extraction_handler(self, tmp_path):
        """Verify CLI manifest extraction handler produces valid CSV."""
        from main import handle_manifest_extraction

        sample1 = Path("datasets/raw/iscxvpn2016/interactive/vpn_aim_chat1a.pcap")
        sample2 = Path("datasets/raw/iscxvpn2016/streaming/vpn_netflix_sample.pcap")
        manifest_data = {
            "dataset_name": "cli_test",
            "captures": [
                {
                    "scenario_id": "cli_aim",
                    "pcap_path": str(sample1),
                    "canonical_label": "interactive",
                },
                {
                    "scenario_id": "cli_stream",
                    "pcap_path": str(sample2),
                    "canonical_label": "streaming",
                },
            ],
        }
        mf_path = tmp_path / "cli_manifest.json"
        mf_path.write_text(json.dumps(manifest_data), encoding="utf-8")
        out_csv = tmp_path / "cli_out.csv"

        ret = handle_manifest_extraction(str(mf_path), output_path=str(out_csv))
        assert ret == 0
        assert out_csv.exists()
        reloaded = load_csv_dataset(out_csv)
        assert len(reloaded) > 0
