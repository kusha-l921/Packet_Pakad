"""Unit tests for Phase 3 model persistence and loading.

Tests candidate comparison, model selection, saving joblib + json metadata,
and loading via ModelRegistry.
"""

from pathlib import Path
import json
import pytest

from person2_engine.src.dataset_adapter import load_csv_dataset
from person2_engine.src.feature_schema import FEATURE_ORDER, FEATURE_SCHEMA_VERSION
from person2_engine.src.model_evaluator import evaluate_all_candidates
from person2_engine.src.model_loader import load_model_from_manifest
from person2_engine.src.model_registry import ModelRegistry
from person2_engine.src.model_selector import (
    compare_candidates,
    save_trained_model_and_metadata,
    select_best_candidate,
)
from person2_engine.src.model_trainer import train_candidate_models


@pytest.fixture
def trained_evaluation_fixture():
    """Train and evaluate models on small fixture."""
    ds = load_csv_dataset("datasets/test_fixture_small.csv")
    candidates = train_candidate_models(ds, test_size=0.30, random_state=42)
    reports = evaluate_all_candidates(candidates)
    return ds, candidates, reports


class TestModelPersistence:
    """Tests for model comparison, selection, saving, and loading."""

    def test_compare_candidates_summary(self, trained_evaluation_fixture):
        """Verify formatted comparison table includes all models."""
        _, _, reports = trained_evaluation_fixture
        table = compare_candidates(reports)
        assert "PHASE 3: CANDIDATE MODEL COMPARISON SUMMARY" in table
        assert "random_forest" in table
        assert "logistic_regression" in table

    def test_select_best_candidate_picks_highest_f1(self, trained_evaluation_fixture):
        """Verify model selector chooses the model with highest Macro F1."""
        _, _, reports = trained_evaluation_fixture
        best_key = select_best_candidate(reports)
        best_f1 = reports[best_key].f1_macro
        for k, rep in reports.items():
            assert rep.f1_macro <= best_f1

    def test_save_and_load_trained_model(self, trained_evaluation_fixture, tmp_path: Path):
        """Verify trained model and metadata are saved and loaded correctly."""
        ds, candidates, reports = trained_evaluation_fixture
        cand = candidates["random_forest"]
        rep = reports["random_forest"]

        model_path, meta_path = save_trained_model_and_metadata(
            candidate=cand,
            evaluation=rep,
            output_dir=tmp_path,
            model_id="test_rf_model",
            dataset_name=ds.metadata.name,
        )

        assert model_path.is_file()
        assert meta_path.is_file()

        # Load raw metadata
        meta_data = json.loads(meta_path.read_text(encoding="utf-8"))
        assert meta_data["model_id"] == "test_rf_model"
        assert meta_data["feature_count"] == 25
        assert meta_data["feature_schema_version"] == FEATURE_SCHEMA_VERSION
        assert meta_data["feature_names"] == list(FEATURE_ORDER)

        # Load through load_model_from_manifest
        adapter = load_model_from_manifest(meta_path)
        assert adapter is not None
        assert adapter.metadata.model_id == "test_rf_model"
        assert adapter.metadata.model_type == "random_forest"

        # Check that adapter can predict a test vector
        test_vec = [10.0] * 25
        test_vec[FEATURE_ORDER.index("forward_packet_ratio")] = 0.5
        test_vec[FEATURE_ORDER.index("backward_packet_ratio")] = 0.5
        pred = adapter.predict(adapter.preprocess(test_vec))
        assert pred.label in ds.get_classes()
        assert 0.0 <= pred.confidence <= 1.0

    def test_model_registry_discovers_persisted_model(self, trained_evaluation_fixture, tmp_path: Path):
        """Verify ModelRegistry discovers saved model manifests in custom registry directory."""
        ds, candidates, reports = trained_evaluation_fixture
        cand = candidates["extra_trees"]
        rep = reports["extra_trees"]

        save_trained_model_and_metadata(
            candidate=cand,
            evaluation=rep,
            output_dir=tmp_path,
            model_id="test_et_registry",
            dataset_name=ds.metadata.name,
        )

        registry_dir = tmp_path / "models" / "registry"
        registry = ModelRegistry(registry_dir=registry_dir)
        discovered = registry.discover_models()

        assert "test_et_registry" in discovered
        model_adapter = discovered["test_et_registry"]
        assert model_adapter.metadata.model_id == "test_et_registry"
