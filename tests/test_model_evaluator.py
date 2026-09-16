"""Unit tests for Phase 3 model evaluator module.

Tests calculation of accuracy, Macro F1, per-class metrics, confusion matrices,
inference latency, and feature importances.
"""

import pytest

from person2_engine.src.dataset_adapter import load_csv_dataset
from person2_engine.src.model_evaluator import (
    ModelEvaluationReport,
    evaluate_all_candidates,
    evaluate_candidate_model,
    extract_feature_importances,
)
from person2_engine.src.model_trainer import train_candidate_models


@pytest.fixture
def trained_candidates_fixture():
    """Train candidate models on small benchmark fixture."""
    ds = load_csv_dataset("datasets/test_fixture_small.csv")
    return train_candidate_models(ds, test_size=0.30, random_state=42)


class TestModelEvaluator:
    """Tests for model evaluation metrics and explainability."""

    def test_evaluate_candidate_model_produces_complete_report(self, trained_candidates_fixture):
        """Verify report contains all required metrics, matrices, and timings."""
        cand = trained_candidates_fixture["random_forest"]
        report = evaluate_candidate_model(cand)

        assert isinstance(report, ModelEvaluationReport)
        assert 0.0 <= report.accuracy <= 1.0
        assert 0.0 <= report.f1_macro <= 1.0
        assert 0.0 <= report.precision_macro <= 1.0
        assert 0.0 <= report.recall_macro <= 1.0
        assert report.inference_latency_ms >= 0.0
        assert len(report.confusion_matrix) == len(report.classes)
        assert set(report.per_class_metrics.keys()) == set(report.classes)

    def test_evaluate_all_candidates(self, trained_candidates_fixture):
        """Verify evaluation runs across all candidate models."""
        reports = evaluate_all_candidates(trained_candidates_fixture)
        assert len(reports) == 4
        for name in ["random_forest", "gradient_boosting", "extra_trees", "logistic_regression"]:
            assert name in reports
            assert reports[name].model_name == name

    def test_tree_feature_importances_extracted(self, trained_candidates_fixture):
        """Verify Gini-based feature importances are extracted and sorted for tree models."""
        rf_cand = trained_candidates_fixture["random_forest"]
        importances = extract_feature_importances(rf_cand.estimator, rf_cand.split_data.feature_names)
        assert len(importances) == 25
        # Verify sorted in descending order
        vals = list(importances.values())
        assert vals == sorted(vals, reverse=True)
        # Sum of tree importances is 1.0
        assert pytest.approx(sum(vals), abs=1e-3) == 1.0

    def test_linear_feature_importances_extracted(self, trained_candidates_fixture):
        """Verify mean absolute coefficient weights are extracted for logistic regression."""
        lr_cand = trained_candidates_fixture["logistic_regression"]
        importances = extract_feature_importances(lr_cand.estimator, lr_cand.split_data.feature_names)
        assert len(importances) == 25
        vals = list(importances.values())
        assert vals == sorted(vals, reverse=True)
        assert all(v >= 0.0 for v in vals)

    def test_render_summary_contains_key_metrics(self, trained_candidates_fixture):
        """Verify human-readable summary renders with no formatting exceptions."""
        cand = trained_candidates_fixture["random_forest"]
        report = evaluate_candidate_model(cand)
        summary = report.render_summary()
        assert "Accuracy:" in summary
        assert "Macro F1 Score:" in summary
        assert "Per-Class Metrics:" in summary
        assert "Top Influential Features:" in summary
