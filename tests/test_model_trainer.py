"""Unit tests for Phase 3 candidate model training pipeline.

Tests data splitting, leakage prevention, candidate model fitting (Random Forest,
Gradient Boosting, Extra Trees, and Logistic Regression), and reproducibility.
"""

from pathlib import Path
import numpy as np
import pytest

from person2_engine.src.dataset_adapter import load_csv_dataset
from person2_engine.src.dataset_models import FlowSample, TrainingDataset, DatasetMetadata
from person2_engine.src.feature_schema import FEATURE_ORDER
from person2_engine.src.model_trainer import (
    build_candidate_estimators,
    prepare_train_test_split,
    train_candidate_models,
)


@pytest.fixture
def small_synthetic_dataset() -> TrainingDataset:
    """Fixture providing a balanced 20-sample synthetic dataset (4 per canonical class)."""
    classes = ["web", "video", "voip", "file_transfer", "interactive"]
    samples = []
    for cls_idx, cls_name in enumerate(classes):
        for s in range(4):
            # Create distinguishable numerical signatures
            vec = [float((cls_idx + 1) * 10 + s + i) for i, _ in enumerate(FEATURE_ORDER)]
            # Valid ratios
            fwd_idx = FEATURE_ORDER.index("forward_packet_ratio")
            bwd_idx = FEATURE_ORDER.index("backward_packet_ratio")
            vec[fwd_idx] = 0.5
            vec[bwd_idx] = 0.5
            samples.append(FlowSample(features=vec, label=cls_name, sample_id=f"{cls_name}_{s}"))

    meta = DatasetMetadata(
        name="test_fixture_small",
        source="unit_test",
        traffic_type="synthetic",
        sample_count=len(samples),
        class_distribution={c: 4 for c in classes},
    )
    return TrainingDataset(samples=samples, metadata=meta)


class TestModelTrainer:
    """Tests for model training, preprocessing isolation, and candidate estimators."""

    def test_build_candidate_estimators_contains_all_four(self):
        """Verify all 4 required lightweight candidate models are constructed."""
        estimators = build_candidate_estimators(random_state=42)
        assert "random_forest" in estimators
        assert "gradient_boosting" in estimators
        assert "extra_trees" in estimators
        assert "logistic_regression" in estimators
        assert len(estimators) == 4

    def test_train_test_split_prevents_data_leakage(self, small_synthetic_dataset):
        """Verify scaler is fit strictly on train partition with zero test leakage."""
        split_data, scaler = prepare_train_test_split(
            small_synthetic_dataset,
            test_size=0.25,
            random_state=42,
            scaler_type="standard_scaler",
        )
        assert len(split_data.y_train) == 15
        assert len(split_data.y_test) == 5
        assert scaler is not None

        # Check that scaler mean matches train data mean, NOT whole dataset mean
        train_mean_feat0 = float(np.mean(split_data.X_train_raw[:, 0]))
        assert np.isclose(scaler.mean_[0], train_mean_feat0, atol=1e-5)

    def test_train_all_candidate_models(self, small_synthetic_dataset):
        """Verify all candidate models train successfully on CPU without error."""
        results = train_candidate_models(small_synthetic_dataset, test_size=0.25, random_state=42)
        assert len(results) == 4
        for name in ["random_forest", "gradient_boosting", "extra_trees", "logistic_regression"]:
            assert name in results
            res = results[name]
            assert res.estimator is not None
            assert res.training_time_seconds >= 0.0
            assert res.split_data is not None

    def test_training_reproducibility(self, small_synthetic_dataset):
        """Verify fixed random seed produces identical model weights / predictions."""
        res1 = train_candidate_models(small_synthetic_dataset, test_size=0.25, random_state=42)
        res2 = train_candidate_models(small_synthetic_dataset, test_size=0.25, random_state=42)

        preds1 = res1["random_forest"].estimator.predict(res1["random_forest"].split_data.X_test)
        preds2 = res2["random_forest"].estimator.predict(res2["random_forest"].split_data.X_test)
        np.testing.assert_array_equal(preds1, preds2)

    def test_train_subset_of_candidates(self, small_synthetic_dataset):
        """Verify selective training of specific candidate models via candidate_keys."""
        results = train_candidate_models(
            small_synthetic_dataset,
            test_size=0.25,
            random_state=42,
            candidate_keys=["random_forest", "logistic_regression"],
        )
        assert set(results.keys()) == {"random_forest", "logistic_regression"}
