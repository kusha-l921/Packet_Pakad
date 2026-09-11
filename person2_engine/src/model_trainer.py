"""Lightweight candidate model training pipeline for Phase 3 tabular flow features.

Trains CPU-friendly baseline classifiers (Random Forest, Gradient Boosting, Extra Trees,
and Logistic Regression) with strict train/test splitting and zero data leakage.
"""

from __future__ import annotations

from dataclasses import dataclass
import logging
import time
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from sklearn.ensemble import ExtraTreesClassifier, GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler, StandardScaler

from person2_engine.src.dataset_models import SplitData, TrainingDataset
from person2_engine.src.feature_schema import FEATURE_ORDER, FEATURE_SCHEMA_VERSION

logger = logging.getLogger(__name__)


@dataclass
class CandidateTrainingResult:
    """Encapsulates a trained candidate model along with fitted scaler, split data, and latency."""

    model_name: str
    model_type: str
    estimator: Any
    scaler: Optional[Any]
    scaler_type: str
    split_data: SplitData
    training_time_seconds: float


from person2_engine.src.dataset_sufficiency import (
    DatasetSufficiencyReport,
    EvaluationMode,
    SufficiencyStatus,
    generate_dataset_sufficiency_report,
)


def prepare_train_test_split(
    dataset: TrainingDataset,
    test_size: float = 0.20,
    random_state: int = 42,
    scaler_type: str = "standard_scaler",
    split_strategy: str = "auto",
) -> Tuple[SplitData, Optional[Any]]:
    """Split dataset into train and test sets, fitting preprocessing strictly on the train partition.

    Guarantees zero data leakage: scaler statistics (mean, std, min, max) are learned exclusively
    from X_train and applied blindly to X_test.

    When multiple capture groups exist, applies group-aware splitting so that capture groups
    do not leak across train and test partitions. Explicitly tags evaluation mode per class:
      - GROUP_ISOLATED: Training and test flows come from completely separate capture groups.
      - WITHIN_CAPTURE_HOLDOUT: Training and test flows are partitioned intra-capture due to lack
        of independent capture diversity.

    Args:
        dataset: TrainingDataset instance.
        test_size: Proportion of dataset to hold out for evaluation (default 20%).
        random_state: Deterministic seed for reproducible splits.
        scaler_type: Preprocessing technique ("standard_scaler", "min_max_scaler", or "identity").
        split_strategy: "auto", "group_aware", or "stratified".

    Returns:
        Tuple of (SplitData, fitted scaler or None).
    """
    X, y = dataset.to_arrays()
    classes = dataset.get_classes()
    groups = dataset.get_groups()

    unique_groups = set(groups)
    use_group_split = (
        split_strategy in {"auto", "group_aware"}
        and len(unique_groups) > len(classes)
        and len(unique_groups) < len(X)
    )

    # Generate sufficiency report
    sufficiency_report = generate_dataset_sufficiency_report(
        raw_samples=getattr(dataset, "raw_dataset", dataset).samples if hasattr(dataset, "raw_dataset") else dataset.samples,
        eligible_samples=dataset.samples,
        dataset_name=dataset.metadata.name,
    )

    per_class_modes: Dict[str, str] = {}
    sufficiency_dict: Dict[str, str] = {
        c: rec.sufficiency_status for c, rec in sufficiency_report.class_records.items()
    }

    chosen_strategy = "stratified"
    train_idx: np.ndarray
    test_idx: np.ndarray

    if use_group_split:
        rng = np.random.RandomState(random_state)
        train_indices: List[int] = []
        test_indices: List[int] = []

        for c in classes:
            c_indices = np.where(y == c)[0]
            c_groups = np.unique(groups[c_indices])

            if len(c_groups) >= 2:
                per_class_modes[c] = EvaluationMode.GROUP_ISOLATED.value

                # Group-level partition: balance groups so test size is close to test_size target
                # without starving train partition
                group_sizes = {g: int(np.sum(groups[c_indices] == g)) for g in c_groups}
                sorted_groups = sorted(c_groups, key=lambda g: group_sizes[g])

                if len(c_groups) == 2:
                    # Choose smaller group for test unless smaller group has 0 flows
                    test_g = {sorted_groups[0]}
                    train_g = {sorted_groups[1]}
                else:
                    # Greedily select groups closest to target test count
                    target_test_count = max(1, int(round(len(c_indices) * test_size)))
                    test_g = set()
                    curr_count = 0
                    for g in sorted_groups:
                        if curr_count + group_sizes[g] <= target_test_count or not test_g:
                            test_g.add(g)
                            curr_count += group_sizes[g]
                        if len(test_g) >= len(c_groups) - 1:
                            break
                    train_g = set(c_groups) - test_g

                # Safety check: ensure both train and test have at least 1 group
                if not train_g:
                    train_g = {sorted_groups[-1]}
                    test_g = set(c_groups) - train_g

                for idx in c_indices:
                    if groups[idx] in test_g:
                        test_indices.append(idx)
                    else:
                        train_indices.append(idx)
            else:
                # Single-group class: partition flows intra-capture to ensure class is evaluated
                per_class_modes[c] = EvaluationMode.WITHIN_CAPTURE_HOLDOUT.value
                n_test = max(1, int(round(len(c_indices) * test_size)))
                perm = rng.permutation(c_indices)
                test_indices.extend(perm[:n_test])
                train_indices.extend(perm[n_test:])

        train_idx = np.array(train_indices)
        test_idx = np.array(test_indices)
        chosen_strategy = "group_aware_capture_split"
        logger.info(
            "Applied group-aware capture split (%d train, %d test across %d capture groups)",
            len(train_idx),
            len(test_idx),
            len(unique_groups),
        )
    else:
        counts = {c: int(np.sum(y == c)) for c in classes}
        stratify = y if all(count >= 2 for count in counts.values()) else None

        train_indices, test_indices = train_test_split(
            np.arange(len(y)),
            test_size=test_size,
            random_state=random_state,
            stratify=stratify,
        )
        train_idx = np.array(train_indices)
        test_idx = np.array(test_indices)
        chosen_strategy = "stratified"
        for c in classes:
            per_class_modes[c] = EvaluationMode.WITHIN_CAPTURE_HOLDOUT.value

    # Determine overall evaluation mode
    has_isolated = any(m == EvaluationMode.GROUP_ISOLATED.value for m in per_class_modes.values())
    has_within = any(m == EvaluationMode.WITHIN_CAPTURE_HOLDOUT.value for m in per_class_modes.values())
    if has_isolated and not has_within:
        overall_eval_mode = EvaluationMode.STRICT_GROUP_EVALUATION.value
    elif not has_isolated and has_within:
        overall_eval_mode = EvaluationMode.WITHIN_CAPTURE_EVALUATION.value
    else:
        overall_eval_mode = EvaluationMode.OVERALL_MIXED_EVALUATION.value

    X_train_raw = X[train_idx]
    X_test_raw = X[test_idx]
    y_train = y[train_idx]
    y_test = y[test_idx]
    groups_train = groups[train_idx]
    groups_test = groups[test_idx]

    scaler = None
    if scaler_type == "standard_scaler":
        scaler = StandardScaler()
        X_train = scaler.fit_transform(X_train_raw)
        X_test = scaler.transform(X_test_raw)
    elif scaler_type == "min_max_scaler":
        scaler = MinMaxScaler()
        X_train = scaler.fit_transform(X_train_raw)
        X_test = scaler.transform(X_test_raw)
    else:
        # Identity / no transformation
        X_train = X_train_raw.copy()
        X_test = X_test_raw.copy()

    split_data = SplitData(
        X_train=X_train,
        X_test=X_test,
        y_train=y_train,
        y_test=y_test,
        feature_names=list(FEATURE_ORDER),
        classes=classes,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        X_train_raw=X_train_raw,
        X_test_raw=X_test_raw,
        groups_train=groups_train,
        groups_test=groups_test,
        split_strategy=chosen_strategy,
        evaluation_mode=overall_eval_mode,
        per_class_evaluation_modes=per_class_modes,
        sufficiency_status=sufficiency_dict,
    )

    return split_data, scaler




def build_candidate_estimators(random_state: int = 42) -> Dict[str, Tuple[str, Any]]:
    """Instantiate the 4 candidate lightweight tabular classifiers.

    Args:
        random_state: Deterministic random seed.

    Returns:
        Dictionary mapping model key to (model_type_string, estimator_instance).
    """
    return {
        "random_forest": (
            "random_forest",
            RandomForestClassifier(
                n_estimators=100,
                max_depth=12,
                random_state=random_state,
                n_jobs=2,
            ),
        ),
        "gradient_boosting": (
            "gradient_boosting",
            GradientBoostingClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=4,
                random_state=random_state,
            ),
        ),
        "extra_trees": (
            "extra_trees",
            ExtraTreesClassifier(
                n_estimators=100,
                max_depth=12,
                random_state=random_state,
                n_jobs=2,
            ),
        ),
        "logistic_regression": (
            "logistic_regression",
            LogisticRegression(
                max_iter=1000,
                random_state=random_state,
            ),
        ),
    }


def train_candidate_models(
    dataset: TrainingDataset,
    test_size: float = 0.20,
    random_state: int = 42,
    scaler_type: str = "standard_scaler",
    candidate_keys: Optional[List[str]] = None,
    split_strategy: str = "auto",
) -> Dict[str, CandidateTrainingResult]:
    """Train all lightweight candidate models on the provided training dataset.

    Args:
        dataset: TrainingDataset instance.
        test_size: Held-out evaluation proportion.
        random_state: Deterministic random seed.
        scaler_type: Preprocessing scaler ("standard_scaler", "min_max_scaler", "identity").
        candidate_keys: Optional list of model keys to train (defaults to all 4).
        split_strategy: Train/test split strategy ("auto", "group_aware", or "stratified").

    Returns:
        Dictionary mapping model key to CandidateTrainingResult.
    """
    split_data, scaler = prepare_train_test_split(
        dataset=dataset,
        test_size=test_size,
        random_state=random_state,
        scaler_type=scaler_type,
        split_strategy=split_strategy,
    )


    all_candidates = build_candidate_estimators(random_state=random_state)
    target_keys = candidate_keys or list(all_candidates.keys())

    results: Dict[str, CandidateTrainingResult] = {}

    for key in target_keys:
        if key not in all_candidates:
            logger.warning("Unknown candidate model key '%s' - skipping", key)
            continue

        model_type, estimator = all_candidates[key]
        logger.info("Training candidate model: %s (%s)", key, model_type)

        t0 = time.perf_counter()
        estimator.fit(split_data.X_train, split_data.y_train)
        duration = time.perf_counter() - t0

        results[key] = CandidateTrainingResult(
            model_name=key,
            model_type=model_type,
            estimator=estimator,
            scaler=scaler,
            scaler_type=scaler_type,
            split_data=split_data,
            training_time_seconds=duration,
        )

    return results
