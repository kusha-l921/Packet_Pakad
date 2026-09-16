"""Comprehensive evaluation metrics calculator for candidate tabular models.

Computes accuracy, macro precision/recall/F1, per-class metrics, confusion matrices,
inference latency, and feature importances on held-out test data.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import time
from typing import Any, Dict, List, Optional
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
)

from person2_engine.src.feature_schema import FEATURE_ORDER
from person2_engine.src.model_trainer import CandidateTrainingResult


@dataclass
class ModelEvaluationReport:
    """Detailed evaluation outcome for a candidate classifier evaluated on held-out test data."""

    model_name: str
    model_type: str
    accuracy: float
    precision_macro: float
    recall_macro: float
    f1_macro: float
    f1_weighted: float
    training_time_seconds: float
    inference_latency_ms: float
    classes: List[str]
    per_class_metrics: Dict[str, Dict[str, float]]
    confusion_matrix: List[List[int]]
    feature_importances: Dict[str, float]
    evaluation_mode: str = "OVERALL_MIXED_EVALUATION"
    per_class_evaluation_modes: Dict[str, str] = field(default_factory=dict)
    per_class_sufficiency: Dict[str, str] = field(default_factory=dict)
    strict_group_metrics: Optional[Dict[str, Any]] = None
    within_capture_metrics: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert evaluation report to dictionary."""
        return asdict(self)

    def render_summary(self) -> str:
        """Render human-readable multi-line summary of metrics."""
        lines = [
            f"MODEL: {self.model_name.upper()} ({self.model_type})",
            f"  Primary Evaluation Mode: {self.evaluation_mode}",
            f"  Accuracy:         {self.accuracy:.4f} ({self.accuracy:.2%})",
            f"  Macro Precision:  {self.precision_macro:.4f}",
            f"  Macro Recall:     {self.recall_macro:.4f}",
            f"  Macro F1 Score:   {self.f1_macro:.4f}",
            f"  Weighted F1:      {self.f1_weighted:.4f}",
            f"  Training Time:    {self.training_time_seconds:.3f}s",
            f"  Inference Latency:{self.inference_latency_ms:.3f}ms / flow",
        ]
        if self.strict_group_metrics:
            sg = self.strict_group_metrics
            lines.append(
                f"  [STRICT_GROUP_EVALUATION] (Classes: {sg.get('classes')}, n={sg.get('test_sample_count')}): "
                f"Acc={sg.get('accuracy'):.4f}, Macro-F1={sg.get('f1_macro'):.4f}"
            )
        if self.within_capture_metrics:
            wc = self.within_capture_metrics
            lines.append(
                f"  [WITHIN_CAPTURE_EVALUATION] (Classes: {wc.get('classes')}, n={wc.get('test_sample_count')}): "
                f"Acc={wc.get('accuracy'):.4f}, Macro-F1={wc.get('f1_macro'):.4f} [WARNING: {wc.get('limitation')}]"
            )
        lines.append("  Per-Class Metrics:")
        for c, m in self.per_class_metrics.items():
            mode = self.per_class_evaluation_modes.get(c, "UNKNOWN")
            suff = self.per_class_sufficiency.get(c, "OK")
            flag = f" [{suff}]" if suff != "SUFFICIENT" else ""
            lines.append(
                f"    {c:<15}: Precision={m['precision']:.3f}, Recall={m['recall']:.3f}, F1={m['f1']:.3f} "
                f"(n={m['support']}, mode={mode}{flag})"
            )

        if self.feature_importances:
            lines.append("  Top Influential Features:")
            top_feats = list(self.feature_importances.items())[:5]
            for rank, (fname, weight) in enumerate(top_feats, 1):
                lines.append(f"    {rank}. {fname:<30}: {weight:.4f}")

        lines.append(
            "\n  [!] Evaluation Notice: Evaluation validity depends on capture diversity. Classes with multiple independent\n"
            "      capture groups are evaluated using GROUP_ISOLATED splitting (unseen-capture validation). Classes with only one\n"
            "      available capture group use WITHIN_CAPTURE_HOLDOUT and are explicitly marked as having insufficient\n"
            "      independent capture diversity. Therefore, the overall experiment (OVERALL_MIXED_EVALUATION) should not\n"
            "      be interpreted as fully unseen-capture validation for every class."
        )

        return "\n".join(lines)


def extract_feature_importances(
    estimator: Any,
    feature_names: List[str] = list(FEATURE_ORDER),
) -> Dict[str, float]:
    """Extract and sort feature importance weights from an estimator.

    Supports tree ensembles (feature_importances_) and linear models (mean abs coef_).

    Args:
        estimator: Trained scikit-learn classifier.
        feature_names: Ordered list of feature names.

    Returns:
        Dictionary mapping feature name to normalized importance weight, sorted descending.
    """
    importances: Dict[str, float] = {}

    if hasattr(estimator, "feature_importances_"):
        raw = estimator.feature_importances_
        total = float(np.sum(raw)) if np.sum(raw) > 0 else 1.0
        normalized = [float(x) / total for x in raw]
        for name, w in zip(feature_names, normalized):
            importances[name] = round(w, 4)
    elif hasattr(estimator, "coef_"):
        raw_coef = np.mean(np.abs(estimator.coef_), axis=0)
        total = float(np.sum(raw_coef)) if np.sum(raw_coef) > 0 else 1.0
        normalized = [float(x) / total for x in raw_coef]
        for name, w in zip(feature_names, normalized):
            importances[name] = round(w, 4)

    # Sort descending by importance
    return dict(sorted(importances.items(), key=lambda item: item[1], reverse=True))


def evaluate_candidate_model(candidate: CandidateTrainingResult) -> ModelEvaluationReport:
    """Evaluate a trained candidate model on its held-out test split.

    Args:
        candidate: CandidateTrainingResult instance.

    Returns:
        Populated ModelEvaluationReport.
    """
    split = candidate.split_data
    estimator = candidate.estimator

    # Measure inference latency on test set
    t0 = time.perf_counter()
    y_pred = estimator.predict(split.X_test)
    total_inf_time = time.perf_counter() - t0
    n_samples = max(len(split.X_test), 1)
    latency_ms = (total_inf_time / n_samples) * 1000.0

    classes = split.classes

    # Aggregate metrics
    acc = float(accuracy_score(split.y_test, y_pred))
    prec_macro, rec_macro, f1_macro, _ = precision_recall_fscore_support(
        split.y_test, y_pred, average="macro", zero_division=0
    )
    _, _, f1_weighted, _ = precision_recall_fscore_support(
        split.y_test, y_pred, average="weighted", zero_division=0
    )

    # Per-class metrics
    p_per, r_per, f_per, sup_per = precision_recall_fscore_support(
        split.y_test, y_pred, labels=classes, zero_division=0
    )
    per_class_metrics: Dict[str, Dict[str, float]] = {}
    for c_name, p, r, f, s in zip(classes, p_per, r_per, f_per, sup_per):
        per_class_metrics[c_name] = {
            "precision": round(float(p), 4),
            "recall": round(float(r), 4),
            "f1": round(float(f), 4),
            "support": int(s),
        }

    # Confusion matrix
    cm = confusion_matrix(split.y_test, y_pred, labels=classes)
    cm_list = cm.tolist()

    # Explainability / feature importances
    feat_importances = extract_feature_importances(estimator, split.feature_names)

    # Evaluation modes and sufficiency metadata
    evaluation_mode = getattr(split, "evaluation_mode", "OVERALL_MIXED_EVALUATION")
    per_class_modes = getattr(split, "per_class_evaluation_modes", {})
    per_class_sufficiency = getattr(split, "sufficiency_status", {})

    # Compute strict group evaluation subset if applicable
    strict_group_metrics: Optional[Dict[str, Any]] = None
    group_isolated_classes = [c for c, m in per_class_modes.items() if m == "GROUP_ISOLATED"]
    if group_isolated_classes:
        mask_sg = [y in group_isolated_classes for y in split.y_test]
        if any(mask_sg):
            X_sg = split.X_test[mask_sg]
            y_sg = [y for y, m in zip(split.y_test, mask_sg) if m]
            y_sg_pred = estimator.predict(X_sg)
            acc_sg = float(accuracy_score(y_sg, y_sg_pred))
            p_sg, r_sg, f_sg, _ = precision_recall_fscore_support(
                y_sg, y_sg_pred, average="macro", zero_division=0
            )
            strict_group_metrics = {
                "accuracy": round(acc_sg, 4),
                "precision_macro": round(float(p_sg), 4),
                "recall_macro": round(float(r_sg), 4),
                "f1_macro": round(float(f_sg), 4),
                "classes": group_isolated_classes,
                "test_sample_count": int(sum(mask_sg)),
            }

    # Compute within-capture evaluation subset if applicable
    within_capture_metrics: Optional[Dict[str, Any]] = None
    within_cap_classes = [c for c, m in per_class_modes.items() if m == "WITHIN_CAPTURE_HOLDOUT"]
    if within_cap_classes:
        mask_wc = [y in within_cap_classes for y in split.y_test]
        if any(mask_wc):
            X_wc = split.X_test[mask_wc]
            y_wc = [y for y, m in zip(split.y_test, mask_wc) if m]
            y_wc_pred = estimator.predict(X_wc)
            acc_wc = float(accuracy_score(y_wc, y_wc_pred))
            p_wc, r_wc, f_wc, _ = precision_recall_fscore_support(
                y_wc, y_wc_pred, average="macro", zero_division=0
            )
            within_capture_metrics = {
                "accuracy": round(acc_wc, 4),
                "precision_macro": round(float(p_wc), 4),
                "recall_macro": round(float(r_wc), 4),
                "f1_macro": round(float(f_wc), 4),
                "classes": within_cap_classes,
                "test_sample_count": int(sum(mask_wc)),
                "limitation": "WITHIN_CAPTURE_HOLDOUT: Training and test flows originate from the same capture group due to lack of independent PCAPs.",
            }

    return ModelEvaluationReport(
        model_name=candidate.model_name,
        model_type=candidate.model_type,
        accuracy=round(acc, 4),
        precision_macro=round(float(prec_macro), 4),
        recall_macro=round(float(rec_macro), 4),
        f1_macro=round(float(f1_macro), 4),
        f1_weighted=round(float(f1_weighted), 4),
        training_time_seconds=round(candidate.training_time_seconds, 4),
        inference_latency_ms=round(latency_ms, 4),
        classes=classes,
        per_class_metrics=per_class_metrics,
        confusion_matrix=cm_list,
        feature_importances=feat_importances,
        evaluation_mode=evaluation_mode,
        per_class_evaluation_modes=per_class_modes,
        per_class_sufficiency=per_class_sufficiency,
        strict_group_metrics=strict_group_metrics,
        within_capture_metrics=within_capture_metrics,
    )


def evaluate_all_candidates(
    candidates: Dict[str, CandidateTrainingResult],
) -> Dict[str, ModelEvaluationReport]:
    """Evaluate all candidate models and return dictionary of reports."""
    reports: Dict[str, ModelEvaluationReport] = {}
    for key, cand in candidates.items():
        reports[key] = evaluate_candidate_model(cand)
    return reports
