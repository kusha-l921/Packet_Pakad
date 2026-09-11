"""Dataset sufficiency and capture diversity reporting engine for Phase 3.5.

Audits class distributions, capture counts, and capture-group diversity to determine
which classes support strict group-isolated evaluation versus within-capture holdout.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
import numpy as np


class EvaluationMode(str, Enum):
    """Categorical evaluation mode for a class or dataset split."""

    GROUP_ISOLATED = "GROUP_ISOLATED"
    WITHIN_CAPTURE_HOLDOUT = "WITHIN_CAPTURE_HOLDOUT"
    STRICT_GROUP_EVALUATION = "STRICT_GROUP_EVALUATION"
    WITHIN_CAPTURE_EVALUATION = "WITHIN_CAPTURE_EVALUATION"
    OVERALL_MIXED_EVALUATION = "OVERALL_MIXED_EVALUATION"


class SufficiencyStatus(str, Enum):
    """Assessment of capture diversity and statistical sufficiency."""

    SUFFICIENT = "SUFFICIENT"
    INSUFFICIENT_CAPTURE_DIVERSITY = "INSUFFICIENT INDEPENDENT CAPTURE DIVERSITY"
    LIMITED_SAMPLE_SIZE = "LIMITED SAMPLE SIZE"


@dataclass
class ClassSufficiencyRecord:
    """Sufficiency and evaluation metadata for a single traffic class."""

    class_name: str
    total_raw_flows: int
    eligible_flows: int
    excluded_flows: int
    capture_count: int
    capture_group_count: int
    capture_groups: List[str]
    evaluation_mode: str
    sufficiency_status: str
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert record to dictionary."""
        return asdict(self)


@dataclass
class DatasetSufficiencyReport:
    """Comprehensive dataset sufficiency report across all traffic classes."""

    dataset_name: str
    total_raw_flows: int
    total_eligible_flows: int
    total_excluded_flows: int
    classes: List[str]
    class_records: Dict[str, ClassSufficiencyRecord] = field(default_factory=dict)
    group_isolated_classes: List[str] = field(default_factory=list)
    within_capture_classes: List[str] = field(default_factory=list)
    overall_evaluation_mode: str = "OVERALL_MIXED_EVALUATION"

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "dataset_name": self.dataset_name,
            "total_raw_flows": self.total_raw_flows,
            "total_eligible_flows": self.total_eligible_flows,
            "total_excluded_flows": self.total_excluded_flows,
            "overall_evaluation_mode": self.overall_evaluation_mode,
            "group_isolated_classes": self.group_isolated_classes,
            "within_capture_classes": self.within_capture_classes,
            "classes": {k: v.to_dict() for k, v in self.class_records.items()},
        }

    def render_table(self) -> str:
        """Render a formatted human-readable ASCII table of data sufficiency."""
        lines = [
            "=" * 90,
            f"   PHASE 3.5: DATASET SUFFICIENCY & CAPTURE DIVERSITY REPORT: {self.dataset_name}",
            "=" * 90,
            f"{'Class':<15} {'Groups':<8} {'Eligible':<10} {'Raw':<8} {'Evaluation Mode':<25} {'Status'}",
            "-" * 90,
        ]

        for c in sorted(self.class_records.keys()):
            rec = self.class_records[c]
            lines.append(
                f"{rec.class_name:<15} {rec.capture_group_count:<8} {rec.eligible_flows:<10} "
                f"{rec.total_raw_flows:<8} {rec.evaluation_mode:<25} {rec.sufficiency_status}"
            )

        lines.append("-" * 90)
        lines.append(f"Total Eligible Flows: {self.total_eligible_flows} (Raw: {self.total_raw_flows}, Excluded: {self.total_excluded_flows})")
        lines.append(f"Group-Isolated Classes ({len(self.group_isolated_classes)}): {self.group_isolated_classes}")
        lines.append(f"Overall Evaluation Mode: {self.overall_evaluation_mode}")
        lines.append("-" * 90)
        lines.append("Evaluation Validity Notice:")
        lines.append("  Evaluation validity depends on capture diversity. Classes with multiple independent capture groups")
        lines.append("  are evaluated using GROUP_ISOLATED splitting (unseen-capture validation). Classes with only one")
        lines.append("  available capture group use WITHIN_CAPTURE_HOLDOUT and are explicitly marked as having insufficient")
        lines.append("  independent capture diversity. Therefore, the overall experiment (OVERALL_MIXED_EVALUATION) should not")
        lines.append("  be interpreted as fully unseen-capture validation for every class.")
        lines.append("=" * 90)
        return "\n".join(lines)

    def render_summary(self) -> str:
        """Alias for render_table."""
        return self.render_table()


def generate_dataset_sufficiency_report(
    raw_samples: List[Any],
    eligible_samples: Optional[List[Any]] = None,
    dataset_name: str = "dataset",
) -> DatasetSufficiencyReport:
    """Generate a sufficiency and capture diversity report from dataset samples.

    Args:
        raw_samples: List of all extracted FlowSample objects (Level 1).
        eligible_samples: Optional list of model-eligible FlowSample objects (Level 2).
        dataset_name: Name of dataset.

    Returns:
        DatasetSufficiencyReport instance.
    """
    if hasattr(raw_samples, "samples"):
        ds_obj = raw_samples
        dataset_name = getattr(ds_obj.metadata, "name", dataset_name)
        raw_list = ds_obj.samples
    else:
        raw_list = list(raw_samples)

    eligible = eligible_samples if eligible_samples is not None else [
        s for s in raw_list if s.metadata.get("model_eligible", True)
    ]

    all_classes = sorted(list({s.label for s in raw_list} | {s.label for s in eligible}))
    class_records: Dict[str, ClassSufficiencyRecord] = {}
    group_isolated: List[str] = []
    within_capture: List[str] = []

    for c in all_classes:
        c_raw = [s for s in raw_list if s.label == c]
        c_elig = [s for s in eligible if s.label == c]

        # Extract unique captures and groups
        captures = sorted(list({s.metadata.get("source_capture", "") for s in c_elig if s.metadata.get("source_capture")}))
        groups = sorted(list({s.group for s in c_elig if s.group}))

        n_groups = len(groups)
        n_elig = len(c_elig)

        if n_groups >= 2 and n_elig >= 10:
            eval_mode = EvaluationMode.GROUP_ISOLATED.value
            status = SufficiencyStatus.SUFFICIENT.value
            notes = f"Independent group evaluation possible across {n_groups} capture groups."
            group_isolated.append(c)
        elif n_groups >= 2 and n_elig < 10:
            eval_mode = EvaluationMode.GROUP_ISOLATED.value
            status = SufficiencyStatus.LIMITED_SAMPLE_SIZE.value
            notes = f"Multiple capture groups exist ({n_groups}), but sample size is small ({n_elig} flows)."
            group_isolated.append(c)
        else:
            eval_mode = EvaluationMode.WITHIN_CAPTURE_HOLDOUT.value
            status = SufficiencyStatus.INSUFFICIENT_CAPTURE_DIVERSITY.value
            notes = "Only 1 capture group available. Requires intra-capture holdout split."
            within_capture.append(c)

        class_records[c] = ClassSufficiencyRecord(
            class_name=c,
            total_raw_flows=len(c_raw),
            eligible_flows=n_elig,
            excluded_flows=len(c_raw) - n_elig,
            capture_count=len(captures),
            capture_group_count=n_groups,
            capture_groups=groups,
            evaluation_mode=eval_mode,
            sufficiency_status=status,
            notes=notes,
        )

    # Determine overall dataset evaluation mode
    if not within_capture and group_isolated:
        overall_mode = EvaluationMode.STRICT_GROUP_EVALUATION.value
    elif not group_isolated and within_capture:
        overall_mode = EvaluationMode.WITHIN_CAPTURE_EVALUATION.value
    else:
        overall_mode = EvaluationMode.OVERALL_MIXED_EVALUATION.value

    return DatasetSufficiencyReport(
        dataset_name=dataset_name,
        total_raw_flows=len(raw_samples),
        total_eligible_flows=len(eligible),
        total_excluded_flows=len(raw_samples) - len(eligible),
        classes=all_classes,
        class_records=class_records,
        group_isolated_classes=group_isolated,
        within_capture_classes=within_capture,
        overall_evaluation_mode=overall_mode,
    )
