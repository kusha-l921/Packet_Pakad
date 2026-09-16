"""Dataset adapters for loading and constructing canonical Phase 3 training datasets.

Supports loading pre-extracted flow feature CSV datasets and constructing datasets
directly from folders of labelled PCAP/PCAPNG captures by running Phase 1 & Phase 2 pipelines.
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from person2_engine.src.dataset_models import DatasetMetadata, FlowSample, TrainingDataset
from person2_engine.src.dataset_validator import validate_csv_dataset, validate_dataset_records
from person2_engine.src.feature_adapter import adapt_dict_to_vector, adapt_flow_to_vector
from person2_engine.src.feature_schema import FEATURE_ORDER, FEATURE_SCHEMA_VERSION
from person2_engine.src.label_mapper import LabelMapper
from person2_engine.src.packet_analyzer import analyze_capture_with_features

logger = logging.getLogger(__name__)


def load_csv_dataset(
    file_path: Union[str, Path],
    label_column: str = "label",
    group_column: Optional[str] = "capture_group",
    dataset_name: Optional[str] = None,
    traffic_type: str = "encrypted_flows",
    ipsec_traffic: bool = False,
    label_mapper: Optional[LabelMapper] = None,
) -> TrainingDataset:
    """Load a verified CSV flow dataset into a TrainingDataset container.

    Args:
        file_path: Path to CSV dataset file.
        label_column: Name of the target label column.
        group_column: Optional column name containing capture group / session ID.
        dataset_name: Optional custom dataset name (defaults to file stem).
        traffic_type: Description of network traffic (e.g. "encrypted_vpn", "proxy_tls").
        ipsec_traffic: Whether dataset contains genuine IPsec/StrongSwan traffic.
        label_mapper: Optional LabelMapper to transform raw labels to canonical classes.

    Returns:
        TrainingDataset instance.

    Raises:
        ValueError: If CSV validation fails.
    """
    path = Path(file_path).resolve()
    report = validate_csv_dataset(path, label_column=label_column)
    if not report.is_valid:
        raise ValueError(
            f"Dataset '{path.name}' failed schema validation:\n" + "\n".join(f"- {e}" for e in report.errors)
        )

    mapper = label_mapper or LabelMapper()
    samples: List[FlowSample] = []
    class_dist: Dict[str, int] = {}

    with open(path, mode="r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for idx, row in enumerate(reader, 1):
            raw_label = row[label_column]
            canonical_label = mapper.map_label(raw_label)
            class_dist[canonical_label] = class_dist.get(canonical_label, 0) + 1

            vector = adapt_dict_to_vector(row, expected_order=FEATURE_ORDER)
            sample_id = row.get("sample_id", f"sample_{idx}")
            group_val = None
            if group_column and group_column in row and row[group_column]:
                group_val = row[group_column]
            elif "capture_group" in row and row["capture_group"]:
                group_val = row["capture_group"]
            elif "group" in row and row["group"]:
                group_val = row["group"]

            sample_meta = {
                "source_dataset": row.get("source_dataset", ""),
                "source_capture": row.get("source_capture", ""),
                "original_label": row.get("original_label", raw_label),
                "model_eligible": (
                    row.get("model_eligible", "True").lower() == "true"
                    if "model_eligible" in row
                    else True
                ),
                "exclusion_reason": row.get("exclusion_reason", "") if "exclusion_reason" in row else None,
            }

            samples.append(
                FlowSample(
                    features=vector,
                    label=canonical_label,
                    sample_id=sample_id,
                    group=group_val,
                    metadata=sample_meta,
                )
            )

    meta = DatasetMetadata(
        name=dataset_name or path.stem,
        source=str(path),
        traffic_type=traffic_type,
        sample_count=len(samples),
        class_distribution=class_dist,
        ipsec_traffic=ipsec_traffic,
        description=f"Loaded from {path.name}",
        feature_schema_version=FEATURE_SCHEMA_VERSION,
    )

    return TrainingDataset(
        samples=samples,
        metadata=meta,
        feature_names=list(FEATURE_ORDER),
        feature_schema_version=FEATURE_SCHEMA_VERSION,
    )


def save_dataset_to_csv(
    dataset: TrainingDataset,
    output_path: Union[str, Path],
    label_column: str = "label",
) -> Path:
    """Serialize a TrainingDataset to a standard CSV file adhering to Schema v1.0.

    Args:
        dataset: TrainingDataset instance.
        output_path: Target CSV file path.
        label_column: Name of the label column.

    Returns:
        Resolved Path to the saved CSV file.
    """
    path = Path(output_path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = list(FEATURE_ORDER) + [label_column]

    with open(path, mode="w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for sample in dataset.samples:
            row: Dict[str, Any] = dict(zip(FEATURE_ORDER, sample.features))
            row[label_column] = sample.label
            writer.writerow(row)

    logger.info("Saved %d dataset samples to %s", len(dataset.samples), path)
    return path


def load_pcap_folder_dataset(
    folder_path: Union[str, Path],
    label_mapper: Optional[LabelMapper] = None,
    dataset_name: Optional[str] = None,
    ipsec_traffic: bool = False,
) -> TrainingDataset:
    """Build a TrainingDataset directly from a folder of labelled PCAP/PCAPNG files.

    Files should be named with their class category (e.g. 'web_01.pcap', 'video_hd.pcapng')
    or structured in subfolders named after classes.

    Args:
        folder_path: Directory containing .pcap or .pcapng files.
        label_mapper: Optional label mapper.
        dataset_name: Dataset identifier.
        ipsec_traffic: Whether captures contain real IPsec traffic.

    Returns:
        TrainingDataset populated with extracted flow features.
    """
    root = Path(folder_path).resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"PCAP folder does not exist: {root}")

    mapper = label_mapper or LabelMapper()
    samples: List[FlowSample] = []
    class_dist: Dict[str, int] = {}

    pcap_files = sorted(
        [p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in {".pcap", ".pcapng"}]
    )

    if not pcap_files:
        raise ValueError(f"No .pcap or .pcapng files found in directory: {root}")

    for pcap_file in pcap_files:
        # Infer class from parent folder name or filename prefix
        inferred_raw_label = pcap_file.parent.name if pcap_file.parent != root else pcap_file.stem.split("_")[0]
        try:
            canonical_label = mapper.map_label(inferred_raw_label)
        except ValueError:
            logger.warning("Skipping file %s: cannot map label '%s'", pcap_file.name, inferred_raw_label)
            continue

        # Extract flows using Phase 1 & Phase 2 pipeline
        res = analyze_capture_with_features(pcap_file)
        if not res.analysis.status.success:
            logger.warning("Failed to analyze capture %s", pcap_file.name)
            continue

        for flow in res.flows:
            if not flow.validation.valid:
                continue
            vector = adapt_flow_to_vector(flow)
            sample_id = f"{pcap_file.stem}_{flow.flow_metadata.flow_id}"
            class_dist[canonical_label] = class_dist.get(canonical_label, 0) + 1
            samples.append(
                FlowSample(
                    features=vector,
                    label=canonical_label,
                    sample_id=sample_id,
                )
            )

    meta = DatasetMetadata(
        name=dataset_name or root.name,
        source=str(root),
        traffic_type="pcap_extracted_flows",
        sample_count=len(samples),
        class_distribution=class_dist,
        ipsec_traffic=ipsec_traffic,
        description=f"Constructed from {len(pcap_files)} PCAPs in {root.name}",
    )

    return TrainingDataset(
        samples=samples,
        metadata=meta,
        feature_names=list(FEATURE_ORDER),
        feature_schema_version=FEATURE_SCHEMA_VERSION,
    )
