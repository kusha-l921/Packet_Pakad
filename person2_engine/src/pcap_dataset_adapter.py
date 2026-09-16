"""Reusable PCAP dataset adapter for manifest-driven dataset extraction.

Converts raw PCAP/PCAPNG capture files into canonical Phase 2 25-feature training datasets.
Decoupled from specific datasets, supporting both UNB/CIC ISCXVPN2016 and future
Person 1 StrongSwan/IPsec captures through a standard manifest contract.
"""

from __future__ import annotations

import csv
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

from person2_engine.src.dataset_models import DatasetMetadata, FlowSample, TrainingDataset
from person2_engine.src.feature_adapter import adapt_flow_to_vector
from person2_engine.src.feature_schema import FEATURE_ORDER, FEATURE_SCHEMA_VERSION
from person2_engine.src.feature_validator import validate_ml_vector
from person2_engine.src.label_mapper import LabelMapper
from person2_engine.src.packet_analyzer import analyze_capture_with_features

logger = logging.getLogger(__name__)


@dataclass
class PcapManifestEntry:
    """A single capture entry in a PCAP dataset manifest."""

    scenario_id: str
    pcap_path: str
    canonical_label: str
    original_label: Optional[str] = None
    source_dataset: str = "iscxvpn2016"
    capture_group: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PcapDatasetManifest:
    """Collection of capture entries forming a dataset manifest."""

    manifest_version: str = "1.0"
    dataset_name: str = "pcap_dataset"
    description: str = ""
    captures: List[PcapManifestEntry] = field(default_factory=list)
    default_source_dataset: str = "iscxvpn2016"
    label_strategy: str = "5_class_aligned"
    source_name: str = "PCAP Capture Repository"

    @property
    def entries(self) -> List[PcapManifestEntry]:
        """Alias for captures list to support both manifest naming conventions."""
        return self.captures

    @property
    def dataset_id(self) -> str:
        """Alias for dataset_name."""
        return self.dataset_name

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PcapDatasetManifest:
        """Parse manifest from dictionary structure."""
        if not isinstance(data, dict):
            raise ValueError("Manifest data must be a dictionary.")

        captures_data = data.get("captures", data.get("entries", []))
        if not isinstance(captures_data, list):
            raise ValueError("Manifest must contain a list of 'captures' or 'entries'.")

        captures: List[PcapManifestEntry] = []
        default_source = data.get("default_source_dataset", data.get("source_dataset", "iscxvpn2016"))

        for entry in captures_data:
            scenario_id = entry.get("scenario_id", "")
            pcap_path = entry.get("pcap_path", "")
            canonical_label = entry.get("canonical_label", "")
            original_label = entry.get("original_label", canonical_label)
            source_dataset = entry.get("source_dataset", default_source)
            capture_group = entry.get("capture_group", Path(pcap_path).stem if pcap_path else scenario_id)
            meta = entry.get("metadata", {})

            if not pcap_path or not canonical_label:
                logger.warning("Skipping invalid manifest entry: missing pcap_path or canonical_label: %s", entry)
                continue

            captures.append(
                PcapManifestEntry(
                    scenario_id=scenario_id or Path(pcap_path).stem,
                    pcap_path=pcap_path,
                    canonical_label=canonical_label,
                    original_label=original_label,
                    source_dataset=source_dataset,
                    capture_group=capture_group,
                    metadata=meta,
                )
            )

        return cls(
            manifest_version=data.get("manifest_version", "1.0"),
            dataset_name=data.get("dataset_name", data.get("dataset_id", "pcap_dataset")),
            description=data.get("description", ""),
            captures=captures,
            default_source_dataset=default_source,
            label_strategy=data.get("label_strategy", "5_class_aligned"),
            source_name=data.get("source_name", "PCAP Capture Repository"),
        )


def load_pcap_manifest(manifest_path: Union[str, Path]) -> PcapDatasetManifest:
    """Load and parse a dataset manifest from JSON or CSV.

    Args:
        manifest_path: Path to manifest file (.json or .csv).

    Returns:
        PcapDatasetManifest instance.

    Raises:
        FileNotFoundError: If manifest file does not exist.
        ValueError: If manifest format is unsupported or invalid.
    """
    path = Path(manifest_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Manifest file not found: {path}")

    suffix = path.suffix.lower()
    if suffix == ".json":
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            raise ValueError(f"Failed to parse JSON manifest {path}: {e}") from e
        return PcapDatasetManifest.from_dict(data)
    elif suffix == ".csv":
        captures: List[PcapManifestEntry] = []
        with open(path, "r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                pcap_path = row.get("pcap_path", "")
                canonical_label = row.get("canonical_label", "")
                if not pcap_path or not canonical_label:
                    continue
                captures.append(
                    PcapManifestEntry(
                        scenario_id=row.get("scenario_id", Path(pcap_path).stem),
                        pcap_path=pcap_path,
                        canonical_label=canonical_label,
                        original_label=row.get("original_label", canonical_label),
                        source_dataset=row.get("source_dataset", "iscxvpn2016"),
                        capture_group=row.get("capture_group", Path(pcap_path).stem),
                    )
                )
        return PcapDatasetManifest(
            manifest_version="1.0",
            dataset_name=path.stem,
            description=f"Loaded from CSV manifest {path.name}",
            captures=captures,
        )
    else:
        raise ValueError(f"Unsupported manifest format '{suffix}'. Supported formats: .json, .csv")


from person2_engine.src.flow_filter import FlowExclusionReason, FlowRelevancePolicy


def extract_flows_from_manifest(
    manifest: Union[PcapDatasetManifest, str, Path],
    base_dir: Optional[Union[str, Path]] = None,
    label_mapper: Optional[LabelMapper] = None,
    ipsec_traffic: bool = False,
    output_csv_path: Optional[Union[str, Path]] = None,
    raw_output_csv_path: Optional[Union[str, Path]] = None,
    audit_output_json_path: Optional[Union[str, Path]] = None,
    relevance_policy: Optional[FlowRelevancePolicy] = None,
) -> TrainingDataset:
    """Extract canonical 25-feature flow samples from PCAPs listed in a manifest.

    Maintains a strict two-tier dataset architecture:
      - Level 1 (Raw Extracted Flows): All flows extracted across PCAPs with full forensic provenance.
      - Level 2 (Model-Eligible Flows): Verified genuine scenario flows passing FlowRelevancePolicy.

    Args:
        manifest: PcapDatasetManifest or path to manifest file.
        base_dir: Optional base directory to resolve relative PCAP paths against.
        label_mapper: Optional label mapper for canonical category mapping.
        ipsec_traffic: Whether dataset contains genuine IPsec traffic.
        output_csv_path: Optional path to serialize model-eligible flows to CSV.
        raw_output_csv_path: Optional path to serialize raw extracted flows to CSV.
        audit_output_json_path: Optional path to serialize flow composition audit to JSON.
        relevance_policy: Optional custom FlowRelevancePolicy instance.

    Returns:
        TrainingDataset populated with model-eligible flow samples (with raw_dataset attached).
    """
    if isinstance(manifest, (str, Path)):
        manifest = load_pcap_manifest(manifest)

    mapper = label_mapper or LabelMapper()
    policy = relevance_policy or FlowRelevancePolicy()
    base = Path(base_dir).resolve() if base_dir else Path.cwd()

    raw_samples: List[FlowSample] = []
    eligible_samples: List[FlowSample] = []
    raw_class_dist: Dict[str, int] = {}
    eligible_class_dist: Dict[str, int] = {}
    exclusions_by_reason: Dict[str, int] = {}
    per_capture_breakdown: Dict[str, Dict[str, Any]] = {}
    processed_captures = 0
    failed_captures: List[str] = []

    for entry in manifest.captures:
        pcap_path = Path(entry.pcap_path)
        if not pcap_path.is_absolute():
            pcap_path = (base / pcap_path).resolve()

        if not pcap_path.is_file():
            logger.warning("Manifest PCAP file not found: %s", pcap_path)
            failed_captures.append(str(pcap_path))
            continue

        # Map label to canonical category
        try:
            canonical_label = mapper.map_label(entry.canonical_label)
        except ValueError:
            logger.warning("Cannot map label '%s' for capture %s", entry.canonical_label, pcap_path.name)
            continue

        # Extract features using existing Phase 1 & Phase 2 pipeline
        res = analyze_capture_with_features(pcap_path)
        if not res.analysis.status.success:
            logger.warning("Packet analysis failed for %s: %s", pcap_path.name, res.analysis.status.errors)
            failed_captures.append(str(pcap_path))
            continue

        cap_raw_count = 0
        cap_eligible_count = 0
        cap_exclusions: Dict[str, int] = {}

        for flow in res.flows:
            if not flow.validation.valid:
                continue

            # Convert to canonical 25-feature vector
            try:
                features = adapt_flow_to_vector(flow)
            except Exception as e:
                logger.warning(
                    "Feature adaptation failed for flow %s in %s: %s",
                    flow.flow_metadata.flow_id,
                    pcap_path.name,
                    e,
                )
                continue

            # Validate against exact 25-feature ML schema
            val = validate_ml_vector(features)
            if not val.valid:
                logger.warning(
                    "Flow feature validation failed for %s: %s",
                    flow.flow_metadata.flow_id,
                    val.errors,
                )
                continue

            # Evaluate relevance against policy
            is_eligible, exclusion_reason = policy.evaluate_flow(
                flow_id=flow.flow_metadata.flow_id,
                protocol=flow.flow_metadata.protocol,
                endpoint_a=flow.flow_metadata.endpoint_a,
                endpoint_b=flow.flow_metadata.endpoint_b,
                scenario_metadata=entry.metadata,
                canonical_label=canonical_label,
            )

            sample_id = f"{entry.scenario_id}_{flow.flow_metadata.flow_id}"
            group = entry.capture_group or entry.scenario_id

            sample_meta = {
                "source_dataset": entry.source_dataset,
                "source_capture": pcap_path.name,
                "original_label": entry.original_label,
                "canonical_label": canonical_label,
                "capture_group": group,
                "protocol": flow.flow_metadata.protocol,
                "endpoint_a": flow.flow_metadata.endpoint_a,
                "endpoint_b": flow.flow_metadata.endpoint_b,
                "model_eligible": is_eligible,
                "exclusion_reason": exclusion_reason or "",
                **entry.metadata,
            }

            sample = FlowSample(
                features=features,
                label=canonical_label,
                sample_id=sample_id,
                group=group,
                metadata=sample_meta,
            )

            raw_samples.append(sample)
            raw_class_dist[canonical_label] = raw_class_dist.get(canonical_label, 0) + 1
            cap_raw_count += 1

            if is_eligible:
                eligible_samples.append(sample)
                eligible_class_dist[canonical_label] = eligible_class_dist.get(canonical_label, 0) + 1
                cap_eligible_count += 1
            else:
                reason_str = exclusion_reason or "UNKNOWN_EXCLUSION"
                exclusions_by_reason[reason_str] = exclusions_by_reason.get(reason_str, 0) + 1
                cap_exclusions[reason_str] = cap_exclusions.get(reason_str, 0) + 1

        processed_captures += 1
        per_capture_breakdown[pcap_path.name] = {
            "scenario_id": entry.scenario_id,
            "assigned_label": canonical_label,
            "canonical_label": canonical_label,
            "capture_group": entry.capture_group or entry.scenario_id,
            "total_flows": cap_raw_count,
            "eligible_flows": cap_eligible_count,
            "excluded_flows": cap_raw_count - cap_eligible_count,
            "exclusions": cap_exclusions,
        }
        logger.info(
            "Processed capture '%s' (%s): %d raw flows (%d eligible, %d excluded)",
            pcap_path.name,
            canonical_label,
            cap_raw_count,
            cap_eligible_count,
            cap_raw_count - cap_eligible_count,
        )

    # Check if IPsec traffic is present across any source
    is_ipsec = ipsec_traffic or any(e.source_dataset == "person1_ipsec" for e in manifest.captures)

    # Build Level 1: Raw Dataset
    raw_meta = DatasetMetadata(
        name=f"{manifest.dataset_name}_raw",
        source=f"manifest:{len(manifest.captures)}_captures",
        traffic_type="raw_extracted_flows",
        sample_count=len(raw_samples),
        class_distribution=raw_class_dist,
        ipsec_traffic=is_ipsec,
        description=f"Raw flows extracted from {processed_captures} PCAP captures (Level 1)",
        feature_schema_version=FEATURE_SCHEMA_VERSION,
    )
    raw_dataset = TrainingDataset(
        samples=raw_samples,
        metadata=raw_meta,
        feature_names=list(FEATURE_ORDER),
        feature_schema_version=FEATURE_SCHEMA_VERSION,
    )

    # Build Level 2: Model-Eligible Dataset
    eligible_meta = DatasetMetadata(
        name=manifest.dataset_name,
        source=f"manifest:{len(manifest.captures)}_captures_filtered",
        traffic_type="model_eligible_flows",
        sample_count=len(eligible_samples),
        class_distribution=eligible_class_dist,
        ipsec_traffic=is_ipsec,
        description=f"Model-eligible flows passing relevance policy ({len(eligible_samples)}/{len(raw_samples)} flows)",
        feature_schema_version=FEATURE_SCHEMA_VERSION,
    )
    eligible_dataset = TrainingDataset(
        samples=eligible_samples,
        metadata=eligible_meta,
        feature_names=list(FEATURE_ORDER),
        feature_schema_version=FEATURE_SCHEMA_VERSION,
    )

    # Attach Level 1 reference and audit dictionary to eligible dataset
    setattr(eligible_dataset, "raw_dataset", raw_dataset)

    # Detect cross-label feature conflicts for raw and eligible datasets
    def _find_conflicts(flow_list: List[FlowSample]) -> List[Dict[str, Any]]:
        vectors: Dict[Tuple[float, ...], List[FlowSample]] = {}
        conflicts: List[Dict[str, Any]] = []
        for s in flow_list:
            vec_key = tuple(round(float(x), 4) for x in s.features)
            if vec_key not in vectors:
                vectors[vec_key] = []
            vectors[vec_key].append(s)
        for vec_key, grp in vectors.items():
            lbls = set(s.label for s in grp)
            if len(lbls) > 1:
                conflicts.append({
                    "labels": sorted(list(lbls)),
                    "count": len(grp),
                    "pcaps": sorted(list(set(s.metadata.get("source_capture", "") for s in grp))),
                    "vector_prefix": list(vec_key[:5]),
                    "flow_ids": [s.metadata.get("flow_id", "") for s in grp],
                })
        return conflicts

    raw_conflicts = _find_conflicts(raw_samples)
    eligible_conflicts = _find_conflicts(eligible_samples)

    audit_report = {
        "dataset_name": manifest.dataset_name,
        "manifest_version": manifest.manifest_version,
        "total_pcaps": processed_captures,
        "total_captures_processed": processed_captures,
        "total_raw_flows": len(raw_samples),
        "total_eligible_flows": len(eligible_samples),
        "total_excluded_flows": len(raw_samples) - len(eligible_samples),
        "exclusion_reasons": dict(sorted(exclusions_by_reason.items(), key=lambda x: x[1], reverse=True)),
        "exclusions_by_reason": dict(sorted(exclusions_by_reason.items(), key=lambda x: x[1], reverse=True)),
        "class_distribution_raw": raw_class_dist,
        "class_distribution_eligible": eligible_class_dist,
        "cross_label_conflicts_raw_count": len(raw_conflicts),
        "cross_label_conflicts_raw": raw_conflicts,
        "cross_label_conflicts_eligible_count": len(eligible_conflicts),
        "cross_label_conflicts_eligible": eligible_conflicts,
        "pcap_composition": per_capture_breakdown,
        "captures": per_capture_breakdown,
    }
    setattr(eligible_dataset.metadata, "audit_report", audit_report)

    # Save outputs if requested
    if output_csv_path:
        out_p = Path(output_csv_path).resolve()
        save_pcap_dataset_to_csv(eligible_dataset, out_p)

        # Automatically save raw and eligible companion files if standard location
        raw_p = Path(raw_output_csv_path).resolve() if raw_output_csv_path else out_p.parent / f"{out_p.stem}_raw.csv"
        save_pcap_dataset_to_csv(raw_dataset, raw_p)

        eligible_companion = out_p.parent / f"{out_p.stem}_eligible.csv"
        if eligible_companion != out_p:
            save_pcap_dataset_to_csv(eligible_dataset, eligible_companion)

        # Save audit report JSON
        audit_p = Path(audit_output_json_path).resolve() if audit_output_json_path else out_p.parent / f"{out_p.stem}_audit.json"
        audit_p.parent.mkdir(parents=True, exist_ok=True)
        with open(audit_p, "w", encoding="utf-8") as f:
            json.dump(audit_report, f, indent=2)
        logger.info("Saved flow composition audit report to %s", audit_p)

    return eligible_dataset


def save_pcap_dataset_to_csv(
    dataset: TrainingDataset,
    output_path: Union[str, Path],
    label_column: str = "label",
    group_column: str = "capture_group",
) -> Path:
    """Save a PCAP flow dataset to CSV including capture group and provenance metadata.

    Args:
        dataset: TrainingDataset instance.
        output_path: Output CSV file path.
        label_column: Label column name.
        group_column: Capture group column name.

    Returns:
        Resolved Path of the saved CSV.
    """
    path = Path(output_path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = list(FEATURE_ORDER) + [
        label_column,
        group_column,
        "sample_id",
        "source_dataset",
        "source_capture",
        "original_label",
        "model_eligible",
        "exclusion_reason",
    ]

    with open(path, mode="w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for sample in dataset.samples:
            row: Dict[str, Any] = dict(zip(FEATURE_ORDER, sample.features))
            row[label_column] = sample.label
            row[group_column] = sample.group or ""
            row["sample_id"] = sample.sample_id or ""
            row["source_dataset"] = sample.metadata.get("source_dataset", "")
            row["source_capture"] = sample.metadata.get("source_capture", "")
            row["original_label"] = sample.metadata.get("original_label", "")
            row["model_eligible"] = str(sample.metadata.get("model_eligible", True))
            row["exclusion_reason"] = sample.metadata.get("exclusion_reason", "")
            writer.writerow(row)

    logger.info("Saved %d canonical flow samples to %s", len(dataset.samples), path)
    return path


def audit_manifest_captures(
    manifest: Union[PcapDatasetManifest, str, Path],
    base_dir: Optional[Union[str, Path]] = None,
    relevance_policy: Optional[FlowRelevancePolicy] = None,
) -> Dict[str, Any]:
    """Execute a comprehensive flow label integrity and background traffic audit.

    Analyzes flow composition across all PCAPs in the manifest without modifying disk.

    Args:
        manifest: PcapDatasetManifest or path to manifest file.
        base_dir: Optional base directory to resolve relative PCAP paths against.
        relevance_policy: Optional custom FlowRelevancePolicy instance.

    Returns:
        Audit report dictionary detailing flow composition, exclusions, and conflict checks.
    """
    dataset = extract_flows_from_manifest(
        manifest=manifest,
        base_dir=base_dir,
        relevance_policy=relevance_policy,
    )
    report = getattr(dataset.metadata, "audit_report", {})
    return report
