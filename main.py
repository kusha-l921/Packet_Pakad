#!/usr/bin/env python3
"""CLI interface for Phase 1, Phase 2, Phase 3, & Phase 4 Network Traffic Analysis Engine."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.resolve()))

from person2_engine.src.packet_analyzer import (
    analyze_capture,
    analyze_capture_with_features,
    analyze_capture_with_predictions,
)
from person2_engine.src.security_analyzer import analyze_capture_security
from person2_engine.src.integration_engine import (
    analyze_capture_complete,
    render_complete_terminal_summary,
)
from person2_engine.src.output_formatter import (
    format_to_json,
    render_flow_features_terminal_summary,
    render_prediction_terminal_summary,
    render_security_terminal_summary,
    render_terminal_summary,
)
from person2_engine.src.dataset_validator import validate_csv_dataset
from person2_engine.src.dataset_adapter import load_csv_dataset
from person2_engine.src.model_trainer import train_candidate_models
from person2_engine.src.model_evaluator import evaluate_all_candidates
from person2_engine.src.model_selector import (
    compare_candidates,
    save_trained_model_and_metadata,
    select_best_candidate,
)
from person2_engine.src.model_registry import get_model_registry


def setup_logging(verbose: bool = False, log_file: str | None = None) -> None:
    """Configure console and optional file logging."""
    level = logging.DEBUG if verbose else logging.INFO
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]

    if log_file:
        log_path = Path(log_file).resolve()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_path, encoding="utf-8"))

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers,
    )


def handle_dataset_validation(dataset_path: str) -> int:
    """Validate a flow dataset against the 25-feature Phase 2 schema contract."""
    p = Path(dataset_path)
    if not p.is_file():
        print(f"[!] Dataset file not found: {p}", file=sys.stderr)
        return 1

    report = validate_csv_dataset(p)
    print("=" * 65)
    print("   PHASE 3: FLOW DATASET VALIDATION REPORT")
    print("=" * 65)
    print(f"Dataset File:       {p.name}")
    print(f"Status:             {'VALID' if report.valid else 'INVALID'}")
    print(f"Schema Version:     {report.feature_schema_version} ({report.feature_count} features)")
    print(f"Total Flow Samples: {report.sample_count}")
    print(f"Detected Classes:   {sorted(report.class_distribution.keys())}")
    print(f"Class Counts:       {report.class_distribution}")
    if report.warnings:
        print("\nWarnings:")
        for w in report.warnings:
            print(f"  [?] {w}")
    if report.errors:
        print("\nErrors:")
        for e in report.errors:
            print(f"  [!] {e}")
    print("=" * 65)
    return 0 if report.valid else 1


def handle_training(dataset_path: str, output_model_id: str | None = None) -> int:
    """Train candidate lightweight tabular models, compare them, and save best."""
    p = Path(dataset_path)
    if not p.is_file():
        print(f"[!] Training dataset file not found: {p}", file=sys.stderr)
        return 1

    print(f"[*] Loading training dataset from: {p}")
    ds = load_csv_dataset(p)
    print(f"[*] Loaded {len(ds.samples)} flow samples with classes: {ds.get_classes()}")

    print("[*] Training candidate lightweight models (Random Forest, Gradient Boosting, Extra Trees, Logistic Regression)...")
    candidates = train_candidate_models(ds, test_size=0.20, random_state=42)
    for name, cand in candidates.items():
        print(f"  + Trained {name} in {cand.training_time_seconds:.3f}s")

    print("[*] Evaluating candidates on held-out test data (20% split)...")
    evaluations = evaluate_all_candidates(candidates)

    print("\n" + compare_candidates(evaluations))

    best_key = select_best_candidate(evaluations)
    winner_rep = evaluations[best_key]
    print(f"\n[+] Selected Optimal Model: '{best_key}' (Macro F1: {winner_rep.f1_macro:.4f}, Latency: {winner_rep.inference_latency_ms:.3f}ms)")

    # Save best model
    paths = save_trained_model_and_metadata(
        candidates[best_key],
        winner_rep,
        model_id=output_model_id,
        dataset_name=ds.metadata.name,
    )
    print(f"[+] Persisted best model artifact:   {paths[0]}")
    print(f"[+] Persisted model contract metadata: {paths[1]}")

    # Also save random forest if another was best, ensuring explainable tree model is persisted
    if best_key != "random_forest" and "random_forest" in candidates:
        rf_paths = save_trained_model_and_metadata(
            candidates["random_forest"],
            evaluations["random_forest"],
            dataset_name=ds.metadata.name,
        )
        print(f"[+] Also persisted tree model:        {rf_paths[0]}")

    return 0


def handle_evaluation(dataset_path: str, model_id: str | None = None) -> int:
    """Evaluate candidate models on a dataset and print detailed per-class metrics."""
    p = Path(dataset_path)
    if not p.is_file():
        print(f"[!] Dataset file not found: {p}", file=sys.stderr)
        return 1

    ds = load_csv_dataset(p)
    candidates = train_candidate_models(ds, test_size=0.20, random_state=42)
    evaluations = evaluate_all_candidates(candidates)

    target_keys = [model_id] if model_id and model_id in evaluations else list(evaluations.keys())
    for k in target_keys:
        print("\n" + "=" * 65)
        print(evaluations[k].render_summary())
        print("=" * 65)
def handle_manifest_extraction(manifest_path: str, output_path: str = "datasets/processed/iscxvpn2016_flows.csv") -> int:
    """Extract canonical 25-feature flow dataset from PCAPs listed in a dataset manifest."""
    from person2_engine.src.pcap_dataset_adapter import extract_flows_from_manifest, save_pcap_dataset_to_csv
    from person2_engine.src.flow_filter import FlowRelevancePolicy

    p = Path(manifest_path)
    if not p.is_file():
        print(f"[!] Dataset manifest file not found: {p}", file=sys.stderr)
        return 1

    out_p = Path(output_path)
    policy = FlowRelevancePolicy()
    print(f"[*] Ingesting PCAP dataset manifest: {p}")
    print("[*] Running Phase 1 packet analysis, Phase 2 flow construction, and Phase 3.5 flow relevance auditing...")

    eligible_dataset = extract_flows_from_manifest(
        manifest=p,
        output_csv_path=out_p,
        relevance_policy=policy,
    )
    raw_dataset = getattr(eligible_dataset, "raw_dataset", eligible_dataset)

    print(f"[+] Level 1 (Raw extracted flows): {len(raw_dataset)} flows saved to {out_p.parent / f'{out_p.stem}_raw{out_p.suffix}'}")
    print(f"[+] Level 2 (Model-eligible flows): {len(eligible_dataset)} flows saved to {out_p}")

    # Exclusions breakdown
    excluded_count = len(raw_dataset) - len(eligible_dataset)
    print(f"[+] Traffic Filter Summary: {len(eligible_dataset)} eligible, {excluded_count} excluded flows")
    reason_counts: dict[str, int] = {}
    for s in raw_dataset.samples:
        if not s.metadata.get("model_eligible", True):
            r = str(s.metadata.get("exclusion_reason", "OTHER"))
            reason_counts[r] = reason_counts.get(r, 0) + 1
    for r, count in sorted(reason_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"    - {r}: {count} flows")

    print(f"[+] Final Model-Eligible Class Distribution: {eligible_dataset.metadata.class_distribution}")
    return 0


def handle_audit_dataset(manifest_path: str) -> int:
    """Perform comprehensive traffic audit and label integrity check on PCAPs in manifest."""
    from person2_engine.src.pcap_dataset_adapter import audit_manifest_captures
    from person2_engine.src.flow_filter import FlowRelevancePolicy

    p = Path(manifest_path)
    if not p.is_file():
        print(f"[!] Dataset manifest file not found: {p}", file=sys.stderr)
        return 1

    policy = FlowRelevancePolicy()
    print(f"[*] Running Phase 3.5 dataset audit on: {p}")
    audit_results = audit_manifest_captures(p, relevance_policy=policy)

    print("=" * 80)
    print("   PHASE 3.5: PCAP FLOW LABEL INTEGRITY & QUALITY AUDIT")
    print("=" * 80)
    print(f"Audited PCAP files:            {audit_results['total_pcaps']}")
    print(f"Total raw flows extracted:     {audit_results['total_raw_flows']}")
    print(f"Total model-eligible flows:    {audit_results['total_eligible_flows']}")
    print(f"Total background/noise flows:  {audit_results['total_excluded_flows']}")
    print(f"Cross-label conflict vectors:  {audit_results['cross_label_conflicts_eligible_count']} (raw had {audit_results['cross_label_conflicts_raw_count']})")
    print("\nBackground & Control Traffic Exclusions:")
    for reason, count in sorted(audit_results['exclusion_reasons'].items(), key=lambda x: x[1], reverse=True):
        print(f"  - {reason:<35}: {count} flows")

    print("\nPer-PCAP Flow Composition:")
    for pcap, comp in audit_results['pcap_composition'].items():
        print(f"  * {pcap:<32} (label: {comp['assigned_label']:<15}): {comp['total_flows']:>4} raw -> {comp['eligible_flows']:>4} eligible ({comp['excluded_flows']:>4} excluded)")

    print("=" * 80)
    return 0


def handle_sufficiency_report(dataset_path: str) -> int:
    """Generate and display dataset sufficiency and capture-group isolation report."""
    from person2_engine.src.dataset_sufficiency import generate_dataset_sufficiency_report

    p = Path(dataset_path)
    if not p.is_file():
        print(f"[!] Dataset file not found: {p}", file=sys.stderr)
        return 1

    ds = load_csv_dataset(p)
    rep = generate_dataset_sufficiency_report(ds)
    print(rep.render_summary())
    return 0


def handle_model_info(model_id: str | None = None) -> int:
    """List registered models and print metadata details."""
    registry = get_model_registry()
    models = registry.discover_models()

    if not models:
        print("[!] No models registered in models/registry/ or models/metadata/.", file=sys.stderr)
        return 1

    print("=" * 75)
    print("   PHASE 3: MODEL REGISTRY & COMPATIBILITY STATUS")
    print("=" * 75)
    print(f"{'Model ID':<35} {'Type':<18} {'Schema':<8} {'IPsec Status':<12}")
    print("-" * 75)

    for mid, model in models.items():
        if model_id and mid != model_id:
            continue
        meta = model.metadata
        if isinstance(meta.ipsec_compatibility, dict):
            compat = str(meta.ipsec_compatibility.get("level", "unknown"))
        elif hasattr(meta.ipsec_compatibility, "level"):
            lvl = meta.ipsec_compatibility.level
            compat = lvl.value if hasattr(lvl, "value") else str(lvl)
        else:
            compat = str(meta.ipsec_compatibility)
        print(f"{mid:<35} {meta.model_type:<18} {meta.feature_schema_version:<8} {compat:<12}")

    print("=" * 75)
    return 0


def main() -> int:
    """CLI entry point for packet capture analysis."""
    parser = argparse.ArgumentParser(
        description="Network Security and Traffic Analysis Engine (Phases 1, 2, 3, & 4)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Phase 1: Packet analysis
  python main.py capture.pcap
  python main.py capture.pcapng --output output/analysis.json

  # Phase 2: Flow detection & feature extraction
  python main.py capture.pcap --features
  python main.py capture.pcap --features --output output/flow_features.json
  python main.py capture.pcap --features --json-only

  # Phase 3: Manifest-based PCAP flow extraction (Real PCAP pipeline)
  python main.py --extract-manifest --manifest datasets/manifests/iscxvpn2016_manifest.json

  # Phase 3: Model training, evaluation, & dataset validation
  python main.py datasets/processed/iscxvpn2016_flows.csv --validate-dataset
  python main.py --train --dataset datasets/processed/iscxvpn2016_flows.csv
  python main.py --evaluate --dataset datasets/processed/iscxvpn2016_flows.csv
  python main.py --model-info

  # Phase 3: Model inference on capture
  python main.py capture.pcap --predict
  python main.py capture.pcap --predict --allow-unverified-domain
  python main.py capture.pcap --predict --output output/predictions.json

  # Phase 4: AI Security Assessment & Explainability
  python main.py capture.pcap --security-analysis
  python main.py capture.pcap -s --output output/security_assessment.json
  python main.py capture.pcap -s --json-only
        """,
    )

    parser.add_argument(
        "capture_path",
        nargs="?",
        default=None,
        help="Path to the .pcap, .pcapng, or .csv file to process",
    )
    parser.add_argument(
        "-c",
        "--complete",
        "--full-analysis",
        action="store_true",
        dest="complete",
        help="Enable Phase 5 unified end-to-end integration analysis (Phases 1-4 combined with validation)",
    )
    parser.add_argument(
        "-s",
        "--security-analysis",
        action="store_true",
        help="Enable Phase 4 AI security assessment, behavioral indicators, and explainability layer",
    )
    parser.add_argument(
        "-p",
        "--predict",
        action="store_true",
        help="Enable Phase 3 model integration and inference layer",
    )
    parser.add_argument(
        "-f",
        "--features",
        action="store_true",
        help="Enable Phase 2 bidirectional flow building and feature extraction",
    )
    parser.add_argument(
        "--train",
        action="store_true",
        help="Train lightweight tabular candidate models on a flow dataset",
    )
    parser.add_argument(
        "--evaluate",
        action="store_true",
        help="Evaluate candidate tabular models on a flow dataset",
    )
    parser.add_argument(
        "--validate-dataset",
        action="store_true",
        help="Validate a CSV dataset against the Phase 2 25-feature schema contract",
    )
    parser.add_argument(
        "--extract-manifest",
        action="store_true",
        help="Extract canonical 25-feature dataset from raw PCAPs using a dataset manifest",
    )
    parser.add_argument(
        "--audit-dataset",
        action="store_true",
        help="Audit PCAP flow composition, background traffic, and label integrity (Phase 3.5)",
    )
    parser.add_argument(
        "--sufficiency-report",
        action="store_true",
        help="Generate dataset sufficiency and capture-group isolation report (Phase 3.5)",
    )
    parser.add_argument(
        "--manifest",
        help="Path to dataset manifest file (JSON/CSV) for PCAP extraction (default: datasets/manifests/iscxvpn2016_manifest.json)",
        default=None,
    )
    parser.add_argument(
        "--model-info",
        action="store_true",
        help="Display metadata and status of discovered models in the model registry",
    )
    parser.add_argument(
        "--dataset",
        help="Path to CSV dataset for training, evaluation, or validation (defaults to datasets/processed/iscxvpn2016_flows.csv)",
        default=None,
    )
    parser.add_argument(
        "--model-id",
        help="Specific model ID to discover/use in the model registry",
        default=None,
    )
    parser.add_argument(
        "--allow-unverified-domain",
        action="store_true",
        help="Allow inference when model is technically compatible but IPsec domain is unverified",
    )
    parser.add_argument(
        "--allow-test-models",
        action="store_true",
        help="Allow test-only models from registry (strictly for testing/demonstration)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Optional destination path to save analysis output as JSON or CSV",
        default=None,
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Print pure JSON output to stdout instead of human-readable summary",
    )
    parser.add_argument(
        "--include-packets",
        action="store_true",
        help="Include per-packet metadata in the Phase 1 JSON output",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable detailed debug logging to stderr",
    )
    parser.add_argument(
        "--log-file",
        help="Path to write log output (e.g. logs/analysis.log)",
        default=None,
    )

    args = parser.parse_args()
    setup_logging(verbose=args.verbose, log_file=args.log_file)

    # 1. Handle Model Information
    if args.model_info:
        return handle_model_info(model_id=args.model_id)

    # 2. Handle Manifest Extraction
    if args.extract_manifest:
        target_manifest = args.manifest or args.capture_path or "datasets/manifests/iscxvpn2016_manifest.json"
        target_output = args.output or "datasets/processed/iscxvpn2016_flows.csv"
        return handle_manifest_extraction(target_manifest, output_path=target_output)

    # 2b. Phase 3.5: Handle Dataset Audit
    if args.audit_dataset:
        target_manifest = args.manifest or args.capture_path or "datasets/manifests/iscxvpn2016_manifest.json"
        return handle_audit_dataset(target_manifest)

    # 2c. Phase 3.5: Handle Sufficiency Report
    if args.sufficiency_report:
        target_dataset = args.dataset or args.capture_path or "datasets/processed/iscxvpn2016_flows.csv"
        return handle_sufficiency_report(target_dataset)

    # 3. Handle Dataset Validation
    if args.validate_dataset:
        target_dataset = args.dataset or args.capture_path
        if not target_dataset:
            print("[!] Error: Specify dataset file path to validate (e.g. python main.py dataset.csv --validate-dataset)", file=sys.stderr)
            return 1
        return handle_dataset_validation(target_dataset)

    default_dataset = (
        "datasets/processed/iscxvpn2016_flows.csv"
        if Path("datasets/processed/iscxvpn2016_flows.csv").is_file()
        else "datasets/synthetic_flows_test_fixture.csv"
    )

    # 4. Handle Training
    if args.train:
        target_dataset = args.dataset or args.capture_path or default_dataset
        return handle_training(target_dataset, output_model_id=args.model_id)

    # 5. Handle Evaluation
    if args.evaluate:
        target_dataset = args.dataset or args.capture_path or default_dataset
        return handle_evaluation(target_dataset, model_id=args.model_id)

    # If no capture_path provided at this point, print help and exit
    if not args.capture_path:
        parser.print_help()
        return 1

    # 4b. Handle Phase 5 Unified Complete Analysis
    if args.complete:
        try:
            result = analyze_capture_complete(
                file_path=args.capture_path,
                model_id=args.model_id,
                output_json=args.output,
                allow_unverified_domain=args.allow_unverified_domain,
                allow_test_models=args.allow_test_models,
                validate_output=True,
            )
            if args.json_only:
                print(result.to_json())
            else:
                print(render_complete_terminal_summary(result))
                if args.output:
                    print(f"\n[+] Unified integration JSON saved to: {args.output}")
            return 0 if result.analysis_metadata.get("analysis_status") == "SUCCESS" else 1
        except Exception as err:
            print(f"[!] Phase 5 complete analysis failed: {err}", file=sys.stderr)
            return 1

    # 5. Handle Phase 4 Security Analysis
    elif args.security_analysis:
        result = analyze_capture_security(
            file_path=args.capture_path,
            model_id=args.model_id,
            output_json=args.output,
            allow_unverified_domain=args.allow_unverified_domain,
            allow_test_models=args.allow_test_models,
        )
        if args.json_only:
            print(result.to_json())
        else:
            print(render_security_terminal_summary(result))
            if args.output:
                print(f"\n[+] Security assessment JSON saved to: {args.output}")
        return 0 if result.analysis_metadata.get("analysis_status") == "SUCCESS" else 1

    # 6. Handle Phase 3 Prediction
    elif args.predict:
        result = analyze_capture_with_predictions(
            file_path=args.capture_path,
            model_id=args.model_id,
            output_json=args.output,
            allow_unverified_domain=args.allow_unverified_domain,
            allow_test_models=args.allow_test_models,
        )
        if args.json_only:
            print(result.to_json())
        else:
            print(render_prediction_terminal_summary(result))
            if args.output:
                print(f"\n[+] Prediction JSON saved to: {args.output}")
        return 0 if result.capture_features.analysis.status.success else 1

    # 6. Handle Phase 2 Features
    elif args.features:
        result = analyze_capture_with_features(
            file_path=args.capture_path,
            output_json=args.output,
        )
        if args.json_only:
            print(result.to_json())
        else:
            print(render_flow_features_terminal_summary(result))
            if args.output:
                print(f"\n[+] Flow features JSON saved to: {args.output}")
        return 0 if result.analysis.status.success else 1

    # 7. Default Phase 1 Packet Analysis
    else:
        result = analyze_capture(
            file_path=args.capture_path,
            output_json=args.output,
            include_packets_in_json=args.include_packets,
        )

        if args.json_only:
            print(format_to_json(result, include_packets=args.include_packets))
        else:
            print(render_terminal_summary(result))
            if args.output:
                print(f"\n[+] Analysis JSON saved to: {args.output}")

        return 0 if result.status.success else 1


if __name__ == "__main__":
    sys.exit(main())


