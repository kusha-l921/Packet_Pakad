"""Packet analyzer engine orchestrating file validation, streaming parsing,
protocol classification, IPsec identification, and statistics calculation.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional

from person2_engine.src.input_handler import validate_file_input
from person2_engine.src.ipsec_detector import IPsecDetector
from person2_engine.src.models import (
    AnalysisResult,
    CaptureInfo,
    ExecutionStatus,
    PacketMetadata,
    PacketStatistics,
    ProtocolSummary,
)
from person2_engine.src.output_formatter import save_json_output
from person2_engine.src.pcap_reader import extract_packet_metadata, safe_read_packets
from person2_engine.src.protocol_detector import ProtocolDetector

logger = logging.getLogger(__name__)


def analyze_capture(
    file_path: str | Path,
    output_json: Optional[str | Path] = None,
    include_packets_in_json: bool = False,
) -> AnalysisResult:
    """Primary public entry point to analyze a PCAP or PCAPNG capture file.

    Performs:
    1. Input validation (existence, extension, size, permissions, corruption checks).
    2. Safe, streaming packet reading and layer extraction.
    3. Layer-2 to Layer-4 protocol detection and aggregate counts.
    4. Dedicated IPsec (ESP, AH, IKE UDP 500, NAT-T UDP 4500) inspection.
    5. Packet length distribution statistics calculation.
    6. Machine-readable structured result assembly and optional JSON output.

    Guarantees:
    - Never raises unhandled exceptions on invalid, corrupted, or unsupported files.
    - Accurately tracks status, errors, and warnings.

    Args:
        file_path: Path to the .pcap or .pcapng file.
        output_json: Optional path to save analysis output as JSON.
        include_packets_in_json: Whether saved JSON includes internal per-packet metadata.

    Returns:
        AnalysisResult containing capture_info, protocol_summary, ipsec_analysis,
        packet_statistics, and status.
    """
    try:
        val = validate_file_input(file_path)
        if not val.is_valid:
            result = AnalysisResult(
                capture_info=CaptureInfo(
                    file_name=val.file_name,
                    file_type=val.file_type,
                    total_packets=0,
                    readable=False,
                ),
                protocol_summary=ProtocolSummary(),
                ipsec_analysis=IPsecDetector().get_analysis(),
                packet_statistics=PacketStatistics(),
                status=ExecutionStatus(
                    success=False,
                    errors=[val.error_message or "File validation failed."],
                    warnings=[val.warning_message] if val.warning_message else [],
                ),
                packets=[],
            )
            if output_json:
                save_json_output(result, output_json, include_packets=include_packets_in_json)
            return result

        # Initialize detectors and aggregators
        protocol_detector = ProtocolDetector()
        ipsec_detector = IPsecDetector()
        packet_records: List[PacketMetadata] = []
        packet_sizes: List[int] = []
        warnings: List[str] = [val.warning_message] if val.warning_message else []
        errors: List[str] = []

        # Safe streaming packet consumption
        reader_generator = safe_read_packets(val.file_path)
        try:
            for idx, packet in reader_generator:
                try:
                    meta = extract_packet_metadata(packet, idx)
                    detected_protos = protocol_detector.process_packet(packet)
                    meta.protocols = detected_protos
                    ipsec_detector.process_packet(packet)

                    packet_sizes.append(meta.length)
                    packet_records.append(meta)
                except Exception as e:
                    warn_msg = f"Failed processing packet #{idx}: {e}"
                    logger.warning(warn_msg)
                    warnings.append(warn_msg)
        except Exception as e:
            err_msg = f"Exception while streaming packets: {e}"
            logger.error(err_msg)
            errors.append(err_msg)

        total_packets = len(packet_records)
        readable = total_packets > 0 or len(errors) == 0

        # Calculate packet size statistics
        if packet_sizes:
            min_size = min(packet_sizes)
            max_size = max(packet_sizes)
            avg_size = round(float(sum(packet_sizes)) / len(packet_sizes), 2)
        else:
            min_size = 0
            max_size = 0
            avg_size = 0.0

        statistics = PacketStatistics(
            minimum_packet_size=min_size,
            maximum_packet_size=max_size,
            average_packet_size=avg_size,
        )

        capture_info = CaptureInfo(
            file_name=val.file_name,
            file_type=val.file_type,
            total_packets=total_packets,
            readable=readable,
        )

        protocol_summary = protocol_detector.get_summary()
        ipsec_analysis = ipsec_detector.get_analysis()

        success = len(errors) == 0

        result = AnalysisResult(
            capture_info=capture_info,
            protocol_summary=protocol_summary,
            ipsec_analysis=ipsec_analysis,
            packet_statistics=statistics,
            status=ExecutionStatus(
                success=success,
                errors=errors,
                warnings=warnings,
            ),
            packets=packet_records,
        )

        if output_json:
            save_json_output(result, output_json, include_packets=include_packets_in_json)

        return result

    except Exception as unexpected_err:
        logger.exception("Unhandled error during capture analysis: %s", unexpected_err)
        file_name = Path(file_path).name if file_path else "unknown"
        ext = Path(file_path).suffix.lstrip(".").lower() if file_path else "unknown"
        fallback_result = AnalysisResult(
            capture_info=CaptureInfo(
                file_name=file_name,
                file_type=ext or "unknown",
                total_packets=0,
                readable=False,
            ),
            protocol_summary=ProtocolSummary(),
            ipsec_analysis=IPsecDetector().get_analysis(),
            packet_statistics=PacketStatistics(),
            status=ExecutionStatus(
                success=False,
                errors=[f"Critical unhandled error: {unexpected_err}"],
                warnings=[],
            ),
            packets=[],
        )
        if output_json:
            try:
                save_json_output(fallback_result, output_json, include_packets=include_packets_in_json)
            except Exception:
                pass
        return fallback_result


def analyze_capture_with_features(
    file_path: str | Path,
    output_json: Optional[str | Path] = None,
) -> CaptureFeaturesResult:
    """Analyze a capture file and extract canonical bidirectional flow features.

    Additive Phase 2 entry point. Executes Phase 1 packet analysis, builds
    canonical bidirectional flows (for TCP, UDP, ESP, AH, ICMP, etc.), extracts
    25 numerical features per flow conforming to Schema v1.0, and validates each
    flow for ML readiness.

    Args:
        file_path: Path to the .pcap or .pcapng file.
        output_json: Optional path to save Phase 2 JSON output.

    Returns:
        CaptureFeaturesResult containing Phase 1 analysis, feature_schema_version,
        flow_summary, and list of FlowResults.
    """
    from person2_engine.src.feature_schema import FEATURE_SCHEMA_VERSION
    from person2_engine.src.flow_builder import FlowBuilder
    from person2_engine.src.flow_models import CaptureFeaturesResult, FlowSummary
    from person2_engine.src.output_formatter import save_flow_features_json

    try:
        # Run Phase 1 analysis to validate file and stream packets
        analysis = analyze_capture(file_path=file_path, output_json=None)

        if not analysis.status.success or not analysis.packets:
            empty_summary = FlowSummary(total_flows=0, valid_flows=0, invalid_flows=0)
            res = CaptureFeaturesResult(
                analysis=analysis,
                feature_schema_version=FEATURE_SCHEMA_VERSION,
                flow_summary=empty_summary,
                flows=[],
            )
            if output_json:
                save_flow_features_json(res, output_json)
            return res

        # Build bidirectional flows and extract features
        builder = FlowBuilder()
        builder.process_packets(analysis.packets)
        flows, summary = builder.build_flow_results()

        res = CaptureFeaturesResult(
            analysis=analysis,
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            flow_summary=summary,
            flows=flows,
        )

        if output_json:
            save_flow_features_json(res, output_json)

        return res

    except Exception as e:
        logger.exception("Unexpected error during flow feature analysis: %s", e)
        # Fallback to Phase 1 error representation
        analysis = analyze_capture(file_path=file_path, output_json=None)
        analysis.status.success = False
        analysis.status.errors.append(f"Flow feature analysis error: {e}")
        from person2_engine.src.feature_schema import FEATURE_SCHEMA_VERSION
        from person2_engine.src.flow_models import CaptureFeaturesResult, FlowSummary
        from person2_engine.src.output_formatter import save_flow_features_json

        res = CaptureFeaturesResult(
            analysis=analysis,
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            flow_summary=FlowSummary(),
            flows=[],
        )
        if output_json:
            try:
                save_flow_features_json(res, output_json)
            except Exception:
                pass
        return res


def analyze_capture_with_predictions(
    file_path: str | Path,
    model_id: Optional[str] = None,
    output_json: Optional[str | Path] = None,
    allow_unverified_domain: bool = False,
    allow_test_models: bool = False,
) -> Any:
    """Analyze a capture file and generate standardized model predictions for all valid flows.

    Additive Phase 3 entry point. Executes Phase 1 packet analysis, builds
    canonical bidirectional flows and extracts Phase 2 features, attempts model
    discovery and compatibility validation, and executes inference (or reports
    MODEL_UNAVAILABLE / INCOMPATIBLE) without guessing or fabricating data.

    Args:
        file_path: Path to the .pcap or .pcapng file.
        model_id: Optional identifier of the model to query in the registry.
        output_json: Optional path to save combined Phase 3 JSON output.
        allow_unverified_domain: Allow inference when TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED.
        allow_test_models: Allow test/dummy models (for automated testing only).

    Returns:
        CapturePredictionResult containing capture_features, prediction_summary,
        and list of FlowPredictionResults.
    """
    from person2_engine.src.inference_engine import predict_flows
    from person2_engine.src.output_formatter import save_prediction_results_json
    from person2_engine.src.prediction_models import CapturePredictionResult, PredictionSummary

    # 1. Run Phase 2 flow feature analysis (which runs Phase 1 packet analysis)
    flow_features_res = analyze_capture_with_features(file_path=file_path, output_json=None)

    # 2. If capture analysis failed or no flows were extracted
    if not flow_features_res.flows:
        res = CapturePredictionResult(
            capture_features=flow_features_res,
            prediction_summary=PredictionSummary(
                total_flows=0,
                predictions_successful=0,
                model_unavailable=0,
                incompatible=0,
                domain_unverified=0,
            ),
            predictions=[],
        )
        if output_json:
            save_prediction_results_json(res, output_json)
        return res

    # 3. Perform inference for each flow
    predictions, summary = predict_flows(
        flow_features_res.flows,
        model_id=model_id,
        allow_unverified_domain=allow_unverified_domain,
        allow_test_models=allow_test_models,
    )

    res = CapturePredictionResult(
        capture_features=flow_features_res,
        prediction_summary=summary,
        predictions=predictions,
    )

    if output_json:
        save_prediction_results_json(res, output_json)

    return res


