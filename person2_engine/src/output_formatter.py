"""Output formatter module for structured analysis results.

Provides JSON serialization, file persistence, and human-readable terminal
summary rendering adhering to the required Phase 1 output contract.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from person2_engine.src.models import AnalysisResult

logger = logging.getLogger(__name__)


def format_to_dict(result: AnalysisResult, include_packets: bool = False) -> dict[str, Any]:
    """Convert an AnalysisResult instance into a Python dictionary.

    Args:
        result: The AnalysisResult object.
        include_packets: Whether to include internal packet-level metadata.

    Returns:
        Structured dictionary adhering to the Phase 1 schema.
    """
    return result.to_dict(include_packets=include_packets)


def format_to_json(
    result: AnalysisResult,
    indent: int = 2,
    include_packets: bool = False,
) -> str:
    """Serialize an AnalysisResult instance to a JSON formatted string.

    Args:
        result: The AnalysisResult object.
        indent: Indentation level for pretty printing.
        include_packets: Whether to include internal packet-level metadata.

    Returns:
        JSON string representation.
    """
    return result.to_json(indent=indent, include_packets=include_packets)


def save_json_output(
    result: AnalysisResult,
    output_path: str | Path,
    indent: int = 2,
    include_packets: bool = False,
) -> Path:
    """Save the analysis result to a JSON file on disk.

    Creates destination parent directories if they do not exist.

    Args:
        result: The AnalysisResult object.
        output_path: Target destination file path.
        indent: JSON indentation.
        include_packets: Whether to include packet-level metadata.

    Returns:
        Path to the saved JSON file.
    """
    path = Path(output_path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)

    json_str = format_to_json(result, indent=indent, include_packets=include_packets)
    path.write_text(json_str, encoding="utf-8")
    logger.info("Saved analysis output to %s", path)
    return path


def render_terminal_summary(result: AnalysisResult) -> str:
    """Render a clean, human-readable summary for terminal/CLI display.

    Args:
        result: The AnalysisResult object.

    Returns:
        Formatted multi-line summary string.
    """
    cap = result.capture_info
    proto = result.protocol_summary
    ipsec = result.ipsec_analysis
    stats = result.packet_statistics
    status = result.status

    lines = [
        "=" * 60,
        "   PHASE 1: PCAP & PACKET ANALYSIS REPORT",
        "=" * 60,
        f"File Name:        {cap.file_name}",
        f"File Type:        {cap.file_type}",
        f"Total Packets:    {cap.total_packets}",
        f"Readable:         {cap.readable}",
        "-" * 60,
        "PROTOCOL BREAKDOWN:",
        f"  Ethernet:       {proto.ethernet}",
        f"  IPv4:           {proto.ipv4}",
        f"  IPv6:           {proto.ipv6}",
        f"  TCP:            {proto.tcp}",
        f"  UDP:            {proto.udp}",
        f"  ICMP:           {proto.icmp}",
        f"  ICMPv6:         {proto.icmpv6}",
        f"  Other:          {proto.other}",
        "-" * 60,
        "IPSEC & IKE ANALYSIS:",
        f"  IPsec Detected: {ipsec.ipsec_detected}",
        f"  ESP Detected:   {ipsec.esp_detected}",
        f"  AH Detected:    {ipsec.ah_detected}",
        f"  IKE Detected:   {ipsec.ike_related_traffic_detected}",
        f"  NAT-T Detected: {ipsec.nat_traversal_related_traffic_detected}",
        f"  IKE Version:    {ipsec.ike_version}",
        "-" * 60,
        "PACKET STATISTICS:",
        f"  Min Size:       {stats.minimum_packet_size} bytes",
        f"  Max Size:       {stats.maximum_packet_size} bytes",
        f"  Avg Size:       {stats.average_packet_size:.2f} bytes",
        "-" * 60,
        f"STATUS:           {'SUCCESS' if status.success else 'FAILED'}",
    ]

    if status.errors:
        lines.append("Errors:")
        for err in status.errors:
            lines.append(f"  [!] {err}")

    if status.warnings:
        lines.append("Warnings:")
        for warn in status.warnings:
            lines.append(f"  [*] {warn}")

    lines.append("=" * 60)
    return "\n".join(lines)


def save_flow_features_json(
    result: Any,
    output_path: str | Path,
    indent: int = 2,
) -> Path:
    """Save the Phase 2 capture features result to a JSON file on disk.

    Creates destination parent directories if they do not exist.

    Args:
        result: CaptureFeaturesResult instance.
        output_path: Target destination file path.
        indent: JSON indentation.

    Returns:
        Path to the saved JSON file.
    """
    path = Path(output_path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)

    json_str = result.to_json(indent=indent)
    path.write_text(json_str, encoding="utf-8")
    logger.info("Saved flow features output to %s", path)
    return path


def render_flow_features_terminal_summary(result: Any) -> str:
    """Render a comprehensive human-readable summary including Phase 1 metrics and Phase 2 flow features.

    Args:
        result: CaptureFeaturesResult instance.

    Returns:
        Formatted multi-line summary string.
    """
    base_summary = render_terminal_summary(result.analysis)
    flow_summary = result.flow_summary

    lines = [
        base_summary,
        "",
        "=" * 60,
        "   PHASE 2: BIDIRECTIONAL FLOWS & FEATURE SUMMARY",
        "=" * 60,
        f"Schema Version:   {result.feature_schema_version}",
        f"Total Flows:      {flow_summary.total_flows}",
        f"Valid Flows:      {flow_summary.valid_flows}",
        f"Invalid Flows:    {flow_summary.invalid_flows}",
        "-" * 60,
    ]

    if result.flows:
        lines.append(f"DETECTED FLOWS (showing up to 5 of {len(result.flows)}):")
        for i, f in enumerate(result.flows[:5], 1):
            meta = f.flow_metadata
            ipsec = f.ipsec_metadata
            feats = f.features
            val = f.validation
            lines.extend([
                f"  Flow #{i}: {meta.flow_id}",
                f"    Endpoints: {meta.endpoint_a} <--> {meta.endpoint_b}",
                f"    Packets:   Total={feats['total_packets']:.0f} (Fwd={feats['forward_packets']:.0f}, Bwd={feats['backward_packets']:.0f})",
                f"    Bytes:     Total={feats['total_bytes']:.0f} (Fwd={feats['forward_bytes']:.0f}, Bwd={feats['backward_bytes']:.0f})",
                f"    Duration:  {feats['flow_duration_seconds']:.4f}s | Rate: {feats['packets_per_second']:.1f} pkt/s, {feats['bytes_per_second']:.1f} B/s",
                f"    IPsec:     is_ipsec={ipsec.is_ipsec_related}, esp={ipsec.esp_detected}, ike={ipsec.ike_related}",
                f"    Valid:     {val.valid}" + (f" (Errors: {val.errors})" if not val.valid else ""),
                "",
            ])
    else:
        lines.append("No flows detected in capture.")

    lines.append("=" * 60)
    return "\n".join(lines)


def save_prediction_results_json(
    result: Any,
    output_path: str | Path,
    indent: int = 2,
) -> Path:
    """Save Phase 3 combined capture prediction results to a formatted JSON file.

    Args:
        result: CapturePredictionResult instance.
        output_path: Target destination file path.
        indent: JSON indentation.

    Returns:
        Path to the saved JSON file.
    """
    path = Path(output_path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)

    json_str = result.to_json(indent=indent)
    path.write_text(json_str, encoding="utf-8")
    logger.info("Saved capture predictions output to %s", path)
    return path


def render_prediction_terminal_summary(result: Any) -> str:
    """Render a comprehensive human-readable summary including Phase 1, Phase 2, and Phase 3 predictions.

    Args:
        result: CapturePredictionResult instance.

    Returns:
        Formatted multi-line summary string.
    """
    base_summary = render_flow_features_terminal_summary(result.capture_features)
    pred_summary = result.prediction_summary

    lines = [
        base_summary,
        "",
        "=" * 60,
        "   PHASE 3: MODEL INTEGRATION & INFERENCE SUMMARY",
        "=" * 60,
        f"Total Flows Evaluated:      {pred_summary.total_flows}",
        f"Predictions Successful:     {pred_summary.predictions_successful}",
        f"Model Unavailable:          {pred_summary.model_unavailable}",
        f"Incompatible Models:        {pred_summary.incompatible}",
        f"Domain Unverified:          {pred_summary.domain_unverified}",
        "-" * 60,
    ]

    if result.predictions:
        lines.append(f"PREDICTION OUTCOMES (showing up to 5 of {len(result.predictions)}):")
        for i, (f, p) in enumerate(zip(result.capture_features.flows[:5], result.predictions[:5]), 1):
            flow_id = f.flow_metadata.flow_id
            lines.append(f"  Flow #{i}: {flow_id}")
            lines.append(f"    Status: {p.model_status}")
            if p.prediction:
                lines.append(
                    f"    Prediction: {p.prediction.label} (Index: {p.prediction.class_index}, "
                    f"Conf: {p.prediction.confidence:.2%})"
                )
            if p.reason:
                lines.append(f"    Reason: {p.reason}")
            if p.feature_importance:
                top_3 = list(p.feature_importance.items())[:3]
                lines.append(f"    Explainability (Top Features): {', '.join(f'{k} ({v:.3f})' for k, v in top_3)}")
            if p.warnings:
                for w in p.warnings:
                    lines.append(f"    Warning: {w}")
            if p.compatibility_errors:
                for e in p.compatibility_errors:
                    lines.append(f"    Error: {e}")
            lines.append("")

    else:
        lines.append("No flows available for inference.")

    lines.append("=" * 60)
    return "\n".join(lines)


def save_security_results_json(
    result: Any,
    output_path: str | Path,
    indent: int = 2,
) -> Path:
    """Save Phase 4 security assessment results to a formatted JSON file.

    Args:
        result: CaptureSecurityResult instance.
        output_path: Target destination file path.
        indent: JSON indentation.

    Returns:
        Path to the saved JSON file.
    """
    path = Path(output_path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)

    json_str = result.to_json(indent=indent)
    path.write_text(json_str, encoding="utf-8")
    logger.info("Saved security assessment output to %s", path)
    return path


def render_security_terminal_summary(result: Any) -> str:
    """Render comprehensive executive summary for Phase 4 Security Assessment.

    Args:
        result: CaptureSecurityResult instance.

    Returns:
        Formatted multi-line summary string.
    """
    meta = result.analysis_metadata
    summary = result.capture_summary
    model_info = result.model_information

    lines = [
        "=" * 65,
        "   PHASE 4: AI SECURITY ASSESSMENT & BEHAVIORAL RISK REPORT",
        "=" * 65,
        f"File Name:            {meta.get('file_name', 'Unknown')}",
        f"Total Flows Analyzed: {summary.total_flows}",
        f"Overall Risk Level:   {summary.overall_risk_level} (Score: {summary.overall_risk_score}/100)",
        f"Average Confidence:   {summary.average_confidence:.1%}",
        f"Model In Use:         {model_info.get('model_id', 'Unknown')}",
        "-" * 65,
        "BEHAVIORAL RISK TIER DISTRIBUTION:",
        f"  LOW (0-24):         {summary.risk_distribution.get('LOW', 0)} flows",
        f"  MEDIUM (25-49):     {summary.risk_distribution.get('MEDIUM', 0)} flows",
        f"  HIGH (50-74):       {summary.risk_distribution.get('HIGH', 0)} flows",
        f"  CRITICAL (75-100):  {summary.risk_distribution.get('CRITICAL', 0)} flows",
        "-" * 65,
        "TRAFFIC CATEGORY RESEMBLANCE:",
    ]
    for cat, count in sorted(summary.traffic_distribution.items()):
        lines.append(f"  {cat:<18}: {count} flows")

    behavioral_top_indicators = [
        ind for ind in summary.top_indicators if ind.get("indicator_id") != "LOW_CLASSIFICATION_CONFIDENCE"
    ]
    if behavioral_top_indicators:
        lines.extend([
            "-" * 65,
            "TOP OBSERVED BEHAVIORAL RISK INDICATORS:",
        ])
        for ind in behavioral_top_indicators:
            lines.append(
                f"  [!] {ind['indicator_id']:<32} : {ind['occurrences']} occurrences ({ind['frequency_pct']:.1%})"
            )

    if result.flows:
        lines.extend([
            "-" * 65,
            "PER-FLOW BEHAVIORAL FINDINGS & MODEL UNCERTAINTY:",
        ])
        sorted_flows = sorted(
            result.flows,
            key=lambda x: x.security_assessment.get("risk_score", 0),
            reverse=True,
        )
        for i, f in enumerate(sorted_flows[:5], 1):
            pred = f.prediction
            sec = f.security_assessment
            beh = f.behavior
            unc = getattr(f, "model_uncertainty", {}) or {}

            lines.extend([
                f"  Flow #{i}: {f.flow_id} [{f.endpoints}]",
                f"    Category Resemblance: {pred.get('traffic_category')} ({pred.get('confidence_level')}, Conf: {pred.get('confidence'):.1%})",
                f"    Observed Pattern:     {beh.traffic_pattern}",
                f"    BEHAVIORAL RISK:      {sec.get('risk_level')} (Score: {sec.get('risk_score')}/100)",
            ])

            if unc.get("present"):
                lines.append("    MODEL UNCERTAINTY:    PRESENT (Does not strongly match known categories; 0 risk points added)")
            else:
                lines.append("    MODEL UNCERTAINTY:    NONE")

            behavioral_indicators = [
                ind for ind in sec.get("indicators", []) if ind.get("indicator_id") != "LOW_CLASSIFICATION_CONFIDENCE"
            ]
            if behavioral_indicators:
                lines.append(f"    Risk Indicators:      {', '.join(ind['indicator_id'] for ind in behavioral_indicators)}")
            lines.append(f"    Explanation:          {f.explainability.get('summary')}")
            lines.append("")

    lines.append("=" * 65)
    return "\n".join(lines)


