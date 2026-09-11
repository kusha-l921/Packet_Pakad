"""Security indicator engine detecting observable network anomalies from flow features.

Evaluates explainable indicators with deterministic severities, point contributions,
and supporting feature evidence. Crucially distinguishes behavioral observation from
attack attribution.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from person2_engine.src.security_models import (
    ScoreContribution,
    SecurityIndicator,
    determine_confidence_level,
)

# Configurable Behavioral Risk Indicator Thresholds & Points
INDICATOR_CONFIG: Dict[str, Dict[str, Any]] = {
    "UNUSUAL_HIGH_UPLOAD_VOLUME": {
        "severity": "HIGH",
        "points": 25,
        "min_upload_bytes": 200_000,
        "min_upload_ratio": 0.85,
    },
    "UNUSUAL_HIGH_PACKET_RATE": {
        "severity": "MEDIUM",
        "points": 20,
        "min_pps": 250.0,
    },
    "UNUSUAL_BURST_ACTIVITY": {
        "severity": "MEDIUM",
        "points": 15,
        "min_burst_count": 100,
        "min_burst_fraction": 0.70,
    },
    "LONG_LIVED_HIGH_VOLUME_FLOW": {
        "severity": "MEDIUM",
        "points": 15,
        "min_duration": 600.0,  # 10 minutes
        "min_volume": 500_000,  # 500 KB
    },
    "PERIODIC_LOW_VOLUME_ACTIVITY": {
        "severity": "LOW",
        "points": 10,
        "max_volume": 5_000,
        "min_packets": 15,
        "max_iat_std": 0.05,
    },
    "STRONG_DIRECTIONAL_ASYMMETRY": {
        "severity": "LOW",
        "points": 10,
        "min_asymmetry_ratio": 0.95,
        "min_volume": 20_000,
    },
}


class IndicatorEngine:
    """Evaluates flow features and prediction status to trigger explainable security indicators."""

    def __init__(self, config: Optional[Dict[str, Dict[str, Any]]] = None) -> None:
        self.config = config or INDICATOR_CONFIG

    def evaluate_indicators(
        self,
        features: Dict[str, float],
        prediction_dict: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[SecurityIndicator], List[ScoreContribution]]:
        """Evaluate flow features and prediction metadata for observable security indicators.

        Args:
            features: 25 Phase 2 flow features.
            prediction_dict: Dictionary representation of prediction result.

        Returns:
            Tuple of (list of SecurityIndicator, list of ScoreContribution).
        """
        indicators: List[SecurityIndicator] = []
        contributions: List[ScoreContribution] = []

        total_bytes = int(features.get("total_bytes", 0))
        forward_bytes = int(features.get("forward_bytes", 0))
        backward_bytes = int(features.get("backward_bytes", 0))
        total_packets = int(features.get("total_packets", 0))
        pps = float(features.get("packets_per_second", 0.0))
        duration = float(features.get("flow_duration_seconds", 0.0))
        fwd_byte_ratio = float(features.get("forward_byte_ratio", 0.5))
        bwd_byte_ratio = float(features.get("backward_byte_ratio", 0.5))
        max_pkts_1s = int(features.get("maximum_packets_in_one_second", 0))
        std_iat = float(features.get("standard_deviation_inter_arrival_time", 0.0))
        mean_iat = float(features.get("mean_inter_arrival_time", 0.0))

        confidence = float(prediction_dict.get("confidence", 1.0)) if prediction_dict else 1.0
        pred_status = prediction_dict.get("prediction_status", "") if prediction_dict else ""

        # 1. Unusual High Upload Volume
        cfg_upload = self.config.get("UNUSUAL_HIGH_UPLOAD_VOLUME", {})
        upload_triggered = False
        if forward_bytes >= cfg_upload.get("min_upload_bytes", 200_000) and fwd_byte_ratio >= cfg_upload.get(
            "min_upload_ratio", 0.85
        ):
            upload_triggered = True
            reason = (
                f"Flow transferred an unusually high outbound volume ({forward_bytes:,} bytes, "
                f"{fwd_byte_ratio:.1%} of flow) with dominant forward asymmetry."
            )
            ind = SecurityIndicator(
                indicator_id="UNUSUAL_HIGH_UPLOAD_VOLUME",
                severity=cfg_upload.get("severity", "HIGH"),
                reason=reason,
                supporting_features={
                    "forward_bytes": forward_bytes,
                    "forward_byte_ratio": fwd_byte_ratio,
                    "total_bytes": total_bytes,
                },
            )
            indicators.append(ind)
            contributions.append(
                ScoreContribution(
                    indicator="UNUSUAL_HIGH_UPLOAD_VOLUME",
                    points=cfg_upload.get("points", 25),
                    reason=reason,
                )
            )

        # 2. Unusual High Packet Rate
        cfg_rate = self.config.get("UNUSUAL_HIGH_PACKET_RATE", {})
        if pps >= cfg_rate.get("min_pps", 250.0):
            reason = f"Flow exhibited an unusually high packet rate ({pps:.1f} pkts/sec) over {duration:.2f}s."
            ind = SecurityIndicator(
                indicator_id="UNUSUAL_HIGH_PACKET_RATE",
                severity=cfg_rate.get("severity", "MEDIUM"),
                reason=reason,
                supporting_features={
                    "packets_per_second": pps,
                    "total_packets": total_packets,
                    "flow_duration_seconds": duration,
                },
            )
            indicators.append(ind)
            contributions.append(
                ScoreContribution(
                    indicator="UNUSUAL_HIGH_PACKET_RATE",
                    points=cfg_rate.get("points", 20),
                    reason=reason,
                )
            )

        # 3. Unusual Burst Activity
        cfg_burst = self.config.get("UNUSUAL_BURST_ACTIVITY", {})
        min_burst_cnt = cfg_burst.get("min_burst_count", 100)
        min_burst_frac = cfg_burst.get("min_burst_fraction", 0.70)
        is_burst = max_pkts_1s >= min_burst_cnt or (
            total_packets >= 30 and (max_pkts_1s / total_packets) >= min_burst_frac
        )
        if is_burst:
            burst_ratio = (max_pkts_1s / total_packets) if total_packets > 0 else 0.0
            reason = (
                f"Peak 1-second burst concentrated {max_pkts_1s} packets "
                f"({burst_ratio:.1%} of all {total_packets} packets in flow)."
            )
            ind = SecurityIndicator(
                indicator_id="UNUSUAL_BURST_ACTIVITY",
                severity=cfg_burst.get("severity", "MEDIUM"),
                reason=reason,
                supporting_features={
                    "maximum_packets_in_one_second": max_pkts_1s,
                    "total_packets": total_packets,
                    "burst_ratio": round(burst_ratio, 4),
                },
            )
            indicators.append(ind)
            contributions.append(
                ScoreContribution(
                    indicator="UNUSUAL_BURST_ACTIVITY",
                    points=cfg_burst.get("points", 15),
                    reason=reason,
                )
            )

        # 4. Long-Lived High-Volume Flow
        cfg_long = self.config.get("LONG_LIVED_HIGH_VOLUME_FLOW", {})
        if duration >= cfg_long.get("min_duration", 600.0) and total_bytes >= cfg_long.get("min_volume", 500_000):
            reason = (
                f"Flow persisted for {duration:.1f} seconds ({duration / 60.0:.1f} mins) with "
                f"substantial byte volume ({total_bytes:,} bytes)."
            )
            ind = SecurityIndicator(
                indicator_id="LONG_LIVED_HIGH_VOLUME_FLOW",
                severity=cfg_long.get("severity", "MEDIUM"),
                reason=reason,
                supporting_features={
                    "flow_duration_seconds": duration,
                    "total_bytes": total_bytes,
                },
            )
            indicators.append(ind)
            contributions.append(
                ScoreContribution(
                    indicator="LONG_LIVED_HIGH_VOLUME_FLOW",
                    points=cfg_long.get("points", 15),
                    reason=reason,
                )
            )

        # 5. Periodic Low-Volume Activity (Beaconing-like timing)
        cfg_periodic = self.config.get("PERIODIC_LOW_VOLUME_ACTIVITY", {})
        if (
            total_packets >= cfg_periodic.get("min_packets", 15)
            and total_bytes <= cfg_periodic.get("max_volume", 5_000)
            and std_iat <= cfg_periodic.get("max_iat_std", 0.05)
            and mean_iat >= 0.1
        ):
            reason = (
                f"Low-volume flow ({total_bytes} bytes across {total_packets} packets) exhibited "
                f"periodic timing (mean IAT={mean_iat:.3f}s, std={std_iat:.4f}s)."
            )
            ind = SecurityIndicator(
                indicator_id="PERIODIC_LOW_VOLUME_ACTIVITY",
                severity=cfg_periodic.get("severity", "LOW"),
                reason=reason,
                supporting_features={
                    "mean_inter_arrival_time": mean_iat,
                    "standard_deviation_inter_arrival_time": std_iat,
                    "total_bytes": total_bytes,
                    "total_packets": total_packets,
                },
            )
            indicators.append(ind)
            contributions.append(
                ScoreContribution(
                    indicator="PERIODIC_LOW_VOLUME_ACTIVITY",
                    points=cfg_periodic.get("points", 10),
                    reason=reason,
                )
            )

        # 6. Strong Directional Asymmetry (if not already captured by high upload)
        cfg_asym = self.config.get("STRONG_DIRECTIONAL_ASYMMETRY", {})
        min_asym = cfg_asym.get("min_asymmetry_ratio", 0.95)
        min_asym_vol = cfg_asym.get("min_volume", 20_000)
        if not upload_triggered and (fwd_byte_ratio >= min_asym or bwd_byte_ratio >= min_asym) and total_bytes >= min_asym_vol:
            direction = "forward (outbound)" if fwd_byte_ratio >= min_asym else "backward (inbound)"
            ratio = max(fwd_byte_ratio, bwd_byte_ratio)
            reason = f"Flow exhibits extreme directional asymmetry ({direction} {ratio:.1%}) with {total_bytes:,} total bytes."
            ind = SecurityIndicator(
                indicator_id="STRONG_DIRECTIONAL_ASYMMETRY",
                severity=cfg_asym.get("severity", "LOW"),
                reason=reason,
                supporting_features={
                    "dominant_ratio": ratio,
                    "forward_byte_ratio": fwd_byte_ratio,
                    "backward_byte_ratio": bwd_byte_ratio,
                    "total_bytes": total_bytes,
                },
            )
            indicators.append(ind)
            contributions.append(
                ScoreContribution(
                    indicator="STRONG_DIRECTIONAL_ASYMMETRY",
                    points=cfg_asym.get("points", 10),
                    reason=reason,
                )
            )

        return indicators, contributions
