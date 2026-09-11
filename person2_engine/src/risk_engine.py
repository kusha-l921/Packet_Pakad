"""Risk scoring and explainability engine for Phase 4 Security Assessment.

Computes transparent, additive numerical risk scores (0-100), maps them to deterministic
risk tiers (LOW, MEDIUM, HIGH, CRITICAL), and constructs human-readable explanatory summaries
traceable to real features and behavioral indicators.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from person2_engine.src.security_models import (
    BehaviorProfile,
    RiskLevel,
    RiskScore,
    ScoreContribution,
    SecurityIndicator,
    determine_risk_level,
)


class RiskEngine:
    """Computes transparent risk scores and generates explanatory narratives."""

    @staticmethod
    def calculate_risk_score(contributions: List[ScoreContribution]) -> RiskScore:
        """Calculate capped additive risk score from list of indicator contributions.

        Args:
            contributions: List of ScoreContribution items triggered for the flow.

        Returns:
            RiskScore instance with total_score clamped to [0, 100], risk_level, and contributions.
        """
        raw_score = sum(c.points for c in contributions)
        clamped_score = max(0, min(100, int(raw_score)))
        level = determine_risk_level(clamped_score)

        return RiskScore(
            total_score=clamped_score,
            risk_level=level,
            contributions=contributions,
        )

    @staticmethod
    def generate_flow_explanation(
        prediction_dict: Dict[str, Any],
        behavior: BehaviorProfile,
        indicators: List[SecurityIndicator],
        risk_score: RiskScore,
    ) -> str:
        """Construct a coherent, human-readable narrative explaining the flow assessment.

        Synthesizes the prediction category, confidence level, behavioral observations,
        and any triggered security indicators into a factual, non-fabricated summary.

        Args:
            prediction_dict: Model prediction metadata.
            behavior: Flow behavior profile and observations.
            indicators: Triggered security indicators.
            risk_score: Calculated risk score and level.

        Returns:
            Multi-sentence explanatory string.
        """
        category = prediction_dict.get("traffic_category", "unknown")
        confidence = float(prediction_dict.get("confidence", 0.0))
        conf_level = prediction_dict.get("confidence_level", "UNKNOWN")

        # 1. Prediction context
        pred_clause = (
            f"Flow statistically resembles '{category}' traffic with {conf_level.lower()} confidence ({confidence:.1%})."
        )
        if conf_level == "LOW":
            pred_clause = (
                f"Flow does not strongly match known traffic categories (top statistical resemblance: "
                f"'{category}' at {confidence:.1%} confidence)."
            )

        # 2. Behavioral context
        pattern = behavior.traffic_pattern
        metrics = behavior.metrics_summary
        total_pkts = metrics.get("total_packets", 0)
        total_bytes = metrics.get("total_bytes", 0)
        duration = metrics.get("duration_seconds", 0.0)

        behavior_clause = (
            f"Observable behavior aligns with '{pattern}', transferring {total_bytes:,} bytes "
            f"across {total_pkts} packets over {duration:.2f} seconds."
        )

        # 3. Security indicators and behavioral risk assessment
        if not indicators:
            risk_clause = (
                f"No elevated behavioral risk indicators were observed. The flow is evaluated at "
                f"{risk_score.risk_level} behavioral risk (score: {risk_score.total_score}/100)."
            )
        else:
            ind_names = [ind.indicator_id for ind in indicators]
            reasons_summary = "; ".join(ind.reason for ind in indicators)
            risk_clause = (
                f"Flagged {len(indicators)} behavioral indicator(s) [{', '.join(ind_names)}]: {reasons_summary} "
                f"Resulting behavioral risk assessment is {risk_score.risk_level} risk (score: {risk_score.total_score}/100)."
            )

        return f"{pred_clause} {behavior_clause} {risk_clause}"
