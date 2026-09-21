"""Deterministic flow selection for report context building."""

from typing import Any
from ..models.facts import FlowFact


class FlowSelector:
    """Selects the most notable flows deterministically according to strict prioritization rules.
    
    Prioritization order:
    1. Flows with CRITICAL or HIGH risk (highest risk_score descending)
    2. Flows with active behavioral indicators
    3. Flows with notable model uncertainty / low margin
    4. IPsec-related flows (protocol 50/51 or UDP port 500/4500)
    5. Highest byte volume remaining flows
    """

    @classmethod
    def parse_flow(cls, raw_flow: dict[str, Any]) -> FlowFact:
        """Parse raw flow dictionary into a FlowFact without altering numbers."""
        flow_id = str(raw_flow.get("flow_id", raw_flow.get("id", "unknown_flow")))

        flow_meta = raw_flow.get("flow_metadata", {})
        endpoints = {}
        if "endpoint_a" in flow_meta and "endpoint_b" in flow_meta:
            endpoints = {
                "endpoint_a": str(flow_meta["endpoint_a"]),
                "endpoint_b": str(flow_meta["endpoint_b"]),
            }

        five_tuple = raw_flow.get("five_tuple", {
            "src_ip": raw_flow.get("src_ip", endpoints.get("endpoint_a", "0.0.0.0").split(":")[0]),
            "dst_ip": raw_flow.get("dst_ip", endpoints.get("endpoint_b", "0.0.0.0").split(":")[0]),
            "src_port": raw_flow.get("src_port", 0),
            "dst_port": raw_flow.get("dst_port", 0),
            "protocol": flow_meta.get("protocol", raw_flow.get("protocol", "TCP")),
        })

        proto = str(flow_meta.get("protocol", raw_flow.get("protocol", five_tuple.get("protocol", "")))).upper()

        features = dict(raw_flow.get("features", {}))

        packets = int(features.get("total_packets", raw_flow.get("packets", raw_flow.get("packet_count", 0))))
        total_bytes = int(features.get("total_bytes", raw_flow.get("bytes", raw_flow.get("total_bytes", 0))))
        duration = float(features.get("flow_duration_seconds", raw_flow.get("duration_seconds", raw_flow.get("duration", 0.0))))

        # Security assessment
        sec = raw_flow.get("security_assessment", {})
        risk_score = int(sec.get("risk_score", raw_flow.get("risk_score", raw_flow.get("risk", 0))))
        risk_level = str(sec.get("risk_level", raw_flow.get("risk_level", "LOW"))).upper()

        raw_inds = sec.get("indicators", raw_flow.get("indicators", raw_flow.get("triggered_indicators", [])))
        indicators = []
        for item in raw_inds:
            if isinstance(item, dict) and "indicator_id" in item:
                indicators.append(str(item["indicator_id"]))
            elif isinstance(item, str):
                indicators.append(item)

        # IPsec
        s_port = five_tuple.get("src_port", 0)
        d_port = five_tuple.get("dst_port", 0)
        is_ipsec = bool(
            raw_flow.get("is_ipsec", False)
            or flow_meta.get("is_ipsec_related", False)
            or flow_meta.get("esp_detected", False)
            or flow_meta.get("ah_detected", False)
            or proto in ("50", "ESP", "51", "AH")
            or s_port in (500, 4500)
            or d_port in (500, 4500)
        )

        # Prediction
        pred = raw_flow.get("prediction", {})
        predicted_category = pred.get("traffic_category", pred.get("predicted_category", raw_flow.get("predicted_category", raw_flow.get("category"))))
        confidence = float(pred["confidence"]) if "confidence" in pred and pred["confidence"] is not None else None
        pred_status = pred.get("prediction_status")
        probs = {k: float(v) for k, v in pred.get("probabilities", {}).items()}

        # Uncertainty
        unc = raw_flow.get("model_uncertainty", {})
        unc_present = bool(unc.get("present", False))
        unc_flags = list(unc.get("flags", []))

        # Explainability & Summary
        expl = raw_flow.get("explainability", {})
        expl_summary = expl.get("summary")
        summary_text = raw_flow.get("summary")

        return FlowFact(
            flow_id=flow_id,
            five_tuple=five_tuple,
            protocol=proto,
            endpoints=endpoints,
            packets=packets,
            bytes=total_bytes,
            duration_seconds=duration,
            risk_score=risk_score,
            risk_level=risk_level,
            indicators=indicators,
            features=features,
            is_ipsec=is_ipsec,
            predicted_category=predicted_category,
            confidence=confidence,
            prediction_status=pred_status,
            probabilities=probs,
            uncertainty_present=unc_present,
            uncertainty_flags=unc_flags,
            explainability_summary=expl_summary,
            summary=summary_text,
        )

    @classmethod
    def select_notable_flows(
        cls,
        raw_flows: list[dict[str, Any]],
        max_flows: int = 5,
    ) -> list[FlowFact]:
        """Select up to max_flows deterministic notable flows."""
        if not raw_flows or max_flows <= 0:
            return []

        parsed_flows = [cls.parse_flow(f) for f in raw_flows]

        # Scoring function for prioritization
        def priority_key(flow: FlowFact) -> tuple[int, int, int, int, int]:
            # Priority 1: High/Critical risk score (score >= 50 gives higher tier)
            tier1 = 1 if flow.risk_score >= 50 else 0
            # Priority 2: Has active indicators
            tier2 = len(flow.indicators)
            # Priority 3: High risk score generally
            tier3 = flow.risk_score
            # Priority 4: Is IPsec
            tier4 = 1 if flow.is_ipsec else 0
            # Priority 5: Byte volume
            tier5 = flow.bytes
            return (tier1, tier2, tier3, tier4, tier5)

        # Sort descending by priority, breaking ties deterministically by flow_id
        sorted_flows = sorted(
            parsed_flows,
            key=lambda f: (priority_key(f), f.flow_id),
            reverse=True,
        )

        return sorted_flows[:max_flows]
