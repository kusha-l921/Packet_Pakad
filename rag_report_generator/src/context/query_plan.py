"""Deterministic query plan construction from AnalysisFacts."""

from dataclasses import dataclass, field
from typing import Any
from ..models.facts import AnalysisFacts


@dataclass
class SectionQueryPlan:
    """Targeted retrieval queries organized by report section."""
    ipsec_queries: list[str] = field(default_factory=list)
    classification_queries: list[str] = field(default_factory=list)
    behavioral_queries: list[str] = field(default_factory=list)
    uncertainty_queries: list[str] = field(default_factory=list)
    limitation_queries: list[str] = field(default_factory=list)

    def all_queries(self) -> list[str]:
        """Return flat list of all unique queries in deterministic order."""
        seen = set()
        flat = []
        for q_list in [
            self.ipsec_queries,
            self.classification_queries,
            self.behavioral_queries,
            self.uncertainty_queries,
            self.limitation_queries,
        ]:
            for q in q_list:
                if q not in seen:
                    seen.add(q)
                    flat.append(q)
        return flat

    def to_dict(self) -> dict[str, Any]:
        return {
            "ipsec_queries": list(self.ipsec_queries),
            "classification_queries": list(self.classification_queries),
            "behavioral_queries": list(self.behavioral_queries),
            "uncertainty_queries": list(self.uncertainty_queries),
            "limitation_queries": list(self.limitation_queries),
            "all_queries": self.all_queries(),
        }


class QueryPlanner:
    """Constructs a deterministic query plan from AnalysisFacts without LLM invocation."""

    @classmethod
    def build_plan(cls, facts: AnalysisFacts) -> SectionQueryPlan:
        plan = SectionQueryPlan()

        # 1. IPsec Section Queries
        if facts.ipsec.detected:
            if facts.ipsec.esp_detected:
                plan.ipsec_queries.append("ESP Encapsulating Security Payload meaning")
            if facts.ipsec.ah_detected:
                plan.ipsec_queries.append("AH Authentication Header meaning")
            if facts.ipsec.ike_detected:
                plan.ipsec_queries.append("IKE Internet Key Exchange meaning")
            if facts.ipsec.nat_t_detected:
                plan.ipsec_queries.append("NAT-T UDP encapsulation meaning")
            if not (facts.ipsec.esp_detected or facts.ipsec.ah_detected or facts.ipsec.ike_detected or facts.ipsec.nat_t_detected):
                plan.ipsec_queries.append("IPsec protocol detection overview")
        else:
            # IPsec not detected - query general IPsec overview only if relevant
            pass

        # 2. Classification Section Queries
        cat = facts.classification.predicted_category
        if cat and cat != "unknown":
            plan.classification_queries.append(f"{cat} traffic category resemblance classification")
        plan.classification_queries.append("traffic category resemblance versus application identification")

        # 3. Behavioral Risk Queries
        if facts.behavioral.triggered_indicators:
            for ind in facts.behavioral.triggered_indicators:
                plan.behavioral_queries.append(f"{ind} meaning")
        plan.behavioral_queries.append("Phase 4 behavioral risk scoring and severity tiers")

        # Feature queries from selected flows
        notable_features = set()
        for flow in facts.selected_flows:
            for feat_name in flow.features.keys():
                if feat_name in ("packets_per_second", "forward_byte_ratio", "flow_duration", "packet_rate"):
                    notable_features.add(feat_name)
        for feat in sorted(notable_features):
            plan.behavioral_queries.append(f"{feat} feature meaning")

        # 4. Uncertainty Queries
        if facts.model_uncertainty.level in ("HIGH", "MEDIUM"):
            plan.uncertainty_queries.append("model uncertainty confidence entropy margin")
        plan.uncertainty_queries.append("model uncertainty versus behavioral risk")

        # 5. Limitations & Domain Queries
        if "UNVERIFIED" in facts.ipsec.domain_validation_status or "UNVERIFIED" in facts.classification.prediction_status:
            plan.limitation_queries.append("TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED meaning")
        elif "VERIFIED" in facts.ipsec.domain_validation_status:
            plan.limitation_queries.append("VERIFIED_IPSEC domain validation")

        eval_mode = facts.evaluation.evaluation_mode
        if eval_mode:
            plan.limitation_queries.append(f"{eval_mode} evaluation mode meaning")

        plan.limitation_queries.append("behavioral risk non-malice disclaimer limitations")

        return plan
