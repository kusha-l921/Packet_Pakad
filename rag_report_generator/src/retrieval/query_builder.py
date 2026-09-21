"""Deterministic Query Builder for project domain concepts."""

import logging

logger = logging.getLogger(__name__)


class QueryBuilder:
    """Constructs focused, deterministic retrieval queries from project concepts and identifiers."""

    # Behavioral Indicators
    INDICATOR_MAP = {
        "UNUSUAL_HIGH_UPLOAD_VOLUME": "UNUSUAL_HIGH_UPLOAD_VOLUME outbound data volume behavioral risk indicator meaning",
        "UNUSUAL_HIGH_PACKET_RATE": "UNUSUAL_HIGH_PACKET_RATE meaning behavioral risk indicator",
        "UNUSUAL_BURST_ACTIVITY": "UNUSUAL_BURST_ACTIVITY burst activity peak packet burst indicator meaning",
        "LONG_LIVED_HIGH_VOLUME_FLOW": "LONG_LIVED_HIGH_VOLUME_FLOW persistent flow bulk data duration indicator meaning",
        "PERIODIC_LOW_VOLUME_ACTIVITY": "PERIODIC_LOW_VOLUME_ACTIVITY periodic activity low volume timing regularity indicator meaning",
        "STRONG_DIRECTIONAL_ASYMMETRY": "STRONG_DIRECTIONAL_ASYMMETRY directional asymmetry byte ratio imbalance indicator meaning",
    }

    # IPsec Domain Validation
    DOMAIN_STATUS_MAP = {
        "TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED": "IPsec domain validation technically compatible unverified",
        "VERIFIED IPSEC": "IPsec domain validation verified IPsec traffic",
        "allow_unverified_domain": "IPsec allow_unverified_domain configuration override unverified inference",
    }

    # Evaluation Modes
    EVALUATION_MODE_MAP = {
        "GROUP_ISOLATED": "GROUP_ISOLATED dataset evaluation capture holdout unseen validation",
        "WITHIN_CAPTURE_HOLDOUT": "WITHIN_CAPTURE_HOLDOUT dataset evaluation holdout capture data leakage",
        "OVERALL_MIXED_EVALUATION": "OVERALL_MIXED_EVALUATION mixed evaluation benchmark dataset unseen capture",
    }

    # Protocol Concepts
    PROTOCOL_MAP = {
        "ESP": "ESP Encapsulating Security Payload Protocol 50 encryption integrity IPsec",
        "AH": "AH Authentication Header Protocol 51 integrity authentication NAT incompatibility",
        "IKE": "IKE Internet Key Exchange UDP 500 SA negotiation key exchange",
        "IKEv1": "IKEv1 Phase 1 Main Aggressive Mode Phase 2 Quick Mode",
        "IKEv2": "IKEv2 IKE_SA_INIT IKE_AUTH MOBIKE NAT detection",
        "NAT-T": "NAT-T NAT Traversal UDP 4500 ESP encapsulation PAT",
        "IPsec": "IPsec architecture transport mode tunnel mode security association SPI payload opacity",
    }

    # Traffic Categories
    CATEGORY_MAP = {
        "web": "web traffic category statistical resemblance conversational hypertext",
        "video": "video traffic category statistical resemblance streaming media MTU",
        "voip": "voip traffic category statistical resemblance audio codec periodic",
        "file_transfer": "file_transfer traffic category statistical resemblance bulk transfer",
        "interactive": "interactive traffic category statistical resemblance shell typing",
    }

    @classmethod
    def build_indicator_query(cls, indicator: str) -> str:
        """Construct deterministic query for a behavioral risk indicator."""
        ind_clean = indicator.strip()
        if ind_clean in cls.INDICATOR_MAP:
            return cls.INDICATOR_MAP[ind_clean]
        return f"{ind_clean} behavioral risk indicator meaning interpretation"

    @classmethod
    def build_feature_query(cls, feature_name: str) -> str:
        """Construct deterministic query for a Phase 2 flow feature."""
        feat_clean = feature_name.strip()
        return f"{feat_clean} traffic flow feature meaning interpretation"

    @classmethod
    def build_domain_query(cls, domain_status: str) -> str:
        """Construct deterministic query for IPsec domain validation status."""
        dom_clean = domain_status.strip()
        if dom_clean in cls.DOMAIN_STATUS_MAP:
            return cls.DOMAIN_STATUS_MAP[dom_clean]
        return f"{dom_clean} IPsec domain validation policy override"

    @classmethod
    def build_evaluation_query(cls, eval_mode: str) -> str:
        """Construct deterministic query for evaluation modes."""
        mode_clean = eval_mode.strip()
        if mode_clean in cls.EVALUATION_MODE_MAP:
            return cls.EVALUATION_MODE_MAP[mode_clean]
        return f"{mode_clean} dataset evaluation mode capture holdout"

    @classmethod
    def build_uncertainty_query(cls, uncertainty_concept: str) -> str:
        """Construct deterministic query for ML model uncertainty."""
        concept_clean = uncertainty_concept.strip()
        return f"{concept_clean} model uncertainty confidence tier behavioral risk separation"

    @classmethod
    def build_protocol_query(cls, protocol: str) -> str:
        """Construct deterministic query for IPsec/network protocols."""
        proto_clean = protocol.strip()
        if proto_clean in cls.PROTOCOL_MAP:
            return cls.PROTOCOL_MAP[proto_clean]
        return f"{proto_clean} protocol IPsec security architecture"

    @classmethod
    def build_category_query(cls, category: str) -> str:
        """Construct deterministic query for traffic category resemblance."""
        cat_clean = category.strip().lower()
        if cat_clean in cls.CATEGORY_MAP:
            return cls.CATEGORY_MAP[cat_clean]
        return f"{cat_clean} traffic category resemblance statistical profile"
