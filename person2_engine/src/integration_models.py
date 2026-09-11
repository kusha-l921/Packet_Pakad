"""Phase 5 Integration Data Models and Schema Contract for Person 3 Handoff.

Defines the final, stable, unified data structures combining Phase 1 packet analysis,
Phase 2 flow feature extraction, Phase 3 ML classification, and Phase 4 explainable
behavioral risk assessment under INTEGRATION_SCHEMA_VERSION = "1.0".
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

INTEGRATION_SCHEMA_VERSION: str = "1.0"


def _clean_json_value(val: Any) -> Any:
    """Recursively convert NumPy scalars, Paths, and custom objects to JSON-serializable types."""
    import numpy as np

    if isinstance(val, (np.bool_, bool)):
        return bool(val)
    elif isinstance(val, (np.floating, float)):
        # Handle nan / inf
        if np.isnan(val) or np.isinf(val):
            return 0.0
        return round(float(val), 4)
    elif isinstance(val, (np.integer, int)):
        return int(val)
    elif isinstance(val, Path):
        return str(val)
    elif isinstance(val, dict):
        return {str(k): _clean_json_value(v) for k, v in val.items()}
    elif isinstance(val, (list, tuple)):
        return [_clean_json_value(v) for v in val]
    return val


@dataclass
class UnifiedFlowResult:
    """Standardized representation of a single network flow in the Phase 5 output contract."""

    flow_id: str
    flow_metadata: Dict[str, Any]
    features: Dict[str, float]
    prediction: Dict[str, Any]
    model_uncertainty: Dict[str, Any]
    behavior: Dict[str, Any]
    security_assessment: Dict[str, Any]
    summary: str
    explainability: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert flow assessment to a JSON-serializable Python dictionary."""
        d = {
            "flow_id": self.flow_id,
            "flow_metadata": _clean_json_value(self.flow_metadata),
            "features": {k: round(float(v), 4) for k, v in self.features.items()},
            "prediction": _clean_json_value(self.prediction),
            "model_uncertainty": _clean_json_value(self.model_uncertainty),
            "behavior": _clean_json_value(self.behavior),
            "security_assessment": _clean_json_value(self.security_assessment),
            "explainability": _clean_json_value(self.explainability),
            "summary": self.summary,
        }
        return d


@dataclass
class UnifiedCaptureResult:
    """Top-level unified integration result uniting all 4 phases into one standard contract."""

    analysis_metadata: Dict[str, Any]
    capture_summary: Dict[str, Any]
    ipsec_analysis: Dict[str, Any]
    flows: List[UnifiedFlowResult] = field(default_factory=list)
    integration_schema_version: str = INTEGRATION_SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        """Convert entire capture assessment to a JSON-serializable Python dictionary."""
        return {
            "integration_schema_version": self.integration_schema_version,
            "analysis_metadata": _clean_json_value(self.analysis_metadata),
            "capture_summary": _clean_json_value(self.capture_summary),
            "ipsec_analysis": _clean_json_value(self.ipsec_analysis),
            "flows": [f.to_dict() for f in self.flows],
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize unified capture result to a formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def to_json_file(self, path: Union[str, Path], indent: int = 2) -> None:
        """Save formatted JSON representation to disk."""
        p = Path(path).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(self.to_json(indent=indent))
