"""Model metadata definitions and contracts for Phase 3.

Defines strict metadata structures, model operational states, prediction tasks,
and domain verification indicators required for model compatibility validation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
import json
from pathlib import Path
from typing import Any, Dict, List, Optional



class ModelStatus(str, Enum):
    """Operational readiness status of an AI/ML model."""

    READY_FOR_INFERENCE = "READY_FOR_INFERENCE"
    INCOMPATIBLE = "INCOMPATIBLE"
    MODEL_UNAVAILABLE = "MODEL_UNAVAILABLE"
    TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED = "TECHNICALLY_COMPATIBLE_DOMAIN_UNVERIFIED"


class PredictionTask(str, Enum):
    """Supported network intelligence prediction tasks."""

    APPLICATION_CATEGORY = "application_category"
    ATTACK_TYPE = "attack_type"
    VPN_DETECTION = "vpn_detection"
    ENCRYPTED_TRAFFIC_CATEGORY = "encrypted_traffic_category"
    ANOMALY_DETECTION = "anomaly_detection"
    UNKNOWN = "unknown"


class InputType(str, Enum):
    """Input modality expected by the model architecture."""

    FLOW_FEATURES = "flow_features"
    RAW_PACKET_BYTES = "raw_packet_bytes"
    TOKENIZED_BYTES = "tokenized_bytes"


class IPsecCompatibilityLevel(str, Enum):
    """Verified level of model compatibility with IPsec/StrongSwan encrypted traffic."""

    VERIFIED = "verified"
    VERIFIED_IPSEC = "verified_ipsec"
    UNVERIFIED = "unverified"
    INCOMPATIBLE = "incompatible"
    UNKNOWN = "unknown"


@dataclass
class ModelMetadata:
    """Strict metadata contract specifying the requirements of a machine learning model."""

    model_id: str
    model_name: str
    model_version: str
    model_type: str
    prediction_task: str
    input_type: str
    feature_schema_version: str
    feature_names: List[str]
    feature_count: int
    preprocessing: Dict[str, Any]
    labels: Dict[str, str]
    training_domain: Dict[str, Any] = field(default_factory=dict)
    ipsec_compatibility: Dict[str, Any] = field(default_factory=dict)
    artifact_path: Optional[str] = None
    is_test_only: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert model metadata to a dictionary."""
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        """Serialize metadata to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ModelMetadata:
        """Instantiate ModelMetadata from a dictionary with validation."""
        required_fields = [
            "model_id",
            "model_name",
            "prediction_task",
            "input_type",
            "feature_schema_version",
            "feature_names",
            "feature_count",
            "preprocessing",
            "labels",
        ]
        for f in required_fields:
            if f not in data:
                raise ValueError(f"Missing required metadata field: '{f}'")

        pred_task = str(data["prediction_task"])
        valid_tasks = {t.value for t in PredictionTask}
        if pred_task not in valid_tasks:
            raise ValueError(f"Invalid prediction_task: '{pred_task}'. Supported: {sorted(valid_tasks)}")

        inp_type = str(data["input_type"])
        valid_inputs = {i.value for i in InputType}
        if inp_type not in valid_inputs:
            raise ValueError(f"Invalid input_type: '{inp_type}'. Supported: {sorted(valid_inputs)}")

        labels_raw = data.get("labels", {})
        labels = {str(k): str(v) for k, v in labels_raw.items()}

        return cls(
            model_id=str(data["model_id"]),
            model_name=str(data["model_name"]),
            model_version=str(data.get("model_version", "1.0")),
            model_type=str(data.get("model_type", "classifier")),
            prediction_task=pred_task,
            input_type=inp_type,
            feature_schema_version=str(data["feature_schema_version"]),
            feature_names=list(data["feature_names"]),
            feature_count=int(data["feature_count"]),
            preprocessing=dict(data.get("preprocessing", {})),
            labels=labels,
            training_domain=dict(data.get("training_domain", {})),
            ipsec_compatibility=dict(data.get("ipsec_compatibility", {})),
            artifact_path=data.get("artifact_path"),
            is_test_only=bool(data.get("is_test_only", False)),
        )

    @classmethod
    def from_json(cls, json_str: str) -> ModelMetadata:
        """Load ModelMetadata from a JSON string."""
        return cls.from_dict(json.loads(json_str))

    @classmethod
    def from_json_file(cls, file_path: str | Path) -> ModelMetadata:
        """Load ModelMetadata from a JSON file."""
        path = Path(file_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Metadata file not found: {path}")
        return cls.from_json(path.read_text(encoding="utf-8"))

