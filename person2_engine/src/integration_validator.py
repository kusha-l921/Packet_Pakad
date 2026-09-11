"""Dedicated integration-level validator for Phase 5 output contract.

Validates schema compliance, feature integrity, model prediction bounds,
strict model uncertainty isolation, behavioral risk scoring consistency,
and JSON serialization safety before Person 3 handoff.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import math
from typing import Any, Dict, List, Set, Union

import numpy as np

from person2_engine.src.feature_schema import FEATURE_ORDER, FEATURE_SCHEMA_VERSION
from person2_engine.src.feature_validator import validate_flow_features
from person2_engine.src.integration_models import (
    INTEGRATION_SCHEMA_VERSION,
    UnifiedCaptureResult,
)
from person2_engine.src.security_models import (
    CONFIDENCE_HIGH_THRESHOLD,
    CONFIDENCE_MEDIUM_THRESHOLD,
    RISK_CRITICAL_THRESHOLD,
    RISK_HIGH_THRESHOLD,
    RISK_MEDIUM_THRESHOLD,
    determine_confidence_level,
    determine_risk_level,
)


@dataclass
class IntegrationValidationReport:
    """Standardized validation outcome for Phase 5 integration results."""

    valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    total_flows_validated: int = 0

    def add_error(self, message: str) -> None:
        """Register a fatal schema or architectural violation."""
        self.errors.append(message)
        self.valid = False

    def add_warning(self, message: str) -> None:
        """Register a non-fatal observation."""
        self.warnings.append(message)


# Recognized uncertainty codes that must never contaminate behavioral risk
DISALLOWED_BEHAVIORAL_INDICATOR_CODES: Set[str] = {
    "LOW_CLASSIFICATION_CONFIDENCE",
    "MODEL_UNCERTAINTY",
    "UNKNOWN_CATEGORY_RESEMBLANCE",
    "CLASSIFICATION_UNCERTAINTY",
}

VALID_RISK_LEVELS: Set[str] = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
VALID_CONFIDENCE_LEVELS: Set[str] = {"HIGH", "MEDIUM", "LOW", "UNKNOWN"}


def validate_integration_result(
    result: Union[Dict[str, Any], UnifiedCaptureResult],
) -> IntegrationValidationReport:
    """Perform rigorous end-to-end validation on the unified integration result.

    Args:
        result: UnifiedCaptureResult instance or dictionary representation.

    Returns:
        IntegrationValidationReport detailing validation pass/fail, errors, and warnings.
    """
    report = IntegrationValidationReport(valid=True)

    if isinstance(result, UnifiedCaptureResult):
        data = result.to_dict()
    elif isinstance(result, dict):
        data = result
    else:
        report.add_error(f"Expected dict or UnifiedCaptureResult, got {type(result).__name__}")
        return report

    # 1. Schema Validation
    schema_ver = data.get("integration_schema_version")
    if not schema_ver:
        report.add_error("Missing required top-level key: 'integration_schema_version'")
    elif schema_ver != INTEGRATION_SCHEMA_VERSION:
        report.add_error(
            f"Unsupported integration_schema_version '{schema_ver}', expected '{INTEGRATION_SCHEMA_VERSION}'"
        )

    required_sections = ["analysis_metadata", "capture_summary", "ipsec_analysis", "flows"]
    for sec in required_sections:
        if sec not in data:
            report.add_error(f"Missing required top-level section: '{sec}'")
        elif not isinstance(data[sec], (dict, list)):
            report.add_error(f"Section '{sec}' must be a dict or list, got {type(data[sec]).__name__}")

    flows = data.get("flows", [])
    if not isinstance(flows, list):
        report.add_error(f"'flows' must be a list, got {type(flows).__name__}")
        return report

    # Check flow_id uniqueness
    seen_flow_ids: Set[str] = set()
    for idx, f in enumerate(flows):
        if not isinstance(f, dict):
            report.add_error(f"Flow #{idx} is not a dictionary")
            continue
        fid = f.get("flow_id")
        if not fid:
            report.add_error(f"Flow #{idx} is missing 'flow_id'")
        elif fid in seen_flow_ids:
            report.add_error(f"Duplicate flow_id found: '{fid}' at index #{idx}")
        else:
            seen_flow_ids.add(fid)

    report.total_flows_validated = len(flows)

    # 2. Per-Flow Validations
    for idx, f in enumerate(flows):
        fid = f.get("flow_id", f"flow_index_{idx}")

        # A. Required flow sections
        flow_required_keys = [
            "flow_metadata",
            "features",
            "prediction",
            "model_uncertainty",
            "behavior",
            "security_assessment",
            "summary",
        ]
        for rk in flow_required_keys:
            if rk not in f:
                report.add_error(f"Flow '{fid}' missing required field: '{rk}'")

        # B. Feature Validation (Phase 2 schema)
        feats = f.get("features", {})
        if isinstance(feats, dict):
            if len(feats) != 25:
                report.add_error(
                    f"Flow '{fid}' has {len(feats)} features, expected exactly 25 Phase 2 features"
                )

            # Validate using Phase 2 validator
            p2_val = validate_flow_features(feats)
            if not p2_val.valid:
                for err in p2_val.errors:
                    report.add_error(f"Flow '{fid}' feature validation error: {err}")
            for warn in p2_val.warnings:
                report.add_warning(f"Flow '{fid}' feature warning: {warn}")

            # Explicit check for NaN / Inf
            for fname, val in feats.items():
                if isinstance(val, (float, np.floating)):
                    if math.isnan(val) or math.isinf(val):
                        report.add_error(f"Flow '{fid}' feature '{fname}' contains NaN or Infinity: {val}")
        else:
            report.add_error(f"Flow '{fid}' 'features' must be a dict, got {type(feats).__name__}")

        # C. Prediction Validation
        pred = f.get("prediction", {})
        if isinstance(pred, dict):
            conf = pred.get("confidence")
            if conf is not None:
                if not isinstance(conf, (int, float, np.floating)):
                    report.add_error(f"Flow '{fid}' prediction confidence is not a number: {conf}")
                elif not (0.0 <= float(conf) <= 1.0):
                    report.add_error(f"Flow '{fid}' prediction confidence out of bounds [0.0, 1.0]: {conf}")

            conf_level = pred.get("confidence_level")
            if conf_level and conf_level not in VALID_CONFIDENCE_LEVELS:
                report.add_error(f"Flow '{fid}' invalid confidence_level: '{conf_level}'")
        else:
            report.add_error(f"Flow '{fid}' 'prediction' must be a dict, got {type(pred).__name__}")

        # D. Model Uncertainty Isolation Validation
        unc = f.get("model_uncertainty", {})
        if isinstance(unc, dict):
            if "present" not in unc or not isinstance(unc["present"], bool):
                report.add_error(f"Flow '{fid}' model_uncertainty missing boolean 'present'")
            flags = unc.get("flags", [])
            if not isinstance(flags, list):
                report.add_error(f"Flow '{fid}' model_uncertainty 'flags' must be a list")
        else:
            report.add_error(f"Flow '{fid}' 'model_uncertainty' must be a dict, got {type(unc).__name__}")

        # E. Behavioral Risk Validation & Strict Isolation Check
        sec = f.get("security_assessment", {})
        if isinstance(sec, dict):
            score = sec.get("risk_score")
            if score is None:
                report.add_error(f"Flow '{fid}' security_assessment missing 'risk_score'")
            elif not isinstance(score, int) or not (0 <= score <= 100):
                report.add_error(f"Flow '{fid}' risk_score must be an integer in [0, 100], got {score}")

            level = sec.get("risk_level")
            if not level or level not in VALID_RISK_LEVELS:
                report.add_error(f"Flow '{fid}' invalid risk_level: '{level}'")

            # Check expected level alignment
            if score is not None and level in VALID_RISK_LEVELS:
                expected_level = determine_risk_level(score)
                if level != expected_level:
                    report.add_error(
                        f"Flow '{fid}' risk_level '{level}' does not match expected '{expected_level}' for score {score}"
                    )

            # STRICT ISOLATION AUDIT: Check that model uncertainty NEVER contaminated behavioral indicators
            ind_list = sec.get("indicators", [])
            if isinstance(ind_list, list):
                for ind in ind_list:
                    iid = ind.get("indicator_id") if isinstance(ind, dict) else str(ind)
                    if iid in DISALLOWED_BEHAVIORAL_INDICATOR_CODES:
                        report.add_error(
                            f"CRITICAL ARCHITECTURAL LEAKAGE: Model uncertainty code '{iid}' "
                            f"found inside security_assessment.indicators for flow '{fid}'!"
                        )

            contrib_list = sec.get("score_contributions", [])
            if isinstance(contrib_list, list):
                for c in contrib_list:
                    cid = c.get("indicator") if isinstance(c, dict) else str(c)
                    if cid in DISALLOWED_BEHAVIORAL_INDICATOR_CODES:
                        report.add_error(
                            f"CRITICAL ARCHITECTURAL LEAKAGE: Model uncertainty code '{cid}' "
                            f"found inside security_assessment.score_contributions for flow '{fid}'!"
                        )
        else:
            report.add_error(f"Flow '{fid}' 'security_assessment' must be a dict, got {type(sec).__name__}")

        # F. Summary String Validation
        summary = f.get("summary")
        if summary is None or not isinstance(summary, str) or len(summary.strip()) == 0:
            report.add_error(f"Flow '{fid}' missing non-empty 'summary' string")

    # 3. JSON Safety Serialization Check
    try:
        serialized = json.dumps(data)
        # Verify round-trip parsing
        parsed = json.loads(serialized)
        if not isinstance(parsed, dict):
            report.add_error("JSON round-trip failed to produce dict")
    except (TypeError, ValueError, OverflowError) as json_err:
        report.add_error(f"JSON serialization safety failed: {json_err}")

    # Check for leaked NaN or Infinity strings in serialized output
    if "NaN" in serialized or "Infinity" in serialized:
        report.add_error("JSON output contains illegal NaN or Infinity values")

    return report
