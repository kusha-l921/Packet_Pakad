"""person2_engine root package."""

from person2_engine.src.feature_extractor import (
    extract_flow_features,
    flow_features_to_vector,
)
from person2_engine.src.feature_schema import (
    FEATURE_DEFINITIONS,
    FEATURE_MAP,
    FEATURE_ORDER,
    FEATURE_SCHEMA_VERSION,
)
from person2_engine.src.feature_validator import (
    validate_flow_features,
    validate_ml_vector,
)
from person2_engine.src.flow_builder import FlowBuilder
from person2_engine.src.flow_models import (
    CaptureFeaturesResult,
    Flow,
    FlowKey,
    FlowMetadata,
    FlowPacketRecord,
    FlowResult,
    FlowSummary,
    FlowValidationResult,
    IPsecFlowMetadata,
)
from person2_engine.src.models import (
    AnalysisResult,
    CaptureInfo,
    ExecutionStatus,
    IPsecAnalysis,
    PacketMetadata,
    PacketStatistics,
    ProtocolSummary,
)
from person2_engine.src.packet_analyzer import (
    analyze_capture,
    analyze_capture_with_features,
    analyze_capture_with_predictions,
)
from person2_engine.src.inference_engine import (
    predict_flow,
    predict_flows,
)
from person2_engine.src.model_registry import (
    ModelRegistry,
    get_model_registry,
)
from person2_engine.src.model_metadata import (
    IPsecCompatibilityLevel,
    InputType,
    ModelMetadata,
    ModelStatus,
    PredictionTask,
)
from person2_engine.src.model_validator import validate_model_compatibility
from person2_engine.src.model_adapter import (
    DummyTestModelAdapter,
    ModelAdapter,
    SklearnModelAdapter,
)
from person2_engine.src.prediction_models import (
    CapturePredictionResult,
    FlowPredictionResult,
    Prediction,
    PredictionSummary,
)
from person2_engine.src.evaluation import (
    ScenarioManifest,
    evaluate_capture_predictions,
)
from person2_engine.src.output_formatter import (
    render_prediction_terminal_summary,
    save_prediction_results_json,
)
from person2_engine.src.dataset_models import (
    DatasetMetadata,
    FlowSample,
    SplitData,
    TrainingDataset,
)
from person2_engine.src.dataset_validator import (
    DatasetValidationReport,
    validate_csv_dataset,
    validate_dataset_records,
)
from person2_engine.src.label_mapper import (
    CANONICAL_CATEGORIES,
    DEFAULT_LABEL_MAPPING,
    LabelMapper,
)
from person2_engine.src.feature_adapter import (
    adapt_dict_to_vector,
    adapt_flow_to_vector,
)
from person2_engine.src.dataset_adapter import (
    load_csv_dataset,
    load_pcap_folder_dataset,
    save_dataset_to_csv,
)
from person2_engine.src.model_trainer import (
    CandidateTrainingResult,
    prepare_train_test_split,
    train_candidate_models,
)
from person2_engine.src.model_evaluator import (
    ModelEvaluationReport,
    evaluate_all_candidates,
    evaluate_candidate_model,
    extract_feature_importances,
)
from person2_engine.src.model_selector import (
    compare_candidates,
    save_trained_model_and_metadata,
    select_best_candidate,
)
from person2_engine.src.flow_filter import (
    FlowExclusionReason,
    FlowRelevancePolicy,
    evaluate_flow,
    filter_flow_samples,
)
from person2_engine.src.dataset_sufficiency import (
    ClassSufficiencyRecord,
    DatasetSufficiencyReport,
    EvaluationMode,
    SufficiencyStatus,
    generate_dataset_sufficiency_report,
)
from person2_engine.src.pcap_dataset_adapter import (
    audit_manifest_captures,
    extract_flows_from_manifest,
    save_pcap_dataset_to_csv,
)

from person2_engine.src.security_models import (
    BehaviorProfile,
    CaptureSecurityResult,
    CaptureSecuritySummary,
    ConfidenceLevel,
    FlowSecurityResult,
    RiskLevel,
    RiskScore,
    ScoreContribution,
    SecurityIndicator,
    SECURITY_SCHEMA_VERSION,
    determine_confidence_level,
    determine_risk_level,
)
from person2_engine.src.behavior_engine import BehaviorEngine
from person2_engine.src.indicator_engine import IndicatorEngine
from person2_engine.src.risk_engine import RiskEngine
from person2_engine.src.security_analyzer import (
    aggregate_capture_security,
    analyze_capture_security,
    analyze_flow_security,
)
from person2_engine.src.output_formatter import (
    render_security_terminal_summary,
    save_security_results_json,
)
from person2_engine.src.integration_models import (
    INTEGRATION_SCHEMA_VERSION,
    UnifiedCaptureResult,
    UnifiedFlowResult,
)
from person2_engine.src.integration_validator import (
    IntegrationValidationReport,
    validate_integration_result,
)
from person2_engine.src.integration_engine import (
    analyze_capture_complete,
    render_complete_terminal_summary,
)

__all__ = [
    # Phase 1
    "analyze_capture",
    "AnalysisResult",
    "CaptureInfo",
    "ExecutionStatus",
    "IPsecAnalysis",
    "PacketMetadata",
    "PacketStatistics",
    "ProtocolSummary",
    # Phase 2
    "analyze_capture_with_features",
    "flow_features_to_vector",
    "extract_flow_features",
    "validate_flow_features",
    "validate_ml_vector",
    "FEATURE_SCHEMA_VERSION",
    "FEATURE_ORDER",
    "FEATURE_DEFINITIONS",
    "FEATURE_MAP",
    "FlowBuilder",
    "FlowKey",
    "Flow",
    "FlowMetadata",
    "IPsecFlowMetadata",
    "FlowPacketRecord",
    "FlowResult",
    "FlowSummary",
    "FlowValidationResult",
    "CaptureFeaturesResult",
    # Phase 3: Core & Inference
    "analyze_capture_with_predictions",
    "predict_flow",
    "predict_flows",
    "ModelRegistry",
    "get_model_registry",
    "ModelMetadata",
    "ModelStatus",
    "PredictionTask",
    "InputType",
    "IPsecCompatibilityLevel",
    "validate_model_compatibility",
    "ModelAdapter",
    "DummyTestModelAdapter",
    "SklearnModelAdapter",
    "Prediction",
    "FlowPredictionResult",
    "PredictionSummary",
    "CapturePredictionResult",
    "ScenarioManifest",
    "evaluate_capture_predictions",
    "render_prediction_terminal_summary",
    "save_prediction_results_json",
    # Phase 3: Dataset & Training
    "DatasetMetadata",
    "FlowSample",
    "TrainingDataset",
    "SplitData",
    "DatasetValidationReport",
    "validate_csv_dataset",
    "validate_dataset_records",
    "CANONICAL_CATEGORIES",
    "DEFAULT_LABEL_MAPPING",
    "LabelMapper",
    "adapt_dict_to_vector",
    "adapt_flow_to_vector",
    "load_csv_dataset",
    "save_dataset_to_csv",
    "load_pcap_folder_dataset",
    "CandidateTrainingResult",
    "prepare_train_test_split",
    "train_candidate_models",
    "ModelEvaluationReport",
    "evaluate_candidate_model",
    "evaluate_all_candidates",
    "extract_feature_importances",
    "compare_candidates",
    "select_best_candidate",
    "save_trained_model_and_metadata",
    # Phase 3.5: Dataset Quality & Provenance
    "FlowExclusionReason",
    "FlowRelevancePolicy",
    "evaluate_flow",
    "filter_flow_samples",
    "EvaluationMode",
    "SufficiencyStatus",
    "ClassSufficiencyRecord",
    "DatasetSufficiencyReport",
    "generate_dataset_sufficiency_report",
    "extract_flows_from_manifest",
    "save_pcap_dataset_to_csv",
    "audit_manifest_captures",
    # Phase 4: AI Security Assessment
    "analyze_capture_security",
    "analyze_flow_security",
    "aggregate_capture_security",
    "BehaviorEngine",
    "IndicatorEngine",
    "RiskEngine",
    "ConfidenceLevel",
    "RiskLevel",
    "ScoreContribution",
    "RiskScore",
    "SecurityIndicator",
    "BehaviorProfile",
    "FlowSecurityResult",
    "CaptureSecuritySummary",
    "CaptureSecurityResult",
    "SECURITY_SCHEMA_VERSION",
    "determine_confidence_level",
    "determine_risk_level",
    "render_security_terminal_summary",
    "save_security_results_json",
    # Phase 5: Unified End-to-End Integration
    "analyze_capture_complete",
    "INTEGRATION_SCHEMA_VERSION",
    "UnifiedCaptureResult",
    "UnifiedFlowResult",
    "validate_integration_result",
    "IntegrationValidationReport",
    "render_complete_terminal_summary",
]


