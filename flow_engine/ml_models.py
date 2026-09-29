"""
flow_engine/ml_models.py — Production ML Engines for Encrypted IPsec / ESP Traffic:

Model C: Covert Channel & Data Exfiltration Detection (Unsupervised Isolation Forest)
Model D: Traffic Analysis & Side-Channel Metadata Leakage Evaluation (Random Forest Classifier)

Designed to evaluate the 25 statistical flow metrics extracted from sliding windows by FlowRecord.
Serializes to and loads from the models/ directory using joblib.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
import joblib

from .mlAdapter import FEATURE_NAMES

logger = logging.getLogger("flow_engine.ml_models")

MODELS_DIR = Path(__file__).resolve().parent.parent / "models"
COVERT_MODEL_PATH = MODELS_DIR / "covert_channel_isolation_forest.joblib"
SIDE_CHANNEL_MODEL_PATH = MODELS_DIR / "traffic_analysis_side_channel.joblib"


class CovertChannelDetector:
    """
    Model C: Covert Channel & Data Exfiltration Detection.

    The Problem: Adversaries who gain access to an endpoint use established IPsec tunnels
    as covert conduits to exfiltrate data or maintain stealthy C2 channels.

    The ML Scope: An unsupervised anomaly detection model (Isolation Forest) trained on
    normal baseline flow metrics detects anomalous exfiltration patterns (unusual burst sizes,
    timing anomalies, or unauthorized protocol encapsulation).
    """

    def __init__(self, contamination: float = 0.05, random_state: int = 42) -> None:
        self.contamination = contamination
        self.random_state = random_state
        self.model: Optional[IsolationForest] = None
        self.is_trained: bool = False

    def train_baseline(self, X_normal: Optional[np.ndarray] = None) -> None:
        """Trains the Isolation Forest on benign baseline flow distributions."""
        if X_normal is None:
            X_normal = self._generate_synthetic_baseline(n_samples=600)

        self.model = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            random_state=self.random_state,
            max_samples="auto",
        )
        self.model.fit(X_normal)
        self.is_trained = True
        logger.info("[CovertChannelDetector] Trained Isolation Forest on %d baseline samples.", len(X_normal))

    def evaluate(self, features: Dict[str, float]) -> Dict[str, Any]:
        """Evaluates a 25-feature flow window for data exfiltration and covert channel anomalies."""
        if not self.is_trained or self.model is None:
            self.train_baseline()

        vector = np.array([[float(features.get(k, 0.0)) for k in FEATURE_NAMES]])
        raw_pred = self.model.predict(vector)[0]  # 1 = Normal, -1 = Anomaly
        # score_samples returns negative anomaly score (lower means more anomalous)
        raw_score = float(self.model.score_samples(vector)[0])

        # Normalize score to 0.0 (normal) - 1.0 (highly anomalous)
        anomaly_score = float(np.clip(1.0 - (raw_score + 0.5), 0.0, 1.0))
        is_anomaly = bool(raw_pred == -1 or anomaly_score > 0.65)

        # Diagnose specific anomaly indicators
        indicators: List[str] = []
        threat_type = "NORMAL_ENTERPRISE_TRAFFIC"
        risk_level = "LOW"

        bps = features.get("bytes_per_second", 0.0)
        pps = features.get("packets_per_second", 0.0)
        fwd_byte_ratio = features.get("forward_byte_ratio", 0.5)
        mean_iat = features.get("mean_inter_arrival_time", 0.0)
        std_iat = features.get("standard_deviation_inter_arrival_time", 0.0)
        max_pkts_1s = features.get("maximum_packets_in_one_second", 0.0)
        mean_pkt_size = features.get("mean_packet_size", 0.0)

        if is_anomaly:
            if fwd_byte_ratio > 0.85 and bps > 150000:
                threat_type = "DATA_EXFILTRATION_BURST"
                risk_level = "HIGH"
                indicators.append(f"Heavy asymmetric egress flow: {fwd_byte_ratio*100:.1f}% forward volume ({bps/1024:.1f} KB/s)")
            elif std_iat < 0.005 and mean_iat > 0.5:
                threat_type = "COVERT_C2_BEACONING"
                risk_level = "HIGH"
                indicators.append(f"Near-zero inter-arrival jitter (std={std_iat*1000:.1f}ms): High-regularity C2 beacon signature")
            elif max_pkts_1s > 400 or bps > 500000:
                threat_type = "EXFILTRATION_SPIKE"
                risk_level = "CRITICAL"
                indicators.append(f"Unprecedented packet rate spike: {max_pkts_1s:.0f} pkts/s during burst window")
            elif mean_pkt_size > 1420:
                threat_type = "UNAUTHORIZED_ENCAPSULATION_TUNNEL"
                risk_level = "MEDIUM"
                indicators.append(f"Jumbo MTU encapsulation detected: Mean packet length {mean_pkt_size:.0f} bytes")
            else:
                threat_type = "STATISTICAL_FLOW_ANOMALY"
                risk_level = "MEDIUM"
                indicators.append("Flow variance deviates significantly from baseline multidimensional cluster")
        else:
            threat_type = "BENIGN_ENTERPRISE_FLOW"
            risk_level = "LOW"

        return {
            "is_anomaly": is_anomaly,
            "anomaly_score": round(anomaly_score, 4),
            "threat_type": threat_type,
            "risk_level": risk_level,
            "indicators": indicators,
            "raw_decision": int(raw_pred),
        }

    def _generate_synthetic_baseline(self, n_samples: int = 600) -> np.ndarray:
        """Generates representative normal enterprise IPsec traffic flows."""
        np.random.seed(self.random_state)
        samples = []
        for _ in range(n_samples):
            # Mix of normal enterprise patterns (Video, VoIP, Web browsing, DB queries)
            flow_type = np.random.choice(["video", "voip", "web", "ssh"])
            if flow_type == "video":
                pkts = np.random.randint(150, 400)
                mean_size = np.random.normal(1320, 40)
                fwd_ratio = np.random.uniform(0.1, 0.3)  # mostly download
                iat = np.random.normal(0.02, 0.005)
            elif flow_type == "voip":
                pkts = np.random.randint(50, 200)
                mean_size = np.random.normal(160, 20)
                fwd_ratio = np.random.uniform(0.45, 0.55)  # balanced
                iat = np.random.normal(0.02, 0.002)
            elif flow_type == "web":
                pkts = np.random.randint(20, 100)
                mean_size = np.random.normal(700, 200)
                fwd_ratio = np.random.uniform(0.3, 0.5)
                iat = np.random.exponential(0.1)
            else:  # ssh / terminal
                pkts = np.random.randint(15, 60)
                mean_size = np.random.normal(120, 30)
                fwd_ratio = np.random.uniform(0.4, 0.6)
                iat = np.random.exponential(0.3)

            dur = max(0.5, pkts * iat)
            total_bytes = pkts * mean_size
            row = [
                float(pkts),
                float(pkts * fwd_ratio),
                float(pkts * (1 - fwd_ratio)),
                float(total_bytes),
                float(total_bytes * fwd_ratio),
                float(total_bytes * (1 - fwd_ratio)),
                float(max(40, mean_size - 100)),
                float(min(1500, mean_size + 100)),
                float(mean_size),
                float(np.random.uniform(10, 80)),
                float(mean_size),
                float(mean_size),
                float(mean_size),
                float(dur),
                float(pkts / dur),
                float(total_bytes / dur),
                float(iat),
                float(max(0.001, iat * 0.2)),
                float(iat * 3.0),
                float(iat * 0.4),
                float(fwd_ratio),
                float(1 - fwd_ratio),
                float(fwd_ratio),
                float(1 - fwd_ratio),
                float(pkts / max(1.0, dur) * 1.5),
            ]
            samples.append(row)
        return np.array(samples, dtype=np.float32)


class SideChannelLeakageEvaluator:
    """
    Model D: Traffic Analysis & Side-Channel Metadata Leakage Evaluation.

    The Problem: Even with strong AEAD ciphers (AES-256-GCM), variable packet sizes
    and transmission timing can leak sensitive information to passive wire eavesdroppers
    (e.g., website fingerprinting, keystroke timing, voice activity detection).

    The ML Scope: Feature extraction on packet size histograms, inter-arrival time distributions,
    burst volume ratios. Machine learning classifiers (Random Forest) evaluate the tunnel's
    resilience against traffic analysis attacks.
    """

    CLASSES = [
        "VIDEO_STREAMING_BURST",
        "VOIP_SPEECH_ACTIVITY",
        "WEB_FINGERPRINT_BROWSING",
        "INTERACTIVE_SHELL_KEYSTROKE",
        "BULK_DATA_TRANSFER",
    ]

    def __init__(self, n_estimators: int = 120, random_state: int = 42) -> None:
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.model: Optional[RandomForestClassifier] = None
        self.is_trained: bool = False

    def train(self, X: Optional[np.ndarray] = None, y: Optional[np.ndarray] = None) -> None:
        """Trains the Random Forest classifier to identify identifiable application signatures."""
        if X is None or y is None:
            X, y = self._generate_synthetic_training_set(n_per_class=120)

        self.model = RandomForestClassifier(
            n_estimators=self.n_estimators,
            random_state=self.random_state,
            max_depth=12,
        )
        self.model.fit(X, y)
        self.is_trained = True
        logger.info("[SideChannelLeakageEvaluator] Trained classifier with %d samples across %d classes.", len(X), len(self.CLASSES))

    def evaluate(self, features: Dict[str, float]) -> Dict[str, Any]:
        """Evaluates side-channel leakage susceptibility on wire-eavesdropped ESP metrics."""
        if not self.is_trained or self.model is None:
            self.train()

        vector = np.array([[float(features.get(k, 0.0)) for k in FEATURE_NAMES]])
        predicted_idx = self.model.predict(vector)[0]
        predicted_class = self.CLASSES[int(predicted_idx)]

        probs = self.model.predict_proba(vector)[0]
        confidence = float(max(probs))
        class_distribution = {
            self.CLASSES[i]: round(float(probs[i]), 3)
            for i in range(len(self.CLASSES))
        }

        # Calculate Side-Channel Vulnerability
        # If the wire eavesdropper can classify the traffic payload with high confidence,
        # side-channel leakage is HIGH.
        mean_pkt_size = features.get("mean_packet_size", 0.0)
        std_pkt_size = features.get("standard_deviation_packet_size", 0.0)

        if confidence > 0.85:
            leakage_risk = "HIGH"
            tfc_padding_needed = True
            remediation = (
                "Enable ESP Traffic Flow Confidentiality (TFC) padding (mandate esp_tfc = 1400 in swanctl.conf) "
                "to equalize packet lengths and prevent wire eavesdropper application fingerprinting."
            )
        elif confidence > 0.65:
            leakage_risk = "MEDIUM"
            tfc_padding_needed = True
            remediation = "Apply adaptive padding or traffic masking to attenuate variable packet-size histograms."
        else:
            leakage_risk = "LOW"
            tfc_padding_needed = False
            remediation = "Traffic features exhibit sufficient variance or uniform padding; side-channel risk within tolerance."

        return {
            "predicted_class": predicted_class,
            "eavesdropper_confidence": round(confidence, 3),
            "class_distribution": class_distribution,
            "side_channel_leakage_risk": leakage_risk,
            "tfc_padding_recommended": tfc_padding_needed,
            "mean_packet_size": round(mean_pkt_size, 1),
            "std_packet_size": round(std_pkt_size, 1),
            "remediation": remediation,
        }

    def _generate_synthetic_training_set(self, n_per_class: int = 120) -> Tuple[np.ndarray, np.ndarray]:
        """Generates synthetic training distributions for side-channel signature detection."""
        np.random.seed(self.random_state)
        X_list, y_list = [], []

        for class_idx, class_name in enumerate(self.CLASSES):
            for _ in range(n_per_class):
                if class_name == "VIDEO_STREAMING_BURST":
                    pkts = np.random.randint(150, 500)
                    mean_size = np.random.normal(1328, 30)
                    std_size = np.random.uniform(40, 100)
                    iat = np.random.normal(0.02, 0.004)
                    fwd_ratio = np.random.uniform(0.1, 0.25)
                elif class_name == "VOIP_SPEECH_ACTIVITY":
                    pkts = np.random.randint(80, 250)
                    mean_size = np.random.normal(172, 15)
                    std_size = np.random.uniform(5, 20)
                    iat = np.random.normal(0.02, 0.001)
                    fwd_ratio = np.random.uniform(0.48, 0.52)
                elif class_name == "WEB_FINGERPRINT_BROWSING":
                    pkts = np.random.randint(30, 120)
                    mean_size = np.random.normal(680, 150)
                    std_size = np.random.uniform(150, 400)
                    iat = np.random.exponential(0.08)
                    fwd_ratio = np.random.uniform(0.25, 0.45)
                elif class_name == "INTERACTIVE_SHELL_KEYSTROKE":
                    pkts = np.random.randint(15, 60)
                    mean_size = np.random.normal(108, 12)
                    std_size = np.random.uniform(2, 10)
                    iat = np.random.exponential(0.35)
                    fwd_ratio = np.random.uniform(0.5, 0.6)
                else:  # BULK_DATA_TRANSFER
                    pkts = np.random.randint(300, 800)
                    mean_size = np.random.normal(1420, 10)
                    std_size = np.random.uniform(1, 15)
                    iat = np.random.uniform(0.001, 0.005)
                    fwd_ratio = np.random.uniform(0.85, 0.98)

                dur = max(0.5, pkts * iat)
                total_bytes = pkts * mean_size
                row = [
                    float(pkts),
                    float(pkts * fwd_ratio),
                    float(pkts * (1 - fwd_ratio)),
                    float(total_bytes),
                    float(total_bytes * fwd_ratio),
                    float(total_bytes * (1 - fwd_ratio)),
                    float(max(40, mean_size - 100)),
                    float(min(1500, mean_size + 100)),
                    float(mean_size),
                    float(std_size),
                    float(mean_size),
                    float(mean_size),
                    float(mean_size),
                    float(dur),
                    float(pkts / dur),
                    float(total_bytes / dur),
                    float(iat),
                    float(max(0.001, iat * 0.2)),
                    float(iat * 3.0),
                    float(iat * 0.4),
                    float(fwd_ratio),
                    float(1 - fwd_ratio),
                    float(fwd_ratio),
                    float(1 - fwd_ratio),
                    float(pkts / max(1.0, dur) * 1.5),
                ]
                X_list.append(row)
                y_list.append(class_idx)

        return np.array(X_list, dtype=np.float32), np.array(y_list, dtype=np.int32)


class UnifiedMLTrafficSuite:
    """
    Unified Orchestrator combining Model C (Covert Channel / Exfiltration)
    and Model D (Traffic Analysis / Side-Channel Leakage Evaluation).

    Exposes the standard predict() interface for FlowEngine / MLModelAdapter.
    """

    def __init__(self, auto_save: bool = True) -> None:
        self.covert_detector = CovertChannelDetector()
        self.side_channel_evaluator = SideChannelLeakageEvaluator()
        self.auto_save = auto_save
        self._initialize_or_load()

    def _initialize_or_load(self) -> None:
        """Loads serialized models from disk if present, else trains and saves them."""
        MODELS_DIR.mkdir(parents=True, exist_ok=True)

        if COVERT_MODEL_PATH.exists():
            try:
                self.covert_detector.model = joblib.load(COVERT_MODEL_PATH)
                self.covert_detector.is_trained = True
                logger.info("Loaded Covert Channel model from %s", COVERT_MODEL_PATH)
            except Exception as e:
                logger.warning("Failed loading covert model, retraining: %s", e)
                self.covert_detector.train_baseline()
                if self.auto_save:
                    joblib.dump(self.covert_detector.model, COVERT_MODEL_PATH)
        else:
            self.covert_detector.train_baseline()
            if self.auto_save:
                joblib.dump(self.covert_detector.model, COVERT_MODEL_PATH)

        if SIDE_CHANNEL_MODEL_PATH.exists():
            try:
                self.side_channel_evaluator.model = joblib.load(SIDE_CHANNEL_MODEL_PATH)
                self.side_channel_evaluator.is_trained = True
                logger.info("Loaded Side-Channel model from %s", SIDE_CHANNEL_MODEL_PATH)
            except Exception as e:
                logger.warning("Failed loading side-channel model, retraining: %s", e)
                self.side_channel_evaluator.train()
                if self.auto_save:
                    joblib.dump(self.side_channel_evaluator.model, SIDE_CHANNEL_MODEL_PATH)
        else:
            self.side_channel_evaluator.train()
            if self.auto_save:
                joblib.dump(self.side_channel_evaluator.model, SIDE_CHANNEL_MODEL_PATH)

    def evaluate_features(self, features: Dict[str, float]) -> Dict[str, Any]:
        """Runs both Model C and Model D inference on a single 25-metric flow feature dict."""
        covert_res = self.covert_detector.evaluate(features)
        side_res = self.side_channel_evaluator.evaluate(features)

        # Composite label
        composite_verdict = side_res["predicted_class"]
        if covert_res["is_anomaly"]:
            composite_verdict = f"ANOMALY_{covert_res['threat_type']}"

        return {
            "verdict": composite_verdict,
            "covert_channel_detection": covert_res,
            "side_channel_evaluation": side_res,
            "model_metadata": {
                "covert_model": "IsolationForest (Unsupervised Baseline)",
                "side_channel_model": "RandomForestClassifier (Traffic Fingerprinting)",
                "feature_count": 25,
            },
        }

    def predict(self, X: List[List[float]]) -> List[str]:
        """Conforms to the TrafficClassifierProtocol expected by FlowEngine / MLModelAdapter."""
        results = []
        for vec in X:
            feat_dict = {FEATURE_NAMES[i]: vec[i] for i in range(min(len(vec), len(FEATURE_NAMES)))}
            res = self.evaluate_features(feat_dict)
            results.append(res["verdict"])
        return results


# Global singleton instance ready for instant invocation
ml_suite = UnifiedMLTrafficSuite()
