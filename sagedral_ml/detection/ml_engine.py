"""
MLEngine class for two-stage anomaly detection and attack classification using LightGBM.
"""

import os
import json
import logging
from dataclasses import dataclass
from typing import Dict, List, Any, Optional
import numpy as np
import joblib

logger = logging.getLogger("sagedral_ml.detection.ml")

FEATURE_NAMES = [
    "duration", "total_fwd_packets", "total_bwd_packets", "total_fwd_bytes", "total_bwd_bytes",
    "fwd_packet_len_mean", "fwd_packet_len_std", "bwd_packet_len_mean", "bwd_packet_len_std",
    "flow_bytes_per_sec", "flow_packets_per_sec", "fwd_iat_mean", "fwd_iat_std",
    "bwd_iat_mean", "bwd_iat_std", "psh_flag_count", "urg_flag_count", "syn_flag_count",
    "fin_flag_count", "rst_flag_count", "ack_flag_count", "avg_fwd_segment_size",
    "avg_bwd_segment_size", "fwd_header_len", "bwd_header_len", "down_up_ratio",
    "protocol", "dst_port"
]


@dataclass
class MLResult:
    anomaly_score: float = 0.0
    is_anomaly: bool = False
    attack_class: str = "NORMAL"
    class_confidence: float = 0.0
    model_version: str = "none"


class MLEngine:
    """
    Two-Stage LightGBM Machine Learning detection engine.
    """

    def __init__(
        self,
        model_dir: str = "/var/lib/sagedral-ml/models",
        anomaly_threshold: float = 0.7,
        classifier_threshold: float = 0.6,
        enabled: bool = True,
    ):
        self.model_dir = model_dir
        self.anomaly_threshold = anomaly_threshold
        self.classifier_threshold = classifier_threshold
        self.enabled = enabled

        self.anomaly_model = None
        self.classifier_model = None
        self.feature_names = FEATURE_NAMES
        self.model_loaded = False
        self.version = "1.0.0"

        if self.enabled:
            self.load_models()

    def load_models(self) -> bool:
        """Load binary anomaly detector and multiclass attack classifier models."""
        anomaly_path = os.path.join(self.model_dir, "anomaly_detector.pkl")
        classifier_path = os.path.join(self.model_dir, "attack_classifier.pkl")
        features_path = os.path.join(self.model_dir, "feature_names.json")

        if not os.path.exists(anomaly_path):
            logger.warning(f"ML anomaly model not found at {anomaly_path}. ML detection disabled.")
            self.model_loaded = False
            return False

        try:
            self.anomaly_model = joblib.load(anomaly_path)
            if os.path.exists(classifier_path):
                self.classifier_model = joblib.load(classifier_path)

            if os.path.exists(features_path):
                with open(features_path, "r") as f:
                    self.feature_names = json.load(f)

            self.model_loaded = True
            logger.info("Successfully loaded ML detection models.")
            return True
        except Exception as e:
            logger.error(f"Failed to load ML models from {self.model_dir}: {e}")
            self.model_loaded = False
            return False

    def predict(self, feature_vector: Dict[str, Any]) -> MLResult:
        if not self.enabled or not self.model_loaded or self.anomaly_model is None:
            return MLResult(
                anomaly_score=0.0,
                is_anomaly=False,
                attack_class="NORMAL",
                class_confidence=0.0,
                model_version="none",
            )

        try:
            # Construct array in strict feature order
            row = [float(feature_vector.get(name, 0.0)) for name in self.feature_names]
            x_arr = np.array([row], dtype=np.float32)

            # Stage 1: Anomaly Detection
            if hasattr(self.anomaly_model, "predict_proba"):
                probs = self.anomaly_model.predict_proba(x_arr)
                anomaly_score = float(probs[0][1]) if probs.shape[1] > 1 else float(probs[0][0])
            else:
                pred = self.anomaly_model.predict(x_arr)
                anomaly_score = float(pred[0])

            is_anomaly = anomaly_score >= self.anomaly_threshold
            attack_class = "NORMAL"
            confidence = 1.0 - anomaly_score if not is_anomaly else anomaly_score

            # Stage 2: Multiclass Attack Classification (if anomaly detected)
            if is_anomaly and self.classifier_model is not None:
                if hasattr(self.classifier_model, "predict_proba"):
                    cls_probs = self.classifier_model.predict_proba(x_arr)[0]
                    top_idx = int(np.argmax(cls_probs))
                    confidence = float(cls_probs[top_idx])

                    classes = getattr(self.classifier_model, "classes_", None)
                    if classes is not None and top_idx < len(classes):
                        attack_class = str(classes[top_idx])
                    else:
                        attack_class = f"Anomaly_Class_{top_idx}"
                else:
                    cls_pred = self.classifier_model.predict(x_arr)
                    attack_class = str(cls_pred[0])

                if confidence < self.classifier_threshold and attack_class != "NORMAL":
                    attack_class = "Unknown_Anomaly"

            return MLResult(
                anomaly_score=anomaly_score,
                is_anomaly=is_anomaly,
                attack_class=attack_class,
                class_confidence=confidence,
                model_version=self.version,
            )
        except Exception as e:
            logger.error(f"Error during ML prediction: {e}")
            return MLResult(
                anomaly_score=0.0,
                is_anomaly=False,
                attack_class="NORMAL",
                class_confidence=0.0,
                model_version="error",
            )
