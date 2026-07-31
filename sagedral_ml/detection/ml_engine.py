"""
MLEngine class for two-stage anomaly detection and attack classification using LightGBM.
"""

import os
import json
import logging
import time
from collections import deque
from dataclasses import dataclass
from typing import Dict, List, Any, Optional
import numpy as np
import joblib

try:
    from lightgbm import LGBMClassifier
    _LIGHTGBM_AVAILABLE = True
except Exception:
    _LIGHTGBM_AVAILABLE = False

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

ATTACK_CLASSES = [
    "NORMAL", "DDoS", "PortScan", "BruteForce",
    "DoS_Slowloris", "WebAttack", "Botnet", "Infiltration", "Exfiltration",
]
ACTIVE_MODEL_MANIFEST = "active_model.json"


def resolve_model_artifact_dir(model_dir):
    """Return pointer-selected artifacts, or the legacy root on absent/bad pointers."""
    root = os.path.realpath(os.path.abspath(os.path.expanduser(model_dir)))
    manifest = os.path.join(root, ACTIVE_MODEL_MANIFEST)
    if not os.path.exists(manifest):
        return root
    try:
        with open(manifest, "r") as handle:
            payload = json.load(handle)
        relative = payload.get("artifact_dir") if isinstance(payload, dict) else None
        if not isinstance(relative, str) or not relative or os.path.isabs(relative):
            raise ValueError("artifact_dir must be a non-empty relative path")
        target = os.path.realpath(os.path.abspath(os.path.join(root, relative)))
        if os.path.commonpath((root, target)) != root or not os.path.isdir(target):
            raise ValueError("artifact_dir escapes model directory or is missing")
        return target
    except Exception as exc:
        logger.warning("Ignoring invalid model manifest %s: %s; using legacy root", manifest, exc)
        return root


class RuleBasedFallbackModel:
    """
    Lightweight rule-based fallback model used when LightGBM/scikit-learn not available
    or no pretrained .pkl files exist. Provides heuristic anomaly scoring + attack classification
    so ML Model Loaded stays True and detection pipeline remains active.
    """

    classes_ = np.array(ATTACK_CLASSES)

    def __init__(self):
        self.n_features_in_ = len(FEATURE_NAMES)

    @staticmethod
    def _rows_from_X(X):
        rows = np.asarray(X, dtype=float)
        if rows.ndim == 1:
            rows = rows.reshape(1, -1)
        return rows

    @staticmethod
    def _score(row):
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}
        pps = float(row[idx["flow_packets_per_sec"]])
        bps = float(row[idx["flow_bytes_per_sec"]])
        syn = float(row[idx["syn_flag_count"]])
        rst = float(row[idx["rst_flag_count"]])
        psh = float(row[idx["psh_flag_count"]])
        fwd_std = float(row[idx["fwd_packet_len_std"]])
        fwd_pkts = float(row[idx["total_fwd_packets"]])
        dur = max(float(row[idx["duration"]]), 1e-6)
        ratio = float(row[idx["down_up_ratio"]])
        dst_port = float(row[idx["dst_port"]])

        z_pps = min(pps / 8000.0, 2.5)
        z_bps = min(bps / 1e7, 2.5)
        z_syn = min(syn / 40.0, 2.5)
        z_rst = min(rst / 20.0, 2.0)
        z_std = min(fwd_std / 300.0, 2.0)
        z_short = min((fwd_pkts / dur) / 500.0, 2.0) if dur > 0 else 0.0

        score = 0.5 * (z_pps + z_bps) + 0.25 * z_syn + 0.15 * z_rst + 0.05 * z_std + 0.05 * z_short
        score = 1.0 - np.exp(-max(score, 0.0) / 1.5)
        return float(np.clip(score, 0.0, 1.0))

    def predict_proba(self, X):
        probabilities = []
        for row in self._rows_from_X(X):
            a_score = self._score(row)
            probabilities.append([1.0 - a_score, a_score])
        return np.asarray(probabilities, dtype=np.float32)

    def predict(self, X):
        probs = self.predict_proba(X)
        return (probs[:, 1] >= 0.5).astype(int)


class RuleBasedFallbackClassifier:
    """Multiclass rule-based classifier fallback."""

    classes_ = np.array(ATTACK_CLASSES)

    def __init__(self):
        self.n_features_in_ = len(FEATURE_NAMES)

    @staticmethod
    def _rows_from_X(X):
        rows = np.asarray(X, dtype=float)
        if rows.ndim == 1:
            rows = rows.reshape(1, -1)
        return rows

    def _row_probabilities(self, row):
        idx = {name: i for i, name in enumerate(FEATURE_NAMES)}
        pps = float(row[idx["flow_packets_per_sec"]])
        bps = float(row[idx["flow_bytes_per_sec"]])
        syn = float(row[idx["syn_flag_count"]])
        urg = float(row[idx["urg_flag_count"]])
        psh = float(row[idx["psh_flag_count"]])
        rst = float(row[idx["rst_flag_count"]])
        fwd_pkts = float(row[idx["total_fwd_packets"]])
        dur = max(float(row[idx["duration"]]), 1e-6)
        dst_port = float(row[idx["dst_port"]])
        proto = float(row[idx["protocol"]])

        scores = {}
        scores["NORMAL"] = 0.3
        scores["DDoS"] = min(pps / 5000.0 + bps / 5e6 + syn / 50.0, 3.0)
        scores["PortScan"] = min(syn / 8.0 + rst / 5.0 + (fwd_pkts / dur) / 200.0, 3.0)
        scores["BruteForce"] = 0.0
        if dst_port in (22.0, 3389.0, 21.0, 23.0):
            scores["BruteForce"] = min((fwd_pkts / dur) / 10.0 + psh / 15.0, 3.0)
        scores["DoS_Slowloris"] = 0.0
        if dur > 5.0 and fwd_pkts > 5:
            scores["DoS_Slowloris"] = min((psh + urg) / 20.0 + dur / 60.0, 3.0)
        scores["WebAttack"] = 0.0
        if dst_port in (80.0, 443.0, 8080.0, 8443.0):
            scores["WebAttack"] = min(psh / 30.0 + bps / 2e6, 3.0)
        scores["Botnet"] = min(urg / 10.0 + psh / 40.0 + (bps / 3e6) * 0.5, 3.0)
        scores["Infiltration"] = min(urg / 5.0 + (1.0 if dst_port in (4444.0, 31337.0, 1337.0) else 0.0), 3.0)
        scores["Exfiltration"] = min(bps / 1e7 + (1.0 if dst_port in (53.0, 123.0) else 0.0) * 0.5, 3.0)

        names = list(ATTACK_CLASSES)
        raw = np.array([scores[c] for c in names], dtype=np.float32)
        exp = np.exp(raw - raw.max())
        probs = exp / exp.sum()
        return probs

    def predict_proba(self, X):
        return np.asarray(
            [
                self._row_probabilities(row)
                for row in self._rows_from_X(X)
            ],
            dtype=np.float32,
        )

    def predict(self, X):
        probs = self.predict_proba(X)
        indexes = np.argmax(probs, axis=1)
        return np.asarray([self.classes_[int(index)] for index in indexes])


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
        self.model_profile: Dict[str, Any] = {}
        self.model_metadata: Dict[str, Any] = {}
        self._drift_window = deque(maxlen=100)
        self._drift_status: Dict[str, Any] = {
            "detected": False,
            "psi": 0.0,
            "sample_count": 0,
            "checked_at": None,
        }

        if self.enabled:
            self.load_models()

    def configure_drift(self, window_size: int = 100) -> None:
        """Set runtime drift window without changing model artifacts."""
        self._drift_window = deque(
            list(self._drift_window)[-max(10, int(window_size)):],
            maxlen=max(10, int(window_size)),
        )

    def _create_rulebased_fallback(self) -> bool:
        """Load zero-dependency rule-based fallback models (always succeeds)."""
        try:
            anomaly_model = RuleBasedFallbackModel()
            classifier_model = RuleBasedFallbackClassifier()

            os.makedirs(self.model_dir, exist_ok=True)
            anomaly_path = os.path.join(self.model_dir, "anomaly_detector.pkl")
            classifier_path = os.path.join(self.model_dir, "attack_classifier.pkl")
            features_path = os.path.join(self.model_dir, "feature_names.json")
            metadata_path = os.path.join(self.model_dir, "model_metadata.json")
            profile_path = os.path.join(self.model_dir, "model_profile.json")

            try:
                joblib.dump(anomaly_model, anomaly_path)
                joblib.dump(classifier_model, classifier_path)
                with open(features_path, "w") as f:
                    json.dump(FEATURE_NAMES, f, indent=2)
                with open(metadata_path, "w") as f:
                    json.dump(
                        {
                            "version": "1.0.0-rulebased",
                            "source": "rulebased-fallback",
                            "generated_at": time.time(),
                        },
                        f,
                        indent=2,
                    )
                try:
                    os.unlink(profile_path)
                except OSError:
                    pass
            except (OSError, PermissionError) as e:
                logger.warning(f"Could not persist rule-based fallback models to {self.model_dir}: {e}")

            self.anomaly_model = anomaly_model
            self.classifier_model = classifier_model
            self.feature_names = FEATURE_NAMES
            self.model_loaded = True
            self.version = "1.0.0-rulebased"
            self.model_metadata = {
                "version": self.version,
                "source": "rulebased-fallback",
                "generated_at": time.time(),
                "validation_note": "Rule-based fallback; validation metrics unavailable.",
            }
            logger.warning(
                "Loaded RULE-BASED fallback ML models (LightGBM/scikit-learn unavailable or no .pkl files). "
                "Install dependencies and/or train with a real dataset for better detection accuracy. "
                "Run: pip install lightgbm scikit-learn && "
                "python -m sagedral_ml.scripts.train_model --dataset /path/to/cicids.csv"
            )
            return True
        except Exception as e:
            logger.error(f"Failed to create rule-based fallback models: {e}")
            self.model_loaded = False
            return False

    def _create_fallback_models(self) -> bool:
        """Generate LightGBM synthetic fallback models if possible; otherwise use rule-based fallback."""
        if _LIGHTGBM_AVAILABLE:
            try:
                n_normal = 400
                n_anomaly = 80
                n_features = len(FEATURE_NAMES)
                rng = np.random.default_rng(seed=42)

                X_normal = np.abs(rng.normal(loc=0.5, scale=0.25, size=(n_normal, n_features)))
                X_normal = np.clip(X_normal, 0.0, 5.0)

                X_anomaly = np.abs(rng.normal(loc=2.5, scale=0.8, size=(n_anomaly, n_features)))
                X_anomaly = np.clip(X_anomaly, 0.0, 10.0)

                X_bin = np.vstack([X_normal, X_anomaly]).astype(np.float32)
                y_bin = np.array([0] * n_normal + [1] * n_anomaly, dtype=np.int32)

                n_per_class = max(40, n_anomaly // (len(ATTACK_CLASSES) - 1))
                X_multi_list = [X_normal[:n_per_class]]
                y_multi_list = ["NORMAL"] * n_per_class

                class_seeds = [1, 2, 3, 5, 7, 11, 13, 17]
                for idx, cls_name in enumerate(ATTACK_CLASSES[1:]):
                    rng_c = np.random.default_rng(seed=class_seeds[idx % len(class_seeds)])
                    loc_shift = 1.5 + 0.4 * idx
                    X_cls = np.abs(rng_c.normal(loc=loc_shift, scale=0.6 + 0.05 * idx, size=(n_per_class, n_features)))
                    X_cls = np.clip(X_cls, 0.0, 10.0)
                    X_multi_list.append(X_cls)
                    y_multi_list.extend([cls_name] * n_per_class)

                X_multi = np.vstack(X_multi_list).astype(np.float32)
                y_multi = np.array(y_multi_list)

                try:
                    anomaly_model = LGBMClassifier(
                        n_estimators=50,
                        learning_rate=0.1,
                        num_leaves=15,
                        random_state=42,
                        verbosity=-1,
                    )
                    # Keep a deterministic held-out slice for transparent synthetic metrics.
                    bin_train = np.concatenate((np.arange(0, 320), np.arange(400, 464)))
                    bin_valid = np.concatenate((np.arange(320, 400), np.arange(464, 480)))
                    anomaly_model.fit(X_bin[bin_train], y_bin[bin_train])

                    classifier_model = LGBMClassifier(
                        n_estimators=50,
                        learning_rate=0.1,
                        num_leaves=15,
                        random_state=42,
                        verbosity=-1,
                    )
                    # Split each fixed class block independently so validation sees every class.
                    class_train, class_valid = [], []
                    for start in range(0, len(X_multi), n_per_class):
                        split = start + int(n_per_class * 0.8)
                        class_train.extend(range(start, split))
                        class_valid.extend(range(split, start + n_per_class))
                    classifier_model.fit(X_multi[class_train], y_multi[class_train])
                except Exception as lgbm_err:
                    logger.warning(
                        f"LightGBM fallback training skipped ({lgbm_err}). Falling back to rule-based models."
                    )
                    return self._create_rulebased_fallback()

                # Compute deterministic held-out metrics (synthetic data only).
                bin_pred = anomaly_model.predict(X_bin[bin_valid])
                anomaly_accuracy = float(np.mean(bin_pred == y_bin[bin_valid]))
                anomaly_f1 = float(2 * np.sum((bin_pred == 1) & (y_bin[bin_valid] == 1)) /
                                   max(2 * np.sum((bin_pred == 1) & (y_bin[bin_valid] == 1)) +
                                       np.sum((bin_pred == 1) & (y_bin[bin_valid] == 0)) +
                                       np.sum((bin_pred == 0) & (y_bin[bin_valid] == 1)), 1))
                multi_valid = np.asarray(class_valid, dtype=int)
                classifier_accuracy = float(np.mean(classifier_model.predict(X_multi[multi_valid]) == y_multi[multi_valid]))
                metadata = {
                    "version": "1.0.0-fallback",
                    "source": "synthetic-fallback",
                    "generated_at": time.time(),
                    "anomaly_accuracy": anomaly_accuracy,
                    "anomaly_f1": anomaly_f1,
                    "classifier_accuracy": classifier_accuracy,
                    "validation_note": "Metrics are deterministic held-out synthetic validation only; train on a labeled production dataset before relying on accuracy.",
                }
                self.model_metadata = metadata
                os.makedirs(self.model_dir, exist_ok=True)
                anomaly_path = os.path.join(self.model_dir, "anomaly_detector.pkl")
                classifier_path = os.path.join(self.model_dir, "attack_classifier.pkl")
                features_path = os.path.join(self.model_dir, "feature_names.json")
                metadata_path = os.path.join(
                    self.model_dir, "model_metadata.json"
                )
                profile_path = os.path.join(
                    self.model_dir, "model_profile.json"
                )

                try:
                    joblib.dump(anomaly_model, anomaly_path)
                    joblib.dump(classifier_model, classifier_path)
                    with open(features_path, "w") as f:
                        json.dump(FEATURE_NAMES, f, indent=2)
                    with open(metadata_path, "w") as f:
                        json.dump(
                            metadata,
                            f,
                            indent=2,
                        )
                    try:
                        os.unlink(profile_path)
                    except OSError:
                        pass
                except (OSError, PermissionError) as e:
                    logger.warning(f"Could not persist fallback models to {self.model_dir}: {e}. Using in-memory models only.")

                self.anomaly_model = anomaly_model
                self.classifier_model = classifier_model
                self.feature_names = FEATURE_NAMES
                self.model_loaded = True
                self.version = "1.0.0-fallback"
                logger.warning(
                    "Generated and loaded FALLBACK ML models from synthetic data. "
                    "For production detection, train with a real dataset using: "
                    "python -m sagedral_ml.scripts.train_model --dataset /path/to/cicids.csv"
                )
                return True
            except Exception as e:
                logger.warning(f"Failed to create LightGBM fallback models ({e}), using rule-based fallback.")
                return self._create_rulebased_fallback()
        else:
            return self._create_rulebased_fallback()

    def load_models(self) -> bool:
        """Load binary anomaly detector and multiclass attack classifier models."""
        self.model_profile = {}
        self.model_metadata = {}
        self.version = "1.0.0"
        artifact_dir = resolve_model_artifact_dir(self.model_dir)
        anomaly_path = os.path.join(artifact_dir, "anomaly_detector.pkl")
        classifier_path = os.path.join(artifact_dir, "attack_classifier.pkl")
        features_path = os.path.join(artifact_dir, "feature_names.json")
        profile_path = os.path.join(artifact_dir, "model_profile.json")
        metadata_path = os.path.join(artifact_dir, "model_metadata.json")

        if not os.path.exists(anomaly_path):
            logger.warning(f"ML anomaly model not found at {anomaly_path}. Generating fallback models...")
            return self._create_fallback_models()

        try:
            self.anomaly_model = joblib.load(anomaly_path)
            if os.path.exists(classifier_path):
                self.classifier_model = joblib.load(classifier_path)

            if os.path.exists(features_path):
                with open(features_path, "r") as f:
                    self.feature_names = json.load(f)
            if os.path.exists(profile_path):
                with open(profile_path, "r") as f:
                    loaded_profile = json.load(f)
                if isinstance(loaded_profile, dict):
                    self.model_profile = loaded_profile
            if os.path.exists(metadata_path):
                with open(metadata_path, "r") as f:
                    metadata = json.load(f)
                if isinstance(metadata, dict):
                    self.model_metadata = metadata
                    self.version = str(metadata.get("version", self.version))

            self.model_loaded = True
            logger.info("Successfully loaded ML detection models.")
            return True
        except Exception as e:
            logger.error(f"Failed to load ML models from {artifact_dir}: {e}. Attempting fallback models...")
            return self._create_fallback_models()

    def _track_drift_row(self, row: List[float]) -> None:
        self._drift_window.append(np.asarray(row, dtype=np.float64))
        if (
            not self.model_profile
            or len(self._drift_window) < self._drift_window.maxlen
        ):
            self._drift_status["sample_count"] = len(self._drift_window)
            return
        means = self.model_profile.get("feature_mean", {})
        stds = self.model_profile.get("feature_std", {})
        if not isinstance(means, dict) or not isinstance(stds, dict):
            return
        matrix = np.vstack(self._drift_window)
        expected = np.asarray(
            [0.0228, 0.1359, 0.3413, 0.3413, 0.1359, 0.0228],
            dtype=np.float64,
        )
        psi_values = []
        for index, name in enumerate(self.feature_names):
            std = max(float(stds.get(name, 0.0) or 0.0), 1e-9)
            mean = float(means.get(name, 0.0) or 0.0)
            edges = np.asarray(
                [
                    -np.inf,
                    mean - 2 * std,
                    mean - std,
                    mean,
                    mean + std,
                    mean + 2 * std,
                    np.inf,
                ]
            )
            counts, _ = np.histogram(matrix[:, index], bins=edges)
            observed = counts.astype(np.float64) / max(float(counts.sum()), 1.0)
            observed = np.clip(observed, 1e-6, None)
            exp_safe = np.clip(expected, 1e-6, None)
            psi_values.append(
                float(np.sum((observed - exp_safe) * np.log(observed / exp_safe)))
            )
        psi = float(np.mean(psi_values)) if psi_values else 0.0
        self._drift_status = {
            "detected": psi > 0.25,
            "psi": psi,
            "sample_count": len(self._drift_window),
            "checked_at": time.time(),
        }

    def get_drift_status(self, threshold: float = 0.25) -> Dict[str, Any]:
        status = dict(self._drift_status)
        status["threshold"] = float(threshold)
        status["detected"] = float(status.get("psi", 0.0)) > float(threshold)
        status["profile_loaded"] = bool(self.model_profile)
        return status

    def predict_batch(
        self, feature_vectors: List[Dict[str, Any]]
    ) -> List[MLResult]:
        """Run both model stages in vectorized batches."""
        if not feature_vectors:
            return []
        if not self.enabled or not self.model_loaded or self.anomaly_model is None:
            return [MLResult(model_version="none") for _ in feature_vectors]
        try:
            rows = [
                [float(vector.get(name, 0.0)) for name in self.feature_names]
                for vector in feature_vectors
            ]
            x_arr = np.asarray(rows, dtype=np.float32)
            if hasattr(self.anomaly_model, "predict_proba"):
                raw = self.anomaly_model.predict_proba(x_arr)
                scores = raw[:, 1] if raw.shape[1] > 1 else raw[:, 0]
            else:
                scores = np.asarray(self.anomaly_model.predict(x_arr), dtype=float)
            results = []
            anomaly_indexes = [
                index
                for index, score in enumerate(scores)
                if float(score) >= self.anomaly_threshold
            ]
            classified = {}
            if anomaly_indexes and self.classifier_model is not None:
                subset = x_arr[anomaly_indexes]
                if hasattr(self.classifier_model, "predict_proba"):
                    class_probs = self.classifier_model.predict_proba(subset)
                    classes = getattr(self.classifier_model, "classes_", None)
                    for local_index, source_index in enumerate(anomaly_indexes):
                        top_index = int(np.argmax(class_probs[local_index]))
                        confidence = float(class_probs[local_index][top_index])
                        class_name = (
                            str(classes[top_index])
                            if classes is not None and top_index < len(classes)
                            else "Anomaly_Class_%d" % top_index
                        )
                        classified[source_index] = (class_name, confidence)
                else:
                    predictions = self.classifier_model.predict(subset)
                    for local_index, source_index in enumerate(anomaly_indexes):
                        classified[source_index] = (
                            str(predictions[local_index]),
                            float(scores[source_index]),
                        )
            for index, score_value in enumerate(scores):
                score = float(score_value)
                is_anomaly = score >= self.anomaly_threshold
                attack_class, confidence = classified.get(
                    index,
                    ("NORMAL", 1.0 - score if not is_anomaly else score),
                )
                if (
                    is_anomaly
                    and confidence < self.classifier_threshold
                    and attack_class != "NORMAL"
                ):
                    attack_class = "Unknown_Anomaly"
                self._track_drift_row(rows[index])
                results.append(
                    MLResult(
                        anomaly_score=score,
                        is_anomaly=is_anomaly,
                        attack_class=attack_class,
                        class_confidence=float(confidence),
                        model_version=self.version,
                    )
                )
            return results
        except Exception as exc:
            logger.error("Error during batch ML prediction: %s", exc)
            return [MLResult(model_version="error") for _ in feature_vectors]

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
            self._track_drift_row(row)

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
