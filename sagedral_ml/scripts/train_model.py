"""
Script to train LightGBM Anomaly Detector and Attack Classifier models.
Usage: python -m sagedral_ml.scripts.train_model --dataset /path/to/cicids.csv --output-dir /var/lib/sagedral-ml/models
"""

import os
import json
import argparse
import logging
import time
import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, f1_score
from lightgbm import LGBMClassifier

from sagedral_ml.detection.ml_engine import FEATURE_NAMES

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("sagedral_ml.scripts.train")


def train_models(
    dataset_path: str,
    output_dir: str,
    validation_split: float = 0.2,
):
    if not 0.05 <= float(validation_split) <= 0.5:
        raise ValueError("validation_split must be between 0.05 and 0.5")
    os.makedirs(output_dir, exist_ok=True)
    logger.info(f"Loading dataset from {dataset_path}...")

    df = pd.read_csv(dataset_path)
    df.columns = df.columns.str.strip().str.lower()

    # Feature column alignment
    features = [f for f in FEATURE_NAMES if f in df.columns]
    if len(features) < len(FEATURE_NAMES):
        logger.warning(f"Dataset has {len(features)} of 28 required features. Missing features will be filled with 0.")

    # Fill missing columns
    for f in FEATURE_NAMES:
        if f not in df.columns:
            df[f] = 0.0

    X = df[FEATURE_NAMES].fillna(0.0).replace([np.inf, -np.inf], 0.0)

    # Label extraction
    label_col = "label" if "label" in df.columns else "attack_type"
    if label_col not in df.columns:
        raise ValueError("Dataset must contain a 'label' or 'attack_type' column.")

    y_raw = df[label_col].astype(str)
    y_binary = (y_raw.str.upper() != "BENIGN") & (y_raw.str.upper() != "NORMAL")

    logger.info(f"Dataset size: {len(X)} rows. Anomaly proportion: {y_binary.mean()*100:.2f}%")

    # Split dataset
    X_train, X_val, y_bin_train, y_bin_val, y_raw_train, y_raw_val = train_test_split(
        X,
        y_binary,
        y_raw,
        test_size=float(validation_split),
        random_state=42,
        stratify=y_binary,
    )

    # ================= Stage 1: Binary Anomaly Detector =================
    logger.info("Training Stage 1: LightGBM Binary Anomaly Detector...")
    anomaly_model = LGBMClassifier(
        n_estimators=100,
        learning_rate=0.05,
        num_leaves=31,
        random_state=42,
        verbosity=-1,
    )
    anomaly_model.fit(X_train, y_bin_train)

    val_preds = anomaly_model.predict(X_val)
    acc = accuracy_score(y_bin_val, val_preds)
    f1 = f1_score(y_bin_val, val_preds)
    logger.info(f"Stage 1 Anomaly Detector Accuracy: {acc:.4f}, F1-Score: {f1:.4f}")

    # ================= Stage 2: Multiclass Attack Classifier =================
    logger.info("Training Stage 2: LightGBM Multiclass Attack Classifier...")
    classifier_model = LGBMClassifier(
        n_estimators=100,
        learning_rate=0.05,
        num_leaves=31,
        random_state=42,
        verbosity=-1,
    )
    classifier_model.fit(X_train, y_raw_train)

    cls_preds = classifier_model.predict(X_val)
    cls_acc = accuracy_score(y_raw_val, cls_preds)
    logger.info(f"Stage 2 Attack Classifier Accuracy: {cls_acc:.4f}")

    # Save models and feature order
    anomaly_path = os.path.join(output_dir, "anomaly_detector.pkl")
    classifier_path = os.path.join(output_dir, "attack_classifier.pkl")
    feature_path = os.path.join(output_dir, "feature_names.json")
    profile_path = os.path.join(output_dir, "model_profile.json")
    metadata_path = os.path.join(output_dir, "model_metadata.json")

    joblib.dump(anomaly_model, anomaly_path)
    joblib.dump(classifier_model, classifier_path)
    with open(feature_path, "w") as f:
        json.dump(FEATURE_NAMES, f, indent=2)
    normal_mask = ~y_binary
    profile_source = X.loc[normal_mask] if bool(normal_mask.any()) else X
    with open(profile_path, "w") as f:
        json.dump(
            {
                "feature_mean": {
                    name: float(profile_source[name].mean())
                    for name in FEATURE_NAMES
                },
                "feature_std": {
                    name: float(profile_source[name].std(ddof=0) or 0.0)
                    for name in FEATURE_NAMES
                },
                "normal_sample_count": int(len(profile_source)),
                "generated_at": time.time(),
            },
            f,
            indent=2,
        )
    version = "1.0.%d" % int(time.time())
    with open(metadata_path, "w") as f:
        json.dump(
            {
                "version": version,
                "trained_at": time.time(),
                "dataset_rows": int(len(X)),
                "anomaly_accuracy": float(acc),
                "anomaly_f1": float(f1),
                "classifier_accuracy": float(cls_acc),
            },
            f,
            indent=2,
        )

    logger.info(f"Models successfully saved to {output_dir}")
    return {
        "version": version,
        "anomaly_accuracy": float(acc),
        "anomaly_f1": float(f1),
        "classifier_accuracy": float(cls_acc),
    }


def main():
    parser = argparse.ArgumentParser(description="Train SAGEDRAL-ML LightGBM Models")
    parser.add_argument("--dataset", required=True, help="Path to input CSV dataset")
    parser.add_argument("--output-dir", default="/var/lib/sagedral-ml/models", help="Output directory")
    parser.add_argument("--validation-split", type=float, default=0.2)
    args = parser.parse_args()

    train_models(args.dataset, args.output_dir, args.validation_split)


if __name__ == "__main__":
    main()
