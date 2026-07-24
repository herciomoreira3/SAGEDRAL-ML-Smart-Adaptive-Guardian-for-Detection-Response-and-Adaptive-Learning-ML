"""
Script to evaluate trained LightGBM models against a test dataset.
Usage: python -m sagedral_ml.scripts.evaluate_model --test-data /path/to/test.csv --model-dir /var/lib/sagedral-ml/models
"""

import os
import json
import argparse
import logging
import pandas as pd
import numpy as np
import joblib
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

from sagedral_ml.detection.ml_engine import FEATURE_NAMES

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("sagedral_ml.scripts.evaluate")


def evaluate_models(test_data_path: str, model_dir: str):
    logger.info(f"Loading test data from {test_data_path}...")
    df = pd.read_csv(test_data_path)
    df.columns = df.columns.str.strip().str.lower()

    for f in FEATURE_NAMES:
        if f not in df.columns:
            df[f] = 0.0

    X_test = df[FEATURE_NAMES].fillna(0.0).replace([np.inf, -np.inf], 0.0)

    label_col = "label" if "label" in df.columns else "attack_type"
    y_test_raw = df[label_col].astype(str)
    y_test_binary = (y_test_raw.str.upper() != "BENIGN") & (y_test_raw.str.upper() != "NORMAL")

    anomaly_path = os.path.join(model_dir, "anomaly_detector.pkl")
    classifier_path = os.path.join(model_dir, "attack_classifier.pkl")

    if not os.path.exists(anomaly_path):
        raise FileNotFoundError(f"Anomaly model not found at {anomaly_path}")

    anomaly_model = joblib.load(anomaly_path)
    anom_preds = anomaly_model.predict(X_test)

    logger.info("=== Stage 1: Anomaly Detector Evaluation ===")
    logger.info(f"Accuracy: {accuracy_score(y_test_binary, anom_preds):.4f}")
    logger.info("\n" + classification_report(y_test_binary, anom_preds))

    if os.path.exists(classifier_path):
        classifier_model = joblib.load(classifier_path)
        cls_preds = classifier_model.predict(X_test)
        logger.info("=== Stage 2: Attack Classifier Evaluation ===")
        logger.info(f"Accuracy: {accuracy_score(y_test_raw, cls_preds):.4f}")
        logger.info("\n" + classification_report(y_test_raw, cls_preds))


def main():
    parser = argparse.ArgumentParser(description="Evaluate SAGEDRAL-ML LightGBM Models")
    parser.add_argument("--test-data", required=True, help="Path to test CSV dataset")
    parser.add_argument("--model-dir", default="/var/lib/sagedral-ml/models", help="Model directory")
    args = parser.parse_args()

    evaluate_models(args.test_data, args.model_dir)


if __name__ == "__main__":
    main()
