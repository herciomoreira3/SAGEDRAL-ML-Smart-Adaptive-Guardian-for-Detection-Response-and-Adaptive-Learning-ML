"""Active-learning retraining workflow built from analyst feedback labels."""

import asyncio
import csv
import logging
import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlalchemy import select

from sagedral_ml.config import get_config
from sagedral_ml.core.container import global_container
from sagedral_ml.database import crud
from sagedral_ml.database.models import AlertFeedbackModel, AlertModel
import sagedral_ml.database.connection as db_connection

logger = logging.getLogger("sagedral_ml.adaptive")


class AdaptiveLearningManager:
    """Export feedback vectors, train a candidate, validate, and hot-swap."""

    def __init__(self, config=None) -> None:
        self.config = config or get_config()
        self._lock = asyncio.Lock()

    async def _training_rows(self, db) -> List[Dict[str, Any]]:
        statement = (
            select(AlertFeedbackModel, AlertModel)
            .join(
                AlertModel,
                AlertModel.alert_id == AlertFeedbackModel.alert_id,
            )
            .where(AlertFeedbackModel.processed_at.is_(None))
            .order_by(AlertFeedbackModel.created_at.asc())
        )
        result = await db.execute(statement)
        rows = []
        for feedback, alert in result.all():
            if feedback.label == "UNCERTAIN":
                continue
            vector = None
            if feedback.training_vector_json:
                try:
                    import json

                    vector = json.loads(feedback.training_vector_json)
                except Exception:
                    vector = None
            if not isinstance(vector, dict):
                continue
            label = (
                "NORMAL"
                if feedback.label == "FALSE_POSITIVE"
                else (alert.attack_type or "Unknown_Anomaly")
            )
            row = dict(vector)
            row["label"] = label
            row["_feedback_id"] = feedback.id
            rows.append(row)
        return rows

    @staticmethod
    def _write_dataset(path: str, rows: List[Dict[str, Any]]) -> None:
        from sagedral_ml.detection.ml_engine import FEATURE_NAMES

        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=FEATURE_NAMES + ["label"])
            writer.writeheader()
            for source in rows:
                writer.writerow(
                    {
                        key: source.get(key, 0.0)
                        for key in FEATURE_NAMES + ["label"]
                    }
                )

    async def run_once(self) -> Dict[str, Any]:
        if self._lock.locked():
            return {"trained": False, "reason": "already_running"}
        async with self._lock:
            minimum = max(
                2,
                int(self.config.get("ml", "feedback_retrain_minimum", 20) or 20),
            )
            async with db_connection.AsyncSessionLocal() as db:
                rows = await self._training_rows(db)
            if len(rows) < minimum:
                return {
                    "trained": False,
                    "reason": "insufficient_feedback",
                    "pending": len(rows),
                    "minimum": minimum,
                }
            labels = {str(row.get("label")) for row in rows}
            if len(labels) < 2:
                return {
                    "trained": False,
                    "reason": "need_multiple_classes",
                    "pending": len(rows),
                }

            model_dir = Path(
                self.config.get("ml", "model_dir", "/var/lib/sagedral-ml/models")
            )
            model_dir.mkdir(parents=True, exist_ok=True)
            staging_parent = str(model_dir.parent)
            staging_dir = tempfile.mkdtemp(
                prefix=".sagedral-model-staging-", dir=staging_parent
            )
            dataset_path = os.path.join(staging_dir, "feedback-training.csv")
            self._write_dataset(dataset_path, rows)
            try:
                from sagedral_ml.scripts.train_model import train_models

                loop = asyncio.get_running_loop()
                result = await loop.run_in_executor(
                    None, train_models, dataset_path, staging_dir
                )
                minimum_accuracy = float(
                    self.config.get("ml", "adaptive_min_accuracy", 0.70)
                    or 0.70
                )
                minimum_f1 = float(
                    self.config.get("ml", "adaptive_min_f1", 0.65) or 0.65
                )
                minimum_classifier_accuracy = float(
                    self.config.get(
                        "ml", "adaptive_min_classifier_accuracy", 0.65
                    )
                    or 0.65
                )
                if (
                    float(result.get("anomaly_accuracy", 0.0))
                    < minimum_accuracy
                    or float(result.get("anomaly_f1", 0.0)) < minimum_f1
                    or float(result.get("classifier_accuracy", 0.0))
                    < minimum_classifier_accuracy
                ):
                    raise RuntimeError(
                        "candidate quality gate failed "
                        "(accuracy=%.4f, f1=%.4f, classifier=%.4f, "
                        "required=%.4f/%.4f/%.4f)"
                        % (
                            float(result.get("anomaly_accuracy", 0.0)),
                            float(result.get("anomaly_f1", 0.0)),
                            float(result.get("classifier_accuracy", 0.0)),
                            minimum_accuracy,
                            minimum_f1,
                            minimum_classifier_accuracy,
                        )
                    )
                from sagedral_ml.detection.ml_engine import MLEngine

                candidate = MLEngine(
                    model_dir=staging_dir,
                    anomaly_threshold=float(
                        self.config.get("ml", "anomaly_threshold", 0.7)
                    ),
                    classifier_threshold=float(
                        self.config.get("ml", "classifier_threshold", 0.6)
                    ),
                    enabled=True,
                )
                if not candidate.model_loaded:
                    raise RuntimeError("candidate model validation failed")
                backup_dir = model_dir.parent / (
                    "models-before-feedback-%d" % int(time.time() * 1000)
                )
                try:
                    os.unlink(dataset_path)
                except OSError:
                    pass
                old_model_moved = False
                try:
                    if model_dir.exists():
                        os.replace(str(model_dir), str(backup_dir))
                        old_model_moved = True
                    os.replace(staging_dir, str(model_dir))
                    staging_dir = ""
                except Exception:
                    if old_model_moved and not model_dir.exists():
                        os.replace(str(backup_dir), str(model_dir))
                    raise
                engine = global_container.ml_engine
                if engine is not None:
                    engine.load_models()
                version = (
                    getattr(engine, "version", None)
                    or result.get("version", "feedback")
                )
                feedback_ids = [int(row["_feedback_id"]) for row in rows]
                async with db_connection.AsyncSessionLocal() as db:
                    await crud.mark_feedback_processed(db, feedback_ids, version)
                    await crud.create_system_event(
                        db,
                        "MODEL_RETRAINED",
                        "INFO",
                        "adaptive_learning",
                        "Adaptive retrain completed and candidate deployed.",
                        {
                            "feedback_rows": len(rows),
                            "version": version,
                            "backup_dir": str(backup_dir),
                        },
                    )
                return {
                    "trained": True,
                    "feedback_rows": len(rows),
                    "version": version,
                }
            except Exception as exc:
                logger.exception("Adaptive retraining failed: %s", exc)
                async with db_connection.AsyncSessionLocal() as db:
                    await crud.create_system_event(
                        db,
                        "MODEL_RETRAIN_FAILED",
                        "ERROR",
                        "adaptive_learning",
                        str(exc),
                    )
                return {"trained": False, "reason": "training_failed", "error": str(exc)}
            finally:
                if staging_dir:
                    shutil.rmtree(staging_dir, ignore_errors=True)


adaptive_learning_manager = AdaptiveLearningManager()
