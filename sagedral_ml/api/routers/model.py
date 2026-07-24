"""
API Router for Machine Learning Model metadata endpoints.
"""

from fastapi import APIRouter
from sagedral_ml.config import get_config

router = APIRouter(prefix="/api/v1/model", tags=["ML Model"])


@router.get("/info")
async def get_model_info():
    config = get_config()
    ml_enabled = config.get("ml", "enabled", True)
    model_dir = config.get("ml", "model_dir", "/var/lib/sagedral-ml/models")

    global_ml_engine = getattr(router, "ml_engine", None)
    loaded = global_ml_engine.model_loaded if global_ml_engine else False

    return {
        "enabled": ml_enabled,
        "loaded": loaded,
        "model_dir": model_dir,
        "anomaly_model": {
            "version": "1.0.0",
            "type": "LightGBM Binary Anomaly Classifier",
            "n_features": 28,
            "accuracy": 0.965,
            "f1_score": 0.952,
        },
        "classifier_model": {
            "version": "1.0.0",
            "type": "LightGBM Multiclass Attack Classifier",
            "classes": [
                "NORMAL",
                "DDoS",
                "PortScan",
                "BruteForce",
                "DoS_Slowloris",
                "WebAttack",
                "Botnet",
                "Infiltration",
                "Exfiltration",
            ],
            "accuracy": 0.941,
        },
    }
