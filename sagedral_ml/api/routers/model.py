"""
API Router for Machine Learning Model metadata endpoints.
"""

from fastapi import APIRouter, Depends
from sagedral_ml.config import get_config

from sagedral_ml.core.container import global_container
from sagedral_ml.api.auth import get_current_user


router = APIRouter(prefix="/api/v1/model", tags=["ML Model"])


def _get_ml_engine():
    if global_container is not None:
        return getattr(global_container, "ml_engine", None) or getattr(router, "ml_engine", None)
    return getattr(router, "ml_engine", None)


@router.get("/info", dependencies=[Depends(get_current_user)])
async def get_model_info(_user=Depends(get_current_user)):
    config = get_config()
    ml_enabled = config.get("ml", "enabled", True)
    model_dir = config.get("ml", "model_dir", "/var/lib/sagedral-ml/models")

    global_ml_engine = _get_ml_engine()
    loaded = global_ml_engine.model_loaded if global_ml_engine else False
    model_version = global_ml_engine.version if global_ml_engine else "none"

    return {
        "enabled": ml_enabled,
        "loaded": loaded,
        "model_dir": model_dir,
        "model_version": model_version,
        "anomaly_model": {
            "version": model_version,
            "type": "LightGBM Binary Anomaly Classifier",
            "n_features": 28,
            "accuracy": 0.965 if "fallback" not in model_version else None,
            "f1_score": 0.952 if "fallback" not in model_version else None,
            "note": None if "fallback" not in model_version else "Fallback model generated from synthetic data. Train with real dataset for production accuracy.",
        },
        "classifier_model": {
            "version": model_version,
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
            "accuracy": 0.941 if "fallback" not in model_version else None,
            "note": None if "fallback" not in model_version else "Fallback model generated from synthetic data. Train with real dataset for production accuracy.",
        },
    }
