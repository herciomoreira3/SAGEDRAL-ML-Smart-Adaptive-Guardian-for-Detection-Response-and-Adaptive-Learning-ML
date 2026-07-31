"""
API Router for Machine Learning Model metadata endpoints.
"""

import math

from fastapi import APIRouter, Depends
from sagedral_ml.config import get_config

from sagedral_ml.core.container import global_container
from sagedral_ml.api.auth import get_current_user


router = APIRouter(prefix="/api/v1/model", tags=["ML Model"])


def _get_ml_engine():
    return global_container.ml_engine


def _metric(metadata, key):
    """Return only finite metrics in the normalized [0, 1] range."""
    value = metadata.get(key) if isinstance(metadata, dict) else None
    if isinstance(value, bool):
        return None
    try:
        value = float(value)
    except (TypeError, ValueError):
        return None
    return value if math.isfinite(value) and 0.0 <= value <= 1.0 else None


@router.get("/info", dependencies=[Depends(get_current_user)])
async def get_model_info(_user=Depends(get_current_user)):
    config = get_config()
    ml_enabled = config.get("ml", "enabled", True)
    model_dir = config.get("ml", "model_dir", "/var/lib/sagedral-ml/models")

    global_ml_engine = _get_ml_engine()
    loaded = global_ml_engine.model_loaded if global_ml_engine else False
    model_version = global_ml_engine.version if global_ml_engine else "none"
    metadata = (
        global_ml_engine.model_metadata
        if global_ml_engine is not None
        else {}
    )
    is_fallback = any(
        marker in model_version.lower()
        for marker in ("fallback", "rulebased", "none", "unattached")
    )

    return {
        "enabled": ml_enabled,
        "loaded": loaded,
        "model_dir": model_dir,
        "model_version": model_version,
        "anomaly_model": {
            "version": model_version,
            "type": "LightGBM Binary Anomaly Classifier",
            "n_features": 28,
            "accuracy": _metric(metadata, "anomaly_accuracy"),
            "f1_score": _metric(metadata, "anomaly_f1"),
            "note": None if not is_fallback else "Fallback model active. Train with a labeled production dataset before relying on ML accuracy.",
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
            "accuracy": _metric(metadata, "classifier_accuracy"),
            "note": None if not is_fallback else "Fallback model active. Train with a labeled production dataset before relying on ML accuracy.",
        },
    }
