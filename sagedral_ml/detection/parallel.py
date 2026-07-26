"""Optional multi-process ML inference pool for bypassing the Python GIL."""

import logging
from concurrent.futures import ProcessPoolExecutor
from typing import Any, Dict, List, Optional

from sagedral_ml.detection.ml_engine import FEATURE_NAMES, MLEngine, MLResult

logger = logging.getLogger("sagedral_ml.detection.parallel")
_WORKER_ENGINE = None  # type: Optional[MLEngine]


def _initialize_worker(settings: Dict[str, Any]) -> None:
    global _WORKER_ENGINE
    _WORKER_ENGINE = MLEngine(**settings)


def _predict_chunk(vectors: List[Dict[str, Any]]) -> List[MLResult]:
    if _WORKER_ENGINE is None:
        raise RuntimeError("ML process worker is not initialized")
    return _WORKER_ENGINE.predict_batch(vectors)


class MultiprocessMLEngine:
    """Coordinator-compatible facade around worker-local model instances."""

    def __init__(self, coordinator: MLEngine, workers: int) -> None:
        self.coordinator = coordinator
        self.workers = max(1, int(workers))
        settings = {
            "model_dir": coordinator.model_dir,
            "anomaly_threshold": coordinator.anomaly_threshold,
            "classifier_threshold": coordinator.classifier_threshold,
            "enabled": coordinator.enabled,
        }
        self._pool = ProcessPoolExecutor(
            max_workers=self.workers,
            initializer=_initialize_worker,
            initargs=(settings,),
        )

    @property
    def feature_names(self):
        return self.coordinator.feature_names

    @property
    def version(self):
        return self.coordinator.version

    def predict_batch(
        self, feature_vectors: List[Dict[str, Any]]
    ) -> List[MLResult]:
        if not feature_vectors:
            return []
        chunk_size = max(
            1, (len(feature_vectors) + self.workers - 1) // self.workers
        )
        chunks = [
            feature_vectors[index : index + chunk_size]
            for index in range(0, len(feature_vectors), chunk_size)
        ]
        results = []
        for batch in self._pool.map(_predict_chunk, chunks):
            results.extend(batch)
        for vector in feature_vectors:
            row = [
                float(vector.get(name, 0.0))
                for name in self.coordinator.feature_names
            ]
            self.coordinator._track_drift_row(row)
        return results

    def close(self) -> None:
        self._pool.shutdown(wait=True)
