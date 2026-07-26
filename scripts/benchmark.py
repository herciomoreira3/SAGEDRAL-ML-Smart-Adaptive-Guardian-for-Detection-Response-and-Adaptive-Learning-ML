"""Small deterministic detection benchmark for release regression checks."""

import argparse
import json
import tempfile
import time

from sagedral_ml.detection.ml_engine import FEATURE_NAMES, MLEngine
from sagedral_ml.detection.signature_engine import SignatureEngine


def run(iterations: int) -> dict:
    flow = {name: 0.0 for name in FEATURE_NAMES}
    flow.update(
        {
            "duration": 1.0,
            "total_fwd_packets": 120,
            "syn_flag_count": 110,
            "flow_packets_per_sec": 120.0,
            "dst_port": 443,
        }
    )
    with tempfile.TemporaryDirectory(prefix="sagedral-benchmark-") as model_dir:
        signature = SignatureEngine()
        ml = MLEngine(model_dir=model_dir)
        batch = [flow] * min(32, iterations)
        started = time.perf_counter()
        completed = 0
        while completed < iterations:
            current = batch[: min(len(batch), iterations - completed)]
            ml.predict_batch(current)
            for item in current:
                signature.evaluate(item)
            completed += len(current)
        elapsed = time.perf_counter() - started
    return {
        "iterations": iterations,
        "elapsed_seconds": elapsed,
        "flows_per_second": iterations / max(elapsed, 1e-9),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--minimum-fps", type=float, default=1.0)
    args = parser.parse_args()
    result = run(max(1, args.iterations))
    print(json.dumps(result, indent=2))
    if result["flows_per_second"] < args.minimum_fps:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
