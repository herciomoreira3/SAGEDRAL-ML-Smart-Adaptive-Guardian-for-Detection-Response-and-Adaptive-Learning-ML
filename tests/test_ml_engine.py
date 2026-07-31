"""
Basic unit tests for MLEngine fallback behaviour.
"""

import os

import pytest

from sagedral_ml.detection.ml_engine import MLEngine
from sagedral_ml.detection.ml_engine import resolve_model_artifact_dir


def test_model_artifact_resolution_uses_legacy_root_without_pointer(tmp_path):
    assert resolve_model_artifact_dir(str(tmp_path)) == str(tmp_path)


def test_model_artifact_resolution_rejects_traversal_pointer(tmp_path):
    (tmp_path / "active_model.json").write_text('{"artifact_dir": "../outside"}')
    assert resolve_model_artifact_dir(str(tmp_path)) == str(tmp_path)


def test_model_artifact_resolution_rejects_symlink_escape(tmp_path):
    outside = tmp_path.parent / (tmp_path.name + "-outside")
    outside.mkdir()
    linked = tmp_path / "versions"
    try:
        os.symlink(str(outside), str(linked), target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlinks are unavailable")
    (tmp_path / "active_model.json").write_text(
        '{"artifact_dir": "versions/model"}'
    )
    (outside / "model").mkdir()
    assert resolve_model_artifact_dir(str(tmp_path)) == str(tmp_path)


def test_ml_engine_initializes_without_trained_models(tmp_path):
    engine = MLEngine(
        model_dir=str(tmp_path),
        anomaly_threshold=0.7,
        classifier_threshold=0.6,
        enabled=True,
    )
    assert engine is not None
    assert engine.version is not None


def test_fallback_metadata_is_available_in_memory(tmp_path):
    engine = MLEngine(model_dir=str(tmp_path), enabled=True)
    assert engine.model_metadata.get("version") == engine.version
    if engine.version.endswith("-fallback"):
        assert 0.0 <= engine.model_metadata["anomaly_accuracy"] <= 1.0
        assert 0.0 <= engine.model_metadata["anomaly_f1"] <= 1.0
        assert 0.0 <= engine.model_metadata["classifier_accuracy"] <= 1.0
        assert "synthetic" in engine.model_metadata["validation_note"]


def test_ml_engine_predict_returns_scores(tmp_path):
    engine = MLEngine(
        model_dir=str(tmp_path),
        anomaly_threshold=0.7,
        classifier_threshold=0.6,
        enabled=True,
    )
    feature_vector = {
        "duration": 1.0,
        "total_fwd_packets": 10,
        "total_bwd_packets": 2,
        "total_fwd_bytes": 1000,
        "total_bwd_bytes": 200,
        "fwd_packet_len_mean": 100.0,
        "fwd_packet_len_std": 10.0,
        "bwd_packet_len_mean": 100.0,
        "bwd_packet_len_std": 10.0,
        "flow_bytes_per_sec": 1200.0,
        "flow_packets_per_sec": 12.0,
        "fwd_iat_mean": 0.1,
        "fwd_iat_std": 0.01,
        "bwd_iat_mean": 0.2,
        "bwd_iat_std": 0.02,
        "psh_flag_count": 0,
        "urg_flag_count": 0,
        "syn_flag_count": 5,
        "fin_flag_count": 0,
        "rst_flag_count": 0,
        "ack_flag_count": 3,
        "avg_fwd_segment_size": 100.0,
        "avg_bwd_segment_size": 100.0,
        "fwd_header_len": 200,
        "bwd_header_len": 40,
        "down_up_ratio": 0.2,
        "protocol": 6,
        "dst_port": 443,
    }
    result = engine.predict(feature_vector)
    assert result.anomaly_score is not None
    assert 0.0 <= result.anomaly_score <= 1.0
