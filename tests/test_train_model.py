import numpy as np
import pandas as pd
import pytest

from sagedral_ml.scripts import train_model as trainer
from sagedral_ml.scripts.train_model import FEATURE_NAMES, _map_label, ingest_dataset
from sagedral_ml.detection.ml_engine import MLEngine, resolve_model_artifact_dir


class PickleFakeClassifier:
    """Module-level so joblib validation exercises real serialization."""
    def __init__(self, **kwargs):
        pass
    def fit(self, x, y):
        self.value = list(y)[0]
        return self
    def predict(self, x):
        return np.array([self.value] * len(x))


def _frame(labels, cic=True):
    columns = {}
    for index, feature in enumerate(FEATURE_NAMES[:20]):
        name = {
            "duration": "Flow Duration",
            "total_fwd_packets": "Tot Fwd Pkts",
            "total_bwd_packets": "Tot Bwd Pkts",
            "total_fwd_bytes": "TotLen Fwd Pkts",
            "fwd_iat_mean": "Fwd IAT Mean",
        }.get(feature, feature)
        columns[name] = [float(index + 1)] * len(labels)
    columns[" Label "] = labels
    return pd.DataFrame(columns)


@pytest.mark.parametrize("raw, expected", [
    ("BENIGN", "NORMAL"), ("DDoS attacks-LOIC-HTTP", "DDoS"),
    ("PortScan", "PortScan"), ("FTP-Patator", "BruteForce"),
    ("Web Attack – Brute Force", "WebAttack"), ("Brute Force -Web", "WebAttack"),
    ("XSS", "WebAttack"), ("SQL Injection", "WebAttack"), ("Bot", "Botnet"),
    ("Infiltration", "Infiltration"), ("Exfiltration", "Exfiltration"),
    ("Infilteration", "Infiltration"),
    ("DoS attacks-GoldenEye", "DoS_Slowloris"), ("DoS attacks-Slowloris", "DoS_Slowloris"),
    ("DoS attacks-SlowHTTPTest", "DoS_Slowloris"), ("DoS attacks-Hulk", "DoS_Slowloris"),
    ("Heartbleed", None),
])
def test_label_taxonomy(raw, expected):
    assert _map_label(raw) == expected


@pytest.mark.parametrize("label", ["NORMAL", "DDoS", "PortScan", "BruteForce", "DoS_Slowloris", "WebAttack", "Botnet", "Infiltration", "Exfiltration"])
def test_canonical_labels_are_stable(label):
    assert _map_label(label) == label


def test_recursive_ingestion_and_alias_units(tmp_path):
    first = _frame(["BENIGN", "DDoS attacks-LOIC-HTTP"])
    first["Flow Duration"] = [1000000, np.inf]
    first["Fwd IAT Mean"] = [2000000, 3000000]
    second = _frame(["NORMAL", "FTP-Patator"])
    first.to_csv(tmp_path / "day-a.csv", index=False)
    second.to_csv(tmp_path / "day-b.csv", index=False)
    features, labels, report = ingest_dataset(tmp_path)
    normal = features.loc[labels.reset_index(drop=True) == "NORMAL"]
    assert ((normal["duration"] == 1.0) & (normal["fwd_iat_mean"] == 2.0)).any()
    assert report["file_count"] == 2
    assert set(labels) == {"NORMAL", "DDoS", "BruteForce"}


def test_canonical_time_units_unchanged(tmp_path):
    frame = _frame(["NORMAL", "DDoS"])
    frame = frame.rename(columns={"Flow Duration": "duration", "Fwd IAT Mean": "fwd_iat_mean"})
    frame["duration"] = [1000000, 2000000]
    frame["fwd_iat_mean"] = [3000000, 4000000]
    frame.to_csv(tmp_path / "canonical.csv", index=False)
    features, _, _ = ingest_dataset(tmp_path / "canonical.csv")
    assert set(features["duration"]) == {1000000, 2000000}
    assert set(features["fwd_iat_mean"]) == {3000000, 4000000}


def test_all_time_aliases_convert_and_canonical_stay_unchanged(tmp_path):
    aliases = {"duration": "Flow Duration", "fwd_iat_mean": "Fwd IAT Mean", "fwd_iat_std": "Fwd IAT Std", "bwd_iat_mean": "Bwd IAT Mean", "bwd_iat_std": "Bwd IAT Std"}
    raw = _frame(["NORMAL", "DDoS"])
    for feature, alias in aliases.items():
        source = {"duration": "Flow Duration", "fwd_iat_mean": "Fwd IAT Mean"}.get(feature, feature)
        raw = raw.rename(columns={source: alias})
        raw[alias] = [1000000, 2000000]
    raw.to_csv(tmp_path / "raw.CSV", index=False)
    converted, _, _ = ingest_dataset(tmp_path / "raw.CSV")
    assert all(set(converted[feature]) == {1.0, 2.0} for feature in aliases)
    canonical = _frame(["NORMAL", "DDoS"])
    for feature in aliases:
        source = {"duration": "Flow Duration", "fwd_iat_mean": "Fwd IAT Mean"}.get(feature, feature)
        if source in canonical.columns:
            canonical = canonical.rename(columns={source: feature})
        canonical[feature] = [1000000, 2000000]
    canonical.to_csv(tmp_path / "canonical.csv", index=False)
    unchanged, _, _ = ingest_dataset(tmp_path / "canonical.csv")
    assert all(set(unchanged[feature]) == {1000000, 2000000} for feature in aliases)


def test_per_file_minimum_coverage(tmp_path):
    good = _frame(["NORMAL", "DDoS"])
    bad = pd.DataFrame({"Flow Duration": [1], "Label": ["NORMAL"]})
    good.to_csv(tmp_path / "good.csv", index=False)
    bad.to_csv(tmp_path / "bad.csv", index=False)
    with pytest.raises(ValueError, match="bad.csv"):
        ingest_dataset(tmp_path)


def test_bounded_training_artifacts(tmp_path, monkeypatch):
    monkeypatch.setattr(trainer, "LGBMClassifier", PickleFakeClassifier)
    fsync_calls = []
    original_fsync = trainer._fsync_path
    def track_fsync(path, directory=False):
        fsync_calls.append((str(path), directory))
        return original_fsync(path, directory)
    monkeypatch.setattr(trainer, "_fsync_path", track_fsync)
    labels = ["NORMAL"] * 6 + ["DDoS"] * 6
    frame = _frame(labels)
    frame["Flow Duration"] = list(range(len(frame)))
    frame.to_csv(tmp_path / "train.csv", index=False)
    output = tmp_path / "models"
    trainer.train_models(str(tmp_path), str(output), validation_split=0.25)
    artifact_dir = trainer.Path(resolve_model_artifact_dir(str(output)))
    assert (output / "active_model.json").exists()
    assert artifact_dir.parent == output / "versions"
    for name in ("anomaly_detector.pkl", "attack_classifier.pkl", "feature_names.json", "model_profile.json", "model_metadata.json"):
        assert (artifact_dir / name).exists()
    metadata = __import__("json").loads((artifact_dir / "model_metadata.json").read_text())
    assert metadata["dataset_rows"] == 12
    assert metadata["class_distribution"]["NORMAL"] == 6
    engine = MLEngine(model_dir=str(output), enabled=True)
    assert engine.model_loaded is True
    assert engine.version == metadata["version"]
    assert {trainer.Path(path).name for path, directory in fsync_calls if not directory} >= set(trainer.MANAGED_ARTIFACTS)


def test_chunked_cap_is_deterministic_and_reports_counts(tmp_path):
    labels = ["BENIGN"] * 7 + ["DDoS attacks-LOIC-HTTP"] * 7
    frame = _frame(labels)
    frame["Flow Duration"] = list(range(len(frame)))
    frame.to_csv(tmp_path / "many.csv", index=False)
    first_x, first_y, first_report = ingest_dataset(tmp_path, max_rows_per_class=3, chunksize=2)
    second_x, second_y, second_report = ingest_dataset(tmp_path, max_rows_per_class=3, chunksize=5)
    assert first_y.value_counts().to_dict() == {"NORMAL": 3, "DDoS": 3}
    assert first_x.equals(second_x)
    assert first_y.tolist() == second_y.tolist()
    assert first_report["source_rows"] == 14
    assert first_report["valid_pre_sample_rows"] == 14
    assert first_report["per_class_seen"] == {"NORMAL": 7, "DDoS": 7}
    assert first_report["per_class_retained"] == {"NORMAL": 3, "DDoS": 3}
    assert first_report["not_retained_rows"] == 8
    assert first_report["chunksize"] == 2
    assert first_report["sampling_applied"] is True
    assert second_report["retained_rows"] == 6


def test_zero_cap_keeps_all_unique_rows(tmp_path):
    frame = _frame(["BENIGN", "BENIGN", "DDoS attacks-LOIC-HTTP", "DDoS attacks-LOIC-HTTP"])
    frame["Flow Duration"] = [1, 1, 2, 3]
    frame.to_csv(tmp_path / "full.csv", index=False)
    _, labels, report = ingest_dataset(tmp_path, max_rows_per_class=0, chunksize=1)
    assert len(labels) == 3
    assert report["sampling_applied"] is False
    assert report["deduplicated_rows"] == 1
    assert report["not_retained_rows"] == 0


def test_failed_staging_validation_keeps_live_artifacts(tmp_path, monkeypatch):
    output = tmp_path / "models"
    output.mkdir()
    (output / "sentinel.txt").write_text("old")
    for name in trainer.MANAGED_ARTIFACTS:
        (output / name).write_text("old")
    frame = _frame(["BENIGN"] * 4 + ["DDoS attacks-LOIC-HTTP"] * 4)
    frame["Flow Duration"] = list(range(len(frame)))
    frame.to_csv(tmp_path / "train.csv", index=False)
    monkeypatch.setattr(trainer, "LGBMClassifier", PickleFakeClassifier)
    monkeypatch.setattr(trainer, "_validate_artifact_set", lambda _: (_ for _ in ()).throw(ValueError("broken stage")))
    with pytest.raises(ValueError, match="broken stage"):
        trainer.train_models(str(tmp_path / "train.csv"), str(output), validation_split=0.25)
    assert (output / "sentinel.txt").read_text() == "old"
    assert all((output / name).read_text() == "old" for name in trainer.MANAGED_ARTIFACTS)
    assert not list(tmp_path.glob(".models.staging-*"))


def test_pointer_publish_failure_keeps_old_pointer_and_cleans_orphan(tmp_path, monkeypatch):
    output = tmp_path / "models"
    output.mkdir()
    versions = output / "versions"
    versions.mkdir()
    old = versions / "old"
    old.mkdir()
    (old / "sentinel.txt").write_text("old")
    (output / "active_model.json").write_text('{"artifact_dir": "versions/old", "version": "old"}')
    staging = versions / ".staging-test"
    staging.mkdir()
    (staging / "sentinel.txt").write_text("new")
    monkeypatch.setattr(trainer.os, "replace", lambda source, destination: (_ for _ in ()).throw(OSError("injected pointer failure")))
    with pytest.raises(OSError, match="injected pointer failure"):
        trainer._publish_artifact_set(staging, output, "new")
    assert __import__("json").loads((output / "active_model.json").read_text())["artifact_dir"] == "versions/old"
    assert (old / "sentinel.txt").read_text() == "old"
    assert not list(versions.glob("new-*"))
    assert not list(output.glob(".active-*.json"))


def test_root_fsync_failure_never_deletes_newly_active_version(tmp_path, monkeypatch):
    output = tmp_path / "models"
    output.mkdir()
    versions = output / "versions"
    versions.mkdir()
    staging = versions / ".staging-test"
    staging.mkdir()
    (staging / "sentinel.txt").write_text("new")
    original_fsync = trainer._fsync_path

    def fail_root_fsync(path, directory=False):
        if directory and trainer.Path(path).resolve() == output.resolve():
            raise OSError("injected root fsync failure")
        return original_fsync(path, directory)

    monkeypatch.setattr(trainer, "_fsync_path", fail_root_fsync)
    with pytest.raises(OSError, match="injected root fsync failure"):
        trainer._publish_artifact_set(staging, output, "new")

    pointer = __import__("json").loads((output / "active_model.json").read_text())
    active = (output / pointer["artifact_dir"]).resolve()
    assert active.is_dir()
    assert (active / "sentinel.txt").read_text() == "new"


def test_invalid_unknown_and_dedup_counts(tmp_path):
    frame = _frame(["NORMAL", "NORMAL", "DDoS", "Heartbleed"])
    frame["Flow Duration"] = [np.nan, np.nan, np.inf, 4]
    frame.to_csv(tmp_path / "counts.csv", index=False)
    features, _, report = ingest_dataset(tmp_path / "counts.csv")
    assert report["unknown_label_rows"] == 1
    assert report["invalid_numeric_values"] == 3
    assert report["deduplicated_rows"] is None
    assert report["reservoir_duplicate_rows"] == 1
    assert np.isfinite(features.to_numpy()).all()


def test_capped_duplicate_after_eviction_is_not_claimed_as_exact_dedup(tmp_path):
    frame = _frame(["BENIGN", "BENIGN", "BENIGN", "DDoS attacks-LOIC-HTTP", "DDoS attacks-LOIC-HTTP"])
    frame["Flow Duration"] = [1, 2, 1, 3, 4]
    frame.to_csv(tmp_path / "duplicates.csv", index=False)
    _, labels, report = ingest_dataset(tmp_path, max_rows_per_class=1, chunksize=1)
    assert len(labels) == 2
    assert report["deduplicated_rows"] is None
    assert report["not_retained_rows"] == report["valid_pre_sample_rows"] - report["retained_rows"]


def test_split_guard(tmp_path):
    _frame(["NORMAL", "DDoS"]).to_csv(tmp_path / "tiny.csv", index=False)
    with pytest.raises(ValueError, match="at least 2"):
        trainer.train_models(str(tmp_path / "tiny.csv"), str(tmp_path / "out"))
