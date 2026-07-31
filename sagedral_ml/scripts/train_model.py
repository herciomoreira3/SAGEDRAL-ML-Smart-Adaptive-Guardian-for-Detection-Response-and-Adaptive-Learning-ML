"""Train SAGEDRAL models from canonical or CICIDS flow CSV files."""

import argparse
import json
import logging
import os
import re
import tempfile
import time
import uuid
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.metrics import accuracy_score, f1_score
from sklearn.model_selection import train_test_split

from sagedral_ml.detection.ml_engine import FEATURE_NAMES

logger = logging.getLogger("sagedral_ml.scripts.train")
MIN_FEATURE_COVERAGE = 20
TIME_FEATURES = ("duration", "fwd_iat_mean", "fwd_iat_std", "bwd_iat_mean", "bwd_iat_std")


def _normalize_header(value):
    value = str(value).replace("\ufeff", "").strip().lower()
    return re.sub(r"[^a-z0-9]+", "", value)


def _is_canonical_header(raw_name, feature):
    """Canonical columns are exact snake_case names (aside from BOM/space)."""
    return str(raw_name).replace("\ufeff", "").strip().lower() == feature


_ALIASES = {
    "duration": ("flow duration",),
    "total_fwd_packets": ("total fwd packets", "tot fwd pkts"),
    "total_bwd_packets": ("total backward packets", "total bwd packets", "tot bwd pkts"),
    "total_fwd_bytes": ("total length of fwd packets", "totlen fwd pkts"),
    "total_bwd_bytes": ("total length of bwd packets", "totlen bwd pkts"),
    "fwd_packet_len_mean": ("fwd packet length mean", "fwd pkt len mean"),
    "fwd_packet_len_std": ("fwd packet length std", "fwd pkt len std"),
    "bwd_packet_len_mean": ("bwd packet length mean", "bwd pkt len mean"),
    "bwd_packet_len_std": ("bwd packet length std", "bwd pkt len std"),
    "flow_bytes_per_sec": ("flow bytes/s", "flow bytes s"),
    "flow_packets_per_sec": ("flow packets/s", "flow pkts/s"),
    "fwd_iat_mean": ("fwd iat mean",),
    "fwd_iat_std": ("fwd iat std",),
    "bwd_iat_mean": ("bwd iat mean",),
    "bwd_iat_std": ("bwd iat std",),
    "psh_flag_count": ("psh flag count", "psh flag cnt"),
    "urg_flag_count": ("urg flag count", "urg flag cnt"),
    "syn_flag_count": ("syn flag count", "syn flag cnt"),
    "fin_flag_count": ("fin flag count", "fin flag cnt"),
    "rst_flag_count": ("rst flag count", "rst flag cnt"),
    "ack_flag_count": ("ack flag count", "ack flag cnt"),
    "avg_fwd_segment_size": ("avg fwd segment size", "fwd seg size avg"),
    "avg_bwd_segment_size": ("avg bwd segment size", "bwd seg size avg"),
    "fwd_header_len": ("fwd header length", "fwd header len"),
    "bwd_header_len": ("bwd header length", "bwd header len"),
    "down_up_ratio": ("down/up ratio", "down up ratio"),
    "protocol": ("protocol",),
    "dst_port": ("destination port", "dst port"),
}
_ALIAS_TO_FEATURE = {_normalize_header(name): name for name in FEATURE_NAMES}
for _feature, _aliases in _ALIASES.items():
    for _alias in _aliases:
        _ALIAS_TO_FEATURE[_normalize_header(_alias)] = _feature
_LABEL_HEADERS = {_normalize_header(name) for name in ("label", "attack_type", "attack type", "attacklabel")}
MANAGED_ARTIFACTS = (
    "anomaly_detector.pkl", "attack_classifier.pkl", "feature_names.json",
    "model_profile.json", "model_metadata.json",
)


def _dataset_files(dataset_path):
    path = Path(dataset_path)
    if path.is_file():
        return [path] if path.suffix.lower() == ".csv" else []
    if path.is_dir():
        return sorted((item for item in path.rglob("*") if item.is_file() and item.suffix.lower() == ".csv"), key=lambda item: str(item).lower())
    return []


def _map_label(value):
    text = str(value).strip().upper().replace("–", "-").replace("—", "-")
    text = re.sub(r"[^A-Z0-9]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    canonical = {"NORMAL", "DDOS", "PORTSCAN", "BRUTEFORCE", "DOS SLOWLORIS", "WEBATTACK", "BOTNET", "INFILTRATION", "EXFILTRATION"}
    if text in canonical:
        return {"NORMAL": "NORMAL", "DDOS": "DDoS", "PORTSCAN": "PortScan", "BRUTEFORCE": "BruteForce", "DOS SLOWLORIS": "DoS_Slowloris", "WEBATTACK": "WebAttack", "BOTNET": "Botnet", "INFILTRATION": "Infiltration", "EXFILTRATION": "Exfiltration"}[text]
    if text in ("BENIGN", "NORMAL"):
        return "NORMAL"
    if "DDOS" in text.replace(" ", ""):
        return "DDoS"
    if any(token in text for token in ("WEB ATTACK", "WEB BRUTE", "XSS", "SQL INJECTION")) or ("BRUTE FORCE" in text and any(token in text for token in ("WEB", "XSS"))):
        return "WebAttack"
    if any(token in text for token in ("FTP-PATATOR", "SSH-PATATOR", "BRUTE FORCE", "BRUTEFORCE", "PATATOR")):
        return "BruteForce"
    if "PORTSCAN" in text.replace(" ", "") or "PORT SCAN" in text:
        return "PortScan"
    if "BOT" in text:
        return "Botnet"
    if "INFILTRATION" in text:
        return "Infiltration"
    if "INFILTERATION" in text:
        return "Infiltration"
    if "EXFILTRATION" in text:
        return "Exfiltration"
    if any(token in text for token in ("DOS HULK", "DOS GOLDENEYE", "DOS SLOWHTTPTEST", "DOS SLOWLORIS", "DOS ATTACKS HULK", "DOS ATTACKS GOLDENEYE", "DOS ATTACKS SLOWHTTPTEST", "DOS ATTACKS SLOWLORIS")):
        return "DoS_Slowloris"
    return None


def _resolve_columns(columns):
    mapping = {}
    for column in columns:
        normalized = _normalize_header(column)
        if normalized in _LABEL_HEADERS:
            mapping.setdefault("__label__", column)
        elif normalized in _ALIAS_TO_FEATURE:
            mapping.setdefault(_ALIAS_TO_FEATURE[normalized], column)
    return mapping


def ingest_dataset(dataset_path, max_rows_per_class=100000, chunksize=100000):
    """Read CICIDS files one chunk at a time, retaining deterministic class samples."""
    if int(max_rows_per_class) < 0:
        raise ValueError("max_rows_per_class must be zero or greater")
    if int(chunksize) <= 0:
        raise ValueError("chunksize must be positive")
    files = _dataset_files(dataset_path)
    if not files:
        raise ValueError("No CSV files found in --dataset path")
    root = Path(dataset_path) if Path(dataset_path).is_dir() else None
    # In capped mode this is the only corpus-sized state: at most cap rows/class.
    retained = {}
    frames = []  # Full-corpus mode is explicit and intentionally memory hungry.
    source_formats = set()
    union_missing = set()
    source_rows = 0
    unknown_labels = 0
    invalid_numeric = 0
    deduplicated_rows = 0
    valid_rows = 0
    per_class_seen = {}
    file_metadata = []
    for file_path in files:
        header = pd.read_csv(file_path, encoding="utf-8-sig", nrows=0)
        mapping = _resolve_columns(header.columns)
        if "__label__" not in mapping:
            raise ValueError("%s has no Label or attack_type column" % file_path.name)
        missing = set(FEATURE_NAMES) - set(mapping)
        coverage = len(FEATURE_NAMES) - len(missing)
        if coverage < MIN_FEATURE_COVERAGE:
            raise ValueError("%s matched only %d/%d features; minimum is %d" % (file_path.name, coverage, len(FEATURE_NAMES), MIN_FEATURE_COVERAGE))
        union_missing.update(missing)
        selected = list(dict.fromkeys([mapping[name] for name in FEATURE_NAMES if name in mapping] + [mapping["__label__"]]))
        converted = []
        for feature in TIME_FEATURES:
            if feature in mapping and not _is_canonical_header(mapping[feature], feature):
                converted.append(feature)
        source_formats.add("CICFlowMeter" if converted else "canonical")
        file_metadata.append({"name": str(file_path.relative_to(root)) if root else file_path.name, "feature_coverage": coverage, "missing_features": sorted(missing), "time_converted_features": converted})
        file_rows = 0
        # Header was read above, so only required source columns are decoded here.
        for raw in pd.read_csv(file_path, encoding="utf-8-sig", usecols=selected, chunksize=int(chunksize)):
            source_rows += len(raw)
            file_rows += len(raw)
            output = pd.DataFrame(index=raw.index)
            for feature in FEATURE_NAMES:
                if feature not in mapping:
                    output[feature] = np.float32(0.0)
                    continue
                values = pd.to_numeric(raw[mapping[feature]], errors="coerce")
                if feature in TIME_FEATURES and feature in converted:
                    values = values / 1000000.0
                invalid_numeric += int((values.isna() | ~np.isfinite(values)).sum())
                output[feature] = values.replace([np.inf, -np.inf], np.nan).fillna(0.0).astype(np.float32)
            labels = raw[mapping["__label__"]].map(_map_label)
            unknown_labels += int(labels.isna().sum())
            output["label"] = labels
            output = output[labels.notna()].copy()
            valid_rows += len(output)
            for name, count in output["label"].value_counts().items():
                per_class_seen[name] = per_class_seen.get(name, 0) + int(count)
            if not int(max_rows_per_class):
                frames.append(output)
                continue
            # Stable values make top-N independent of chunk boundaries and source order.
            output["__priority__"] = pd.util.hash_pandas_object(output[FEATURE_NAMES + ["label"]], index=False).astype("uint64")
            for label, group in output.groupby("label", sort=False):
                prior = retained.get(label)
                candidates = group if prior is None else pd.concat((prior, group), ignore_index=True)
                before = len(candidates)
                candidates = candidates.drop_duplicates(subset=FEATURE_NAMES + ["label"])
                deduplicated_rows += before - len(candidates)
                retained[label] = candidates.nsmallest(int(max_rows_per_class), "__priority__", keep="first").reset_index(drop=True)
        file_metadata[-1]["source_rows"] = file_rows
    sampled = bool(int(max_rows_per_class))
    if sampled:
        data = pd.concat([retained[name] for name in sorted(retained)], ignore_index=True) if retained else pd.DataFrame()
        if not data.empty:
            data = data.drop(columns=["__priority__"])
    else:
        logger.warning("max_rows_per_class=0: accumulating the full corpus in memory")
        data = pd.concat(frames, ignore_index=True)
        before_dedup = len(data)
        data = data.drop_duplicates(subset=FEATURE_NAMES + ["label"]).reset_index(drop=True)
        deduplicated_rows = before_dedup - len(data)
    if union_missing:
        logger.warning("Unavailable features filled with zero: %s", ", ".join(sorted(union_missing)))
    if unknown_labels:
        logger.warning("Dropped %d rows with unsupported labels", unknown_labels)
    if invalid_numeric:
        logger.warning("Replaced %d invalid numeric values with zero", invalid_numeric)
    if len(data) == 0 or data["label"].nunique() < 2 or "NORMAL" not in set(data["label"]):
        raise ValueError("Need usable rows with at least two classes including NORMAL")
    retained_counts = {name: int(count) for name, count in data["label"].value_counts().items()}
    report = {"files": [item["name"] for item in file_metadata], "file_count": len(files), "file_details": file_metadata, "source_rows": source_rows, "rows_seen": source_rows, "valid_pre_sample_rows": valid_rows, "retained_rows": len(data), "sample_counts": retained_counts, "per_class_seen": per_class_seen, "per_class_retained": retained_counts, "dropped_rows": source_rows - len(data), "deduplicated_rows": None if sampled else deduplicated_rows, "reservoir_duplicate_rows": deduplicated_rows if sampled else 0, "not_retained_rows": valid_rows - len(data) if sampled else 0, "unknown_label_rows": unknown_labels, "dropped_unknown_labels": unknown_labels, "invalid_numeric_values": invalid_numeric, "feature_coverage": len(FEATURE_NAMES) - len(union_missing), "missing_features": sorted(union_missing), "source_format": "+".join(sorted(source_formats)), "time_unit_normalization": "CICFlowMeter duration/IAT aliases divide microseconds by 1e6; canonical columns unchanged", "chunksize": int(chunksize), "max_rows_per_class": int(max_rows_per_class), "sampling_applied": sampled}
    return data[FEATURE_NAMES], data["label"], report


def _validate_artifact_set(directory):
    """Reject incomplete or unreadable staged artifacts before they become live."""
    directory = Path(directory)
    for name in ("anomaly_detector.pkl", "attack_classifier.pkl"):
        joblib.load(str(directory / name))
    loaded = {}
    for name in ("feature_names.json", "model_profile.json", "model_metadata.json"):
        with open(str(directory / name), "r", encoding="utf-8") as handle:
            loaded[name] = json.load(handle)
    if loaded["feature_names.json"] != list(FEATURE_NAMES):
        raise ValueError("staged feature_names.json does not match runtime features")
    for key in ("dataset_rows", "class_distribution", "version", "trained_at"):
        if key not in loaded["model_metadata.json"]:
            raise ValueError("staged metadata is missing %s" % key)


def _fsync_path(path, directory=False):
    """Durability barrier where supported; Windows does not fsync directories."""
    if os.name == "nt" and directory:
        return
    # Regular files are opened writable because fsync/_commit may reject a
    # read-only descriptor. Directories use the POSIX read-only directory fd.
    flags = os.O_RDONLY if directory else os.O_RDWR
    if os.name == "nt" and hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if directory and hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(str(path), flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish_artifact_set(staging_dir, output_dir, version):
    """Publish immutable version then atomically advance the root pointer."""
    staging_dir = Path(staging_dir).resolve()
    output_dir = Path(output_dir).expanduser().resolve()
    if output_dir == output_dir.parent:
        raise ValueError("output directory must not be a filesystem root")
    versions = (output_dir / "versions").resolve()
    if versions.parent != output_dir or staging_dir.parent != versions or not staging_dir.is_dir():
        raise ValueError("staging directory must be contained directly in output_root/versions")
    final_dir = versions / ("%s-%s" % (str(version).replace(os.sep, "_"), uuid.uuid4().hex))
    pointer = output_dir / "active_model.json"
    pointer_temp = None
    published = False
    try:
        os.rename(str(staging_dir), str(final_dir))
        _fsync_path(versions, directory=True)
        relative = os.path.relpath(str(final_dir), str(output_dir))
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=str(output_dir), prefix=".active-", suffix=".json", delete=False) as handle:
            pointer_temp = Path(handle.name)
            json.dump({"artifact_dir": relative, "version": version}, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(str(pointer_temp), str(pointer))
        pointer_temp = None
        # From this point the new version may already be active. Never delete it,
        # even if the directory durability barrier below reports a failure.
        published = True
        _fsync_path(output_dir, directory=True)
    except Exception:
        if pointer_temp is not None and pointer_temp.exists():
            pointer_temp.unlink()
        if final_dir.exists() and not published:
            import shutil
            shutil.rmtree(str(final_dir), ignore_errors=True)
        raise
    return final_dir


def train_models(dataset_path, output_dir, validation_split=0.2, max_rows_per_class=100000, chunksize=100000):
    if not 0.05 <= float(validation_split) <= 0.5:
        raise ValueError("validation_split must be between 0.05 and 0.5")
    X, y, report = ingest_dataset(dataset_path, max_rows_per_class=max_rows_per_class, chunksize=chunksize)
    counts = y.value_counts()
    if (counts < 2).any():
        raise ValueError("Each retained class needs at least 2 rows for stratification: %s" % counts.to_dict())
    validation_rows = int(np.ceil(len(y) * float(validation_split)))
    if validation_rows < y.nunique() or len(y) - validation_rows < y.nunique():
        raise ValueError("validation_split leaves too few rows for every retained class; add samples or adjust split")
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=float(validation_split), random_state=42, stratify=y)
    binary_train = y_train != "NORMAL"
    binary_val = y_val != "NORMAL"
    logger.info("Dataset rows: %d; class distribution: %s", len(y), y.value_counts().to_dict())
    logger.info("Training on %d rows; holdout validation has %d rows", len(X_train), len(X_val))
    anomaly = LGBMClassifier(n_estimators=100, learning_rate=0.05, num_leaves=31, random_state=42, verbosity=-1).fit(X_train, binary_train)
    classifier = LGBMClassifier(n_estimators=100, learning_rate=0.05, num_leaves=31, random_state=42, verbosity=-1).fit(X_train, y_train)
    anomaly_pred = anomaly.predict(X_val)
    anomaly_accuracy = accuracy_score(binary_val, anomaly_pred)
    try:
        anomaly_f1 = f1_score(binary_val, anomaly_pred, zero_division=0)
    except TypeError:
        anomaly_f1 = f1_score(binary_val, anomaly_pred)
    classifier_accuracy = accuracy_score(y_val, classifier.predict(X_val))
    logger.info("Stage metrics: anomaly accuracy=%.4f f1=%.4f classifier accuracy=%.4f", anomaly_accuracy, anomaly_f1, classifier_accuracy)
    output_path = Path(output_dir).expanduser().resolve()
    if output_path == output_path.parent:
        raise ValueError("output directory must not be a filesystem root")
    output_path.mkdir(parents=True, exist_ok=True)
    versions_path = (output_path / "versions").resolve()
    if versions_path.parent != output_path:
        raise ValueError("versions directory escapes output root")
    versions_path.mkdir(exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=str(versions_path))).resolve()
    try:
        joblib.dump(anomaly, str(staging / "anomaly_detector.pkl"))
        joblib.dump(classifier, str(staging / "attack_classifier.pkl"))
        with open(str(staging / "feature_names.json"), "w", encoding="utf-8") as handle:
            json.dump(FEATURE_NAMES, handle, indent=2)
        normal = X[y == "NORMAL"]
        with open(str(staging / "model_profile.json"), "w", encoding="utf-8") as handle:
            json.dump({"feature_mean": {name: float(normal[name].mean()) for name in FEATURE_NAMES}, "feature_std": {name: float(normal[name].std(ddof=0) or 0.0) for name in FEATURE_NAMES}, "normal_sample_count": int(len(normal)), "generated_at": time.time()}, handle, indent=2)
        version = "1.0.%d" % int(time.time())
        report.update({"dataset_rows": len(X), "class_distribution": {name: int(count) for name, count in y.value_counts().items()}, "validation_split": float(validation_split), "split_strategy": "stratified_random", "random_state": 42, "validation_caveat": "Holdout validation is not cross-day or production accuracy.", "anomaly_accuracy": float(anomaly_accuracy), "anomaly_f1": float(anomaly_f1), "classifier_accuracy": float(classifier_accuracy), "version": version, "trained_at": time.time()})
        with open(str(staging / "model_metadata.json"), "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
        for name in MANAGED_ARTIFACTS:
            _fsync_path(staging / name)
        _fsync_path(staging, directory=True)
        _validate_artifact_set(staging)
        _publish_artifact_set(staging, output_path, version)
    except Exception:
        if staging.exists():
            import shutil
            shutil.rmtree(str(staging), ignore_errors=True)
        raise
    logger.info("Models successfully saved to %s", output_dir)
    return {"version": version, "anomaly_accuracy": float(anomaly_accuracy), "anomaly_f1": float(anomaly_f1), "classifier_accuracy": float(classifier_accuracy)}


def main():
    parser = argparse.ArgumentParser(description="Train SAGEDRAL-ML LightGBM models")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--output-dir", default="/var/lib/sagedral-ml/models")
    parser.add_argument("--validation-split", type=float, default=0.2)
    parser.add_argument("--max-rows-per-class", type=int, default=100000)
    args = parser.parse_args()
    train_models(args.dataset, args.output_dir, args.validation_split, args.max_rows_per_class)


if __name__ == "__main__":
    main()
