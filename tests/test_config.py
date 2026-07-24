"""
Unit tests for sagedral_ml.config module.
"""

import os
import pytest
from sagedral_ml.config import Config, load_config, get_config, DEFAULT_CONFIG_DICT


def test_default_config_loading():
    config = load_config()
    assert config.get("capture", "interface") == "eth0"
    assert config.get("decision", "block_threshold") == 0.7
    assert config.get("ips", "preferred_backend") == "nftables"


def test_env_var_override(monkeypatch):
    monkeypatch.setenv("SAGEDRAL_CAPTURE_INTERFACE", "wlan0")
    monkeypatch.setenv("SAGEDRAL_DECISION_BLOCK_THRESHOLD", "0.85")
    monkeypatch.setenv("SAGEDRAL_IPS_ENABLED", "false")

    config = load_config()
    assert config.get("capture", "interface") == "wlan0"
    assert config.get("decision", "block_threshold") == 0.85
    assert config.get("ips", "enabled") is False


def test_config_validation():
    bad_data = {
        "capture": {"interface": ""},
        "ml": {"anomaly_threshold": 1.5},
        "decision": {"alert_threshold": 0.9, "block_threshold": 0.7},
        "ips": {"preferred_backend": "invalid_backend"},
    }
    cfg = Config(bad_data)
    errors = cfg.validate()
    assert len(errors) >= 3


def test_section_get():
    config = Config({"feature_extraction": {"flow_timeout": 60}})
    assert isinstance(config.get("feature_extraction"), dict)
    assert config.get("feature_extraction", {}) == {"flow_timeout": 60}
    assert config.get("non_existent", {}) == {}
