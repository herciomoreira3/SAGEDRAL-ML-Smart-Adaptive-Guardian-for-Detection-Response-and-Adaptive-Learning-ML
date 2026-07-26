"""
Unit tests for sagedral_ml.config module.
"""

import os
from pathlib import Path

import pytest
from sagedral_ml.config import (
    Config,
    ConfigError,
    load_config,
    get_config,
    DEFAULT_CONFIG_DICT,
)
import sagedral_ml.config as config_module


@pytest.fixture(autouse=True)
def preserve_global_config():
    """Unit config loads must not replace the session-wide API test config."""
    previous = config_module._config_instance
    yield
    config_module._config_instance = previous


def test_default_config_loading():
    config = load_config()
    assert config.get("capture", "interface") == ""
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


def test_explicit_service_config_path(monkeypatch, tmp_path):
    config_path = tmp_path / "service-config.toml"
    config_path.write_text(
        '[capture]\ninterface = "enp0s8"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("SAGEDRAL_CONFIG_PATH", str(config_path))

    config = load_config()

    assert config.get("capture", "interface") == "enp0s8"
    assert config.last_loaded_path == str(config_path)


def test_missing_explicit_service_config_fails_clearly(monkeypatch, tmp_path):
    missing_path = tmp_path / "missing.toml"
    monkeypatch.setenv("SAGEDRAL_CONFIG_PATH", str(missing_path))

    with pytest.raises(ConfigError, match="SAGEDRAL_CONFIG_PATH does not exist"):
        load_config()


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


def test_systemd_service_has_deterministic_runtime_paths():
    root = Path(__file__).resolve().parents[1]
    service = (root / "systemd" / "sagedral-ml.service").read_text(
        encoding="utf-8"
    )

    assert "Environment=HOME=/var/lib/sagedral-ml" in service
    assert (
        "Environment=SAGEDRAL_CONFIG_PATH=/etc/sagedral/config.toml"
        in service
    )
    assert "User=sagedral" in service
    assert "ReadWritePaths=/etc/sagedral /var/lib/sagedral-ml" in service


def test_installer_repairs_service_permissions():
    root = Path(__file__).resolve().parents[1]
    installer = (root / "scripts" / "install.sh").read_text(encoding="utf-8")

    assert "chmod 2770 /etc/sagedral" in installer
    assert "chown root:sagedral /etc/sagedral/config.toml" in installer
    assert "chown -R sagedral:sagedral /var/lib/sagedral-ml" in installer
