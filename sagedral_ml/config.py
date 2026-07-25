"""
Configuration manager for SAGEDRAL-ML system.
Loads TOML configuration files, handles environment variable overrides,
validates config schemas, and exports default config templates.
"""

import os
import sys
import logging
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

import tomli as _tomli

import tomli_w

logger = logging.getLogger("sagedral_ml.config")

DEFAULT_CONFIG_PATH = Path("/etc/sagedral/config.toml")
USER_CONFIG_PATH = Path.home() / ".config" / "sagedral" / "config.toml"

DEFAULT_CONFIG_DICT: Dict[str, Any] = {
    "general": {
        "log_level": "INFO",
        "log_file": "/var/log/sagedral-ml.log",
        "data_dir": "/var/lib/sagedral-ml",
    },
    "capture": {
        "interface": "",                        # KOSONG = auto-detect (recommended).
                                                # Auto-select prefer bridged / physical non-NAT
                                                # interface (penalize 10.0.2.0/24 VirtualBox NAT).
                                                # Isi manual: misal "eth1", "wlan0", "enp0s8" etc.
        "bpf_filter": "",
        "promiscuous": True,
        "queue_maxsize": 10000,
    },
    "feature_extraction": {
        "flow_timeout": 60,
        "max_packets_per_flow": 1000,
    },
    "signature": {
        "enabled": True,
        "custom_rules_file": "",
        "disabled_rules": [],
    },
    "ml": {
        "enabled": True,
        "anomaly_threshold": 0.7,
        "classifier_threshold": 0.6,
        "model_dir": "/var/lib/sagedral-ml/models",
        "retrain_on_startup": False,
    },
    "decision": {
        "alert_threshold": 0.5,
        "block_threshold": 0.7,
        "weight_signature": 0.4,
        "weight_ml": 0.6,
        "dedup_window": 300,
    },
    "ips": {
        "enabled": True,
        "preferred_backend": "nftables",
        "auto_unblock_after": 3600,
        "whitelist": ["127.0.0.1", "::1"],
    },
    "api": {
        "host": "0.0.0.0",
        "port": 8000,
        "cors_origins": ["http://localhost:5173", "http://localhost:3000"],
    },
    "database": {
        "path": "/var/lib/sagedral-ml/sagedral.db",
        "retention_days_alerts": 30,
        "retention_days_traffic": 7,
    },
}


class ConfigError(Exception):
    """Exception raised for errors in configuration."""
    pass


def generate_default_toml_string() -> str:
    """Generate default TOML configuration string with comments."""
    return """# SAGEDRAL-ML System Configuration File
# Version 1.0.0

[general]
log_level = "INFO"                      # DEBUG, INFO, WARNING, ERROR, CRITICAL
log_file = "/var/log/sagedral-ml.log"
data_dir = "/var/lib/sagedral-ml"

[capture]
interface = ""                          # "" = auto-detect interface (RECOMMENDED).
                                        # Auto-detect heuristic: choose non-10.0.2.0/24
                                        # (skips VirtualBox NAT eth0 10.0.2.15) so it
                                        # prefers eth1 / enp0s8 (Bridged).
                                        # Override manual: "eth1", "wlan0", "enp0s8" etc.
bpf_filter = ""                         # BPF filter string (e.g., "tcp port 80 or udp")
promiscuous = true
queue_maxsize = 10000

[feature_extraction]
flow_timeout = 60                       # Seconds before flow is considered completed
max_packets_per_flow = 1000            # Max packets per flow

[signature]
enabled = true
custom_rules_file = ""                  # Optional path to custom Python rules file
disabled_rules = []                     # List of rule IDs to disable (e.g. ["SIG-002"])

[ml]
enabled = true
anomaly_threshold = 0.7                 # Score >= threshold indicates anomaly (0.0 - 1.0)
classifier_threshold = 0.6             # Minimum confidence for multiclass classifier
model_dir = "/var/lib/sagedral-ml/models"
retrain_on_startup = false

[decision]
alert_threshold = 0.5                   # Score >= threshold generates alert
block_threshold = 0.7                   # Score >= threshold triggers IPS block
weight_signature = 0.4
weight_ml = 0.6
dedup_window = 300                      # Seconds to suppress duplicate alerts per IP

[ips]
enabled = true
preferred_backend = "nftables"          # "nftables" or "iptables"
auto_unblock_after = 3600               # Seconds before auto-unblocking IP (0 = permanent)
whitelist = [
    "127.0.0.1",
    "::1",
]

[api]
host = "0.0.0.0"
port = 8000
cors_origins = ["http://localhost:5173", "http://localhost:3000"]

[database]
path = "/var/lib/sagedral-ml/sagedral.db"
retention_days_alerts = 30
retention_days_traffic = 7
"""


class Config:
    """System configuration container."""

    def __init__(self, data: Dict[str, Any]):
        self._data = data

    @property
    def data(self) -> Dict[str, Any]:
        return self._data

    def get(self, section: str, key: Any = None, default: Any = None) -> Any:
        if key is None:
            return self._data.get(section, {})
        if not isinstance(key, str):
            return self._data.get(section, key)
        sec_data = self._data.get(section, {})
        if isinstance(sec_data, dict):
            return sec_data.get(key, default)
        return default

    def to_dict(self) -> Dict[str, Any]:
        return self._data

    def validate(self) -> List[str]:
        """Validate configuration values and return list of validation error messages."""
        errors = []
        capture_iface = self.get("capture", "interface", "")
        if not capture_iface:
            errors.append("capture.interface required and cannot be empty")

        anomaly_th = self.get("ml", "anomaly_threshold", 0.7)
        if not (0.0 <= float(anomaly_th) <= 1.0):
            errors.append("ml.anomaly_threshold must be between 0.0 and 1.0")

        block_th = self.get("decision", "block_threshold", 0.7)
        if not (0.0 <= float(block_th) <= 1.0):
            errors.append("decision.block_threshold must be between 0.0 and 1.0")

        alert_th = self.get("decision", "alert_threshold", 0.5)
        if not (0.0 <= float(alert_th) <= 1.0):
            errors.append("decision.alert_threshold must be between 0.0 and 1.0")

        if float(alert_th) > float(block_th):
            errors.append("decision.alert_threshold cannot be greater than decision.block_threshold")

        backend = self.get("ips", "preferred_backend", "nftables")
        if backend not in ("nftables", "iptables"):
            errors.append("ips.preferred_backend must be 'nftables' or 'iptables'")

        return errors


_config_instance: Optional[Config] = None


def _deep_update(base: Dict[str, Any], update: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively update nested dict."""
    for key, value in update.items():
        if isinstance(value, dict) and key in base and isinstance(base[key], dict):
            _deep_update(base[key], value)
        else:
            base[key] = value
    return base


def load_config(custom_path: Optional[str] = None) -> Config:
    """
    Load configuration from TOML file, override with environment variables,
    and return Config object.
    """
    global _config_instance

    config_dict = getattr(sys, "_sagedral_base_config", None)
    if config_dict is None:
        import copy
        config_dict = copy.deepcopy(DEFAULT_CONFIG_DICT)

    config_file_path: Optional[Path] = None

    if custom_path:
        config_file_path = Path(custom_path)
    elif USER_CONFIG_PATH.exists():
        config_file_path = USER_CONFIG_PATH
    elif DEFAULT_CONFIG_PATH.exists():
        config_file_path = DEFAULT_CONFIG_PATH

    if config_file_path and config_file_path.exists():
        try:
            with open(config_file_path, "rb") as f:
                loaded = _tomli.load(f)
                _deep_update(config_dict, loaded)
                logger.info(f"Loaded configuration from {config_file_path}")
        except Exception as e:
            logger.warning(f"Failed to load config file {config_file_path}: {e}")

    # Override with Environment Variables: SAGEDRAL_<SECTION>_<KEY>=value
    for env_var, val in os.environ.items():
        if env_var.startswith("SAGEDRAL_"):
            parts = env_var[9:].lower().split("_", 1)
            if len(parts) == 2:
                sec, key = parts[0], parts[1]
                if sec in config_dict:
                    # Convert types
                    current_val = config_dict[sec].get(key)
                    if isinstance(current_val, bool):
                        config_dict[sec][key] = val.lower() in ("true", "1", "yes")
                    elif isinstance(current_val, int):
                        try:
                            config_dict[sec][key] = int(val)
                        except ValueError:
                            pass
                    elif isinstance(current_val, float):
                        try:
                            config_dict[sec][key] = float(val)
                        except ValueError:
                            pass
                    elif isinstance(current_val, list):
                        config_dict[sec][key] = [x.strip() for x in val.split(",")]
                    else:
                        config_dict[sec][key] = val

    _config_instance = Config(config_dict)
    return _config_instance


def get_config() -> Config:
    """Get global Config instance."""
    global _config_instance
    if _config_instance is None:
        _config_instance = load_config()
    return _config_instance
