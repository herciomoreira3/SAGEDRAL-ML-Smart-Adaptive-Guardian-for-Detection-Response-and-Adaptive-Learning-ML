"""
Configuration manager for SAGEDRAL-ML system.
Loads TOML configuration files, handles environment variable overrides,
validates config schemas, and exports default config templates.
"""

import os
import sys
import shutil
import logging
import copy
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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
        "backend": "scapy",
        "watchdog_idle_seconds": 30,
    },
    "feature_extraction": {
        "flow_timeout": 60,
        "max_packets_per_flow": 1000,
        "max_active_flows": 50000,
    },
    "signature": {
        "enabled": True,
        "custom_rules_file": "",
        "custom_rules_dir": "/var/lib/sagedral-ml/custom-rules",
        "disabled_rules": [],
        "params": {},
        "whitelist_overrides": {},
    },
    "ml": {
        "enabled": True,
        "anomaly_threshold": 0.7,
        "classifier_threshold": 0.6,
        "model_dir": "/var/lib/sagedral-ml/models",
        "retrain_on_startup": False,
        "batch_size": 32,
        "batch_timeout_ms": 50,
        "drift_enabled": True,
        "drift_window_size": 100,
        "drift_psi_threshold": 0.25,
        "feedback_retrain_minimum": 20,
        "feedback_retrain_interval_hours": 24,
        "adaptive_learning_enabled": True,
        "adaptive_min_accuracy": 0.70,
        "adaptive_min_f1": 0.65,
        "adaptive_min_classifier_accuracy": 0.65,
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
        "whitelist_notes": {},
        "strike_escalation_enabled": True,
        "rate_limit_enabled": False,
        "rate_limit_connections": 100,
        "rate_limit_window_seconds": 60,
        "rate_limit_block_seconds": 300,
    },
    "api": {
        "host": "0.0.0.0",
        "port": 8000,
        "cors_origins": ["http://localhost:5173", "http://localhost:3000"],
        "trusted_proxies": ["127.0.0.1", "::1"],
        "csp_enabled": True,
        "metrics_enabled": True,
        "global_rate_limit_per_minute": 600,
    },
    "database": {
        "backend": "sqlite",
        "connection_string": "",
        "path": "/var/lib/sagedral-ml/sagedral.db",
        "retention_days_alerts": 30,
        "retention_days_traffic": 7,
        "backup_dir": "/var/lib/sagedral-ml/backups",
        "backup_interval_hours": 24,
        "backup_retention_days": 30,
        "run_migrations": True,
    },
    "auth": {
        "secret_key": "",
        "access_token_expire_minutes": 480,
        "algorithm": "HS256",
        "default_admin_username": "admin",
        "default_admin_password": "",
        "default_admin_email": "admin@sagedral.local",
        "admin_secret_file": "/var/lib/sagedral-ml/.sagedral-admin-secret",
        "jwt_secret_file": "/var/lib/sagedral-ml/.sagedral-jwt-secret",
    },
    "geolocation": {
        "enabled": False,
        "db_path": "/usr/share/GeoIP/GeoLite2-Country.mmdb",
    },
    "siem": {
        "enabled": False,
        "minimum_severity": "MEDIUM",
        "syslog_host": "",
        "syslog_port": 514,
        "syslog_protocol": "udp",
        "webhook_urls": [],
        "webhook_timeout_seconds": 5,
    },
    "notifications": {
        "enabled": False,
        "minimum_severity": "HIGH",
        "telegram_bot_token": "",
        "telegram_chat_id": "",
        "smtp_host": "",
        "smtp_port": 587,
        "smtp_starttls": True,
        "smtp_username": "",
        "smtp_password": "",
        "email_sender": "",
        "email_recipients": [],
    },
    "ha": {
        "enabled": False,
        "node_id": "",
        "peer_urls": [],
        "shared_secret": "",
        "sync_interval_seconds": 30,
    },
    "performance": {
        "detection_workers": 1,
        "profile_enabled": False,
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
backend = "scapy"                       # scapy | libpcap | af_packet
watchdog_idle_seconds = 30

[feature_extraction]
flow_timeout = 60                       # Seconds before flow is considered completed
max_packets_per_flow = 1000            # Max packets per flow
max_active_flows = 50000               # Safety cap against high-cardinality flow exhaustion

[signature]
enabled = true
custom_rules_file = ""                  # Optional path to custom Python rules file
custom_rules_dir = "/var/lib/sagedral-ml/custom-rules"  # Whitelisted directory for custom rule files
disabled_rules = []                     # List of rule IDs to disable (e.g. ["SIG-002"])
params = {}                              # Per-rule overrides, e.g. [signature.params.SIG-001]
whitelist_overrides = {}                # CIDR/IP -> rule IDs ignored for that source

[ml]
enabled = true
anomaly_threshold = 0.7                 # Score >= threshold indicates anomaly (0.0 - 1.0)
classifier_threshold = 0.6             # Minimum confidence for multiclass classifier
model_dir = "/var/lib/sagedral-ml/models"
retrain_on_startup = false
batch_size = 32
batch_timeout_ms = 50
drift_enabled = true
drift_window_size = 100
drift_psi_threshold = 0.25
feedback_retrain_minimum = 20
feedback_retrain_interval_hours = 24
adaptive_learning_enabled = true
adaptive_min_accuracy = 0.70
adaptive_min_f1 = 0.65
adaptive_min_classifier_accuracy = 0.65

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
whitelist_notes = {}
strike_escalation_enabled = true
rate_limit_enabled = false
rate_limit_connections = 100
rate_limit_window_seconds = 60
rate_limit_block_seconds = 300

[api]
host = "0.0.0.0"
port = 8000
cors_origins = ["http://localhost:5173", "http://localhost:3000"]
trusted_proxies = ["127.0.0.1", "::1"]
csp_enabled = true
metrics_enabled = true
global_rate_limit_per_minute = 600

[database]
backend = "sqlite"
connection_string = ""                # PostgreSQL example: postgresql+asyncpg://user:pass@host/db
path = "/var/lib/sagedral-ml/sagedral.db"
retention_days_alerts = 30
retention_days_traffic = 7
backup_dir = "/var/lib/sagedral-ml/backups"
backup_interval_hours = 24
backup_retention_days = 30
run_migrations = true

[auth]
secret_key = ""                       # "" = auto-generate random on first startup (set persistent secret for production).
access_token_expire_minutes = 480    # 8 jam
algorithm = "HS256"
default_admin_username = "admin"
default_admin_password = ""           # "" = generate random first-admin password and write admin_secret_file.
default_admin_email = "admin@sagedral.local"
admin_secret_file = "/var/lib/sagedral-ml/.sagedral-admin-secret"
jwt_secret_file = "/var/lib/sagedral-ml/.sagedral-jwt-secret"

[geolocation]
enabled = false
db_path = "/usr/share/GeoIP/GeoLite2-Country.mmdb"

[siem]
enabled = false
minimum_severity = "MEDIUM"
syslog_host = ""
syslog_port = 514
syslog_protocol = "udp"
webhook_urls = []
webhook_timeout_seconds = 5

[notifications]
enabled = false
minimum_severity = "HIGH"
telegram_bot_token = ""
telegram_chat_id = ""
smtp_host = ""
smtp_port = 587
smtp_starttls = true
smtp_username = ""
smtp_password = ""
email_sender = ""
email_recipients = []

[ha]
enabled = false
node_id = ""
peer_urls = []
shared_secret = ""
sync_interval_seconds = 30

[performance]
detection_workers = 1
profile_enabled = false
"""


class Config:
    """System configuration container."""

    sensitive_keys: List[str] = [
        "auth.secret_key",
        "auth.default_admin_password",
        "database.connection_string",
        "siem.webhook_urls",
        "notifications.telegram_bot_token",
        "notifications.smtp_password",
        "ha.shared_secret",
    ]

    requires_restart_keys: List[str] = [
        "capture.interface",
        "capture.bpf_filter",
        "capture.promiscuous",
        "capture.queue_maxsize",
        "capture.backend",
        "capture.watchdog_idle_seconds",
        "feature_extraction.flow_timeout",
        "feature_extraction.max_packets_per_flow",
        "feature_extraction.max_active_flows",
        "signature.enabled",
        "signature.custom_rules_file",
        "signature.custom_rules_dir",
        "signature.disabled_rules",
        "signature.params",
        "signature.whitelist_overrides",
        "ml.enabled",
        "ml.anomaly_threshold",
        "ml.classifier_threshold",
        "ml.model_dir",
        "ml.retrain_on_startup",
        "ml.batch_size",
        "ml.batch_timeout_ms",
        "ml.drift_enabled",
        "ml.drift_window_size",
        "ml.drift_psi_threshold",
        "ml.feedback_retrain_minimum",
        "ml.feedback_retrain_interval_hours",
        "ml.adaptive_learning_enabled",
        "ml.adaptive_min_accuracy",
        "ml.adaptive_min_f1",
        "ml.adaptive_min_classifier_accuracy",
        "decision.weight_signature",
        "decision.weight_ml",
        "ips.enabled",
        "ips.preferred_backend",
        "ips.auto_unblock_after",
        "ips.whitelist",
        "ips.whitelist_notes",
        "ips.strike_escalation_enabled",
        "ips.rate_limit_enabled",
        "ips.rate_limit_connections",
        "ips.rate_limit_window_seconds",
        "ips.rate_limit_block_seconds",
        "api.host",
        "api.port",
        "api.cors_origins",
        "api.trusted_proxies",
        "api.csp_enabled",
        "api.metrics_enabled",
        "api.global_rate_limit_per_minute",
        "database.backend",
        "database.connection_string",
        "database.path",
        "database.retention_days_alerts",
        "database.retention_days_traffic",
        "database.backup_dir",
        "database.backup_interval_hours",
        "database.backup_retention_days",
        "database.run_migrations",
        "general.log_level",
        "general.log_file",
        "general.data_dir",
        "geolocation.enabled",
        "geolocation.db_path",
        "siem.enabled",
        "siem.minimum_severity",
        "siem.syslog_host",
        "siem.syslog_port",
        "siem.syslog_protocol",
        "siem.webhook_urls",
        "notifications.enabled",
        "notifications.minimum_severity",
        "notifications.telegram_bot_token",
        "notifications.telegram_chat_id",
        "notifications.smtp_host",
        "notifications.smtp_port",
        "notifications.email_recipients",
        "ha.enabled",
        "ha.node_id",
        "ha.peer_urls",
        "ha.shared_secret",
        "performance.detection_workers",
    ]

    def __init__(self, data: Dict[str, Any]):
        self._data = data
        self._last_loaded_path: Optional[str] = None

    @property
    def data(self) -> Dict[str, Any]:
        return self._data

    @property
    def last_loaded_path(self) -> Optional[str]:
        return self._last_loaded_path

    @last_loaded_path.setter
    def last_loaded_path(self, value: Optional[str]) -> None:
        self._last_loaded_path = value

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

    def to_safe_dict(self, mask: str = "********") -> Dict[str, Any]:
        """Return a copy safe to expose through the API or CLI."""
        result = copy.deepcopy(self._data)
        for dotted_key in self.sensitive_keys:
            section, key = dotted_key.split(".", 1)
            section_data = result.get(section)
            if isinstance(section_data, dict) and section_data.get(key):
                section_data[key] = mask
        return result

    def validate(self) -> List[str]:
        """Validate configuration values and return list of validation error messages."""
        errors = []
        capture_iface = self.get("capture", "interface", "")
        if capture_iface is not None and not isinstance(capture_iface, str):
            errors.append("capture.interface must be a string; use empty string for auto-detect")

        anomaly_th = self.get("ml", "anomaly_threshold", 0.7)
        try:
            anomaly_th_float = float(anomaly_th)
        except (TypeError, ValueError):
            anomaly_th_float = -1.0
        if not (0.0 <= anomaly_th_float <= 1.0):
            errors.append("ml.anomaly_threshold must be between 0.0 and 1.0")

        for threshold_key in (
            "classifier_threshold",
            "drift_psi_threshold",
            "adaptive_min_accuracy",
            "adaptive_min_f1",
            "adaptive_min_classifier_accuracy",
        ):
            try:
                threshold_value = float(self.get("ml", threshold_key, 0.0))
            except (TypeError, ValueError):
                threshold_value = -1.0
            if not 0.0 <= threshold_value <= 1.0:
                errors.append(
                    "ml.%s must be between 0.0 and 1.0" % threshold_key
                )

        block_th = self.get("decision", "block_threshold", 0.7)
        try:
            block_th_float = float(block_th)
        except (TypeError, ValueError):
            block_th_float = -1.0
        if not (0.0 <= block_th_float <= 1.0):
            errors.append("decision.block_threshold must be between 0.0 and 1.0")

        alert_th = self.get("decision", "alert_threshold", 0.5)
        try:
            alert_th_float = float(alert_th)
        except (TypeError, ValueError):
            alert_th_float = -1.0
        if not (0.0 <= alert_th_float <= 1.0):
            errors.append("decision.alert_threshold must be between 0.0 and 1.0")

        if 0.0 <= alert_th_float <= 1.0 and 0.0 <= block_th_float <= 1.0 and alert_th_float > block_th_float:
            errors.append("decision.alert_threshold cannot be greater than decision.block_threshold")

        backend = self.get("ips", "preferred_backend", "nftables")
        if backend not in ("nftables", "iptables"):
            errors.append("ips.preferred_backend must be 'nftables' or 'iptables'")

        capture_backend = self.get("capture", "backend", "scapy")
        if capture_backend not in ("scapy", "libpcap", "af_packet"):
            errors.append("capture.backend must be 'scapy', 'libpcap', or 'af_packet'")

        database_backend = self.get("database", "backend", "sqlite")
        if database_backend not in ("sqlite", "postgresql"):
            errors.append("database.backend must be 'sqlite' or 'postgresql'")
        if database_backend == "postgresql" and not self.get(
            "database", "connection_string", ""
        ):
            errors.append(
                "database.connection_string is required when database.backend='postgresql'"
            )

        configured_secret = self.get("auth", "secret_key", "")
        if configured_secret and len(str(configured_secret).strip()) < 32:
            errors.append(
                "auth.secret_key must contain at least 32 characters or be empty"
            )
        if self.get("auth", "algorithm", "HS256") not in (
            "HS256",
            "HS384",
            "HS512",
        ):
            errors.append("auth.algorithm must be HS256, HS384, or HS512")
        if self.get("siem", "syslog_protocol", "udp") not in ("udp", "tcp"):
            errors.append("siem.syslog_protocol must be 'udp' or 'tcp'")
        if self.get("ha", "enabled", False) and len(
            str(self.get("ha", "shared_secret", "") or "")
        ) < 24:
            errors.append(
                "ha.shared_secret must contain at least 24 characters when HA is enabled"
            )
        for section, key in (
            ("siem", "webhook_urls"),
            ("ha", "peer_urls"),
        ):
            values = self.get(section, key, []) or []
            if not isinstance(values, list):
                errors.append("%s.%s must be a list" % (section, key))
                continue
            for value in values:
                if not str(value).startswith(("http://", "https://")):
                    errors.append(
                        "%s.%s entries must use http:// or https://"
                        % (section, key)
                    )

        for section, key in (
            ("capture", "queue_maxsize"),
            ("feature_extraction", "max_active_flows"),
            ("ml", "batch_size"),
            ("ml", "drift_window_size"),
            ("ips", "rate_limit_connections"),
            ("api", "global_rate_limit_per_minute"),
        ):
            try:
                if int(self.get(section, key, 1)) <= 0:
                    errors.append(f"{section}.{key} must be greater than zero")
            except (TypeError, ValueError):
                errors.append(f"{section}.{key} must be an integer")

        return errors

    def save(self, path: Optional[str] = None) -> bool:
        target_path = path or self._last_loaded_path
        if not target_path:
            logger.error("Cannot save config: no path specified and no last_loaded_path available.")
            return False

        target = Path(target_path)
        backup_path = target.with_suffix(target.suffix + ".bak")
        target_dir = target.parent
        try:
            if target_dir and not target_dir.exists():
                target_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.error(f"Failed to create config directory {target_dir}: {e}")
            return False

        backup_created = False
        if target.exists():
            try:
                shutil.copy2(target, backup_path)
                backup_created = True
                logger.debug(f"Created config backup at {backup_path}")
            except Exception as e:
                logger.error(f"Failed to create config backup: {e}")
                return False

        try:
            with open(target, "wb") as f:
                tomli_w.dump(self._data, f)
            logger.info(f"Configuration saved successfully to {target}")
            self._last_loaded_path = str(target)
            if backup_created:
                try:
                    backup_path.unlink()
                except Exception:
                    pass
            return True
        except Exception as e:
            logger.error(f"Failed to write config to {target}: {e}")
            if backup_created:
                try:
                    shutil.copy2(backup_path, target)
                    logger.info(f"Rolled back config from backup {backup_path}")
                except Exception as rollback_err:
                    logger.error(f"Rollback failed: {rollback_err}")
            return False

    def _flatten_dict(self, d: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
        flat: Dict[str, Any] = {}
        for k, v in d.items():
            full_key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                flat.update(self._flatten_dict(v, full_key))
            else:
                flat[full_key] = v
        return flat

    def get_changed_restart_keys(self, other_data: Dict[str, Any]) -> List[str]:
        current_flat = self._flatten_dict(self._data)
        other_flat = self._flatten_dict(other_data)
        changed: List[str] = []
        for key in self.requires_restart_keys:
            cur_val = current_flat.get(key)
            other_val = other_flat.get(key)
            if cur_val != other_val:
                changed.append(key)
        return changed


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

    base_config = getattr(sys, "_sagedral_base_config", None)
    config_dict = copy.deepcopy(
        base_config if base_config is not None else DEFAULT_CONFIG_DICT
    )

    config_file_path: Optional[Path] = None
    environment_path = os.environ.get("SAGEDRAL_CONFIG_PATH", "").strip()
    require_existing_path = False

    if custom_path:
        config_file_path = Path(custom_path)
    elif environment_path:
        # Services must not depend on whichever HOME systemd happens to
        # provide.  An explicit path is also safer than silently falling back
        # to defaults when a production config is unreadable.
        config_file_path = Path(environment_path)
        require_existing_path = True
    else:
        for candidate in (USER_CONFIG_PATH, DEFAULT_CONFIG_PATH):
            try:
                if candidate.exists():
                    config_file_path = candidate
                    break
            except OSError as exc:
                raise ConfigError(
                    "Cannot inspect configuration path %s: %s"
                    % (candidate, exc)
                )

    config_path_exists = False
    if config_file_path is not None:
        try:
            config_path_exists = config_file_path.exists()
        except OSError as exc:
            raise ConfigError(
                "Cannot inspect configuration path %s: %s"
                % (config_file_path, exc)
            )

    if require_existing_path and not config_path_exists:
        raise ConfigError(
            "Configured SAGEDRAL_CONFIG_PATH does not exist: %s"
            % config_file_path
        )

    if config_file_path and config_path_exists:
        try:
            with open(config_file_path, "rb") as f:
                loaded = _tomli.load(f)
                _deep_update(config_dict, loaded)
                logger.info(f"Loaded configuration from {config_file_path}")
        except Exception as e:
            raise ConfigError(
                "Cannot read configuration file %s: %s"
                % (config_file_path, e)
            )

    # Override with Environment Variables: SAGEDRAL_<SECTION>_<KEY>=value
    for env_var, val in os.environ.items():
        if env_var == "SAGEDRAL_CONFIG_PATH":
            continue
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
    if config_file_path:
        _config_instance.last_loaded_path = str(config_file_path)
    return _config_instance


def get_config() -> Config:
    """Get global Config instance."""
    global _config_instance
    if _config_instance is None:
        _config_instance = load_config()
    return _config_instance
