"""
Shared pytest fixtures for SAGEDRAL-ML test suite.
"""

import copy
import os
import sys

import pytest

from sagedral_ml.config import DEFAULT_CONFIG_DICT


@pytest.fixture(scope="session", autouse=True)
def configure_test_environment():
    """Use isolated test config with known admin credentials."""
    test_cfg = copy.deepcopy(DEFAULT_CONFIG_DICT)
    test_cfg["auth"]["secret_key"] = "pytest-secret-key-minimum-32-characters-long"
    test_cfg["auth"]["default_admin_password"] = "testadmin123"
    test_cfg["auth"]["default_admin_username"] = "admin"
    test_cfg["database"]["path"] = os.path.join(
        os.environ.get("TEMP", "/tmp"), "sagedral-pytest.db"
    )
    test_cfg["database"]["backup_dir"] = os.path.join(
        os.environ.get("TEMP", "/tmp"), "sagedral-pytest-backups"
    )
    test_cfg_path = os.path.join(os.environ.get("TEMP", "/tmp"), "sagedral-pytest-config.toml")
    test_cfg["general"]["data_dir"] = os.path.join(os.environ.get("TEMP", "/tmp"), "sagedral-pytest-data")

    sys._sagedral_base_config = test_cfg
    import sagedral_ml.config as config_mod
    config_mod._config_instance = None
    from sagedral_ml.config import load_config
    cfg = load_config(test_cfg_path)
    with open(test_cfg_path, "wb") as f:
        import tomli_w
        tomli_w.dump(cfg.to_dict(), f)
    cfg.last_loaded_path = test_cfg_path
    config_mod._config_instance = cfg
    yield
    config_mod._config_instance = None
    if hasattr(sys, "_sagedral_base_config"):
        delattr(sys, "_sagedral_base_config")

    db_path = test_cfg["database"]["path"]
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(db_path + suffix)
        except OSError:
            pass
