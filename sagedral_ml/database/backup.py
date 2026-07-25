"""
Automatic SQLite database backup manager for SAGEDRAL-ML.
Creates gzip-compressed backups with configurable retention policy.
"""

import gzip
import logging
import os
import shutil
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from sagedral_ml.config import get_config

logger = logging.getLogger("sagedral_ml.database.backup")


class DatabaseBackupManager:
    """Handles scheduled and on-demand SQLite database backups."""

    def __init__(self, config=None):
        self.config = config or get_config()

    def _db_path(self) -> str:
        return self.config.get("database", "path", "/var/lib/sagedral-ml/sagedral.db")

    def _backup_dir(self) -> Path:
        backup_dir = Path(
            self.config.get("database", "backup_dir", "/var/lib/sagedral-ml/backups")
        )
        backup_dir.mkdir(parents=True, exist_ok=True)
        return backup_dir

    def _checkpoint_wal(self, db_path: str) -> None:
        """Flush WAL pages so the on-disk DB file is consistent for copying."""
        if not os.path.exists(db_path):
            return
        try:
            conn = sqlite3.connect(db_path, timeout=30)
            try:
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
                conn.commit()
            finally:
                conn.close()
        except Exception as e:
            logger.warning(f"WAL checkpoint before backup failed (continuing): {e}")

    def _list_backups(self) -> List[Path]:
        backup_dir = self._backup_dir()
        files = sorted(
            list(backup_dir.glob("sagedral-*.db.gz")),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        return files

    def _apply_retention(self) -> int:
        """Remove backups older than backup_retention_days."""
        retention_days = int(self.config.get("database", "backup_retention_days", 30) or 30)
        if retention_days <= 0:
            return 0

        cutoff = time.time() - (retention_days * 86400)
        removed = 0
        for path in self._list_backups():
            try:
                if path.stat().st_mtime < cutoff:
                    path.unlink()
                    removed += 1
            except Exception as e:
                logger.warning(f"Failed to remove old backup {path}: {e}")
        if removed:
            logger.info(f"Removed {removed} expired database backup(s).")
        return removed

    def run_full_backup(self, output_path: Optional[str] = None) -> Optional[str]:
        """
        Create a gzip-compressed copy of the SQLite database.

        Returns the path to the created ``.db.gz`` file, or ``None`` on failure.
        """
        db_path = self._db_path()
        if not os.path.exists(db_path):
            logger.warning(f"Database file not found, skip backup: {db_path}")
            return None

        self._checkpoint_wal(db_path)

        ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        if output_path:
            dest = Path(output_path)
        else:
            dest = self._backup_dir() / f"sagedral-{ts}.db.gz"

        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp_copy = dest.with_suffix(".tmp")

        try:
            shutil.copy2(db_path, str(tmp_copy))
            with open(tmp_copy, "rb") as src_f:
                with gzip.open(dest, "wb", compresslevel=6) as gz_f:
                    shutil.copyfileobj(src_f, gz_f)
            tmp_copy.unlink()
            logger.info(f"Database backup created: {dest} ({dest.stat().st_size} bytes)")
            self._apply_retention()
            return str(dest)
        except Exception as e:
            logger.error(f"Database backup failed: {e}")
            try:
                if tmp_copy.exists():
                    tmp_copy.unlink()
            except Exception:
                pass
            return None
