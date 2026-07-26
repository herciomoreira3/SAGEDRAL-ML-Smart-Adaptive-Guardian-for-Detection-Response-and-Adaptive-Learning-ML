"""
SQLAlchemy async database connection setup and session management.
"""

import logging
import os
import asyncio
from pathlib import Path
from typing import AsyncGenerator, Optional
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sagedral_ml.config import get_config

Base = declarative_base()
logger = logging.getLogger("sagedral_ml.database.connection")

_engine = None
AsyncSessionLocal = None  # exported module-level so orchestrator can use it directly
_migrations_applied = False


def get_db_url() -> str:
    config = get_config()
    backend = str(config.get("database", "backend", "sqlite") or "sqlite").lower()
    connection_string = str(
        config.get("database", "connection_string", "") or ""
    ).strip()
    if backend == "postgresql":
        if not connection_string:
            raise RuntimeError(
                "database.connection_string wajib diisi untuk backend PostgreSQL"
            )
        if connection_string.startswith("postgresql://"):
            connection_string = connection_string.replace(
                "postgresql://", "postgresql+asyncpg://", 1
            )
        return connection_string

    db_path = config.get("database", "path", "/var/lib/sagedral-ml/sagedral.db")
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    return f"sqlite+aiosqlite:///{db_path}"


def _set_sqlite_pragmas(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.execute("PRAGMA cache_size=-65536;")
        cursor.execute("PRAGMA temp_store=MEMORY;")
    except Exception as e:
        import logging
        logging.getLogger("sagedral_ml.database").debug(
            f"Note: could not apply some SQLite pragmas: {e}"
        )
    finally:
        cursor.close()


def init_engine():
    global _engine, AsyncSessionLocal
    if _engine is None:
        db_url = get_db_url()
        is_sqlite = db_url.startswith("sqlite+")
        engine_kwargs = {"echo": False, "pool_pre_ping": True}
        if is_sqlite:
            engine_kwargs["connect_args"] = {"timeout": 30}
        _engine = create_async_engine(db_url, **engine_kwargs)
        if is_sqlite:
            event.listen(_engine.sync_engine, "connect", _set_sqlite_pragmas)
        AsyncSessionLocal = sessionmaker(
            _engine, class_=AsyncSession, expire_on_commit=False
        )
    return _engine


async def init_db():
    """Create tables and apply safe additive migrations.

    Alembic remains the authoritative production migration path when enabled,
    while ``create_all`` plus the additive compatibility migration preserves
    upgrades from existing v1 SQLite installations.
    """
    global _migrations_applied
    config = get_config()
    if config.get("database", "run_migrations", True) and not _migrations_applied:
        loop = asyncio.get_running_loop()
        _migrations_applied = bool(
            await loop.run_in_executor(None, run_alembic_migrations)
        )
    engine = init_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_run_lightweight_sqlite_migrations)


def run_alembic_migrations() -> bool:
    """Upgrade the configured database schema to the bundled Alembic head."""
    try:
        from alembic import command
        from alembic.config import Config as AlembicConfig

        project_root = Path(__file__).resolve().parents[2]
        ini_path = project_root / "alembic.ini"
        if not ini_path.exists():
            logger.warning(
                "alembic.ini not found at %s; using create_all compatibility path.",
                ini_path,
            )
            return False
        alembic_config = AlembicConfig(str(ini_path))
        alembic_config.set_main_option(
            "script_location",
            str(Path(__file__).resolve().parent / "migrations"),
        )
        command.upgrade(alembic_config, "head")
        return True
    except Exception as exc:
        # Existing v1 installations still receive the additive compatibility
        # migration. The explicit CLI command can be rerun after fixing a
        # PostgreSQL credential or driver problem.
        logger.warning("Alembic migration could not run: %s", exc)
        return False


def _run_lightweight_sqlite_migrations(sync_conn) -> None:
    """Apply minimal additive SQLite migrations for deployments without Alembic.

    SQLAlchemy ``create_all`` does not add columns to existing tables. Fase 1 adds
    non-breaking nullable/default columns, so a tiny introspection-based migration
    keeps old installations bootable until a full Alembic system is introduced.
    """
    try:
        dialect_name = sync_conn.engine.dialect.name
    except Exception:
        dialect_name = ""
    if dialect_name != "sqlite":
        return

    existing = set()
    try:
        rows = sync_conn.exec_driver_sql("PRAGMA table_info(alerts)").fetchall()
        existing = {row[1] for row in rows}
    except Exception:
        return

    column_sql = {
        "status": "ALTER TABLE alerts ADD COLUMN status VARCHAR(20) DEFAULT 'open'",
        "feedback_label": "ALTER TABLE alerts ADD COLUMN feedback_label VARCHAR(30)",
        "feedback_notes": "ALTER TABLE alerts ADD COLUMN feedback_notes TEXT",
        "closed_at": "ALTER TABLE alerts ADD COLUMN closed_at FLOAT",
        "src_country": "ALTER TABLE alerts ADD COLUMN src_country VARCHAR(100)",
        "src_country_code": "ALTER TABLE alerts ADD COLUMN src_country_code VARCHAR(8)",
        "feature_vector_json": "ALTER TABLE alerts ADD COLUMN feature_vector_json TEXT",
    }
    for column, sql in column_sql.items():
        if column not in existing:
            sync_conn.exec_driver_sql(sql)

    feedback_existing = set()
    try:
        rows = sync_conn.exec_driver_sql(
            "PRAGMA table_info(alert_feedback)"
        ).fetchall()
        feedback_existing = {row[1] for row in rows}
    except Exception:
        return
    feedback_columns = {
        "training_vector_json": (
            "ALTER TABLE alert_feedback ADD COLUMN training_vector_json TEXT"
        ),
        "processed_at": "ALTER TABLE alert_feedback ADD COLUMN processed_at FLOAT",
        "model_version": (
            "ALTER TABLE alert_feedback ADD COLUMN model_version VARCHAR(64)"
        ),
    }
    for column, sql in feedback_columns.items():
        if column not in feedback_existing:
            sync_conn.exec_driver_sql(sql)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency injection yield for FastAPI routes."""
    init_engine()
    async with AsyncSessionLocal() as session:
        yield session
