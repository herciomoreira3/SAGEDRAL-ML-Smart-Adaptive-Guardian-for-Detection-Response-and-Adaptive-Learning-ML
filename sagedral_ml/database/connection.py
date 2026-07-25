"""
SQLAlchemy async database connection setup and session management.
"""

import os
from typing import AsyncGenerator
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.engine import Engine
from sagedral_ml.config import get_config

Base = declarative_base()

_engine = None
AsyncSessionLocal = None  # exported module-level so orchestrator can use it directly


def get_db_url() -> str:
    config = get_config()
    db_path = config.get("database", "path", "/var/lib/sagedral-ml/sagedral.db")
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    return f"sqlite+aiosqlite:///{db_path}"


@event.listens_for(Engine, "connect")
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
        _engine = create_async_engine(
            db_url,
            echo=False,
            connect_args={"timeout": 30},
        )
        AsyncSessionLocal = sessionmaker(
            _engine, class_=AsyncSession, expire_on_commit=False
        )
    return _engine


async def init_db():
    """Create all database tables."""
    engine = init_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_run_lightweight_sqlite_migrations)


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
    }
    for column, sql in column_sql.items():
        if column not in existing:
            sync_conn.exec_driver_sql(sql)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency injection yield for FastAPI routes."""
    init_engine()
    async with AsyncSessionLocal() as session:
        yield session
