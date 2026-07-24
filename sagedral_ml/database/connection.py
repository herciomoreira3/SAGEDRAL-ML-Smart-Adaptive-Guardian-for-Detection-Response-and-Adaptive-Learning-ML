"""
SQLAlchemy async database connection setup and session management.
"""

import os
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker, declarative_base
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


def init_engine():
    global _engine, AsyncSessionLocal
    if _engine is None:
        db_url = get_db_url()
        _engine = create_async_engine(db_url, echo=False)
        AsyncSessionLocal = sessionmaker(
            _engine, class_=AsyncSession, expire_on_commit=False
        )
    return _engine


async def init_db():
    """Create all database tables."""
    engine = init_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency injection yield for FastAPI routes."""
    init_engine()
    async with AsyncSessionLocal() as session:
        yield session
