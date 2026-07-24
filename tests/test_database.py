"""
Unit tests for async database CRUD operations.
"""

import pytest
import pytest_asyncio
import time
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from sagedral_ml.database.connection import Base
from sagedral_ml.database import crud


@pytest_asyncio.fixture
async def async_session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session_factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session_factory() as session:
        yield session

    await engine.dispose()


@pytest.mark.asyncio
async def test_create_and_get_alerts(async_session):
    alert_data = {
        "alert_id": "test-uuid-1",
        "timestamp": time.time(),
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "src_port": 12345,
        "dst_port": 80,
        "protocol": "TCP",
        "attack_type": "DDoS",
        "severity": "HIGH",
        "final_score": 0.85,
        "action_taken": "BLOCKED",
        "signature_matched": ["SIG-001"],
        "ml_anomaly_score": 0.9,
        "flow_duration": 1.5,
        "total_bytes": 3000,
    }

    created = await crud.create_alert(async_session, alert_data)
    assert created.alert_id == "test-uuid-1"

    alerts, total = await crud.get_alerts(async_session, page=1, limit=10)
    assert total == 1
    assert alerts[0].src_ip == "192.168.1.100"


@pytest.mark.asyncio
async def test_block_and_unblock_ip_db(async_session):
    blocked = await crud.block_ip_db(async_session, ip="10.0.0.55", reason="Test block", duration_seconds=60)
    assert blocked.ip == "10.0.0.55"
    assert blocked.is_active == 1

    is_blocked = await crud.is_ip_blocked_db(async_session, "10.0.0.55")
    assert is_blocked is True

    unblocked = await crud.unblock_ip_db(async_session, "10.0.0.55")
    assert unblocked is True

    is_blocked_after = await crud.is_ip_blocked_db(async_session, "10.0.0.55")
    assert is_blocked_after is False
