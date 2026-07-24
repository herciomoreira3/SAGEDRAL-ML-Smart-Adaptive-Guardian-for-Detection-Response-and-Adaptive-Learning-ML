"""
Integration tests for FastAPI endpoints.
"""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sagedral_ml.api.main import create_app
from sagedral_ml.database.connection import init_db


@pytest_asyncio.fixture
async def client():
    app = create_app()
    # Ensure DB tables are created before tests run
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_get_status(client):
    res = await client.get("/api/v1/status")
    assert res.status_code == 200
    data = res.json()
    assert "status" in data
    assert data["status"] == "running"


@pytest.mark.asyncio
async def test_get_alerts_endpoint(client):
    res = await client.get("/api/v1/alerts?page=1&limit=10")
    assert res.status_code == 200
    data = res.json()
    assert "total" in data
    assert "data" in data


@pytest.mark.asyncio
async def test_block_valid_ip(client):
    res = await client.post("/api/v1/blocked-ips", json={
        "ip": "10.100.100.100",
        "reason": "Test manual block",
        "duration_seconds": 60,
    })
    assert res.status_code == 200
    assert res.json()["success"] is True


@pytest.mark.asyncio
async def test_block_whitelisted_ip_rejected(client):
    res = await client.post("/api/v1/blocked-ips", json={
        "ip": "127.0.0.1",
        "reason": "Should be rejected",
        "duration_seconds": 60,
    })
    assert res.status_code == 403


@pytest.mark.asyncio
async def test_get_config_endpoint(client):
    res = await client.get("/api/v1/config")
    assert res.status_code == 200
    data = res.json()
    assert "capture" in data
    assert "decision" in data


@pytest.mark.asyncio
async def test_get_model_info_endpoint(client):
    res = await client.get("/api/v1/model/info")
    assert res.status_code == 200
    data = res.json()
    assert "anomaly_model" in data
