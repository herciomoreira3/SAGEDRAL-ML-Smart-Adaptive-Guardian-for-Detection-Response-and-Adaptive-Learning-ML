"""
Integration tests for FastAPI endpoints.
"""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sagedral_ml.api.main import create_app
from sagedral_ml.database.connection import init_db
from sagedral_ml.auth.security import seed_default_admin
from sagedral_ml.api.routers.model import _metric
from sagedral_ml.api.routers import model as model_router
from sagedral_ml.core.container import global_container
import sagedral_ml.database.connection as _db_conn


@pytest_asyncio.fixture
async def client():
    app = create_app()
    await init_db()
    async with _db_conn.AsyncSessionLocal() as db:
        await seed_default_admin(db)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def auth_headers(client):
    res = await client.post(
        "/api/v1/auth/login",
        data={"username": "admin", "password": "testadmin123"},
    )
    assert res.status_code == 200, res.text
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_get_status(client):
    res = await client.get("/api/v1/status")
    assert res.status_code == 200
    data = res.json()
    assert "status" in data
    assert data["status"] == "running"


@pytest.mark.asyncio
async def test_login_success(client):
    res = await client.post(
        "/api/v1/auth/login",
        data={"username": "admin", "password": "testadmin123"},
    )
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_get_alerts_requires_auth(client):
    res = await client.get("/api/v1/alerts?page=1&limit=10")
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_get_alerts_endpoint(client, auth_headers):
    res = await client.get("/api/v1/alerts?page=1&limit=10", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert "total" in data
    assert "data" in data


@pytest.mark.asyncio
async def test_block_valid_ip(client, auth_headers):
    res = await client.post(
        "/api/v1/blocked-ips",
        json={
            "ip": "10.100.100.100",
            "reason": "Test manual block",
            "duration_seconds": 60,
        },
        headers=auth_headers,
    )
    assert res.status_code == 200
    assert res.json()["success"] is True


@pytest.mark.asyncio
async def test_block_whitelisted_ip_rejected(client, auth_headers):
    res = await client.post(
        "/api/v1/blocked-ips",
        json={
            "ip": "127.0.0.1",
            "reason": "Should be rejected",
            "duration_seconds": 60,
        },
        headers=auth_headers,
    )
    assert res.status_code == 403


@pytest.mark.asyncio
async def test_get_config_endpoint(client, auth_headers):
    res = await client.get("/api/v1/config", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert "capture" in data
    assert "decision" in data


@pytest.mark.asyncio
async def test_get_model_info_endpoint(client, auth_headers):
    res = await client.get("/api/v1/model/info", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert "anomaly_model" in data


def test_model_metric_normalization_preserves_trained_and_rejects_invalid():
    metadata = {"anomaly_accuracy": 0.91, "anomaly_f1": "0.88", "classifier_accuracy": 2.0}
    assert _metric(metadata, "anomaly_accuracy") == 0.91
    assert _metric(metadata, "anomaly_f1") == 0.88
    assert _metric(metadata, "classifier_accuracy") is None
    assert _metric({}, "anomaly_accuracy") is None


@pytest.mark.asyncio
async def test_model_info_fallback_metrics_are_returned_and_normalized(monkeypatch):
    class DummyEngine:
        model_loaded = True
        version = "1.0.0-fallback"
        model_metadata = {
            "anomaly_accuracy": 0.91,
            "anomaly_f1": float("nan"),
            "classifier_accuracy": True,
        }

    monkeypatch.setattr(global_container, "ml_engine", DummyEngine())
    data = await model_router.get_model_info(_user=None)
    assert data["anomaly_model"]["accuracy"] == 0.91
    assert data["anomaly_model"]["f1_score"] is None
    assert data["classifier_model"]["accuracy"] is None
    assert data["anomaly_model"]["note"]


@pytest.mark.asyncio
async def test_capture_stats_unavailable_in_api_only(client, auth_headers):
    unauthenticated = await client.get("/api/v1/capture/stats")
    assert unauthenticated.status_code == 401
    res = await client.get("/api/v1/capture/stats", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "unavailable"
