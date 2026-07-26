import copy
import json
import os
import queue
import time
from unittest.mock import Mock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from sagedral_ml.api.main import create_app
from sagedral_ml.api.websocket import ConnectionManager
from sagedral_ml.adaptive import AdaptiveLearningManager
from sagedral_ml.capture.sniffer import AFPacketCapture, create_packet_capture
from sagedral_ml.config import Config, get_config
from sagedral_ml.database import crud
from sagedral_ml.database.backup import DatabaseBackupManager
from sagedral_ml.database.connection import init_db
from sagedral_ml.database.connection import get_db_url
import sagedral_ml.database.connection as db_connection
from sagedral_ml.detection.ml_engine import FEATURE_NAMES, MLEngine
from sagedral_ml.detection.signature_engine import SignatureEngine
from sagedral_ml.features.extractor import FlowAggregator
from sagedral_ml.ha import HASyncManager
from sagedral_ml.integrations import (
    GeoIPResolver,
    NotificationManager,
    SIEMExporter,
    _severity_allowed,
)
from sagedral_ml.ips.response import (
    ConnectionRateLimiter,
    IPSModule,
    calculate_escalated_duration,
    validate_ip_or_network,
)
from sagedral_ml.observability import MetricsRegistry


@pytest_asyncio.fixture
async def enterprise_client():
    await init_db()
    from sagedral_ml.auth.security import seed_default_admin

    async with db_connection.AsyncSessionLocal() as db:
        await seed_default_admin(db)
    transport = ASGITransport(app=create_app())
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest_asyncio.fixture
async def enterprise_auth(enterprise_client):
    response = await enterprise_client.post(
        "/api/v1/auth/login",
        data={"username": "admin", "password": "testadmin123"},
    )
    assert response.status_code == 200, response.text
    return {"Authorization": "Bearer " + response.json()["access_token"]}


def _flow(**updates):
    vector = {name: 0.0 for name in FEATURE_NAMES}
    vector.update({"duration": 1.0, "protocol": 6, "dst_port": 443})
    vector.update(updates)
    return vector


def test_fallback_batch_returns_one_result_per_flow(tmp_path):
    engine = MLEngine(model_dir=str(tmp_path))
    vectors = [
        _flow(total_fwd_packets=3),
        _flow(
            total_fwd_packets=150,
            syn_flag_count=140,
            flow_packets_per_sec=9000,
        ),
        _flow(protocol=17, flow_packets_per_sec=7000),
    ]
    results = engine.predict_batch(vectors)
    assert len(results) == len(vectors)
    assert all(0.0 <= item.anomaly_score <= 1.0 for item in results)


def test_signature_dsl_parameters_and_whitelist():
    engine = SignatureEngine()
    engine.rule_param_overrides = {
        "SIG-001": {"min_syn_count": 5, "max_ack_count": 10, "max_duration": 5}
    }
    vector = _flow(syn_flag_count=6, ack_flag_count=0)
    assert "SIG-001" in engine.evaluate(vector).matched_rules
    engine.whitelist_overrides = {"SIG-001": ["203.0.113.0/24"]}
    vector["src_ip"] = "203.0.113.8"
    assert "SIG-001" not in engine.evaluate(vector).matched_rules
    with pytest.raises(ValueError):
        engine._compile_safe_condition("__import__('os').system('id')")
    condition = engine._compile_safe_condition(
        "flow.get('dst_port', 0) == 443 and total_fwd_packets >= 1"
    )
    assert condition({"dst_port": 443, "total_fwd_packets": 2}) is True


def test_flow_eviction_and_timeout():
    output = queue.Queue()
    aggregator = FlowAggregator(
        output, {"max_active_flows": 1, "flow_timeout": 1}
    )
    aggregator.process_packet(
        {
            "src_ip": "2001:db8::1",
            "dst_ip": "2001:db8::2",
            "src_port": 1000,
            "dst_port": 443,
            "protocol": 6,
            "pkt_len": 80,
            "header_len": 60,
            "flags": {"SYN": True},
            "timestamp": 1.0,
        }
    )
    aggregator.process_packet(
        {
            "src_ip": "2001:db8::3",
            "dst_ip": "2001:db8::4",
            "src_port": 1001,
            "dst_port": 443,
            "protocol": 6,
            "pkt_len": 80,
            "header_len": 60,
            "flags": {},
            "timestamp": 2.0,
        }
    )
    assert output.get_nowait().src_ip == "2001:db8::1"
    aggregator.cleanup_timeouts(now=4.0)
    assert output.get_nowait().src_ip == "2001:db8::3"


def test_ips_cidr_ipv6_rate_limit_and_escalation():
    assert validate_ip_or_network("10.0.0.12/24") == "10.0.0.0/24"
    assert validate_ip_or_network("2001:db8::1/64") == "2001:db8::/64"
    assert calculate_escalated_duration(60, 1) == 60
    assert calculate_escalated_duration(60, 4) == 10080
    assert calculate_escalated_duration(60, 5) is None

    limiter = ConnectionRateLimiter(maximum=2, window_seconds=10)
    assert limiter.record("198.51.100.1", now=1) is False
    assert limiter.record("198.51.100.1", now=2) is False
    assert limiter.record("198.51.100.1", now=3) is True
    assert limiter.record("198.51.100.1", now=20) is False

    config_whitelist = ["10.0.0.0/8", "2001:db8::/64"]
    with patch("sagedral_ml.ips.response.get_default_gateway", return_value=None), patch(
        "sagedral_ml.ips.response.get_local_ip_addresses", return_value=set()
    ), patch("sagedral_ml.ips.response.shutil.which", return_value=None):
        module = IPSModule(
            enabled=True,
            whitelist=config_whitelist,
            preferred_backend="nftables",
        )
    assert module.is_whitelisted("10.10.1.2") is True
    assert module.is_entry_whitelisted("10.10.0.0/16") is True
    assert module.block_network("198.51.100.0/24") is True


def test_capture_factory_and_afpacket_platform_guard():
    capture = create_packet_capture("scapy", "lo", queue.Queue())
    assert capture.backend == "scapy"
    with pytest.raises(ValueError):
        create_packet_capture("unknown", "lo", queue.Queue())
    ring_capture = AFPacketCapture("lo", queue.Queue())
    with patch("sagedral_ml.capture.sniffer.platform.system", return_value="Windows"):
        with pytest.raises(RuntimeError):
            ring_capture.start()


def test_config_redaction_validation_and_backup(tmp_path):
    db_path = tmp_path / "sagedral.db"
    db_path.write_bytes(b"sqlite-test-data")
    data = copy.deepcopy(get_config().to_dict())
    data["database"]["path"] = str(db_path)
    data["database"]["backup_dir"] = str(tmp_path / "backups")
    data["auth"]["secret_key"] = "super-secret-value-that-must-not-leak"
    data["notifications"]["smtp_password"] = "mail-secret"
    config = Config(data)
    safe = config.to_safe_dict()
    assert safe["auth"]["secret_key"] == "********"
    assert safe["notifications"]["smtp_password"] == "********"
    assert config.to_dict()["auth"]["secret_key"].startswith("super-secret")
    assert config.validate() == []

    manager = DatabaseBackupManager(config)
    result = manager.run_full_backup()
    assert result is not None
    assert result.endswith(".db.gz")
    assert os.path.getsize(result) > 0
    assert manager._list_backups()


def test_postgresql_url_selection():
    data = copy.deepcopy(get_config().to_dict())
    data["database"]["backend"] = "postgresql"
    data["database"]["connection_string"] = (
        "postgresql://sagedral:secret@db.internal/sagedral"
    )
    with patch(
        "sagedral_ml.database.connection.get_config",
        return_value=Config(data),
    ):
        assert get_db_url().startswith("postgresql+asyncpg://")


def test_observability_and_integrations_do_not_leak_or_send_below_threshold():
    registry = MetricsRegistry()
    registry.inc("sagedral_test_total", labels={"severity": 'H"IGH'})
    registry.set("sagedral_test_gauge", 4)
    rendered = registry.render()
    assert 'severity="H\\"IGH"' in rendered
    assert "sagedral_test_gauge 4.000000" in rendered
    assert _severity_allowed("HIGH", "MEDIUM") is True
    assert _severity_allowed("LOW", "HIGH") is False

    config_data = copy.deepcopy(get_config().to_dict())
    config_data["siem"]["enabled"] = True
    config_data["siem"]["minimum_severity"] = "HIGH"
    config_data["siem"]["syslog_host"] = ""
    config_data["siem"]["webhook_urls"] = []
    exporter = SIEMExporter(Config(config_data))
    cef = exporter._cef(
        {
            "severity": "HIGH",
            "attack_type": "Bad|Name\nInjected",
            "src_ip": "198.51.100.1",
            "dst_ip": "192.0.2.1",
        }
    )
    assert "\n" not in cef
    assert "Bad\\|Name" in cef


def test_ha_secret_validation():
    config_data = copy.deepcopy(get_config().to_dict())
    config_data["ha"].update(
        {"enabled": True, "shared_secret": "a-long-ha-shared-secret", "node_id": "node-a"}
    )
    manager = HASyncManager(Config(config_data))
    assert manager.enabled() is True
    assert manager.node_id() == "node-a"
    assert manager.valid_secret("a-long-ha-shared-secret") is True
    assert manager.valid_secret("wrong") is False


@pytest.mark.asyncio
async def test_websocket_topics_keepalive_and_buffer():
    class FakeWebSocket:
        def __init__(self):
            self.accepted = False
            self.messages = []

        async def accept(self):
            self.accepted = True

        async def send_text(self, value):
            self.messages.append(value)

    manager = ConnectionManager(buffer_size=3)
    socket = FakeWebSocket()
    await manager.connect(socket)
    manager.subscribe(socket, "alerts:severity:high")
    await manager.broadcast("new_alert", {"severity": "HIGH", "id": 1})
    await manager.broadcast("new_alert", {"severity": "LOW", "id": 2})
    await manager.ping(socket)
    assert socket.accepted is True
    assert any('"id": 1' in message for message in socket.messages)
    assert not any('"id": 2' in message for message in socket.messages)
    assert socket.messages[-1] == '{"event":"ping","data":{}}'
    manager.disconnect(socket)
    assert socket not in manager.active_connections


@pytest.mark.asyncio
async def test_global_api_rate_limit():
    config = get_config()
    previous = config.get("api", "global_rate_limit_per_minute", 600)
    config.data["api"]["global_rate_limit_per_minute"] = 2
    try:
        transport = ASGITransport(app=create_app())
        async with AsyncClient(
            transport=transport, base_url="http://rate-test"
        ) as client:
            assert (await client.get("/api/v1/status")).status_code == 200
            assert (await client.get("/api/v1/status")).status_code == 200
            limited = await client.get("/api/v1/status")
            assert limited.status_code == 429
            assert limited.headers["retry-after"] == "60"
    finally:
        config.data["api"]["global_rate_limit_per_minute"] = previous


@pytest.mark.asyncio
async def test_adaptive_learning_waits_for_enough_feedback():
    await init_db()
    data = copy.deepcopy(get_config().to_dict())
    data["ml"]["feedback_retrain_minimum"] = 10000
    manager = AdaptiveLearningManager(Config(data))
    result = await manager.run_once()
    assert result["trained"] is False
    assert result["reason"] == "insufficient_feedback"


@pytest.mark.asyncio
async def test_enterprise_api_rbac_rules_feedback_and_audit(
    enterprise_client, enterprise_auth
):
    config_response = await enterprise_client.get(
        "/api/v1/config", headers=enterprise_auth
    )
    assert config_response.status_code == 200
    assert config_response.json()["auth"]["secret_key"] == "********"
    whitelist_alias = await enterprise_client.get(
        "/api/v1/whitelist", headers=enterprise_auth
    )
    assert whitelist_alias.status_code == 200

    partial_update = await enterprise_client.put(
        "/api/v1/config",
        json={"config": {"api": {"metrics_enabled": True}}},
        headers=enterprise_auth,
    )
    assert partial_update.status_code == 200, partial_update.text
    assert "capture" in get_config().to_dict()

    username = "enterprise_analyst"
    existing_users = await enterprise_client.get(
        "/api/v1/users", headers=enterprise_auth
    )
    for row in existing_users.json().get("data", []):
        if row["username"] == username:
            await enterprise_client.delete(
                "/api/v1/users/%s" % row["id"], headers=enterprise_auth
            )
    created_user = await enterprise_client.post(
        "/api/v1/users",
        json={
            "username": username,
            "password": "enterprise-pass-123",
            "role": "analyst",
            "full_name": "Enterprise Analyst",
            "email": "analyst@example.test",
        },
        headers=enterprise_auth,
    )
    assert created_user.status_code == 201, created_user.text
    analyst_id = created_user.json()["id"]
    analyst_login = await enterprise_client.post(
        "/api/v1/auth/login",
        data={"username": username, "password": "enterprise-pass-123"},
    )
    analyst_headers = {
        "Authorization": "Bearer " + analyst_login.json()["access_token"]
    }
    forbidden = await enterprise_client.put(
        "/api/v1/config",
        json={"config": {"api": {"metrics_enabled": False}}},
        headers=analyst_headers,
    )
    assert forbidden.status_code == 403

    rule_id = "TST-ENTERPRISE-RULE"
    await enterprise_client.delete(
        "/api/v1/rules/%s" % rule_id, headers=enterprise_auth
    )
    rule = await enterprise_client.post(
        "/api/v1/rules",
        json={
            "rule_id": rule_id,
            "name": "Enterprise test rule",
            "description": "Safe DSL test",
            "severity": "HIGH",
            "condition_expr": "syn_flag_count > 10",
            "attack_type": "TestAttack",
        },
        headers=enterprise_auth,
    )
    assert rule.status_code == 201, rule.text
    invalid_rule = await enterprise_client.post(
        "/api/v1/rules",
        json={
            "rule_id": "TST-INVALID-RULE",
            "name": "Invalid test rule",
            "severity": "HIGH",
            "condition_expr": "__import__('os').system('id')",
            "attack_type": "TestAttack",
        },
        headers=enterprise_auth,
    )
    assert invalid_rule.status_code == 422
    updated_rule = await enterprise_client.put(
        "/api/v1/rules/%s" % rule_id,
        json={"is_enabled": False},
        headers=enterprise_auth,
    )
    assert updated_rule.status_code == 200

    alert_id = "ALT-ENTERPRISE-TEST"
    async with db_connection.AsyncSessionLocal() as db:
        existing = await crud.get_alert_by_alert_id(db, alert_id)
        if existing is not None:
            await crud.delete_alert(db, alert_id)
        await crud.create_alert(
            db,
            {
                "alert_id": alert_id,
                "timestamp": time.time(),
                "src_ip": "198.51.100.88",
                "dst_ip": "192.0.2.20",
                "src_port": 40000,
                "dst_port": 443,
                "protocol": "TCP",
                "attack_type": "DDoS",
                "severity": "HIGH",
                "final_score": 0.9,
                "action_taken": "ALERTED",
                "signature_matched": ["SIG-001"],
                "feature_vector": _flow(syn_flag_count=120),
                "src_country": "Exampleland",
                "src_country_code": "EX",
            },
        )
    csv_response = await enterprise_client.get(
        "/api/v1/alerts/export.csv", headers=enterprise_auth
    )
    assert csv_response.status_code == 200
    assert alert_id in csv_response.text
    feedback = await enterprise_client.post(
        "/api/v1/alerts/%s/feedback" % alert_id,
        json={"label": "TRUE_POSITIVE", "notes": "verified"},
        headers=analyst_headers,
    )
    assert feedback.status_code == 200, feedback.text
    feedback_status = await enterprise_client.get(
        "/api/v1/feedback/status", headers=analyst_headers
    )
    assert feedback_status.status_code == 200
    drift = await enterprise_client.get(
        "/api/v1/model/drift", headers=enterprise_auth
    )
    assert drift.status_code == 200
    audit = await enterprise_client.get(
        "/api/v1/audit-logs", headers=enterprise_auth
    )
    assert audit.status_code == 200
    assert audit.json()["total"] >= 1
    metrics = await enterprise_client.get("/metrics")
    assert metrics.status_code == 200
    assert "sagedral_blocked_ips_active" in metrics.text
    details = await enterprise_client.get(
        "/api/v1/status/details", headers=enterprise_auth
    )
    assert details.status_code == 200

    assert (
        await enterprise_client.delete(
            "/api/v1/alerts/%s" % alert_id, headers=enterprise_auth
        )
    ).status_code == 200
    assert (
        await enterprise_client.delete(
            "/api/v1/rules/%s" % rule_id, headers=enterprise_auth
        )
    ).status_code == 200
    assert (
        await enterprise_client.delete(
            "/api/v1/users/%s" % analyst_id, headers=enterprise_auth
        )
    ).status_code == 200
