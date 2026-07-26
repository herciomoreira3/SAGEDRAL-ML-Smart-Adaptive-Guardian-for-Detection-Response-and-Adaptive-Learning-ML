"""Regression tests for monitoring-friendly CLI commands."""

import requests
from click.testing import CliRunner

import sagedral_ml.cli as cli_module


class StubResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


def test_status_uses_public_endpoint_without_login(monkeypatch):
    requested_urls = []
    monkeypatch.setattr(cli_module, "_api_headers", lambda: {})

    def fake_get(url, **_kwargs):
        requested_urls.append(url)
        return StubResponse(
            200,
            {
                "status": "running",
                "version": "1.0.0",
                "uptime_seconds": 42,
            },
        )

    monkeypatch.setattr(cli_module.requests, "get", fake_get)
    result = CliRunner().invoke(cli_module.main, ["status"])

    assert result.exit_code == 0, result.output
    assert "Service: RUNNING" in result.output
    assert "login required" in result.output
    assert requested_urls == [cli_module.API_BASE + "/status"]


def test_status_shows_authenticated_details(monkeypatch):
    monkeypatch.setattr(
        cli_module,
        "_api_headers",
        lambda: {"Authorization": "Bearer valid"},
    )
    monkeypatch.setattr(
        cli_module.requests,
        "get",
        lambda *_args, **_kwargs: StubResponse(
            200,
            {
                "interface": "enp0s8",
                "uptime_seconds": 99,
                "blocked_ips_count": 3,
                "ml_model_loaded": True,
            },
        ),
    )

    result = CliRunner().invoke(cli_module.main, ["status"])

    assert result.exit_code == 0, result.output
    assert "enp0s8" in result.output
    assert "Active Blocked IPs: 3" in result.output
    assert "ML Model Loaded:   True" in result.output


def test_status_falls_back_when_token_expired(monkeypatch):
    requested_urls = []
    monkeypatch.setattr(
        cli_module,
        "_api_headers",
        lambda: {"Authorization": "Bearer expired"},
    )

    def fake_get(url, **_kwargs):
        requested_urls.append(url)
        if url.endswith("/status/details"):
            return StubResponse(401, {"detail": "Could not validate credentials"})
        return StubResponse(
            200,
            {
                "status": "running",
                "version": "1.0.0",
                "uptime_seconds": 7,
            },
        )

    monkeypatch.setattr(cli_module.requests, "get", fake_get)
    result = CliRunner().invoke(cli_module.main, ["status"])

    assert result.exit_code == 0, result.output
    assert "Service: RUNNING" in result.output
    assert "token rejected/expired" in result.output
    assert requested_urls == [
        cli_module.API_BASE + "/status/details",
        cli_module.API_BASE + "/status",
    ]


def test_status_returns_nonzero_when_api_unreachable(monkeypatch):
    monkeypatch.setattr(cli_module, "_api_headers", lambda: {})

    def fail_get(*_args, **_kwargs):
        raise requests.ConnectionError("connection refused")

    monkeypatch.setattr(cli_module.requests, "get", fail_get)
    result = CliRunner().invoke(cli_module.main, ["status"])

    assert result.exit_code == 1
    assert "STOPPED / UNREACHABLE" in result.output
    assert "connection refused" in result.output
