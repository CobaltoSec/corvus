"""Tests for OAuthBypassModule."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from corvus.core.models import MCPSurface, OWASPCategory, Severity
from corvus.core.session import ScanSession
from corvus.transport.http import HttpTransport
from corvus.modules.dynamic.oauth_bypass import (
    OAuthBypassModule,
    _detect_auth_headers,
    _detect_auth_in_url,
    _redact_url,
    _try_tools_list,
    _INVALID_BEARER,
)


def _session() -> ScanSession:
    return ScanSession("http://localhost:8000/mcp", "http", Path("/tmp/corvus-test"))


def _surface() -> MCPSurface:
    return MCPSurface(server_name="test-server")


def _http_transport(url: str = "http://localhost:8000/mcp", headers: dict | None = None) -> MagicMock:
    t = MagicMock(spec=HttpTransport)
    t.url = url
    t.timeout = 30.0
    t._extra_headers = headers or {}
    return t


def _stdio_transport() -> MagicMock:
    t = MagicMock()
    t._process = MagicMock()
    # No _client for stdio — but isinstance check matters, so it won't be HttpTransport
    return t


# ── Unit: _detect_auth_headers ────────────────────────────────────────────────

def test_detect_auth_headers_authorization():
    assert _detect_auth_headers({"Authorization": "Bearer tok"}) == ["Authorization"]


def test_detect_auth_headers_x_api_key():
    found = _detect_auth_headers({"X-Api-Key": "secret"})
    assert found == ["X-Api-Key"]


def test_detect_auth_headers_case_insensitive():
    found = _detect_auth_headers({"AUTHORIZATION": "Bearer x"})
    assert found == ["AUTHORIZATION"]


def test_detect_auth_headers_empty():
    assert _detect_auth_headers({}) == []


def test_detect_auth_headers_non_auth():
    assert _detect_auth_headers({"Content-Type": "application/json"}) == []


def test_detect_auth_headers_mixed():
    headers = {"Authorization": "Bearer x", "X-Request-ID": "123", "X-Api-Key": "k"}
    found = _detect_auth_headers(headers)
    assert "Authorization" in found
    assert "X-Api-Key" in found
    assert "X-Request-ID" not in found


# ── Unit: _detect_auth_in_url ─────────────────────────────────────────────────

def test_detect_auth_in_url_token():
    found = _detect_auth_in_url("http://host/mcp?token=abc123")
    assert "token" in found


def test_detect_auth_in_url_api_key():
    found = _detect_auth_in_url("http://host/mcp?api_key=secret")
    assert "api_key" in found


def test_detect_auth_in_url_access_token():
    found = _detect_auth_in_url("http://host/mcp?access_token=xyz")
    assert "access_token" in found


def test_detect_auth_in_url_no_auth_params():
    found = _detect_auth_in_url("http://host/mcp?version=2&format=json")
    assert found == []


def test_detect_auth_in_url_no_query():
    found = _detect_auth_in_url("http://host/mcp")
    assert found == []


# ── Unit: _redact_url ─────────────────────────────────────────────────────────

def test_redact_url_replaces_token():
    url = "http://host/mcp?token=supersecret&version=1"
    redacted = _redact_url(url, ["token"])
    assert "supersecret" not in redacted
    assert "<REDACTED>" in redacted
    assert "version=1" in redacted


def test_redact_url_case_insensitive():
    url = "http://host/mcp?TOKEN=secret"
    redacted = _redact_url(url, ["token"])
    assert "secret" not in redacted


# ── Unit: _try_tools_list ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_try_tools_list_success():
    with patch("corvus.modules.dynamic.oauth_bypass.HttpTransport") as MockHttp:
        instance = AsyncMock()
        instance.__aenter__ = AsyncMock(return_value=instance)
        instance.__aexit__ = AsyncMock(return_value=False)
        instance.send_request = AsyncMock(return_value={"tools": []})
        MockHttp.return_value = instance
        result = await _try_tools_list("http://host/mcp", 10.0, {})
    assert result is True


@pytest.mark.asyncio
async def test_try_tools_list_failure():
    with patch("corvus.modules.dynamic.oauth_bypass.HttpTransport") as MockHttp:
        instance = AsyncMock()
        instance.__aenter__ = AsyncMock(return_value=instance)
        instance.__aexit__ = AsyncMock(return_value=False)
        instance.send_request = AsyncMock(side_effect=RuntimeError("connection refused"))
        MockHttp.return_value = instance
        result = await _try_tools_list("http://host/mcp", 10.0, {})
    assert result is False


@pytest.mark.asyncio
async def test_try_tools_list_caps_timeout():
    captured = {}
    with patch("corvus.modules.dynamic.oauth_bypass.HttpTransport") as MockHttp:
        def capture_init(url, timeout, headers):
            captured["timeout"] = timeout
            inst = AsyncMock()
            inst.__aenter__ = AsyncMock(return_value=inst)
            inst.__aexit__ = AsyncMock(return_value=False)
            inst.send_request = AsyncMock(return_value={"tools": []})
            return inst
        MockHttp.side_effect = capture_init
        await _try_tools_list("http://host/mcp", 120.0, {})
    assert captured["timeout"] == 10.0


# ── Integration: OAuthBypassModule.run ───────────────────────────────────────

@pytest.mark.asyncio
async def test_module_skips_stdio_transport():
    t = _stdio_transport()
    findings = await OAuthBypassModule().run(_surface(), t, _session())
    assert findings == []


@pytest.mark.asyncio
async def test_module_skips_when_no_auth_configured():
    t = _http_transport(headers={"Content-Type": "application/json"})
    findings = await OAuthBypassModule().run(_surface(), t, _session())
    assert findings == []


@pytest.mark.asyncio
async def test_module_detects_token_in_url():
    t = _http_transport(url="http://host/mcp?token=mysecret", headers={})
    findings = await OAuthBypassModule().run(_surface(), t, _session())
    assert findings
    assert any(f.severity == Severity.HIGH for f in findings)
    assert any("URL" in f.title or "query string" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_module_detects_api_key_in_url():
    t = _http_transport(url="http://host/mcp?api_key=secret123", headers={})
    findings = await OAuthBypassModule().run(_surface(), t, _session())
    assert findings
    assert findings[0].owasp_category == OWASPCategory.MCP07_AUTH_AUDIT


@pytest.mark.asyncio
async def test_module_detects_missing_auth_bypass(monkeypatch):
    async def mock_try(url, timeout, headers):
        # Simulate server accepting request with no auth headers
        auth_keys = {k.lower() for k in headers}
        if not any(k in auth_keys for k in ("authorization", "x-api-key")):
            return True
        return True  # probe 1: no auth → success = bypass

    monkeypatch.setattr("corvus.modules.dynamic.oauth_bypass._try_tools_list", mock_try)
    t = _http_transport(headers={"Authorization": "Bearer validtoken"})
    findings = await OAuthBypassModule().run(_surface(), t, _session())
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert critical
    assert "without credentials" in critical[0].title.lower() or "without" in critical[0].title.lower()
    assert critical[0].exploitation_confirmed is True


@pytest.mark.asyncio
async def test_module_detects_invalid_bearer_bypass(monkeypatch):
    async def mock_try(url, timeout, headers):
        auth_val = headers.get("Authorization", headers.get("authorization", ""))
        if auth_val == _INVALID_BEARER:
            return True  # server accepts invalid token
        return False  # server rejects no-auth

    monkeypatch.setattr("corvus.modules.dynamic.oauth_bypass._try_tools_list", mock_try)
    t = _http_transport(headers={"Authorization": "Bearer validtoken"})
    findings = await OAuthBypassModule().run(_surface(), t, _session())
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert critical
    assert "invalid" in critical[0].title.lower()
    assert critical[0].exploitation_confirmed is True


@pytest.mark.asyncio
async def test_module_no_finding_when_auth_enforced(monkeypatch):
    async def mock_try(url, timeout, headers):
        return False  # server always rejects unauthorized requests

    monkeypatch.setattr("corvus.modules.dynamic.oauth_bypass._try_tools_list", mock_try)
    t = _http_transport(headers={"Authorization": "Bearer validtoken"})
    findings = await OAuthBypassModule().run(_surface(), t, _session())
    assert findings == []


@pytest.mark.asyncio
async def test_module_returns_early_after_no_auth_bypass(monkeypatch):
    call_count = 0

    async def mock_try(url, timeout, headers):
        nonlocal call_count
        call_count += 1
        return True  # server accepts everything

    monkeypatch.setattr("corvus.modules.dynamic.oauth_bypass._try_tools_list", mock_try)
    t = _http_transport(headers={"Authorization": "Bearer tok"})
    findings = await OAuthBypassModule().run(_surface(), t, _session())
    # Should return early after probe 1, not run probe 2
    assert call_count == 1
    assert len(findings) == 1


# ── Module metadata ───────────────────────────────────────────────────────────

def test_module_metadata():
    mod = OAuthBypassModule()
    assert mod.name == "oauth-bypass"
    assert mod.owasp_id == "MCP07"
    assert mod.is_static is False
    assert "HTTP" in mod.description or "http" in mod.description.lower()
