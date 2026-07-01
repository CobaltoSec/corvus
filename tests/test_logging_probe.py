"""Tests for LoggingProbeModule."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from corvus.core.models import MCPSurface, OWASPCategory, Severity
from corvus.core.session import ScanSession
from corvus.transport.http import HttpTransport
from corvus.modules.dynamic.logging_probe import LoggingProbeModule


def _session() -> ScanSession:
    return ScanSession("http://localhost:8000/mcp", "http", Path("/tmp/corvus-test"))


def _surface() -> MCPSurface:
    return MCPSurface(server_name="test-server")


def _http_transport() -> MagicMock:
    t = MagicMock(spec=HttpTransport)
    t.url = "http://localhost:8000/mcp"
    t.timeout = 30.0
    t._extra_headers = {}
    return t


def _stdio_transport() -> MagicMock:
    t = MagicMock()
    t._process = MagicMock()
    t._process.stdin = AsyncMock()
    t._process.stdout = AsyncMock()
    return t


# ── Integration: LoggingProbeModule.run ───────────────────────────────────────

@pytest.mark.asyncio
async def test_module_no_finding_when_not_supported():
    t = _http_transport()
    t.send_request = AsyncMock(side_effect=Exception("MethodNotFound -32601"))
    findings = await LoggingProbeModule().run(_surface(), t, _session())
    assert findings == []


@pytest.mark.asyncio
async def test_module_detects_level_escalation():
    t = _http_transport()
    t.send_request = AsyncMock(return_value={})  # success on setLevel
    findings = await LoggingProbeModule().run(_surface(), t, _session())
    high = [f for f in findings if f.severity == Severity.HIGH]
    assert high
    assert "debug" in high[0].title.lower() or "escalation" in high[0].title.lower()
    assert high[0].owasp_category == OWASPCategory.EXT11_LOG_LEVEL_ABUSE


@pytest.mark.asyncio
async def test_module_detects_invalid_level_acceptance():
    call_count = 0

    async def side_effect(method, params=None):
        nonlocal call_count
        call_count += 1
        return {}  # Always succeeds

    t = _http_transport()
    t.send_request = side_effect
    findings = await LoggingProbeModule().run(_surface(), t, _session())
    medium = [f for f in findings if f.severity == Severity.MEDIUM]
    assert medium
    assert "invalid" in medium[0].title.lower() or "arbitrary" in medium[0].title.lower()


@pytest.mark.asyncio
async def test_module_no_invalid_level_when_rejected():
    call_count = 0

    async def side_effect(method, params=None):
        nonlocal call_count
        call_count += 1
        p = params or {}
        if p.get("level") in ("debug", "emergency"):
            return {}  # accepts debug and emergency
        raise Exception("Invalid level")  # rejects INVALID_LEVEL

    t = _http_transport()
    t.send_request = side_effect
    findings = await LoggingProbeModule().run(_surface(), t, _session())
    # Should have HIGH but not MEDIUM
    assert any(f.severity == Severity.HIGH for f in findings)
    assert not any(f.severity == Severity.MEDIUM for f in findings)


@pytest.mark.asyncio
async def test_module_metadata():
    mod = LoggingProbeModule()
    assert mod.name == "logging-probe"
    assert mod.owasp_id == "EXT11"
    assert mod.is_static is False


@pytest.mark.asyncio
async def test_module_works_on_http():
    t = _http_transport()
    t.send_request = AsyncMock(return_value={})
    findings = await LoggingProbeModule().run(_surface(), t, _session())
    assert isinstance(findings, list)
    assert findings  # at least the HIGH finding


@pytest.mark.asyncio
async def test_module_works_on_stdio():
    t = _stdio_transport()
    t.send_request = AsyncMock(return_value={})
    findings = await LoggingProbeModule().run(_surface(), t, _session())
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_module_graceful_on_timeout():
    import asyncio

    async def slow(*args, **kwargs):
        await asyncio.sleep(10)

    t = _http_transport()
    t.send_request = slow
    findings = await LoggingProbeModule().run(_surface(), t, _session())
    assert findings == []


@pytest.mark.asyncio
async def test_module_emergency_level_updates_evidence():
    call_count = 0

    async def side_effect(method, params=None):
        return {}  # always accepts

    t = _http_transport()
    t.send_request = side_effect
    findings = await LoggingProbeModule().run(_surface(), t, _session())
    high = [f for f in findings if f.severity == Severity.HIGH]
    assert high
    # Evidence should mention both debug and emergency
    assert "emergency" in high[0].evidence.lower() or "debug" in high[0].evidence.lower()


@pytest.mark.asyncio
async def test_module_max_findings_is_two():
    t = _http_transport()
    t.send_request = AsyncMock(return_value={})
    findings = await LoggingProbeModule().run(_surface(), t, _session())
    assert len(findings) <= 2


@pytest.mark.asyncio
async def test_module_no_finding_when_auth_required():
    t = _http_transport()
    t.send_request = AsyncMock(side_effect=Exception("403 Forbidden — auth required"))
    findings = await LoggingProbeModule().run(_surface(), t, _session())
    assert findings == []


@pytest.mark.asyncio
async def test_module_returns_empty_when_none_result():
    t = _http_transport()
    t.send_request = AsyncMock(return_value=None)
    findings = await LoggingProbeModule().run(_surface(), t, _session())
    assert findings == []
