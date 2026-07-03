"""Tests for CancellationProbeModule."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from corvus.core.models import MCPSurface, OWASPCategory, Severity
from corvus.core.session import ScanSession
from corvus.transport.http import HttpTransport
from corvus.modules.dynamic.cancellation_probe import (
    CancellationProbeModule,
    _write_raw,
    _read_response,
    _server_alive,
)


def _session() -> ScanSession:
    return ScanSession("stdio://test", "stdio", Path("/tmp/corvus-test"))


def _surface() -> MCPSurface:
    return MCPSurface(server_name="test-server")


def _http_transport() -> MagicMock:
    t = MagicMock(spec=HttpTransport)
    t.url = "http://localhost:8000/mcp"
    t._extra_headers = {}
    # No _process attribute → not stdio
    return t


def _stdio_transport() -> MagicMock:
    t = MagicMock()
    proc = MagicMock()
    proc.stdin = AsyncMock()
    proc.stdout = AsyncMock()
    t._process = proc
    t.send_request = AsyncMock(return_value={"tools": []})
    return t


# ── Unit: _write_raw ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_write_raw_no_process():
    t = MagicMock()
    t._process = None
    result = await _write_raw(t, {"test": "msg"})
    assert result is False


@pytest.mark.asyncio
async def test_write_raw_success():
    t = _stdio_transport()
    result = await _write_raw(t, {"jsonrpc": "2.0", "method": "test"})
    assert result is True


# ── Unit: _read_response ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_read_response_no_process():
    t = MagicMock()
    t._process = None
    result = await _read_response(t, 1.0)
    assert result is None


@pytest.mark.asyncio
async def test_read_response_valid_json():
    t = _stdio_transport()
    response = {"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}
    t._process.stdout.readline = AsyncMock(
        return_value=(json.dumps(response) + "\n").encode()
    )
    result = await _read_response(t, 1.0)
    assert result == response


# ── Integration: CancellationProbeModule.run ──────────────────────────────────

@pytest.mark.asyncio
async def test_module_skips_http_transport():
    t = _http_transport()
    findings = await CancellationProbeModule().run(_surface(), t, _session())
    assert findings == []


@pytest.mark.asyncio
async def test_module_skips_when_no_process():
    t = MagicMock()
    t._process = None
    findings = await CancellationProbeModule().run(_surface(), t, _session())
    assert findings == []


@pytest.mark.asyncio
async def test_module_detects_hang_after_unknown_cancel():
    t = _stdio_transport()
    call_count = 0

    async def readline():
        nonlocal call_count
        call_count += 1
        if call_count <= 2:  # first two reads timeout
            await asyncio.sleep(10)
        return b""

    t._process.stdout.readline = readline
    findings = await CancellationProbeModule().run(_surface(), t, _session())
    high = [f for f in findings if f.severity == Severity.HIGH]
    assert high


@pytest.mark.asyncio
async def test_module_info_when_server_responds_normally():
    t = _stdio_transport()
    response = {"jsonrpc": "2.0", "id": 8200, "result": {"tools": []}}

    t._process.stdout.readline = AsyncMock(
        return_value=(json.dumps(response) + "\n").encode()
    )
    findings = await CancellationProbeModule().run(_surface(), t, _session())
    # Should have at least some findings (INFO level)
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_module_metadata():
    mod = CancellationProbeModule()
    assert mod.name == "cancellation-probe"
    assert mod.owasp_id == "EXT14"
    assert mod.is_static is False


@pytest.mark.asyncio
async def test_module_owasp_category():
    t = _stdio_transport()
    response = {"jsonrpc": "2.0", "id": 8200, "result": {"tools": []}}
    t._process.stdout.readline = AsyncMock(
        return_value=(json.dumps(response) + "\n").encode()
    )
    findings = await CancellationProbeModule().run(_surface(), t, _session())
    for f in findings:
        assert f.owasp_category == OWASPCategory.EXT14_CANCELLATION_RACE


@pytest.mark.asyncio
async def test_module_detects_flood_unresponsive():
    t = _stdio_transport()
    call_count = 0

    async def readline():
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # First tools/list responds normally
            response = {"jsonrpc": "2.0", "id": 8200, "result": {"tools": []}}
            return (json.dumps(response) + "\n").encode()
        # After flood, server doesn't respond
        await asyncio.sleep(10)
        return b""

    t._process.stdout.readline = readline
    findings = await CancellationProbeModule().run(_surface(), t, _session())
    high_flood = [f for f in findings if "flood" in f.title.lower()]
    assert high_flood


@pytest.mark.asyncio
async def test_module_returns_list_always():
    t = _stdio_transport()
    t._process.stdout.readline = AsyncMock(return_value=b"")
    findings = await CancellationProbeModule().run(_surface(), t, _session())
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_write_raw_write_error():
    t = _stdio_transport()
    t._process.stdin.write = MagicMock(side_effect=OSError("broken pipe"))
    result = await _write_raw(t, {"test": "msg"})
    assert result is False


@pytest.mark.asyncio
async def test_server_alive_returns_true():
    t = _stdio_transport()
    t.send_request = AsyncMock(return_value={"tools": []})
    alive = await _server_alive(t)
    assert alive is True


@pytest.mark.asyncio
async def test_server_alive_returns_false_on_exception():
    t = _stdio_transport()
    t.send_request = AsyncMock(side_effect=Exception("connection lost"))
    alive = await _server_alive(t)
    assert alive is False


@pytest.mark.asyncio
async def test_module_skips_when_server_already_dead():
    """Server dead before probe (e.g. from prior proto_fuzz) → no EXT14 cascade FP."""
    t = _stdio_transport()
    t.send_request = AsyncMock(side_effect=Exception("server already dead"))
    findings = await CancellationProbeModule().run(_surface(), t, _session())
    assert findings == []
