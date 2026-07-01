"""Tests for the BatchDosModule."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from corvus.core.models import MCPSurface, OWASPCategory, Severity
from corvus.core.session import ScanSession
from corvus.modules.dynamic.batch_dos import (
    BatchDosModule,
    _check_alive,
    _check_batch_accepted,
    _make_batch,
    _safe_str,
)
from corvus.transport.base import JSONRPCError


# ── Helpers ──────────────────────────────────────────────────────────────────

def _session() -> ScanSession:
    return ScanSession("npx -y test-server", "stdio", Path("/tmp/corvus-test"))


def _surface() -> MCPSurface:
    return MCPSurface(server_name="test-server")


def _stdio_transport(
    *,
    process_alive: bool = True,
    send_request_result=None,
    send_request_raises=None,
) -> MagicMock:
    """Return a mock that looks like a StdioTransport."""
    t = MagicMock()
    process = MagicMock()
    process.stdin = MagicMock()
    process.stdin.write = MagicMock()
    process.stdin.drain = AsyncMock()
    process.stdout = MagicMock()

    if not process_alive:
        process.stdin.drain.side_effect = BrokenPipeError("pipe closed")

    t._process = process
    # No _client attribute for stdio
    del t._client

    if send_request_raises:
        t.send_request = AsyncMock(side_effect=send_request_raises)
    else:
        t.send_request = AsyncMock(return_value=send_request_result or {"tools": []})

    return t


def _http_transport(
    *,
    send_request_result=None,
    send_request_raises=None,
) -> MagicMock:
    """Return a mock that looks like an HttpTransport."""
    t = MagicMock()
    t._client = AsyncMock()
    # No _process attribute for http
    del t._process

    if send_request_raises:
        t.send_request = AsyncMock(side_effect=send_request_raises)
    else:
        t.send_request = AsyncMock(return_value=send_request_result or {"tools": []})

    return t


# ── Unit: _make_batch ─────────────────────────────────────────────────────────

def test_make_batch_size():
    batch = _make_batch(5)
    assert len(batch) == 5


def test_make_batch_ids():
    batch = _make_batch(3, start_id=9000)
    assert [b["id"] for b in batch] == [9000, 9001, 9002]


def test_make_batch_method():
    batch = _make_batch(2)
    assert all(b["method"] == "tools/list" for b in batch)


def test_make_batch_jsonrpc_version():
    batch = _make_batch(1)
    assert batch[0]["jsonrpc"] == "2.0"


# ── Unit: _safe_str ───────────────────────────────────────────────────────────

def test_safe_str_bytes():
    assert _safe_str(b"hello") == "hello"


def test_safe_str_int():
    assert _safe_str(200) == "200"


def test_safe_str_invalid_bytes():
    assert _safe_str(b"\xff\xfe") == "��"


# ── Unit: _check_alive ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_check_alive_returns_true_on_success():
    t = MagicMock()
    t.send_request = AsyncMock(return_value={"tools": []})
    assert await _check_alive(t) is True


@pytest.mark.asyncio
async def test_check_alive_returns_true_on_jsonrpc_error():
    t = MagicMock()
    t.send_request = AsyncMock(side_effect=JSONRPCError(-32601, "Not found"))
    assert await _check_alive(t) is True


@pytest.mark.asyncio
async def test_check_alive_returns_true_on_attribute_error():
    t = MagicMock()
    t.send_request = AsyncMock(side_effect=AttributeError("list has no .get"))
    assert await _check_alive(t) is True


@pytest.mark.asyncio
async def test_check_alive_returns_false_on_runtime_error():
    t = MagicMock()
    t.send_request = AsyncMock(side_effect=RuntimeError("Server closed stdout"))
    assert await _check_alive(t) is False


# ── Unit: _check_batch_accepted ───────────────────────────────────────────────

def test_check_batch_accepted_http_200_array():
    import json
    findings: list = []
    array_body = json.dumps([{"jsonrpc": "2.0", "id": 9000, "result": {"tools": []}}])
    _check_batch_accepted(200, array_body, 5, True, findings)
    assert findings
    assert findings[0].severity == Severity.MEDIUM
    assert "HTTP" in findings[0].title


def test_check_batch_accepted_http_non_200_no_finding():
    findings: list = []
    _check_batch_accepted(400, '{"error": "bad request"}', 5, True, findings)
    assert not findings


def test_check_batch_accepted_http_200_non_array_no_finding():
    findings: list = []
    _check_batch_accepted(200, '{"error": {"code": -32600, "message": "Invalid Request"}}', 5, True, findings)
    assert not findings


def test_check_batch_accepted_stdio_array():
    import json
    findings: list = []
    array_raw = json.dumps([{"jsonrpc": "2.0", "id": 9000, "result": {}}]).encode()
    _check_batch_accepted(array_raw, "", 5, False, findings)
    assert findings
    assert "stdio" in findings[0].title


def test_check_batch_accepted_stdio_error_object_no_finding():
    import json
    findings: list = []
    error_raw = json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32600}}).encode()
    _check_batch_accepted(error_raw, "", 5, False, findings)
    assert not findings


def test_check_batch_accepted_empty_bytes_no_finding():
    findings: list = []
    _check_batch_accepted(b"", "", 5, False, findings)
    assert not findings


# ── Integration: BatchDosModule.run (mocked transport) ───────────────────────

@pytest.mark.asyncio
async def test_module_skips_unsupported_transport():
    t = MagicMock()
    # No _process or _client attributes
    del t._process
    del t._client
    findings = await BatchDosModule().run(_surface(), t, _session())
    assert findings == []


@pytest.mark.asyncio
async def test_module_reports_crash_on_small_batch(monkeypatch):
    """Server disconnects after receiving small batch → HIGH crash finding."""
    t = _stdio_transport()

    call_count = 0

    async def mock_send_batch(transport, batch):
        return b"", ""

    async def mock_check_alive(transport):
        nonlocal call_count
        call_count += 1
        # First alive check (after small batch) → dead
        if call_count == 1:
            return False
        return True

    monkeypatch.setattr("corvus.modules.dynamic.batch_dos._send_batch", mock_send_batch)
    monkeypatch.setattr("corvus.modules.dynamic.batch_dos._check_alive", mock_check_alive)

    findings = await BatchDosModule().run(_surface(), t, _session())
    assert findings
    assert findings[0].severity == Severity.HIGH
    assert "crash" in findings[0].title.lower()
    # Should return early — only one finding
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_module_reports_large_batch_crash(monkeypatch):
    """Small batch OK, large batch crashes → HIGH DoS finding."""
    batch_count = 0

    async def mock_send_batch(transport, batch):
        nonlocal batch_count
        batch_count += 1
        return b'{"error": {"code": -32600}}', ""

    alive_count = 0

    async def mock_check_alive(transport):
        nonlocal alive_count
        alive_count += 1
        if alive_count == 1:
            return True  # alive after small batch
        return False  # dead after large batch

    monkeypatch.setattr("corvus.modules.dynamic.batch_dos._send_batch", mock_send_batch)
    monkeypatch.setattr("corvus.modules.dynamic.batch_dos._check_alive", mock_check_alive)

    t = _stdio_transport()
    findings = await BatchDosModule().run(_surface(), t, _session())
    assert findings
    dos = [f for f in findings if f.severity == Severity.HIGH]
    assert dos
    assert "large" in dos[0].title.lower() or "50" in dos[0].title


@pytest.mark.asyncio
async def test_module_reports_batch_accepted(monkeypatch):
    """Server returns array response → MEDIUM finding."""
    import json

    async def mock_send_batch(transport, batch):
        array_resp = json.dumps([{"jsonrpc": "2.0", "id": i + 9000, "result": {}} for i in range(5)])
        return array_resp.encode(), ""

    async def mock_check_alive(transport):
        return True

    monkeypatch.setattr("corvus.modules.dynamic.batch_dos._send_batch", mock_send_batch)
    monkeypatch.setattr("corvus.modules.dynamic.batch_dos._check_alive", mock_check_alive)

    t = _stdio_transport()
    findings = await BatchDosModule().run(_surface(), t, _session())
    medium = [f for f in findings if f.severity == Severity.MEDIUM]
    assert medium
    assert "batch" in medium[0].title.lower()


@pytest.mark.asyncio
async def test_module_no_finding_when_server_rejects(monkeypatch):
    """Server rejects batch with error → no finding."""
    import json

    async def mock_send_batch(transport, batch):
        error_resp = json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}})
        return error_resp.encode(), ""

    async def mock_check_alive(transport):
        return True

    monkeypatch.setattr("corvus.modules.dynamic.batch_dos._send_batch", mock_send_batch)
    monkeypatch.setattr("corvus.modules.dynamic.batch_dos._check_alive", mock_check_alive)

    t = _stdio_transport()
    findings = await BatchDosModule().run(_surface(), t, _session())
    # No crash, no batch acceptance → either empty or at most MEDIUM for large batch acceptance
    assert all(f.severity != Severity.HIGH for f in findings)


# ── Module metadata ───────────────────────────────────────────────────────────

def test_module_metadata():
    mod = BatchDosModule()
    assert mod.name == "batch-dos"
    assert mod.owasp_id == "EXT01"
    assert not mod.is_static
