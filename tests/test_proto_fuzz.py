"""Tests for proto_fuzz.py — new probes 6/7/8 added in V28."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from corvus.core.models import MCPSurface, OWASPCategory, Severity
from corvus.modules.dynamic.proto_fuzz import (
    ProtoFuzzModule,
    _send_raw_http,
    _send_raw_stdio,
)
from corvus.transport.http import HttpTransport


def _surface() -> MCPSurface:
    return MCPSurface(server_name="test-server")


def _http_transport(url: str = "http://localhost:9999/mcp") -> MagicMock:
    t = MagicMock(spec=HttpTransport)
    t.url = url
    return t


def _stdio_transport() -> MagicMock:
    t = MagicMock()
    # No spec=HttpTransport → isinstance(t, HttpTransport) == False
    del t.spec
    return t


# ── Probe 6: missing jsonrpc field ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_missing_jsonrpc_field_accepted():
    """Server returns result for request without 'jsonrpc' field → LOW finding."""
    t = _http_transport()

    async def mock_send_request(method, params=None):
        raise Exception("not called via send_request")

    t.send_request = AsyncMock(side_effect=Exception("standard probes fail"))

    with patch("corvus.modules.dynamic.proto_fuzz._send_raw_http") as mock_raw, \
         patch("corvus.modules.dynamic.proto_fuzz._send_raw_stdio") as mock_stdio:
        # Probe 6: missing jsonrpc → server accepts
        mock_raw.side_effect = [
            {"result": {"tools": []}},   # probe 6
            {"error": {"code": -32600}}, # probe 7
        ]
        mock_stdio.return_value = None

        # Also mock the standard _probe_method to avoid crash on invalid transport
        with patch("corvus.modules.dynamic.proto_fuzz._probe_method") as mock_probe:
            mock_probe.return_value = (None, -32601)

            # Run only via direct module instantiation with mocked internals
            # Simpler: just test _send_raw_http directly and the finding logic
            pass

    # Direct test: mock at module level
    with patch("corvus.modules.dynamic.proto_fuzz._probe_method", return_value=(None, -32601)), \
         patch("corvus.modules.dynamic.proto_fuzz._send_raw_http",
               return_value={"result": {"tools": []}}), \
         patch("corvus.modules.dynamic.proto_fuzz._send_raw_stdio", return_value=None):
        findings = await ProtoFuzzModule().run(_surface(), t, None)

    low_findings = [f for f in findings if "jsonrpc field" in f.title.lower()]
    assert low_findings, f"Expected LOW finding for missing jsonrpc; got {[f.title for f in findings]}"
    assert low_findings[0].severity == Severity.LOW


@pytest.mark.asyncio
async def test_missing_jsonrpc_field_rejected():
    """Server returns error for request without 'jsonrpc' field → no finding."""
    t = _http_transport()
    with patch("corvus.modules.dynamic.proto_fuzz._probe_method", return_value=(None, -32601)), \
         patch("corvus.modules.dynamic.proto_fuzz._send_raw_http",
               return_value={"error": {"code": -32600, "message": "Invalid Request"}}), \
         patch("corvus.modules.dynamic.proto_fuzz._send_raw_stdio", return_value=None):
        findings = await ProtoFuzzModule().run(_surface(), t, None)

    low_findings = [f for f in findings if "jsonrpc field" in f.title.lower()]
    assert not low_findings


@pytest.mark.asyncio
async def test_array_id_accepted():
    """Server accepts array request ID → MEDIUM finding."""
    t = _http_transport()
    with patch("corvus.modules.dynamic.proto_fuzz._probe_method", return_value=(None, -32601)), \
         patch("corvus.modules.dynamic.proto_fuzz._send_raw_http",
               side_effect=[
                   {"error": {"code": -32600}},   # probe 6 rejected
                   {"result": {"tools": []}},      # probe 7 accepted
               ]), \
         patch("corvus.modules.dynamic.proto_fuzz._send_raw_stdio", return_value=None):
        findings = await ProtoFuzzModule().run(_surface(), t, None)

    medium_findings = [f for f in findings if "array request id" in f.title.lower()]
    assert medium_findings, f"Expected MEDIUM for array ID; got {[f.title for f in findings]}"
    assert medium_findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_meta_token_reflected():
    """progressToken reflected in response → MEDIUM finding."""
    t = _http_transport()

    async def mock_send_request(method, params=None):
        if method == "tools/list" and params and "_meta" in params:
            token = params["_meta"].get("progressToken", "")
            return {"tools": [], "debug": token}  # echoes the token
        raise Exception("other call")

    t.send_request = mock_send_request

    with patch("corvus.modules.dynamic.proto_fuzz._probe_method", return_value=(None, -32601)), \
         patch("corvus.modules.dynamic.proto_fuzz._send_raw_http",
               return_value={"error": {"code": -32600}}), \
         patch("corvus.modules.dynamic.proto_fuzz._send_raw_stdio", return_value=None):
        findings = await ProtoFuzzModule().run(_surface(), t, None)

    meta_findings = [f for f in findings if "progresstoken" in f.title.lower() or "_meta" in f.title.lower()]
    assert meta_findings, f"Expected _meta finding; got {[f.title for f in findings]}"
    assert meta_findings[0].severity == Severity.MEDIUM
