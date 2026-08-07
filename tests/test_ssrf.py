"""Tests for the SSRF module (B1) — including _verify_critical timing FP suppression."""
from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from corvus.core.models import MCPSurface, OWASPCategory, Severity, ToolSpec
from corvus.core.session import ScanSession
from corvus.discovery.enumerator import MCPEnumerator
from corvus.modules.dynamic.ssrf import SSRFModule
from corvus.transport.stdio import StdioTransport

MOCK_SSRF_CMD = ["python", str(Path(__file__).parent / "mock_ssrf_server.py")]


@pytest.mark.asyncio
async def test_ssrf_detects_metadata_content():
    """fetch_url with 169.254.169.254 returns metadata — CRITICAL SSRF confirmed."""
    async with StdioTransport(MOCK_SSRF_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await SSRFModule().run(surface, t, session)

    ssrf_findings = [f for f in findings if f.owasp_category == OWASPCategory.EXT04_SSRF]
    assert ssrf_findings, "SSRF module should detect metadata content in fetch_url response"

    critical = [f for f in ssrf_findings if f.severity == Severity.CRITICAL]
    assert critical, "Should emit CRITICAL finding when metadata content is detected"
    assert critical[0].exploitation_confirmed
    assert critical[0].confidence >= 85
    assert "fetch_url" in critical[0].tool_name


@pytest.mark.asyncio
async def test_ssrf_no_fp_on_benign_tool():
    """probe_host has a 'host' param but returns no metadata — no CRITICAL SSRF."""
    async with StdioTransport(MOCK_SSRF_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await SSRFModule().run(surface, t, session)

    # probe_host should not generate a CRITICAL confirmed finding
    critical = [
        f for f in findings
        if f.severity == Severity.CRITICAL and f.exploitation_confirmed
        and f.tool_name == "probe_host"
    ]
    assert not critical, "probe_host should not produce a confirmed CRITICAL SSRF"


@pytest.mark.asyncio
async def test_ssrf_module_metadata():
    mod = SSRFModule()
    assert mod.owasp_id == "EXT04"
    assert not mod.is_static


@pytest.mark.asyncio
async def test_ssrf_skips_tools_without_url_params():
    """A server with no URL-like params should produce no SSRF findings."""
    from corvus.core.models import MCPSurface, ToolSpec

    surface = MCPSurface(
        server_name="test",
        server_version="0.1",
        protocol_version="2024-11-05",
        tools=[ToolSpec(name="echo", description="Echo", input_schema={
            "type": "object",
            "properties": {"message": {"type": "string"}},
        })],
    )
    async with StdioTransport(MOCK_SSRF_CMD) as t:
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await SSRFModule().run(surface, t, session)

    assert not findings, "No SSRF findings expected for tools without URL params"


# ── _verify_critical timing FP suppression tests ─────────────────────────────


def _make_url_surface() -> MCPSurface:
    """Minimal surface with one URL-param tool for timing tests."""
    return MCPSurface(
        server_name="test",
        server_version="0.1",
        protocol_version="2024-11-05",
        tools=[ToolSpec(
            name="fetch",
            description="Fetch a URL",
            input_schema={
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
        )],
    )


def _make_timeout_transport():
    """Mock transport that raises TimeoutError for SSRF payloads, returns OK otherwise."""
    _SSRF_HOSTS = ("169.254.169.254", "metadata.google", "100.100.100.200")

    async def send_request(method, params):
        if method == "tools/call":
            url_val = (params.get("arguments") or {}).get("url", "")
            if any(h in url_val for h in _SSRF_HOSTS):
                raise asyncio.TimeoutError()
        return {"content": [{"type": "text", "text": "ok"}]}

    mock = MagicMock()
    mock.send_request = send_request
    return mock


@pytest.mark.asyncio
async def test_ssrf_no_high_when_verify_returns_false():
    """Single timeout hit + _verify_timing→False → no HIGH (cold-start FP suppressed)."""
    surface = _make_url_surface()
    transport = _make_timeout_transport()
    module = SSRFModule()
    session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))

    with patch("corvus.modules.dynamic.ssrf._probe_imds_chain", new=AsyncMock(return_value=None)):
        with patch.object(module, "_verify_timing", new=AsyncMock(return_value=False)):
            findings = await module.run(surface, transport, session)

    high = [f for f in findings if f.severity == Severity.HIGH]
    assert not high, (
        "A single timeout hit with _verify_timing=False must NOT produce HIGH "
        "(cold-start FP suppression)"
    )


@pytest.mark.asyncio
async def test_ssrf_high_emitted_when_verify_returns_true():
    """Single timeout hit + _verify_timing→True → HIGH is correctly emitted."""
    surface = _make_url_surface()
    transport = _make_timeout_transport()
    module = SSRFModule()
    session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))

    with patch("corvus.modules.dynamic.ssrf._probe_imds_chain", new=AsyncMock(return_value=None)):
        with patch.object(module, "_verify_timing", new=AsyncMock(return_value=True)):
            findings = await module.run(surface, transport, session)

    high = [f for f in findings if f.severity == Severity.HIGH]
    assert high, "Verified timing SSRF (≥2/3 probes) must emit HIGH"
    assert high[0].tool_name == "fetch"


@pytest.mark.asyncio
async def test_ssrf_skips_search_params_despite_url_desc():
    """Docs-fetch tool: description triggers _URL_DESC, but 'query' param is excluded.

    Regression for issue #1: tools whose description says 'fetch' or 'browse' but
    whose params are search terms (query, q, term, …) must not be SSRF-probed via
    those params — timing signals from cache misses would otherwise produce FP HIGHs.
    """
    surface = MCPSurface(
        server_name="test",
        server_version="0.1",
        protocol_version="2024-11-05",
        tools=[ToolSpec(
            name="get_docs",
            description="Search and pre-fetch every page from the documentation.",
            input_schema={
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
        )],
    )
    mock = MagicMock()
    mock.send_request = AsyncMock(return_value={"content": [{"type": "text", "text": "ok"}]})
    session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
    findings = await SSRFModule().run(surface, mock, session)
    assert not findings, (
        "'query' param must not be SSRF-probed even when tool description triggers _URL_DESC"
    )
