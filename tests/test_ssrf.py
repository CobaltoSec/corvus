"""Tests for the SSRF module (B1)."""
from __future__ import annotations

from pathlib import Path

import pytest

from corvus.core.models import OWASPCategory, Severity
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
