"""Tests for EndpointProbeModule (B2 — resources/read + prompts/get)."""
from __future__ import annotations

from pathlib import Path

import pytest

from .conftest import MOCK_SERVER_CMD
from corvus.core.models import OWASPCategory, Severity
from corvus.core.session import ScanSession
from corvus.discovery.enumerator import MCPEnumerator
from corvus.modules.dynamic.endpoint_probe import EndpointProbeModule
from corvus.transport.stdio import StdioTransport


@pytest.mark.asyncio
async def test_endpoint_probe_detects_credential_in_resource():
    """resources/read for secrets URI should leak API_KEY → CRITICAL MCP01."""
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await EndpointProbeModule().run(surface, t, session)

    cred_findings = [
        f for f in findings
        if f.owasp_category == OWASPCategory.MCP01_TOKEN_EXPOSURE
        and f.severity == Severity.CRITICAL
    ]
    assert cred_findings, "Should detect API_KEY credential in secrets resource"


@pytest.mark.asyncio
async def test_endpoint_probe_detects_traversal_via_resource():
    """Traversal probe via resources/read should detect /etc/passwd content."""
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await EndpointProbeModule().run(surface, t, session)

    traversal_findings = [
        f for f in findings
        if f.owasp_category == OWASPCategory.MCP05_CMD_INJECTION
        and f.exploitation_confirmed
    ]
    assert traversal_findings, "Should detect path traversal via resources/read"
    assert any(f.severity == Severity.CRITICAL for f in traversal_findings)


@pytest.mark.asyncio
async def test_endpoint_probe_detects_template_injection_in_prompt():
    """{{7*7}} in prompts/get argument should evaluate to 49 → CRITICAL MCP05."""
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await EndpointProbeModule().run(surface, t, session)

    template_findings = [
        f for f in findings
        if "Template Injection" in f.title and f.exploitation_confirmed
    ]
    assert template_findings, "Should detect template injection via prompts/get"
    assert template_findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_endpoint_probe_skips_when_no_resources_or_prompts():
    """Surface with no resources and no prompts should produce no findings."""
    from corvus.core.models import MCPSurface

    surface = MCPSurface(
        server_name="test",
        server_version="0.1",
        protocol_version="2024-11-05",
        tools=[],
        resources=[],
        prompts=[],
    )
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await EndpointProbeModule().run(surface, t, session)

    assert not findings


@pytest.mark.asyncio
async def test_endpoint_probe_module_metadata():
    mod = EndpointProbeModule()
    assert not mod.is_static
    assert mod.owasp_id == "MCP01"
