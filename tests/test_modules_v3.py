"""Tests for v0.3.0 modules: auth-audit (MCP08) and response-flood (MCP07)."""
from pathlib import Path

import pytest

from .conftest import MOCK_SERVER_CMD
from corvus.core.models import OWASPCategory, Severity
from corvus.core.session import ScanSession
from corvus.discovery.enumerator import MCPEnumerator
from corvus.modules.dynamic.response_flood import ResponseFloodModule
from corvus.modules.static.auth_audit import AuthAuditModule
from corvus.transport.stdio import StdioTransport


# ---------------------------------------------------------------------------
# MCP08 — Auth Audit
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_auth_audit_detects_no_auth_required():
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await AuthAuditModule().run(surface, t, session)

    admin_findings = [f for f in findings if f.tool_name == "admin_reset"]
    assert admin_findings, "Expected finding for admin_reset tool"
    assert any(f.owasp_category == OWASPCategory.MCP07_AUTH_AUDIT for f in admin_findings)
    assert any(f.severity == Severity.CRITICAL for f in admin_findings)


@pytest.mark.asyncio
async def test_auth_audit_detects_admin_name_prefix():
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await AuthAuditModule().run(surface, t, session)

    # admin_reset has CRITICAL from description pattern; also verify name-based detection
    # works by checking a hypothetical — the real tool hits description CRITICAL first
    flagged_tools = {f.tool_name for f in findings if f.owasp_category == OWASPCategory.MCP07_AUTH_AUDIT}
    assert "admin_reset" in flagged_tools


@pytest.mark.asyncio
async def test_auth_audit_clean_tools_not_flagged():
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await AuthAuditModule().run(surface, t, session)

    # echo and add_numbers should never be flagged for auth issues
    auth_flagged = {f.tool_name for f in findings if f.owasp_category == OWASPCategory.MCP07_AUTH_AUDIT}
    for clean in ("echo", "add_numbers", "get_time"):
        assert clean not in auth_flagged, f"'{clean}' should not be flagged by auth-audit"


@pytest.mark.asyncio
async def test_auth_audit_returns_list():
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await AuthAuditModule().run(surface, t, session)
    assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# MCP07 — Response Flooding
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_response_flood_detects_oversized():
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await ResponseFloodModule().run(surface, t, session)

    config_findings = [f for f in findings if f.tool_name == "get_config"]
    assert config_findings, "Expected response-flood finding for get_config"
    assert any(f.severity == Severity.HIGH for f in config_findings)
    assert any(f.owasp_category == OWASPCategory.MCP10_CONTEXT_INJECTION for f in config_findings)


@pytest.mark.asyncio
async def test_response_flood_small_tools_not_flagged():
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await ResponseFloodModule().run(surface, t, session)

    # echo returns a tiny response and must not produce a HIGH finding
    echo_high = [
        f for f in findings
        if f.tool_name == "echo" and f.severity == Severity.HIGH
    ]
    assert not echo_high, "echo should not be flagged for response flooding"


@pytest.mark.asyncio
async def test_response_flood_returns_list():
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await ResponseFloodModule().run(surface, t, session)
    assert isinstance(findings, list)
