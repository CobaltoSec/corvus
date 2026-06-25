"""Tests for v0.4.0 modules: log-audit (MCP10)."""
from pathlib import Path

import pytest

from .conftest import MOCK_SERVER_CMD
from corvus.core.models import OWASPCategory, Severity
from corvus.core.session import ScanSession
from corvus.discovery.enumerator import MCPEnumerator
from corvus.modules.static.log_audit import LogAuditModule
from corvus.transport.stdio import StdioTransport


@pytest.mark.asyncio
async def test_log_audit_detects_clear_audit_log():
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await LogAuditModule().run(surface, t, session)

    flagged = [f for f in findings if f.tool_name == "clear_audit_log"]
    assert flagged, "Expected finding for clear_audit_log"
    assert any(f.severity == Severity.CRITICAL for f in flagged)
    assert any(f.owasp_category == OWASPCategory.MCP08_LOG_AUDIT for f in flagged)


@pytest.mark.asyncio
async def test_log_audit_detects_get_access_log():
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await LogAuditModule().run(surface, t, session)

    flagged = [f for f in findings if f.tool_name == "get_access_log"]
    assert flagged, "Expected finding for get_access_log"
    assert any(f.severity == Severity.HIGH for f in flagged)
    assert any(f.owasp_category == OWASPCategory.MCP08_LOG_AUDIT for f in flagged)


@pytest.mark.asyncio
async def test_log_audit_clean_tools_not_flagged():
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await LogAuditModule().run(surface, t, session)

    log_flagged = {f.tool_name for f in findings if f.owasp_category == OWASPCategory.MCP08_LOG_AUDIT}
    for clean in ("echo", "add_numbers", "get_time"):
        assert clean not in log_flagged, f"'{clean}' should not be flagged by log-audit"


@pytest.mark.asyncio
async def test_log_audit_returns_list():
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await LogAuditModule().run(surface, t, session)
    assert isinstance(findings, list)
