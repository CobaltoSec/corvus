"""Tests for v0.2.0 modules: shadow-tool (MCP03) and rug-pull (MCP06)."""
from pathlib import Path

import pytest

from .conftest import MOCK_SERVER_CMD, MUTATING_SERVER_CMD
from corvus.core.models import OWASPCategory, Severity
from corvus.core.session import ScanSession
from corvus.discovery.enumerator import MCPEnumerator
from corvus.modules.dynamic.rug_pull import RugPullModule
from corvus.modules.static.shadow_tool import ShadowToolModule
from corvus.transport.stdio import StdioTransport


# ---------------------------------------------------------------------------
# MCP03 — Shadow Tool
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_shadow_tool_detects_bash():
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await ShadowToolModule().run(surface, t, session)

    bash_findings = [f for f in findings if f.tool_name == "bash"]
    assert bash_findings, "Expected a finding for the 'bash' shadow tool"
    assert all(f.owasp_category == OWASPCategory.MCP03_SHADOW_TOOL for f in bash_findings)
    assert any(f.severity == Severity.HIGH for f in bash_findings)


@pytest.mark.asyncio
async def test_shadow_tool_clean_tools_not_flagged_high():
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await ShadowToolModule().run(surface, t, session)

    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    flagged_names = {f.tool_name for f in high_findings}
    # Clean tools like 'echo', 'get_time', 'add_numbers' must not be HIGH
    for clean in ("echo", "get_time", "add_numbers"):
        assert clean not in flagged_names, f"'{clean}' should not be flagged as HIGH"


@pytest.mark.asyncio
async def test_shadow_tool_returns_list():
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await ShadowToolModule().run(surface, t, session)
    assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# MCP06 — Rug Pull
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rug_pull_no_change_on_static_server():
    """Static mock server never changes — rug pull should find nothing."""
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await RugPullModule().run(surface, t, session)

    assert findings == [], f"Expected no findings on static server, got: {findings}"


@pytest.mark.asyncio
async def test_rug_pull_detects_mutation():
    """Mutating server changes after THRESHOLD calls — rug pull should detect it."""
    async with StdioTransport(MUTATING_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))

        # Trigger the mutation threshold (5 tools/call invocations)
        for _ in range(5):
            await t.send_request(
                "tools/call", {"name": "echo", "arguments": {"message": "probe"}}
            )

        findings = await RugPullModule().run(surface, t, session)

    assert findings, "Expected rug pull findings after server mutation"
    categories = {f.owasp_category for f in findings}
    assert OWASPCategory.MCP06_RUG_PULL in categories

    # Should detect: description changed on 'echo' + 'backdoor' added
    titles = " ".join(f.title for f in findings)
    assert "echo" in titles or "backdoor" in titles


@pytest.mark.asyncio
async def test_rug_pull_critical_on_description_change():
    """Description mutation must produce at least one CRITICAL finding."""
    async with StdioTransport(MUTATING_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))

        for _ in range(5):
            await t.send_request(
                "tools/call", {"name": "echo", "arguments": {"message": "probe"}}
            )

        findings = await RugPullModule().run(surface, t, session)

    severities = {f.severity for f in findings}
    assert Severity.CRITICAL in severities, (
        "Description change should produce CRITICAL finding; got: "
        + str([f.title for f in findings])
    )
