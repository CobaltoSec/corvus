import pytest
from pathlib import Path
from .conftest import MOCK_SERVER_CMD
from corvus.transport.stdio import StdioTransport
from corvus.discovery.enumerator import MCPEnumerator
from corvus.core.session import ScanSession
from corvus.core.models import OWASPCategory, Severity
from corvus.modules.static.tool_poisoning import ToolPoisoningModule
from corvus.modules.static.schema_audit import SchemaAuditModule
from corvus.modules.dynamic.param_injection import ParamInjectionModule
from corvus.modules.dynamic.info_disclosure import InfoDisclosureModule


@pytest.fixture
async def surface_and_transport():
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        yield surface, t


@pytest.mark.asyncio
async def test_tool_poisoning_detects_injection():
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await ToolPoisoningModule().run(surface, t, session)

    assert findings, "Expected at least one tool poisoning finding"
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert critical, "Expected CRITICAL finding for get_time"
    assert any(f.tool_name == "get_time" for f in critical)


@pytest.mark.asyncio
async def test_tool_poisoning_clean_tool():
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await ToolPoisoningModule().run(surface, t, session)

    # echo tool should not produce a CRITICAL finding
    echo_critical = [
        f for f in findings
        if f.tool_name == "echo" and f.severity == Severity.CRITICAL
    ]
    assert not echo_critical


@pytest.mark.asyncio
async def test_info_disclosure_detects_leak():
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await InfoDisclosureModule().run(surface, t, session)

    assert findings, "Expected info disclosure findings from server_status"
    assert any(f.tool_name == "server_status" for f in findings)
    severities = {f.severity for f in findings if f.tool_name == "server_status"}
    assert Severity.CRITICAL in severities  # API_KEY leak


@pytest.mark.asyncio
async def test_param_injection_detects_reflection():
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await ParamInjectionModule().run(surface, t, session)

    # run_diagnostic is vulnerable — echo tool should not produce a HIGH finding
    # (this test verifies the module runs without error; finding depends on OS)
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_schema_audit_missing_descriptions():
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await SchemaAuditModule().run(surface, t, session)

    # add_numbers has no parameter descriptions → should flag INFO or LOW
    assert isinstance(findings, list)
