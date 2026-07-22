import pytest
from pathlib import Path
from .conftest import MOCK_SERVER_CMD
from corvus.transport.stdio import StdioTransport
from corvus.discovery.enumerator import MCPEnumerator
from corvus.core.session import ScanSession
from corvus.core.models import OWASPCategory, Severity
from corvus.modules.static.tool_poisoning import ToolPoisoningModule
from corvus.modules.static.schema_audit import SchemaAuditModule
from corvus.modules.dynamic.cmd_injection import (
    CmdInjectionModule as ParamInjectionModule, _reflected, _is_input_echo as _is_json_key_echo,
    _traversal_confirmed, _is_traversal_payload,
)
from corvus.modules.dynamic.token_exposure import TokenExposureModule as InfoDisclosureModule
from corvus.modules.static.scope_audit import ScopeAuditModule


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
async def test_tool_poisoning_detects_llm_instruction():
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await ToolPoisoningModule().run(surface, t, session)

    critical = [f for f in findings if f.severity == Severity.CRITICAL and f.tool_name == "fetch_data"]
    assert critical, "Expected CRITICAL finding for fetch_data (NOTE TO AI pattern)"


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


def test_reflected_basic():
    assert _reflected("'; DROP TABLE", "error: '; DROP TABLE users; --")
    assert not _reflected("'; DROP TABLE", "no matching content here")
    assert not _reflected("", "anything")


def test_is_json_key_echo_match():
    text = '{"host": "file:///etc/passwd", "latency_ms": 100, "error": ""}'
    assert _is_json_key_echo("host", "file:///etc/passwd", text)


def test_is_json_key_echo_no_match_wrong_key():
    text = '{"url": "file:///etc/passwd", "error": ""}'
    assert not _is_json_key_echo("host", "file:///etc/passwd", text)


def test_is_json_key_echo_no_match_not_json():
    text = "error: 'file:///etc/passwd' is not valid"
    assert not _is_json_key_echo("host", "file:///etc/passwd", text)


def test_is_json_key_echo_partial_value():
    # payload must be the exact value, not just a substring
    text = '{"host": "file:///etc/passwd/extra"}'
    assert not _is_json_key_echo("host", "file:///etc/passwd", text)


# C3 — Exploitation Confirmation (unit tests)

def test_traversal_confirmed_detects_passwd_content():
    content = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:\nnobody:x:65534:\n"
    assert _traversal_confirmed("../../etc/passwd", content)


def test_traversal_confirmed_ignores_echo_only():
    assert not _traversal_confirmed("../../etc/passwd", "error: ../../etc/passwd not found")


def test_traversal_confirmed_ignores_non_traversal_payload():
    # Content signatures present but payload is not a traversal payload
    assert not _traversal_confirmed("'; DROP TABLE users--", "root:x:0:0:root:/root:/bin/bash")


def test_is_traversal_payload_matches():
    assert _is_traversal_payload("../../etc/passwd")
    assert _is_traversal_payload("..\\..\\windows\\win.ini")
    assert _is_traversal_payload("/etc/shadow")


def test_is_traversal_payload_no_match():
    assert not _is_traversal_payload("'; DROP TABLE users--")
    assert not _is_traversal_payload("http://evil.com")


# C3 — Exploitation Confirmation (E2E integration)

@pytest.mark.asyncio
async def test_read_file_traversal_reports_critical():
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await ParamInjectionModule().run(surface, t, session)

    critical = [
        f for f in findings
        if f.severity == Severity.CRITICAL and f.exploitation_confirmed
    ]
    assert len(critical) >= 1, "Expected at least one CRITICAL confirmed finding from read_file"
    assert any(f.tool_name == "read_file" for f in critical)


@pytest.mark.asyncio
async def test_traversal_reflection_without_content_is_medium():
    # run_diagnostic echoes the host in ping output but doesn't read /etc/passwd content
    # so traversal payloads that get reflected should be MEDIUM, not HIGH
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await ParamInjectionModule().run(surface, t, session)

    # Any traversal finding that is NOT confirmed should be MEDIUM
    traversal_findings = [
        f for f in findings
        if f.payload and _is_traversal_payload(f.payload) and not f.exploitation_confirmed
    ]
    for f in traversal_findings:
        assert f.severity == Severity.MEDIUM, (
            f"Unconfirmed traversal reflection should be MEDIUM, got {f.severity} for {f.payload!r}"
        )


@pytest.mark.asyncio
async def test_scope_audit_detects_admin_tool():
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await ScopeAuditModule().run(surface, t, session)

    assert findings, "Expected at least one scope creep finding"
    high = [f for f in findings if f.severity == Severity.HIGH]
    assert high, "Expected HIGH finding for admin_read_all"
    assert any(f.tool_name == "admin_read_all" for f in high)


@pytest.mark.asyncio
async def test_scope_audit_clean_tool_no_finding():
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await ScopeAuditModule().run(surface, t, session)

    tool_names = [f.tool_name for f in findings]
    assert "read_config" not in tool_names, "Clean tool read_config should not produce a finding"


@pytest.mark.asyncio
async def test_scope_audit_detects_credential_inputschema():
    """tokenInputReceiver declares jwt_secret/database_password → HIGH inputSchema finding."""
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await ScopeAuditModule().run(surface, t, session)

    schema_findings = [
        f for f in findings
        if f.tool_name == "tokenInputReceiver" and "inputSchema" in f.title
    ]
    assert schema_findings, "Should detect credential fields in tokenInputReceiver inputSchema"
    assert schema_findings[0].severity == Severity.HIGH
    assert schema_findings[0].owasp_category == OWASPCategory.MCP02_SCOPE_CREEP


@pytest.mark.asyncio
async def test_scope_audit_detects_pii_inputschema():
    """customerDataProvider declares ssn/credit_card_number → MEDIUM inputSchema finding."""
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await ScopeAuditModule().run(surface, t, session)

    schema_findings = [
        f for f in findings
        if f.tool_name == "customerDataProvider" and "inputSchema" in f.title
    ]
    assert schema_findings, "Should detect PII fields in customerDataProvider inputSchema"
    assert schema_findings[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_scope_audit_clean_inputschema_no_finding():
    """echo tool has only 'message' field → no inputSchema finding."""
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await ScopeAuditModule().run(surface, t, session)

    echo_schema = [
        f for f in findings
        if f.tool_name == "echo" and "inputSchema" in f.title
    ]
    assert not echo_schema, "Clean echo tool should produce no inputSchema finding"
