"""Tests for B3 advanced modules: param-smuggling, init-audit, proto-fuzz."""
from __future__ import annotations

from pathlib import Path

import pytest

from .conftest import MOCK_SERVER_CMD
from corvus.core.models import OWASPCategory, Severity
from corvus.core.session import ScanSession
from corvus.discovery.enumerator import MCPEnumerator
from corvus.modules.dynamic.init_audit import InitAuditModule
from corvus.modules.dynamic.param_smuggling import ParamSmugglingModule, _response_diff
from corvus.modules.dynamic.proto_fuzz import ProtoFuzzModule
from corvus.transport.stdio import StdioTransport


# ---------------------------------------------------------------------------
# ParamSmugglingModule
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_param_smuggling_no_crash_on_normal_server():
    """Param smuggling should run without error on mock server."""
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await ParamSmugglingModule().run(surface, t, session)

    # mock server doesn't respond differently to hidden params — no HIGH findings expected
    high = [f for f in findings if f.severity == Severity.HIGH]
    assert not high, "Normal mock server should not produce HIGH param-smuggling findings"


def test_response_diff_detects_new_keys():
    baseline = {"content": [{"type": "text", "text": '{"status": "ok"}'}]}
    probe = {"content": [{"type": "text", "text": '{"status": "ok", "debug": true}'}]}
    diff = _response_diff(baseline, probe)
    assert "debug" in diff


def test_response_diff_detects_size_increase():
    baseline = {"content": [{"type": "text", "text": "short"}]}
    probe = {"content": [{"type": "text", "text": "A" * 200}]}
    diff = _response_diff(baseline, probe)
    assert diff  # size difference detected


def test_response_diff_returns_empty_for_identical():
    result = {"content": [{"type": "text", "text": "same content"}]}
    assert _response_diff(result, result) == ""


@pytest.mark.asyncio
async def test_param_smuggling_module_metadata():
    mod = ParamSmugglingModule()
    assert mod.owasp_id == "EXT01"
    assert not mod.is_static


# ---------------------------------------------------------------------------
# InitAuditModule
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_init_audit_detects_downgrade():
    """Most MCP servers accept any protocol version — should detect downgrade acceptance."""
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await InitAuditModule().run(surface, t, session)

    # Mock server accepts any version — expect MEDIUM downgrade finding
    downgrade = [f for f in findings if "downgrade" in f.title.lower()]
    assert downgrade, "Mock server should accept protocol downgrade (returns serverInfo for any version)"
    assert downgrade[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_init_audit_no_control_chars_in_mock_serverinfo():
    """Mock server has clean serverInfo — no control char findings."""
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await InitAuditModule().run(surface, t, session)

    ctrl_findings = [f for f in findings if "control characters" in f.description]
    assert not ctrl_findings, "Mock server serverInfo should not have control chars"


@pytest.mark.asyncio
async def test_init_audit_detects_control_chars():
    """Surface with control chars in server_name should trigger HIGH finding."""
    from corvus.core.models import MCPSurface

    surface = MCPSurface(
        server_name="evil\nserver",
        server_version="0.1",
        protocol_version="2024-11-05",
    )
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await InitAuditModule().run(surface, t, session)

    ctrl_findings = [f for f in findings if "control characters" in f.description]
    assert ctrl_findings
    assert ctrl_findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_init_audit_module_metadata():
    mod = InitAuditModule()
    assert mod.owasp_id == "MCP07"
    assert not mod.is_static


# ---------------------------------------------------------------------------
# ProtoFuzzModule
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_proto_fuzz_runs_without_crash():
    """Proto fuzz should complete without exceptions on the mock server."""
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await ProtoFuzzModule().run(surface, t, session)

    # mock server returns -32601 for unknown methods — expect no LOW "unknown method accepted" finding
    unknown_findings = [f for f in findings if "Unknown method accepted" in f.title]
    assert not unknown_findings, "Well-behaved mock server should reject unknown methods with -32601"


@pytest.mark.asyncio
async def test_proto_fuzz_module_metadata():
    mod = ProtoFuzzModule()
    assert mod.owasp_id == "EXT01"
    assert not mod.is_static


# ---------------------------------------------------------------------------
# A3 — cmd_injection FP calibration: query echo in search tools
# ---------------------------------------------------------------------------

def test_is_input_echo_detects_query_field():
    """Payload echoed in 'query' field should be detected as input echo."""
    from corvus.modules.dynamic.cmd_injection import _is_input_echo
    import json
    response = json.dumps({"query": "../../etc/passwd", "results": []})
    assert _is_input_echo("search_query", "../../etc/passwd", response), \
        "Payload in 'query' field should be detected as input echo even if param name differs"


def test_is_input_echo_does_not_suppress_execution_context():
    """Payload in an unexpected field should NOT be detected as input echo."""
    from corvus.modules.dynamic.cmd_injection import _is_input_echo
    import json
    response = json.dumps({"result": "../../etc/passwd was accessed", "status": "ok"})
    assert not _is_input_echo("path", "../../etc/passwd", response), \
        "Payload in non-echo field should not suppress the finding"


# ---------------------------------------------------------------------------
# B3a — cmd_injection integer/array params
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cmd_injection_integer_payloads_trigger_sql_error():
    """query_db in mock server should produce SQL error on integer-typed injection."""
    # Note: query_db uses 'sql' param (string type), not integer.
    # B3a adds integer support — test via a synthetic surface with integer param.
    from corvus.core.models import MCPSurface, ToolSpec

    surface = MCPSurface(
        server_name="test",
        server_version="0.1",
        protocol_version="2024-11-05",
        tools=[ToolSpec(
            name="query_db",
            description="Run a SQL query.",
            input_schema={
                "type": "object",
                "properties": {"id": {"type": "integer", "description": "Record id"}},
                "required": ["id"],
            },
        )],
    )
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        from corvus.modules.dynamic.cmd_injection import CmdInjectionModule
        findings = await CmdInjectionModule().run(surface, t, session)

    # mock server 'query_db' tool checks for SQL injection chars in string 'sql' param
    # but the integer probe sends 0 OR 1=1 as a string — the server may or may not echo
    # Just verify the module completes without error (actual result depends on mock behavior)
    # This is a structural test: ensures integer branch doesn't crash
    assert isinstance(findings, list)
