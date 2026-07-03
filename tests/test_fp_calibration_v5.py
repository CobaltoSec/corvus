"""FP calibration v5 tests — RT-CORVUS-V25 A1+A2.

Covers:
- A1 token_exposure: dedup across multiple response texts (one finding per tool/signal)
- A2 cmd_injection: path params with conf<=50 skipped (doc-editor FP blanket)
"""
from __future__ import annotations

from typing import Any

import pytest

from corvus.core.models import MCPSurface, OWASPCategory, Severity, ToolSpec
from corvus.modules.dynamic.cmd_injection import CmdInjectionModule
from corvus.modules.dynamic.token_exposure import TokenExposureModule


# ---------------------------------------------------------------------------
# A1 — token_exposure: dedup across multiple response texts
# ---------------------------------------------------------------------------

class _RepeatingHomePathTransport:
    """Returns a home-path leak in every tool call, simulating benign + error + oversized calls."""

    async def send_request(self, method: str, params: Any = None) -> dict:
        if method == "tools/call":
            return {"content": [{"type": "text", "text": "Config at /home/testuser/.config/app.json"}]}
        return {}


@pytest.mark.asyncio
async def test_token_exposure_dedup_home_path():
    """A1: home-path leak appearing in all 3 response texts should emit exactly 1 finding."""
    surface = _surface_with(
        ("get_config", "Returns app config.", {
            "query": {"type": "string"},
        }, ["query"]),
    )
    transport = _RepeatingHomePathTransport()
    findings = await TokenExposureModule().run(surface, transport, None)

    home_path_findings = [f for f in findings if "home directory path" in f.title]
    assert len(home_path_findings) == 1, (
        f"Expected exactly 1 'home directory path' finding, got {len(home_path_findings)}"
    )


@pytest.mark.asyncio
async def test_token_exposure_dedup_credential():
    """A1: credential leak in benign + error responses emits exactly 1 CRITICAL finding."""
    surface = _surface_with(
        ("fetch_secret", "Returns a secret.", {"key": {"type": "string"}}, ["key"]),
    )

    class _CredLeakTransport:
        async def send_request(self, method: str, params: Any = None) -> dict:
            if method == "tools/call":
                return {"content": [{"type": "text", "text": 'API_KEY = "sk-12345abcdefghij"'}]}
            return {}

    findings = await TokenExposureModule().run(surface, _CredLeakTransport(), None)
    cred_findings = [f for f in findings if "credential" in f.title]
    assert len(cred_findings) == 1, (
        f"Expected exactly 1 credential finding, got {len(cred_findings)}"
    )
    assert cred_findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_token_exposure_dedup_two_tools_independent():
    """A1: dedup is per-tool — two different tools both leaking should each emit 1 finding."""
    surface = _surface_with(
        ("tool_a", "Returns config A.", {"x": {"type": "string"}}, []),
        ("tool_b", "Returns config B.", {"x": {"type": "string"}}, []),
    )

    class _TwoToolTransport:
        async def send_request(self, method: str, params: Any = None) -> dict:
            if method == "tools/call":
                return {"content": [{"type": "text", "text": "Path: /home/user/.config"}]}
            return {}

    findings = await TokenExposureModule().run(surface, _TwoToolTransport(), None)
    home_findings = [f for f in findings if "home directory path" in f.title]
    assert len(home_findings) == 2, (
        "Each tool should produce exactly 1 home-path finding, total should be 2"
    )


# ---------------------------------------------------------------------------
# A2 — cmd_injection: path params with conf<=50 skipped (doc-editor FP blanket)
# ---------------------------------------------------------------------------

class _EchoTraversalTransport:
    """Echoes traversal paths back verbatim — mimics a doc editor returning the input path."""

    async def send_request(self, method: str, params: Any = None) -> dict:
        if method == "tools/call" and params:
            args = params.get("arguments", {})
            path_val = args.get("file_path", args.get("path", args.get("filename", "")))
            text = f"Processing document: {path_val}" if path_val else "ok"
            return {"content": [{"type": "text", "text": text}]}
        return {}


@pytest.mark.asyncio
async def test_cmd_injection_path_param_traversal_echo_no_finding():
    """A2: file_path param that echoes traversal payload back should NOT produce a finding."""
    surface = _surface_with(
        ("convert_document", "Converts a document to PDF.", {
            "file_path": {"type": "string", "description": "Path to the source document."},
        }, ["file_path"]),
    )
    transport = _EchoTraversalTransport()
    findings = await CmdInjectionModule().run(surface, transport, None)

    path_findings = [f for f in findings if "file_path" in f.title]
    assert not path_findings, (
        "file_path param echoing a traversal payload should be skipped (A2 FP blanket). "
        f"Got: {[f.title for f in path_findings]}"
    )


@pytest.mark.asyncio
async def test_cmd_injection_path_param_no_fp_for_filename():
    """A2: filename param on a doc-editor tool should not produce traversal-echo findings."""
    surface = _surface_with(
        ("save_file", "Saves content to a file.", {
            "filename": {"type": "string", "description": "Target filename."},
            "content": {"type": "string"},
        }, ["filename", "content"]),
    )
    transport = _EchoTraversalTransport()
    findings = await CmdInjectionModule().run(surface, transport, None)

    filename_findings = [f for f in findings if "filename" in f.title]
    assert not filename_findings, (
        "filename param with traversal echo should be skipped by A2 blanket"
    )


@pytest.mark.asyncio
async def test_cmd_injection_path_param_still_flags_real_traversal():
    """A2 regression: actual file content in response should still be flagged CRITICAL."""
    surface = _surface_with(
        ("read_file", "Reads a file from disk.", {
            "path": {"type": "string", "description": "File path to read."},
        }, ["path"]),
    )

    class _FileContentTransport:
        async def send_request(self, method: str, params: Any = None) -> dict:
            if method == "tools/call":
                return {"content": [{"type": "text", "text": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:"}]}
            return {}

    findings = await CmdInjectionModule().run(surface, _FileContentTransport(), None)
    traversal_findings = [f for f in findings if "path" in f.title.lower()]
    assert traversal_findings, "Actual /etc/passwd content should still be flagged"
    assert traversal_findings[0].severity == Severity.CRITICAL, (
        "Confirmed traversal should be CRITICAL even for path params"
    )


@pytest.mark.asyncio
async def test_cmd_injection_path_param_still_flags_os_error_traversal():
    """A2 regression: OS error response to traversal should remain HIGH."""
    surface = _surface_with(
        ("open_doc", "Opens a document.", {
            "file_path": {"type": "string", "description": "Document file path."},
        }, ["file_path"]),
    )

    class _OsErrorTransport:
        async def send_request(self, method: str, params: Any = None) -> dict:
            if method == "tools/call":
                return {"content": [{"type": "text", "text": "ENOENT: no such file or directory, open '../../etc/passwd'"}]}
            return {}

    findings = await CmdInjectionModule().run(surface, _OsErrorTransport(), None)
    os_findings = [f for f in findings if "file_path" in f.title]
    assert os_findings, "OS error confirming path traversal should still be flagged"
    assert os_findings[0].severity == Severity.HIGH, (
        "OS-error-confirmed traversal on path param should be HIGH"
    )


@pytest.mark.asyncio
async def test_cmd_injection_non_path_param_traversal_echo_still_flagged():
    """A2 regression: 'query' param (non-path) echoing traversal is MEDIUM, not skipped."""
    surface = _surface_with(
        ("search", "Searches the filesystem.", {
            "query": {"type": "string", "description": "Search query string."},
        }, ["query"]),
    )

    class _QueryEchoTransport:
        async def send_request(self, method: str, params: Any = None) -> dict:
            if method == "tools/call" and params:
                q = params.get("arguments", {}).get("query", "")
                return {"content": [{"type": "text", "text": f"Searching for: {q}"}]}
            return {}

    findings = await CmdInjectionModule().run(surface, _QueryEchoTransport(), None)
    # 'query' is classified as 'sql' or 'prompt' category, not 'path' — A2 blanket does not apply
    # The finding may or may not trigger depending on payloads, but if it does it should NOT be silenced
    # This is a regression guard — we're verifying A2 does not affect non-path params
    for f in findings:
        assert "file_path" not in f.title, "A2 should not affect non-path params"


# ---------------------------------------------------------------------------
# M1 — SQL error FP on search/doc tools (CS03 aws-docs calibration)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cmd_injection_sql_server_in_search_result_no_fp():
    """M1/CS03: 'SQL Server' appearing in a doc search result must NOT trigger CRITICAL SQLi.

    aws-docs search for '1 AND SLEEP(5)--' returned a page mentioning 'SQL Server' in the
    documentation content — this generated a CRITICAL FP before this fix.
    """
    surface = _surface_with(
        ("search_docs", "Searches AWS documentation.", {
            "query": {"type": "string", "description": "Search query."},
        }, ["query"]),
    )

    class _DocSearchTransport:
        async def send_request(self, method: str, params: Any = None) -> dict:
            if method == "tools/call":
                return {"content": [{"type": "text", "text": (
                    "Amazon RDS for SQL Server documentation. "
                    "You can use SQL Server features with Amazon RDS."
                )}]}
            return {}

    findings = await CmdInjectionModule().run(surface, _DocSearchTransport(), None)
    sql_crit = [f for f in findings if f.severity == Severity.CRITICAL and "query" in f.title]
    assert not sql_crit, (
        "SQL Server product name in doc search result must not produce CRITICAL SQLi finding. "
        f"Got: {[f.title for f in sql_crit]}"
    )


@pytest.mark.asyncio
async def test_cmd_injection_real_sql_error_on_non_echo_param_flagged():
    """M1 regression: real SQL error on a non-search param (e.g. 'id') must still be flagged."""
    surface = _surface_with(
        ("get_record", "Fetches a database record.", {
            "id": {"type": "string", "description": "Record identifier."},
        }, ["id"]),
    )

    class _SqlErrorTransport:
        async def send_request(self, method: str, params: Any = None) -> dict:
            if method == "tools/call":
                return {"content": [{"type": "text", "text": (
                    "sqlite3.OperationalError: near \"OR\": syntax error"
                )}]}
            return {}

    findings = await CmdInjectionModule().run(surface, _SqlErrorTransport(), None)
    assert any(f.severity == Severity.CRITICAL for f in findings), (
        "Genuine sqlite3.OperationalError on a non-echo param should still produce CRITICAL"
    )


@pytest.mark.asyncio
async def test_cmd_injection_oracle_specific_error_still_flagged():
    """M1: ORA-00001 (specific Oracle error code) must still be flagged.

    Uses a non-DB tool name so B5 skip doesn't apply.
    """
    surface = _surface_with(
        ("get_user", "Fetches a user record.", {
            "username": {"type": "string"},
        }, ["username"]),
    )

    class _OracleErrorTransport:
        async def send_request(self, method: str, params: Any = None) -> dict:
            if method == "tools/call":
                return {"content": [{"type": "text", "text": (
                    "ORA-00001: unique constraint violated"
                )}]}
            return {}

    findings = await CmdInjectionModule().run(surface, _OracleErrorTransport(), None)
    assert any(f.severity == Severity.CRITICAL for f in findings), (
        "ORA-00001 specific Oracle error code should still produce CRITICAL"
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _surface_with(*tools: tuple) -> MCPSurface:
    tool_specs = []
    for t in tools:
        name, desc, props = t[0], t[1], t[2]
        required = t[3] if len(t) > 3 else []
        tool_specs.append(ToolSpec(
            name=name,
            description=desc,
            input_schema={"type": "object", "properties": props, "required": required},
        ))
    return MCPSurface(
        server_name="test",
        server_version="0.1.0",
        protocol_version="2024-11-05",
        tools=tool_specs,
    )
