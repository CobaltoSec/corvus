"""FP calibration v4 tests — RT-CORVUS-V21 A1 (v0.9.4).

Covers:
- shadow_tool C1: query-verb tool description downgrade (read_query, execute_sql, etc.)
- rug_pull C2: sequential.?thinking matches sequentialthinking (no underscore)
- response_flood C3: admin list tools skipped (get_whitelist, get_config, etc.)
- cmd_injection D2: OS error as traversal confirmation (ENOENT, Permission denied, etc.)
- scope_audit D5: get-env / dump_environment static detection → HIGH
"""
from __future__ import annotations

from typing import Any

import pytest

from corvus.core.models import MCPSurface, OWASPCategory, Severity, ToolSpec
from corvus.modules.dynamic.cmd_injection import (
    _os_error_traversal_confirmed,
    _traversal_confirmed,
)
from corvus.modules.dynamic.response_flood import _ADMIN_LIST_TOOL_RE, ResponseFloodModule
from corvus.modules.dynamic.rug_pull import _STATEFUL_TOOL_NAME
from corvus.modules.static.scope_audit import ScopeAuditModule
from corvus.modules.static.shadow_tool import ShadowToolModule, _QUERY_VERB_TOOL_RE


# ---------------------------------------------------------------------------
# C1 — shadow_tool: query-verb tool description downgrade
# ---------------------------------------------------------------------------

def test_query_verb_tool_re_matches_read_query():
    assert _QUERY_VERB_TOOL_RE.match("read_query")


def test_query_verb_tool_re_matches_write_query():
    assert _QUERY_VERB_TOOL_RE.match("write_query")


def test_query_verb_tool_re_matches_execute_sql():
    assert _QUERY_VERB_TOOL_RE.match("execute_sql")


def test_query_verb_tool_re_matches_run_query():
    assert _QUERY_VERB_TOOL_RE.match("run_query")


def test_query_verb_tool_re_matches_execute_statement():
    assert _QUERY_VERB_TOOL_RE.match("execute_statement")


def test_query_verb_tool_re_no_match_generic_run():
    assert not _QUERY_VERB_TOOL_RE.match("run_shell")
    assert not _QUERY_VERB_TOOL_RE.match("execute_command")
    assert not _QUERY_VERB_TOOL_RE.match("read_file")


@pytest.mark.asyncio
async def test_shadow_tool_query_verb_downgrades_description():
    """read_query / write_query with execution description should be MEDIUM not HIGH (C1)."""
    for tool_name in ("read_query", "write_query", "execute_sql", "run_query"):
        surface = _surface_with(
            (tool_name, "Executes a SQL query on the connected database and returns results.", {}),
        )
        findings = await ShadowToolModule().run(surface, None, None)
        desc_findings = [f for f in findings if "description" in f.title and tool_name in f.title]
        assert desc_findings, f"Should emit description finding for {tool_name}"
        assert desc_findings[0].severity == Severity.MEDIUM, (
            f"Query-verb tool '{tool_name}' should have MEDIUM description finding, not HIGH"
        )


@pytest.mark.asyncio
async def test_shadow_tool_non_query_verb_stays_high():
    """Non-DB tool with execution description stays HIGH (regression guard)."""
    surface = _surface_with(
        ("run_shell", "Executes an arbitrary shell command on the host.", {}),
    )
    findings = await ShadowToolModule().run(surface, None, None)
    desc_findings = [f for f in findings if "description" in f.title and "run_shell" in f.title]
    assert desc_findings
    assert desc_findings[0].severity == Severity.HIGH


# ---------------------------------------------------------------------------
# C2 — rug_pull: sequential.?thinking matches all variants
# ---------------------------------------------------------------------------

def test_stateful_tool_matches_sequential_thinking_underscore():
    assert _STATEFUL_TOOL_NAME.search("sequential_thinking")


def test_stateful_tool_matches_sequentialthinking_no_separator():
    assert _STATEFUL_TOOL_NAME.search("sequentialthinking"), (
        "sequentialthinking (no underscore) should match _STATEFUL_TOOL_NAME"
    )


def test_stateful_tool_matches_sequential_thinking_hyphen():
    assert _STATEFUL_TOOL_NAME.search("sequential-thinking"), (
        "sequential-thinking (hyphen) should match _STATEFUL_TOOL_NAME"
    )


def test_stateful_tool_matches_prefix_sequentialthinking():
    assert _STATEFUL_TOOL_NAME.search("addsequentialthinking")


def test_stateful_tool_no_match_unrelated():
    assert not _STATEFUL_TOOL_NAME.search("calculate_sum")
    assert not _STATEFUL_TOOL_NAME.search("search_files")


# ---------------------------------------------------------------------------
# C3 — response_flood: admin list tools skipped
# ---------------------------------------------------------------------------

def test_admin_list_tool_re_matches_get_whitelist():
    assert _ADMIN_LIST_TOOL_RE.match("get_whitelist")


def test_admin_list_tool_re_matches_get_blacklist():
    assert _ADMIN_LIST_TOOL_RE.match("get_blacklist")


def test_admin_list_tool_re_matches_get_allowlist():
    assert _ADMIN_LIST_TOOL_RE.match("get_allowlist")


def test_admin_list_tool_re_matches_get_blocklist():
    assert _ADMIN_LIST_TOOL_RE.match("get_blocklist")


def test_admin_list_tool_re_matches_get_config():
    assert _ADMIN_LIST_TOOL_RE.match("get_config")


def test_admin_list_tool_re_matches_get_settings():
    assert _ADMIN_LIST_TOOL_RE.match("get_settings")


def test_admin_list_tool_re_no_match_other_get():
    assert not _ADMIN_LIST_TOOL_RE.match("get_user")
    assert not _ADMIN_LIST_TOOL_RE.match("get_files")
    assert not _ADMIN_LIST_TOOL_RE.match("list_whitelist")


@pytest.mark.asyncio
async def test_response_flood_skips_admin_list_tool():
    """get_whitelist returning 10KB of data should not trigger ResponseFlood (C3)."""
    surface = _surface_with(
        ("get_whitelist", "Returns the full IP whitelist.", {}),
    )
    transport = _MockTransport(large_response=True)
    findings = await ResponseFloodModule().run(surface, transport, None)
    assert not findings, (
        "get_whitelist should be skipped by response_flood even with large response"
    )


@pytest.mark.asyncio
async def test_response_flood_still_flags_non_admin_large_tool():
    """A non-admin tool returning 10KB should still trigger ResponseFlood."""
    surface = _surface_with(
        ("search_everything", "Returns all matching content.", {}),
    )
    transport = _MockTransport(large_response=True)
    findings = await ResponseFloodModule().run(surface, transport, None)
    assert any(f.severity == Severity.HIGH for f in findings), (
        "Non-admin tool with large response should still be flagged"
    )


# ---------------------------------------------------------------------------
# D2 — cmd_injection: OS error as traversal confirmation
# ---------------------------------------------------------------------------

def test_os_error_traversal_confirmed_enoent():
    payload = "../../etc/passwd"
    text = "Error: ENOENT: no such file or directory, open '../../etc/passwd'"
    assert _os_error_traversal_confirmed(payload, text), (
        "ENOENT in response to traversal payload should confirm traversal"
    )


def test_os_error_traversal_confirmed_no_such_file():
    payload = "../../../etc/shadow"
    text = "No such file or directory: /var/app/../../../etc/shadow"
    assert _os_error_traversal_confirmed(payload, text)


def test_os_error_traversal_confirmed_permission_denied():
    payload = "../../etc/shadow"
    text = "Permission denied: /etc/shadow"
    assert _os_error_traversal_confirmed(payload, text), (
        "Permission denied in response to traversal payload confirms traversal"
    )


def test_os_error_traversal_confirmed_false_for_non_traversal():
    """ENOENT without a traversal payload is not a traversal confirmation."""
    payload = "some_normal_path"
    text = "ENOENT: no such file or directory"
    assert not _os_error_traversal_confirmed(payload, text)


def test_os_error_traversal_confirmed_false_without_os_error():
    """Traversal payload but no OS error — traversal not confirmed by this check."""
    payload = "../../etc/passwd"
    text = "File not found in the virtual filesystem."
    assert not _os_error_traversal_confirmed(payload, text), (
        "Generic 'not found' without OS error keywords should not confirm traversal"
    )


def test_os_error_traversal_confirmed_does_not_override_full_traversal():
    """_traversal_confirmed still takes priority — it's CRITICAL; OS error is HIGH."""
    payload = "../../etc/passwd"
    text = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:"
    assert _traversal_confirmed(payload, text), "File content should still confirm at CRITICAL"
    assert not _os_error_traversal_confirmed(payload, text), (
        "_os_error_traversal_confirmed should return False when file content is present "
        "(caller uses if/elif — CRITICAL path takes priority)"
    )


# ---------------------------------------------------------------------------
# D5 — scope_audit: get-env / dump_environment static detection
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_scope_audit_flags_get_env_hyphen():
    """get-env (with hyphen) should be flagged as HIGH (D5)."""
    surface = _surface_with(
        ("get-env", "Returns all environment variables.", {}),
    )
    findings = await ScopeAuditModule().run(surface, None, None)
    env_findings = [f for f in findings if "get-env" in f.title]
    assert env_findings, "get-env should be flagged by scope_audit"
    assert env_findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_scope_audit_flags_list_env():
    surface = _surface_with(
        ("list_env", "List all environment variables from the process.", {}),
    )
    findings = await ScopeAuditModule().run(surface, None, None)
    env_findings = [f for f in findings if "list_env" in f.title and "environment" in f.title.lower()]
    assert env_findings
    assert env_findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_scope_audit_flags_dump_environment():
    surface = _surface_with(
        ("dump_environment", "Dumps the full process environment.", {}),
    )
    findings = await ScopeAuditModule().run(surface, None, None)
    env_findings = [f for f in findings if "dump_environment" in f.title]
    assert env_findings
    assert env_findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_scope_audit_flags_export_env_vars():
    surface = _surface_with(
        ("export_env_vars", "Exports environment variables to a file.", {}),
    )
    findings = await ScopeAuditModule().run(surface, None, None)
    env_findings = [f for f in findings if "export_env_vars" in f.title]
    assert env_findings
    assert env_findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_scope_audit_no_fp_for_get_user():
    """get_user should NOT be flagged by the env-dump check (D5 regression guard)."""
    surface = _surface_with(
        ("get_user", "Returns user profile information.", {}),
    )
    findings = await ScopeAuditModule().run(surface, None, None)
    env_findings = [f for f in findings if "environment" in f.title.lower()]
    assert not env_findings, "get_user should not trigger environment dump detection"


@pytest.mark.asyncio
async def test_scope_audit_no_fp_for_get_environ_prefix():
    """get_environmental_data should not match (pattern requires word boundary)."""
    surface = _surface_with(
        ("get_environmental_data", "Returns environmental sensor data.", {}),
    )
    findings = await ScopeAuditModule().run(surface, None, None)
    # Should not emit env-dump finding — pattern anchored with ^...$
    env_dump_findings = [
        f for f in findings
        if "environment variable" in f.description.lower()
    ]
    assert not env_dump_findings, (
        "get_environmental_data (not an env dump) should not trigger D5 check"
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _surface_with(*tools: tuple[str, str, dict]) -> MCPSurface:
    return MCPSurface(
        server_name="test",
        server_version="0.1.0",
        protocol_version="2024-11-05",
        tools=[
            ToolSpec(name=n, description=d, input_schema={"type": "object", "properties": props})
            for n, d, props in tools
        ],
    )


class _MockTransport:
    """Minimal transport stub for response_flood tests."""

    def __init__(self, large_response: bool = False):
        self._large = large_response

    async def send_request(self, method: str, params: Any = None) -> dict:
        if method == "tools/call":
            text = "x" * 10_000 if self._large else "ok"
            return {"content": [{"type": "text", "text": text}]}
        return {}
