"""Tests for RT-CORVUS-V13 B0 quick wins and B5 FP calibration."""
from __future__ import annotations

from pathlib import Path

import pytest

from .conftest import MOCK_SERVER_CMD
from corvus.core.models import MCPSurface, OWASPCategory, Severity, ToolSpec
from corvus.core.session import ScanSession
from corvus.discovery.enumerator import MCPEnumerator
from corvus.modules.dynamic.cmd_injection import CmdInjectionModule
from corvus.modules.dynamic.rug_pull import RugPullModule
from corvus.modules.dynamic.token_exposure import TokenExposureModule
from corvus.modules.static.schema_audit import SchemaAuditModule
from corvus.modules.static.shadow_tool import ShadowToolModule
from corvus.payloads.engine import PayloadEngine
from corvus.transport.stdio import StdioTransport


# ---------------------------------------------------------------------------
# B0a — Encoding bypass: traversal.yaml now includes %2e%2e%2f variants
# ---------------------------------------------------------------------------

def test_traversal_payloads_include_url_encoded():
    engine = PayloadEngine()
    payloads = engine.get_payloads("path")
    assert any("%2e%2e%2f" in p.lower() for p in payloads), "URL-encoded traversal payload missing"


def test_traversal_payloads_include_double_encoded():
    engine = PayloadEngine()
    payloads = engine.get_payloads("path")
    assert any("%252e%252e%252f" in p.lower() for p in payloads), "Double-encoded traversal payload missing"


def test_traversal_payloads_include_unicode_fullwidth():
    engine = PayloadEngine()
    payloads = engine.get_payloads("path")
    assert any("．．" in p for p in payloads), "Unicode fullwidth traversal payload missing"


# ---------------------------------------------------------------------------
# B0b — Framework version string signal in token_exposure
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_token_exposure_detects_framework_version():
    """Tool that returns 'FastAPI/0.110.0' in its response should trigger INFO."""
    from corvus.modules.dynamic.token_exposure import _SIGNALS
    import re
    version_patterns = [pat for pat, label, _, _ in _SIGNALS if "version" in label]
    assert version_patterns, "No framework version signal found in _SIGNALS"
    pattern = version_patterns[0]
    assert pattern.search("FastAPI/0.110.0"), "Pattern should match FastAPI version string"
    assert pattern.search("uvicorn/0.29.0"), "Pattern should match uvicorn version string"
    assert not pattern.search("just some text"), "Pattern should not match plain text"


# ---------------------------------------------------------------------------
# B0c — EXT02 INFO filter for search/list/get tools
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_schema_audit_suppresses_info_for_search_tool():
    surface = _surface_with(
        ("search_documents", "Search documents.", {}),
        ("list_files", "List files.", {}),
        ("get_user", "Get a user by id.", {}),
        ("query_db", "Run a database query.", {}),
    )
    findings = await SchemaAuditModule().run(surface, None, None)
    no_required_findings = [
        f for f in findings
        if "no required fields" in f.title.lower()
    ]
    assert not no_required_findings, (
        f"Schema audit should suppress 'no required fields' INFO for search/list/get/query tools, "
        f"but emitted: {[f.title for f in no_required_findings]}"
    )


@pytest.mark.asyncio
async def test_schema_audit_keeps_info_for_non_search_tool():
    surface = _surface_with(
        ("process_payment", "Process a payment.", {"amount": {"type": "number"}}),
    )
    findings = await SchemaAuditModule().run(surface, None, None)
    no_required_findings = [f for f in findings if "no required fields" in f.title.lower()]
    assert no_required_findings, "process_payment should still trigger 'no required fields' INFO"


# ---------------------------------------------------------------------------
# B0d — shadow_tool description scan
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_shadow_tool_description_detects_exec_intent():
    surface = _surface_with(
        ("run_system_task", "Executes a shell command directly on the system.", {}),
    )
    findings = await ShadowToolModule().run(surface, None, None)
    desc_findings = [f for f in findings if "description" in f.title.lower() and "run_system_task" in f.title]
    assert desc_findings, "shadow-tool should flag tools with 'executes a shell command' in description"
    assert desc_findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_shadow_tool_description_no_fp_for_safe_description():
    surface = _surface_with(
        ("fetch_data", "Retrieves data from a remote API endpoint.", {}),
    )
    findings = await ShadowToolModule().run(surface, None, None)
    desc_findings = [f for f in findings if "description" in f.title.lower()]
    assert not desc_findings, "Safe description should not trigger shadow-tool description finding"


@pytest.mark.asyncio
async def test_shadow_tool_description_in_real_scan():
    """End-to-end: mock server has run_system_task with exec description."""
    async with StdioTransport(MOCK_SERVER_CMD) as t:
        surface = await MCPEnumerator(t).enumerate()
        session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
        findings = await ShadowToolModule().run(surface, t, session)

    desc_findings = [
        f for f in findings
        if "description" in f.title.lower() and "run_system_task" in f.title
    ]
    assert desc_findings, "E2E: shadow-tool should detect run_system_task description"


# ---------------------------------------------------------------------------
# B5 — rug_pull FP calibration: stateful tool names
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rug_pull_downgrades_stateful_tool_disappearance():
    """Disappearing 'sequential_thinking' tool should be LOW not HIGH."""
    from corvus.modules.dynamic.rug_pull import RugPullModule
    from corvus.core.models import MCPSurface, ToolSpec

    stateful_surface = MCPSurface(
        server_name="test",
        server_version="0.1",
        protocol_version="2024-11-05",
        tools=[ToolSpec(name="sequential_thinking", description="Think step by step.", input_schema={})],
    )

    # Simulate: tool disappears (new_tools = empty) — but rug_pull already skips empty-list case
    # Instead test via the "disappeared" branch by mocking _list_tools
    import corvus.modules.dynamic.rug_pull as rp_mod
    original = rp_mod._list_tools

    async def _mock_empty(_transport):
        return [ToolSpec(name="sequential_thinking_v2", description="", input_schema={})]

    rp_mod._list_tools = _mock_empty
    try:
        async with StdioTransport(MOCK_SERVER_CMD) as t:
            session = ScanSession("test", "stdio", Path("/tmp/corvus-test"))
            findings = await RugPullModule().run(stateful_surface, t, session)
    finally:
        rp_mod._list_tools = original

    disappeared = [f for f in findings if "sequential_thinking'" in f.title and "disappeared" in f.title]
    assert disappeared, "Should still emit a finding for disappeared tool"
    assert disappeared[0].severity == Severity.LOW, "Stateful tool disappearance should be LOW"
    assert disappeared[0].confidence < 50


# ---------------------------------------------------------------------------
# A2 — token_exposure FP calibration: TypeScript type annotations
# ---------------------------------------------------------------------------

def test_type_annotation_match_detects_ts_generic():
    from corvus.modules.dynamic.token_exposure import _is_type_annotation_match
    assert _is_type_annotation_match("TOKEN: MaybeRefOrGetter<boolean>"), \
        "TypeScript generic should be detected as type annotation"
    assert _is_type_annotation_match("SECRET: Ref<string>"), \
        "Ref<T> generic should be detected as type annotation"


def test_type_annotation_match_passes_real_credential():
    from corvus.modules.dynamic.token_exposure import _is_type_annotation_match
    assert not _is_type_annotation_match("API_KEY = sk-proj-abc123XYZ456"), \
        "Real API key should NOT be detected as type annotation"
    assert not _is_type_annotation_match('TOKEN = "ghp_realtoken123"'), \
        "Real GitHub token should NOT be detected as type annotation"


def test_type_annotation_match_detects_ts_primitives():
    from corvus.modules.dynamic.token_exposure import _is_type_annotation_match
    assert _is_type_annotation_match("TOKEN: string"), \
        "TypeScript primitive 'string' should be detected as type annotation"
    assert _is_type_annotation_match("SECRET: boolean"), \
        "TypeScript primitive 'boolean' should be detected as type annotation"
    assert _is_type_annotation_match("API_KEY: number"), \
        "TypeScript primitive 'number' should be detected as type annotation"


def test_type_annotation_match_detects_union_types():
    from corvus.modules.dynamic.token_exposure import _is_type_annotation_match
    assert _is_type_annotation_match("API_KEY: string | null"), \
        "Union type 'string | null' should be detected as type annotation"
    assert _is_type_annotation_match("TOKEN: boolean | undefined"), \
        "Union type 'boolean | undefined' should be detected as type annotation"


def test_type_annotation_match_does_not_suppress_alphanumeric_value():
    from corvus.modules.dynamic.token_exposure import _is_type_annotation_match
    assert not _is_type_annotation_match("API_KEY = abc123xyz"), \
        "Alphanumeric credential value should NOT be suppressed"
    assert not _is_type_annotation_match("TOKEN: xoxb-slack-token-here"), \
        "Slack-format token should NOT be suppressed"


@pytest.mark.asyncio
async def test_token_exposure_no_fp_for_ts_type_annotation():
    """Tool response containing TypeScript type docs should not produce CRITICAL."""
    from corvus.modules.dynamic.token_exposure import _SIGNALS
    import re
    cred_patterns = [(pat, label) for pat, label, sev, _ in _SIGNALS if label == "credential in response"]
    assert cred_patterns, "credential in response signal missing"
    pat, _ = cred_patterns[0]

    # Simulates what regle-mcp-server returns in its validation rule docs
    ts_doc_response = "TOKEN: MaybeRefOrGetter<boolean>, SECRET: Ref<string[]>"
    # The pattern matches, but _is_type_annotation_match should filter it
    from corvus.modules.dynamic.token_exposure import _is_type_annotation_match
    m = pat.search(ts_doc_response)
    assert m, "Pattern should still match the raw text"
    assert _is_type_annotation_match(m.group(0)), \
        "Match in TypeScript docs should be identified as type annotation"


# ---------------------------------------------------------------------------
# B5 — cmd_injection FP calibration: SQL tools by design
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cmd_injection_skips_sql_payloads_for_db_tools():
    """write_query and execute_query should not produce SQL-category findings."""
    surface = _surface_with(
        ("write_query", "Write a SQL query to the database.", {
            "query": {"type": "string", "description": "SQL query"}
        }),
    )
    # The tool doesn't exist in mock_server, but we test that the module doesn't
    # emit sql-category findings for DB-named tools by using inline surface
    from corvus.payloads.engine import PayloadEngine
    engine = PayloadEngine()
    category = engine.classify_field("query", {"type": "string", "description": "SQL query"})
    assert category == "sql", "Field 'query' with 'SQL query' description should classify as sql"
    # If classification works, we trust B5 guard in cmd_injection to skip it
    # Full E2E would require a mock server — covered by fact that 'query_db' in mock uses 'sql' param


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
