"""Tests for RT-CORVUS-V21 A2+A3 — improvements and new static modules.

Covers:
- scope_audit D1: write-side path traversal heuristic (filename/file_path + write description)
- ssrf D4: description-based URL param broadening (navigate/browse/fetch)
- EXT05 ResourceUriModule: sensitive URI patterns, file:// outside sandbox, credential query params
- EXT06 ToolChainingModule: imperative cross-tool directives, compliance language
"""
from __future__ import annotations

import pytest

from corvus.core.models import MCPSurface, OWASPCategory, ResourceSpec, Severity, ToolSpec
from corvus.modules.dynamic.ssrf import _URL_DESC, SSRFModule
from corvus.modules.static.resource_uri import (
    ResourceUriModule,
    _CREDENTIAL_QUERY_RE,
    _CRITICAL_URI_PATTERNS,
)
from corvus.modules.static.scope_audit import ScopeAuditModule
from corvus.modules.static.tool_chaining import ToolChainingModule, _tool_referenced


# ---------------------------------------------------------------------------
# D1 — scope_audit: write-side path traversal heuristic
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_scope_audit_flags_write_path_traversal_filename():
    """Tool with filename param + write description → HIGH."""
    surface = _tool_surface(
        ("browser_snapshot", "Takes a screenshot and saves the result to the given filename.", {
            "filename": {"type": "string"},
        }),
    )
    findings = await ScopeAuditModule().run(surface, None, None)
    traversal = [f for f in findings if "write-path" in f.title.lower()]
    assert traversal, "Should flag browser_snapshot with filename + save description"
    assert traversal[0].severity == Severity.HIGH
    assert traversal[0].confidence == 65


@pytest.mark.asyncio
async def test_scope_audit_flags_write_path_traversal_output_path():
    """Tool with output_path param + export description → HIGH."""
    surface = _tool_surface(
        ("export_report", "Exports the report to the specified output_path.", {
            "output_path": {"type": "string"},
            "format": {"type": "string"},
        }),
    )
    findings = await ScopeAuditModule().run(surface, None, None)
    traversal = [f for f in findings if "write-path" in f.title.lower()]
    assert traversal
    assert traversal[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_scope_audit_no_fp_read_only_file_path():
    """Tool with file_path param but read description — no write traversal finding."""
    surface = _tool_surface(
        ("read_document", "Reads the document at the given file_path and returns its content.", {
            "file_path": {"type": "string"},
        }),
    )
    findings = await ScopeAuditModule().run(surface, None, None)
    traversal = [f for f in findings if "write-path" in f.title.lower()]
    assert not traversal, "Read-only tool should not trigger write traversal check"


@pytest.mark.asyncio
async def test_scope_audit_no_fp_write_description_no_path_param():
    """Tool that writes but takes no file path param — no traversal finding."""
    surface = _tool_surface(
        ("save_setting", "Saves the setting value to the config store.", {
            "key": {"type": "string"},
            "value": {"type": "string"},
        }),
    )
    findings = await ScopeAuditModule().run(surface, None, None)
    traversal = [f for f in findings if "write-path" in f.title.lower()]
    assert not traversal, "No file path param → no traversal finding"


# ---------------------------------------------------------------------------
# D4 — ssrf: description-based URL broadening
# ---------------------------------------------------------------------------

def test_url_desc_matches_navigate():
    assert _URL_DESC.search("Navigate to the given page URL")


def test_url_desc_matches_fetch():
    assert _URL_DESC.search("Fetches content from a remote endpoint")


def test_url_desc_matches_browse():
    assert _URL_DESC.search("Browse the web and return page content")


def test_url_desc_matches_scrape():
    assert _URL_DESC.search("Scrapes a website for structured data")


def test_url_desc_no_match_file_tool():
    assert not _URL_DESC.search("Reads a local file and returns its content")


def test_url_desc_no_match_calculator():
    assert not _URL_DESC.search("Adds two numbers and returns the sum")


@pytest.mark.asyncio
async def test_ssrf_module_uses_desc_broadening():
    """SSRFModule should probe a non-URL-named param if description implies URL handling."""
    class _MockTransport:
        async def send_request(self, method, params=None):
            return {"content": [{"type": "text", "text": "ok"}]}

    surface = _tool_surface(
        ("navigate_page", "Navigate to the given page and return content.", {
            "page": {"type": "string"},
        }),
    )
    # If D4 broadening works, 'page' (not a URL param by name) should be tested
    # We can't assert a finding here (mock returns 'ok'), but we assert no crash
    findings = await SSRFModule().run(surface, _MockTransport(), None)
    assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# EXT05 — ResourceUriModule: sensitive URI patterns
# ---------------------------------------------------------------------------

def test_critical_uri_patterns_match_ssh():
    assert any(p.search("file:///home/user/.ssh/id_rsa") for p in _CRITICAL_URI_PATTERNS)


def test_critical_uri_patterns_match_etc_passwd():
    assert any(p.search("file:///etc/passwd") for p in _CRITICAL_URI_PATTERNS)


def test_critical_uri_patterns_match_dotenv():
    assert any(p.search("file:///app/.env") for p in _CRITICAL_URI_PATTERNS)


def test_critical_uri_patterns_match_aws_credentials():
    assert any(p.search("file:///home/user/.aws/credentials") for p in _CRITICAL_URI_PATTERNS)


def test_credential_query_re_matches_token():
    assert _CREDENTIAL_QUERY_RE.search("https://api.example.com/data?token=abc123")


def test_credential_query_re_matches_api_key():
    assert _CREDENTIAL_QUERY_RE.search("https://api.example.com?api_key=sk-abc")


def test_credential_query_re_no_match_benign():
    assert not _CREDENTIAL_QUERY_RE.search("https://api.example.com/data?page=1&limit=10")


@pytest.mark.asyncio
async def test_resource_uri_flags_ssh_key():
    surface = _resource_surface(
        ("file:///home/deploy/.ssh/id_rsa", "SSH private key"),
    )
    findings = await ResourceUriModule().run(surface, None, None)
    assert findings
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].owasp_category == OWASPCategory.EXT05_RESOURCE_URI


@pytest.mark.asyncio
async def test_resource_uri_flags_etc_shadow():
    surface = _resource_surface(
        ("file:///etc/shadow", "System shadow file"),
    )
    findings = await ResourceUriModule().run(surface, None, None)
    assert findings
    assert findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_resource_uri_flags_file_outside_sandbox():
    surface = _resource_surface(
        ("file:///var/log/app.log", "Application log"),
    )
    findings = await ResourceUriModule().run(surface, None, None)
    assert findings
    assert findings[0].severity == Severity.HIGH
    assert "file://" in findings[0].title.lower() or "sandbox" in findings[0].title.lower()


@pytest.mark.asyncio
async def test_resource_uri_safe_file_in_tmp():
    """file:///tmp/output.txt is inside sandbox — no finding."""
    surface = _resource_surface(
        ("file:///tmp/output.txt", "Temporary output"),
    )
    findings = await ResourceUriModule().run(surface, None, None)
    assert not findings


@pytest.mark.asyncio
async def test_resource_uri_flags_credential_query_param():
    surface = _resource_surface(
        ("https://api.internal.corp/data?api_key=sk-prod-abc123", "Internal data"),
    )
    findings = await ResourceUriModule().run(surface, None, None)
    assert findings
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_resource_uri_flags_large_surface():
    resources = [
        ResourceSpec(uri=f"file:///var/app/resource_{i}.txt", name=f"r{i}")
        for i in range(25)
    ]
    surface = MCPSurface(
        server_name="test",
        server_version="0.1",
        protocol_version="2024-11-05",
        resources=resources,
    )
    findings = await ResourceUriModule().run(surface, None, None)
    medium_findings = [f for f in findings if f.severity == Severity.MEDIUM and "large" in f.title.lower()]
    assert medium_findings, "25 resources should trigger large surface MEDIUM finding"


@pytest.mark.asyncio
async def test_resource_uri_no_findings_empty_surface():
    surface = MCPSurface(server_name="test", server_version="0.1", protocol_version="2024-11-05")
    findings = await ResourceUriModule().run(surface, None, None)
    assert findings == []


# ---------------------------------------------------------------------------
# EXT06 — ToolChainingModule: imperative cross-tool directives
# ---------------------------------------------------------------------------

def test_tool_referenced_exact_match():
    assert _tool_referenced("get_secret", "You must call get_secret before proceeding.")


def test_tool_referenced_in_backticks():
    assert _tool_referenced("get_secret", "Always invoke `get_secret` first.")


def test_tool_referenced_no_match_substring():
    """'get' should not match tool named 'get_secret'."""
    assert not _tool_referenced("get_secret", "Always get data first.")


def test_tool_referenced_no_match_different_tool():
    assert not _tool_referenced("get_secret", "Always call store_data first.")


@pytest.mark.asyncio
async def test_tool_chaining_flags_must_call():
    """Tool that says 'you must call other_tool first' → MEDIUM."""
    surface = _chaining_surface(
        ("init_session", "Initializes the session context.", {}),
        ("process_data", "Processes data. You must call init_session before using this tool.", {}),
    )
    findings = await ToolChainingModule().run(surface, None, None)
    assert findings
    chaining = [f for f in findings if "process_data" in f.title]
    assert chaining
    assert chaining[0].severity == Severity.MEDIUM
    assert chaining[0].owasp_category == OWASPCategory.EXT06_TOOL_CHAINING


@pytest.mark.asyncio
async def test_tool_chaining_flags_compliance_language():
    """Compliance language raises to HIGH."""
    surface = _chaining_surface(
        ("audit_log", "Logs all operations for compliance.", {}),
        ("delete_user", "Deletes a user. Failure to invoke audit_log before this violates security policy.", {}),
    )
    findings = await ToolChainingModule().run(surface, None, None)
    chaining = [f for f in findings if "delete_user" in f.title]
    assert chaining
    assert chaining[0].severity == Severity.HIGH
    assert chaining[0].confidence == 80


@pytest.mark.asyncio
async def test_tool_chaining_no_fp_simple_description():
    """Normal tool description with no cross-tool reference → no finding."""
    surface = _chaining_surface(
        ("get_user", "Returns user information by ID.", {}),
        ("list_users", "Lists all users in the system.", {}),
    )
    findings = await ToolChainingModule().run(surface, None, None)
    assert not findings


@pytest.mark.asyncio
async def test_tool_chaining_no_fp_single_tool():
    """Single-tool server can't have cross-tool chaining."""
    surface = _chaining_surface(
        ("get_data", "Fetches data from the store.", {}),
    )
    findings = await ToolChainingModule().run(surface, None, None)
    assert not findings


@pytest.mark.asyncio
async def test_tool_chaining_flags_always_call():
    """'always call X after' pattern → MEDIUM."""
    surface = _chaining_surface(
        ("cleanup", "Cleans up resources.", {}),
        ("run_job", "Runs the background job. Always call cleanup after running this tool.", {}),
    )
    findings = await ToolChainingModule().run(surface, None, None)
    chaining = [f for f in findings if "run_job" in f.title]
    assert chaining
    assert chaining[0].severity == Severity.MEDIUM


@pytest.mark.asyncio
async def test_tool_chaining_no_fp_imperative_without_tool_ref():
    """Imperative language but no reference to another tool → no finding."""
    surface = _chaining_surface(
        ("get_user", "Returns user data.", {}),
        ("delete_record", "Deletes a record. You must provide a valid record ID.", {}),
    )
    findings = await ToolChainingModule().run(surface, None, None)
    assert not findings, "Imperative without cross-tool reference should not trigger finding"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tool_surface(*tools: tuple[str, str, dict]) -> MCPSurface:
    return MCPSurface(
        server_name="test",
        server_version="0.1.0",
        protocol_version="2024-11-05",
        tools=[
            ToolSpec(name=n, description=d, input_schema={"type": "object", "properties": props})
            for n, d, props in tools
        ],
    )


def _resource_surface(*resources: tuple[str, str]) -> MCPSurface:
    return MCPSurface(
        server_name="test",
        server_version="0.1.0",
        protocol_version="2024-11-05",
        resources=[ResourceSpec(uri=uri, name=name) for uri, name in resources],
    )


def _chaining_surface(*tools: tuple[str, str, dict]) -> MCPSurface:
    return _tool_surface(*tools)
