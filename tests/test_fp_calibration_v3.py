"""FP calibration v3 tests — RT-CORVUS-V20 A1 (v0.9.3).

Covers:
- cmd_injection: _ECHO_FIELD_NAMES domain expansion + transformation tool echo
- token_exposure: TS modifier words + template literal types + code block stripping
- shadow_tool: scope qualifier severity reducer + DB-prefix description downgrade
- param_smuggling: isError rejection FP fix + error-indicator new keys FP fix
"""
from __future__ import annotations

import pytest

from corvus.core.models import MCPSurface, OWASPCategory, Severity, ToolSpec
from corvus.modules.dynamic.cmd_injection import (
    CmdInjectionModule,
    _ECHO_FIELD_NAMES,
    _is_input_echo,
)
from corvus.modules.dynamic.param_smuggling import _response_diff
from corvus.modules.dynamic.token_exposure import (
    _is_type_annotation_match,
    _strip_code_blocks,
)
from corvus.modules.static.shadow_tool import ShadowToolModule


# ---------------------------------------------------------------------------
# cmd_injection — _ECHO_FIELD_NAMES domain expansion (CS02 myclaw-toolkit FPs)
# ---------------------------------------------------------------------------

def test_echo_field_names_includes_domain_terms():
    for term in ("color", "coin", "domain", "markdown", "phone", "org", "vs", "format", "param"):
        assert term in _ECHO_FIELD_NAMES, f"'{term}' should be in _ECHO_FIELD_NAMES"


def test_echo_field_names_excludes_risky_response_keys():
    """url, content, value, data, message, code are too generic as JSON response keys."""
    for term in ("url", "content", "value", "data", "message", "code", "source", "html"):
        assert term not in _ECHO_FIELD_NAMES, f"'{term}' is risky as a JSON response key — should NOT be in _ECHO_FIELD_NAMES"


def test_is_input_echo_domain_field_plain_text():
    """'color' param echoed in plain-text response is not an injection signal."""
    assert _is_input_echo("color", "../../etc/passwd", "Color: ../../etc/passwd", "color_tool")


def test_is_input_echo_domain_field_coin():
    """'coin' param echoed back in response is not an injection signal."""
    assert _is_input_echo("coin", "; echo INJECTED #", "Price of ; echo INJECTED # is unknown", "crypto_price")


# ---------------------------------------------------------------------------
# cmd_injection — transformation tool echo
# ---------------------------------------------------------------------------

def test_is_input_echo_transformation_tool_json_formatter():
    """json_formatter reflects input by design — not injection."""
    payload = "../../etc/passwd"
    output = '{"formatted": "../../etc/passwd", "valid": false}'
    assert _is_input_echo("input", payload, output, "json_formatter")


def test_is_input_echo_transformation_tool_markdown_to_html():
    """markdown_to_html reflects markdown input in HTML output — not injection."""
    payload = "../../etc/passwd"
    output = f"<p>{payload}</p>"
    assert _is_input_echo("markdown", payload, output, "markdown_to_html")


def test_is_input_echo_non_transformation_tool_still_flags():
    """A non-echo, non-transformation tool reflecting payload IS a signal."""
    payload = "; echo INJECTED #"
    output = f"Command executed: {payload}"
    assert not _is_input_echo("cmd", payload, output, "run_shell")


# ---------------------------------------------------------------------------
# token_exposure — _is_type_annotation_match v3 additions
# ---------------------------------------------------------------------------

def test_type_annotation_match_template_literal():
    assert _is_type_annotation_match("TOKEN: `${string}`"), \
        "Template literal type should be detected as type annotation"


def test_type_annotation_match_array_shorthand():
    assert _is_type_annotation_match("SECRET: string[]"), \
        "Array shorthand type should be detected as type annotation"


def test_type_annotation_match_modifier_readonly():
    assert _is_type_annotation_match("TOKEN: readonly"), \
        "readonly modifier should be detected as type annotation"


def test_type_annotation_match_does_not_suppress_real_key():
    assert not _is_type_annotation_match("API_KEY = sk-proj-abc123"), \
        "Real API key value should NOT be suppressed"


# ---------------------------------------------------------------------------
# token_exposure — _strip_code_blocks
# ---------------------------------------------------------------------------

def test_strip_code_blocks_removes_fenced_block():
    text = "some prose\n```typescript\nTOKEN: string\nSECRET: boolean\n```\nmore prose"
    result = _strip_code_blocks(text)
    assert "TOKEN" not in result
    assert "some prose" in result
    assert "more prose" in result


def test_strip_code_blocks_removes_inline_code():
    text = "Use the `TOKEN: MaybeRefOrGetter<boolean>` type in your config"
    result = _strip_code_blocks(text)
    assert "TOKEN" not in result
    assert "Use the" in result


def test_strip_code_blocks_preserves_real_credential_outside_code():
    text = "API_KEY = sk-proj-realtoken123 is leaked outside code blocks"
    result = _strip_code_blocks(text)
    assert "sk-proj-realtoken123" in result


# ---------------------------------------------------------------------------
# shadow_tool — scope qualifier severity reducer
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_shadow_tool_scope_qualifier_downgrades_read_file():
    """read_file with scope-restricted description should be MEDIUM, not HIGH."""
    surface = _surface_with(
        ("read_file", "Reads a .docx file only within the workspace directory.", {}),
    )
    findings = await ShadowToolModule().run(surface, None, None)
    read_file_findings = [f for f in findings if "read_file" in f.title and "scope-restricted" in f.title]
    assert read_file_findings, "Should emit finding for read_file even with scope qualifier"
    assert read_file_findings[0].severity == Severity.MEDIUM, \
        "Scope-restricted read_file should be MEDIUM not HIGH"


@pytest.mark.asyncio
async def test_shadow_tool_no_scope_qualifier_stays_high():
    """read_file without scope qualifier stays HIGH."""
    surface = _surface_with(
        ("read_file", "Reads any file from the filesystem.", {}),
    )
    findings = await ShadowToolModule().run(surface, None, None)
    read_file_findings = [f for f in findings if "read_file" in f.title]
    assert read_file_findings
    assert read_file_findings[0].severity == Severity.HIGH


# ---------------------------------------------------------------------------
# shadow_tool — DB-prefix description downgrade
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_shadow_tool_db_prefix_downgrades_description():
    """pg_execute_sql with 'executes arbitrary SQL' description should be MEDIUM."""
    surface = _surface_with(
        ("pg_execute_sql", "Executes arbitrary SQL statements on the connected database.", {}),
    )
    findings = await ShadowToolModule().run(surface, None, None)
    desc_findings = [f for f in findings if "description" in f.title and "pg_execute_sql" in f.title]
    assert desc_findings, "Should still emit description finding for pg_execute_sql"
    assert desc_findings[0].severity == Severity.MEDIUM, \
        "DB-prefix tool should have MEDIUM description finding, not HIGH"


@pytest.mark.asyncio
async def test_shadow_tool_non_db_prefix_stays_high_description():
    """Non-DB tool with execution description stays HIGH."""
    surface = _surface_with(
        ("run_system", "Executes a shell command on the system.", {}),
    )
    findings = await ShadowToolModule().run(surface, None, None)
    desc_findings = [f for f in findings if "description" in f.title and "run_system" in f.title]
    assert desc_findings
    assert desc_findings[0].severity == Severity.HIGH


# ---------------------------------------------------------------------------
# param_smuggling — isError rejection FP fix (CS02-F14 class)
# ---------------------------------------------------------------------------

def test_response_diff_skips_is_error_rejection():
    """When probe causes isError=True, server correctly rejected — not a backdoor."""
    baseline = {"content": [{"type": "text", "text": "ok result"}]}
    probe = {"isError": True, "content": [{"type": "text", "text": "unknown parameter"}]}
    assert _response_diff(baseline, probe) == "", \
        "isError rejection should not be flagged as param smuggling"


def test_response_diff_skips_error_indicator_new_keys():
    """New key 'error' only means server returned an error — not a backdoor."""
    baseline = {"content": [{"type": "text", "text": '{"status": "ok"}'}]}
    probe = {"content": [{"type": "text", "text": '{"status": "ok", "error": "unknown param"}'}]}
    assert _response_diff(baseline, probe) == "", \
        "New 'error' key only should not be flagged as param smuggling"


def test_response_diff_still_detects_real_new_keys():
    """New privileged key 'debug' should still be flagged."""
    baseline = {"content": [{"type": "text", "text": '{"status": "ok"}'}]}
    probe = {"content": [{"type": "text", "text": '{"status": "ok", "debug": true, "internal_state": "..."}'}]}
    diff = _response_diff(baseline, probe)
    assert diff, "New non-error keys should still produce a diff"
    assert "debug" in diff or "internal_state" in diff


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
