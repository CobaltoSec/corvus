"""
E2E tests for the Corvus public API contract (v1.0).

These tests validate the API surface from the perspective of a plugin author
or downstream user importing `corvus`. They cover:
  - Top-level importability (__all__ symbols)
  - Finding / ScanResult / Severity / OWASPCategory contracts
  - ScanModule subclassing and execution
  - py.typed marker presence (PEP 561)
  - Version string accessibility
"""
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

import corvus
from corvus import (
    Finding,
    MCPSurface,
    OWASPCategory,
    PromptSpec,
    RawExchange,
    ResourceSpec,
    ScanModule,
    ScanResult,
    Severity,
    ToolSpec,
    __version__,
)


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------

def test_all_symbols_in_dunder_all():
    """Every name in __all__ must be importable from the corvus package."""
    for name in corvus.__all__:
        assert hasattr(corvus, name), f"corvus.__all__ lists '{name}' but it's not importable"


def test_version_is_set():
    assert __version__ != "0.0.0", "Version should be resolved from package metadata"
    parts = __version__.split(".")
    assert len(parts) >= 2, f"Version format unexpected: {__version__!r}"


def test_py_typed_marker_exists():
    """PEP 561 requires a py.typed marker file in the package directory."""
    marker = Path(corvus.__file__).parent / "py.typed"
    assert marker.exists(), f"py.typed marker missing at {marker}"


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

def test_severity_values():
    assert Severity.CRITICAL.value == "critical"
    assert Severity.HIGH.value == "high"
    assert Severity.MEDIUM.value == "medium"
    assert Severity.LOW.value == "low"
    assert Severity.INFO.value == "info"


def test_severity_is_str_enum():
    assert isinstance(Severity.HIGH, str)
    assert Severity.HIGH == "high"


def test_severity_all_five_members():
    members = {s.value for s in Severity}
    assert members == {"critical", "high", "medium", "low", "info"}


# ---------------------------------------------------------------------------
# OWASPCategory
# ---------------------------------------------------------------------------

def test_owasp_top10_ids_present():
    ids = {c.value for c in OWASPCategory}
    for i in range(1, 11):
        assert f"MCP{i:02d}" in ids, f"MCP{i:02d} missing from OWASPCategory"


def test_owasp_extensions_present():
    ids = {c.value for c in OWASPCategory}
    for ext in ("EXT01", "EXT02", "EXT03", "EXT04", "EXT05", "EXT06"):
        assert ext in ids, f"{ext} missing from OWASPCategory"


def test_owasp_is_str_enum():
    assert isinstance(OWASPCategory.MCP01_TOKEN_EXPOSURE, str)
    assert OWASPCategory.MCP01_TOKEN_EXPOSURE == "MCP01"


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

def test_finding_minimal_construction():
    f = Finding(
        owasp_category=OWASPCategory.MCP05_CMD_INJECTION,
        severity=Severity.HIGH,
        title="Test finding",
        description="A test.",
    )
    assert f.severity == Severity.HIGH
    assert f.owasp_category == OWASPCategory.MCP05_CMD_INJECTION
    assert f.tool_name is None
    assert f.confidence == 50  # default


def test_finding_full_construction():
    f = Finding(
        owasp_category=OWASPCategory.MCP04_SUPPLY_CHAIN,
        severity=Severity.CRITICAL,
        title="Supply chain vuln",
        description="lodash has CVE-2021-23337",
        tool_name=None,
        parameter="pkg",
        payload="lodash@4.17.20",
        evidence="lodash@<4.17.21 — CVE-2021-23337",
        remediation="Update lodash to 4.17.21",
        exploitation_confirmed=True,
        confidence=90,
    )
    assert f.severity == Severity.CRITICAL
    assert f.exploitation_confirmed is True
    assert f.confidence == 90


def test_finding_json_serializable():
    f = Finding(
        owasp_category=OWASPCategory.MCP10_CONTEXT_INJECTION,
        severity=Severity.MEDIUM,
        title="Injection test",
        description="Some desc",
    )
    data = json.loads(f.model_dump_json())
    assert data["severity"] == "medium"
    assert data["owasp_category"] == "MCP10"
    assert data["title"] == "Injection test"


def test_finding_severity_roundtrip():
    f = Finding(
        owasp_category=OWASPCategory.MCP02_SCOPE_CREEP,
        severity=Severity.LOW,
        title="Low sev",
        description="desc",
    )
    dumped = f.model_dump()
    restored = Finding(**dumped)
    assert restored.severity == Severity.LOW


# ---------------------------------------------------------------------------
# ToolSpec / MCPSurface
# ---------------------------------------------------------------------------

def test_toolspec_construction():
    t = ToolSpec(name="get_time", description="Returns UTC time")
    assert t.name == "get_time"
    assert t.input_schema == {}


def test_mcpsurface_defaults():
    surface = MCPSurface()
    assert surface.tools == []
    assert surface.resources == []
    assert surface.prompts == []


def test_mcpsurface_with_tools():
    surface = MCPSurface(
        server_name="test-server",
        tools=[ToolSpec(name="ping"), ToolSpec(name="pong")],
    )
    assert len(surface.tools) == 2
    assert surface.tools[0].name == "ping"


# ---------------------------------------------------------------------------
# ScanResult
# ---------------------------------------------------------------------------

def test_scanresult_finding_count_empty():
    result = ScanResult(target="npx test", transport="stdio", surface=MCPSurface())
    counts = result.finding_count
    assert counts["critical"] == 0
    assert counts["high"] == 0


def test_scanresult_finding_count_mixed():
    findings = [
        Finding(owasp_category=OWASPCategory.MCP05_CMD_INJECTION, severity=Severity.CRITICAL,
                title="A", description="d"),
        Finding(owasp_category=OWASPCategory.MCP05_CMD_INJECTION, severity=Severity.CRITICAL,
                title="B", description="d"),
        Finding(owasp_category=OWASPCategory.MCP01_TOKEN_EXPOSURE, severity=Severity.HIGH,
                title="C", description="d"),
        Finding(owasp_category=OWASPCategory.MCP02_SCOPE_CREEP, severity=Severity.LOW,
                title="D", description="d"),
    ]
    result = ScanResult(
        target="npx test", transport="stdio", surface=MCPSurface(), findings=findings
    )
    counts = result.finding_count
    assert counts["critical"] == 2
    assert counts["high"] == 1
    assert counts["medium"] == 0
    assert counts["low"] == 1


def test_scanresult_json_serializable():
    result = ScanResult(
        target="uvx mcp-server-time",
        transport="stdio",
        surface=MCPSurface(server_name="time-server"),
        duration_seconds=1.23,
    )
    data = json.loads(result.model_dump_json())
    assert data["target"] == "uvx mcp-server-time"
    assert data["transport"] == "stdio"
    assert data["duration_seconds"] == pytest.approx(1.23)


# ---------------------------------------------------------------------------
# ScanModule — plugin authoring contract
# ---------------------------------------------------------------------------

class _EchoModule(ScanModule):
    """Minimal custom module for API contract testing."""
    owasp_id = "MCP01"
    category = "Test"
    name = "echo-test"
    description = "Returns a fixed finding for testing."
    is_static = True

    async def run(self, surface, transport, session) -> list[Finding]:
        return [
            Finding(
                owasp_category=OWASPCategory.MCP01_TOKEN_EXPOSURE,
                severity=Severity.INFO,
                title="Echo finding",
                description="Custom module ran successfully.",
                confidence=100,
            )
        ]


def test_scan_module_subclass_attributes():
    m = _EchoModule()
    assert m.name == "echo-test"
    assert m.owasp_id == "MCP01"
    assert m.is_static is True


@pytest.mark.asyncio
async def test_scan_module_run_returns_findings():
    m = _EchoModule()
    findings = await m.run(surface=None, transport=None, session=None)
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert findings[0].confidence == 100


@pytest.mark.asyncio
async def test_scan_module_findings_are_finding_instances():
    m = _EchoModule()
    findings = await m.run(surface=None, transport=None, session=None)
    for f in findings:
        assert isinstance(f, Finding)


def test_scan_module_cannot_instantiate_abstract():
    """ScanModule without run() implementation must raise TypeError."""
    with pytest.raises(TypeError):
        ScanModule()  # type: ignore[abstract]
