import pytest
from pathlib import Path

from corvus.modules.static.supply_chain_python import (
    SupplyChainPythonModule,
    _extract_python_package,
    _parse_pip_audit,
    _run_pip_audit,
)
from corvus.core.models import Severity, OWASPCategory
from corvus.core.session import ScanSession

# --- pip-audit JSON fixtures ---

_AUDIT_HIGH_CVE = [
    {
        "name": "werkzeug",
        "version": "2.3.0",
        "vulns": [
            {
                "id": "GHSA-2g68-c3qc-8985",
                "fix_versions": ["3.0.3"],
                "aliases": ["CVE-2024-34069"],
                "description": "Werkzeug debugger allows RCE via PIN bypass.",
            }
        ],
    }
]

_AUDIT_MEDIUM_NO_CVE = [
    {
        "name": "some-package",
        "version": "1.0.0",
        "vulns": [
            {
                "id": "GHSA-zzzz-zzzz-zzzz",
                "fix_versions": ["1.1.0"],
                "aliases": [],
                "description": "DoS vulnerability — no CVE assigned yet.",
            }
        ],
    }
]

_AUDIT_MULTI_DEP = [
    {
        "name": "mcp-server-sqlite",
        "version": "0.1.0",
        "vulns": [],
    },
    {
        "name": "aiohttp",
        "version": "3.8.0",
        "vulns": [
            {
                "id": "GHSA-abc1-def2-ghi3",
                "fix_versions": ["3.9.0"],
                "aliases": ["CVE-2023-49082"],
                "description": "Request smuggling vulnerability.",
            }
        ],
    },
]

_AUDIT_CLEAN = [
    {"name": "mcp-server-time", "version": "0.1.0", "vulns": []}
]


# --- Unit: _extract_python_package ---

def test_uvx_simple():
    assert _extract_python_package("uvx mcp-server-sqlite") == "mcp-server-sqlite"


def test_uvx_with_args():
    assert _extract_python_package("uvx --no-cache mcp-server-filesystem /data") == "mcp-server-filesystem"


def test_uvx_from_flag():
    assert _extract_python_package("uvx --from mcp-server-time time-server") == "mcp-server-time"


def test_uvx_short_from_flag():
    assert _extract_python_package("uvx -f remnux-mcp-server remnux-server") == "remnux-mcp-server"


def test_uvx_strips_extras():
    assert _extract_python_package("uvx mcp-server-sqlite[extra]") == "mcp-server-sqlite"


def test_uv_run_with():
    assert _extract_python_package("uv run --with mcp-server-time python server.py") == "mcp-server-time"


def test_uv_run_with_equals():
    assert _extract_python_package("uv run --with=mcp-server-sqlite server.py") == "mcp-server-sqlite"


def test_uv_run_with_comma_separated_takes_first():
    assert _extract_python_package("uv run --with mcp-server-time,httpx server.py") == "mcp-server-time"


def test_uv_tool_run():
    assert _extract_python_package("uv tool run mcp-server-filesystem /data") == "mcp-server-filesystem"


def test_uv_tool_install():
    assert _extract_python_package("uv tool install mcp-server-sqlite") == "mcp-server-sqlite"


def test_npx_returns_none():
    assert _extract_python_package("npx -y @modelcontextprotocol/server-filesystem /tmp") is None


def test_python_script_returns_none():
    assert _extract_python_package("python3 server.py") is None


def test_empty_returns_none():
    assert _extract_python_package("") is None


# --- Unit: _parse_pip_audit ---

def test_parse_high_with_cve():
    findings = _parse_pip_audit(_AUDIT_HIGH_CVE, "werkzeug")
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.HIGH
    assert f.confidence == 90
    assert f.owasp_category == OWASPCategory.MCP04_SUPPLY_CHAIN
    assert "CVE-2024-34069" in f.evidence
    assert "werkzeug" in f.title
    assert "GHSA-2g68-c3qc-8985" in f.evidence
    assert f.tool_name is None


def test_parse_medium_no_cve():
    findings = _parse_pip_audit(_AUDIT_MEDIUM_NO_CVE, "some-package")
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.MEDIUM
    assert f.confidence == 65
    assert "no CVE assigned" in f.evidence


def test_parse_multi_dep_only_vulnable():
    findings = _parse_pip_audit(_AUDIT_MULTI_DEP, "mcp-server-sqlite")
    assert len(findings) == 1
    assert "aiohttp" in findings[0].title
    assert "CVE-2023-49082" in findings[0].evidence


def test_parse_clean_no_findings():
    findings = _parse_pip_audit(_AUDIT_CLEAN, "mcp-server-time")
    assert findings == []


def test_parse_fix_version_in_remediation():
    findings = _parse_pip_audit(_AUDIT_HIGH_CVE, "werkzeug")
    assert "3.0.3" in findings[0].remediation


def test_parse_no_fix_remediation():
    deps = [
        {
            "name": "old-pkg",
            "version": "0.1.0",
            "vulns": [
                {
                    "id": "GHSA-xxxx-xxxx-xxxx",
                    "fix_versions": [],
                    "aliases": ["CVE-2024-99999"],
                    "description": "Critical bug with no fix.",
                }
            ],
        }
    ]
    findings = _parse_pip_audit(deps, "old-pkg")
    assert "patched version" in findings[0].remediation


# --- Integration: SupplyChainPythonModule (monkeypatched) ---

@pytest.mark.asyncio
async def test_module_detects_high_vuln(monkeypatch):
    async def mock_audit(pkg: str) -> list[dict]:
        return _AUDIT_HIGH_CVE

    monkeypatch.setattr(
        "corvus.modules.static.supply_chain_python._run_pip_audit", mock_audit
    )
    monkeypatch.setattr(
        "corvus.modules.static.supply_chain_python.shutil.which",
        lambda _: "/usr/bin/pip-audit",
    )

    session = ScanSession("uvx mcp-server-sqlite", "stdio", Path("/tmp/corvus-test"))
    findings = await SupplyChainPythonModule().run(None, None, session)

    assert findings
    assert findings[0].severity == Severity.HIGH
    assert "CVE-2024-34069" in findings[0].evidence


@pytest.mark.asyncio
async def test_module_skips_http_transport():
    session = ScanSession("http://localhost:8080/mcp", "http", Path("/tmp/corvus-test"))
    findings = await SupplyChainPythonModule().run(None, None, session)
    assert findings == []


@pytest.mark.asyncio
async def test_module_skips_npm_cmd():
    session = ScanSession("npx -y @modelcontextprotocol/server-memory", "stdio", Path("/tmp/corvus-test"))
    findings = await SupplyChainPythonModule().run(None, None, session)
    assert findings == []


@pytest.mark.asyncio
async def test_module_skips_when_pip_audit_missing(monkeypatch):
    monkeypatch.setattr(
        "corvus.modules.static.supply_chain_python.shutil.which",
        lambda _: None,
    )
    session = ScanSession("uvx mcp-server-sqlite", "stdio", Path("/tmp/corvus-test"))
    findings = await SupplyChainPythonModule().run(None, None, session)
    assert findings == []


@pytest.mark.asyncio
async def test_module_no_findings_on_clean_audit(monkeypatch):
    async def mock_audit(pkg: str) -> list[dict]:
        return _AUDIT_CLEAN

    monkeypatch.setattr(
        "corvus.modules.static.supply_chain_python._run_pip_audit", mock_audit
    )
    monkeypatch.setattr(
        "corvus.modules.static.supply_chain_python.shutil.which",
        lambda _: "/usr/bin/pip-audit",
    )

    session = ScanSession("uvx mcp-server-time", "stdio", Path("/tmp/corvus-test"))
    findings = await SupplyChainPythonModule().run(None, None, session)
    assert findings == []
