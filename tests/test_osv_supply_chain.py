import pytest
from pathlib import Path

from corvus.modules.static.osv_supply_chain import (
    OsvSupplyChainModule,
    _parse_osv_vulns,
    _query_osv,
)
from corvus.core.models import MCPSurface, Severity, OWASPCategory
from corvus.core.session import ScanSession


# ── OSV.dev response fixtures ────────────────────────────────────────────────

_OSV_HIGH_CVE = [
    {
        "id": "GHSA-7w27-7xwv-x6x2",
        "summary": "mcp-server-sqlite path traversal allows arbitrary file read",
        "aliases": ["CVE-2025-12345"],
        "database_specific": {"severity": "HIGH"},
        "affected": [
            {
                "package": {"name": "mcp-server-sqlite", "ecosystem": "npm"},
                "ranges": [
                    {"events": [{"introduced": "0"}, {"fixed": "0.6.3"}]}
                ],
            }
        ],
    }
]

_OSV_CRITICAL_CVE = [
    {
        "id": "GHSA-43j9-hmpq-cgv7",
        "summary": "remnux-mcp-server unauthenticated RCE",
        "aliases": ["CVE-2025-99999"],
        "database_specific": {"severity": "CRITICAL"},
        "affected": [
            {
                "package": {"name": "remnux-mcp-server", "ecosystem": "PyPI"},
                "ranges": [
                    {"events": [{"introduced": "0"}, {"fixed": "1.2.0"}]}
                ],
            }
        ],
    }
]

_OSV_MODERATE_NO_CVE = [
    {
        "id": "GHSA-xxxx-xxxx-xxxx",
        "summary": "DoS via malformed request",
        "aliases": [],
        "database_specific": {"severity": "MODERATE"},
        "affected": [],
    }
]

_OSV_NO_DB_SEV_WITH_CVE = [
    {
        "id": "GHSA-yyyy-yyyy-yyyy",
        "summary": "SSRF vulnerability",
        "aliases": ["CVE-2024-11111"],
        "database_specific": {},
        "affected": [],
    }
]

_OSV_EMPTY: list = []


# ── Unit: _parse_osv_vulns ───────────────────────────────────────────────────

def test_parse_high_with_cve():
    findings = _parse_osv_vulns(_OSV_HIGH_CVE, "mcp-server-sqlite", "npm")
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.HIGH
    assert f.confidence == 90
    assert f.owasp_category == OWASPCategory.MCP04_SUPPLY_CHAIN
    assert "GHSA-7w27-7xwv-x6x2" in f.title
    assert "CVE-2025-12345" in f.evidence
    assert "mcp-server-sqlite" in f.title
    assert "fixed:0.6.3" in f.evidence


def test_parse_critical_with_cve():
    findings = _parse_osv_vulns(_OSV_CRITICAL_CVE, "remnux-mcp-server", "PyPI")
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.CRITICAL
    assert f.confidence == 90
    assert "GHSA-43j9-hmpq-cgv7" in f.title


def test_parse_moderate_no_cve():
    findings = _parse_osv_vulns(_OSV_MODERATE_NO_CVE, "some-pkg", "npm")
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.MEDIUM
    assert f.confidence == 65
    assert "no CVE assigned" in f.evidence


def test_parse_no_db_severity_with_cve_defaults_high():
    findings = _parse_osv_vulns(_OSV_NO_DB_SEV_WITH_CVE, "pkg", "npm")
    assert findings[0].severity == Severity.HIGH
    assert findings[0].confidence == 90


def test_parse_empty_vulns():
    assert _parse_osv_vulns(_OSV_EMPTY, "safe-pkg", "npm") == []


def test_parse_remediation_links_osv():
    findings = _parse_osv_vulns(_OSV_HIGH_CVE, "mcp-server-sqlite", "npm")
    assert "osv.dev/GHSA-7w27-7xwv-x6x2" in findings[0].remediation


# ── Unit: _query_osv (mocked) ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_query_osv_returns_vulns(monkeypatch):
    from unittest.mock import AsyncMock, MagicMock

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"vulns": _OSV_HIGH_CVE}

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.post = AsyncMock(return_value=mock_resp)

    monkeypatch.setattr(
        "corvus.modules.static.osv_supply_chain.httpx.AsyncClient",
        lambda **kwargs: mock_client,
    )
    result = await _query_osv("mcp-server-sqlite", "npm")
    assert result == _OSV_HIGH_CVE


@pytest.mark.asyncio
async def test_query_osv_non_200_returns_empty(monkeypatch):
    from unittest.mock import AsyncMock, MagicMock

    mock_resp = MagicMock()
    mock_resp.status_code = 500

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.post = AsyncMock(return_value=mock_resp)

    monkeypatch.setattr(
        "corvus.modules.static.osv_supply_chain.httpx.AsyncClient",
        lambda **kwargs: mock_client,
    )
    result = await _query_osv("mcp-server-sqlite", "npm")
    assert result == []


@pytest.mark.asyncio
async def test_query_osv_network_error_returns_empty(monkeypatch):
    import httpx
    from unittest.mock import AsyncMock

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))

    monkeypatch.setattr(
        "corvus.modules.static.osv_supply_chain.httpx.AsyncClient",
        lambda **kwargs: mock_client,
    )
    result = await _query_osv("mcp-server-sqlite", "npm")
    assert result == []


# ── Integration: OsvSupplyChainModule.run ────────────────────────────────────

@pytest.mark.asyncio
async def test_module_stdio_npm(monkeypatch):
    async def mock_query(pkg: str, eco: str) -> list:
        assert pkg == "@modelcontextprotocol/server-filesystem"
        assert eco == "npm"
        return _OSV_HIGH_CVE

    monkeypatch.setattr("corvus.modules.static.osv_supply_chain._query_osv", mock_query)
    session = ScanSession(
        "npx -y @modelcontextprotocol/server-filesystem /tmp",
        "stdio",
        Path("/tmp/corvus-test"),
    )
    findings = await OsvSupplyChainModule().run(None, None, session)
    assert findings
    assert findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_module_stdio_python_uvx(monkeypatch):
    async def mock_query(pkg: str, eco: str) -> list:
        assert pkg == "mcp-server-sqlite"
        assert eco == "PyPI"
        return _OSV_CRITICAL_CVE

    monkeypatch.setattr("corvus.modules.static.osv_supply_chain._query_osv", mock_query)
    session = ScanSession("uvx mcp-server-sqlite", "stdio", Path("/tmp/corvus-test"))
    findings = await OsvSupplyChainModule().run(None, None, session)
    assert findings
    assert findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_module_http_uses_server_name(monkeypatch):
    calls: list[tuple[str, str]] = []

    async def mock_query(pkg: str, eco: str) -> list:
        calls.append((pkg, eco))
        if eco == "npm":
            return _OSV_HIGH_CVE
        return []

    monkeypatch.setattr("corvus.modules.static.osv_supply_chain._query_osv", mock_query)
    surface = MCPSurface(server_name="mcp-server-sqlite", server_version="0.6.2")
    session = ScanSession("http://localhost:8080/mcp", "http", Path("/tmp/corvus-test"))
    findings = await OsvSupplyChainModule().run(surface, None, session)
    assert findings
    assert ("mcp-server-sqlite", "npm") in calls


@pytest.mark.asyncio
async def test_module_http_fallback_to_pypi(monkeypatch):
    """If npm returns nothing for an HTTP target, try PyPI."""
    calls: list[tuple[str, str]] = []

    async def mock_query(pkg: str, eco: str) -> list:
        calls.append((pkg, eco))
        if eco == "PyPI":
            return _OSV_CRITICAL_CVE
        return []

    monkeypatch.setattr("corvus.modules.static.osv_supply_chain._query_osv", mock_query)
    surface = MCPSurface(server_name="remnux-mcp-server")
    session = ScanSession("http://localhost:8080/mcp", "http", Path("/tmp/corvus-test"))
    findings = await OsvSupplyChainModule().run(surface, None, session)
    assert findings
    assert ("remnux-mcp-server", "PyPI") in calls
    assert findings[0].severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_module_http_no_server_name_returns_empty():
    surface = MCPSurface(server_name="")
    session = ScanSession("http://localhost:8080/mcp", "http", Path("/tmp/corvus-test"))
    findings = await OsvSupplyChainModule().run(surface, None, session)
    assert findings == []


@pytest.mark.asyncio
async def test_module_stdio_unknown_cmd_returns_empty():
    session = ScanSession("python3 server.py", "stdio", Path("/tmp/corvus-test"))
    findings = await OsvSupplyChainModule().run(None, None, session)
    assert findings == []


@pytest.mark.asyncio
async def test_module_no_vulns_returns_empty(monkeypatch):
    async def mock_query(pkg: str, eco: str) -> list:
        return []

    monkeypatch.setattr("corvus.modules.static.osv_supply_chain._query_osv", mock_query)
    session = ScanSession("npx -y safe-mcp-server", "stdio", Path("/tmp/corvus-test"))
    findings = await OsvSupplyChainModule().run(None, None, session)
    assert findings == []
