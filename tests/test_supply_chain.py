import pytest
from pathlib import Path

from corvus.modules.static.supply_chain import (
    SupplyChainModule,
    _extract_npm_package,
    _parse_audit,
    _run_npm_audit,
)
from corvus.core.models import Severity, OWASPCategory
from corvus.core.session import ScanSession

_NPM_AUDIT_CRITICAL = {
    "vulnerabilities": {
        "lodash": {
            "name": "lodash",
            "severity": "critical",
            "via": [{"cve": "CVE-2021-23337", "title": "Command Injection in lodash"}],
            "fixAvailable": {"name": "lodash", "version": "4.17.21"},
            "range": "<4.17.21",
        }
    }
}

_NPM_AUDIT_HIGH = {
    "vulnerabilities": {
        "semver": {
            "name": "semver",
            "severity": "high",
            "via": [{"url": "https://github.com/advisories/GHSA-c2qf-rxjj-qqgw", "title": "Regular Expression DoS"}],
            "fixAvailable": {"name": "semver", "version": "7.5.2"},
            "range": "<7.5.2",
        }
    }
}

_NPM_AUDIT_EMPTY = {"vulnerabilities": {}}

_NPM_AUDIT_CASCADE = {
    "vulnerabilities": {
        "@modelcontextprotocol/server-github": {
            "name": "@modelcontextprotocol/server-github",
            "severity": "high",
            "via": ["@modelcontextprotocol/sdk"],   # strings only = cascade
            "fixAvailable": True,
            "range": "*",
        },
        "@modelcontextprotocol/sdk": {
            "name": "@modelcontextprotocol/sdk",
            "severity": "high",
            "via": [{"url": "https://github.com/advisories/GHSA-xxxx-xxxx-xxxx", "title": "Prototype Pollution"}],
            "fixAvailable": {"name": "@modelcontextprotocol/sdk", "version": "1.26.0"},
            "range": "<=1.25.1",
        },
    }
}

_NPM_AUDIT_NO_CVE = {
    "vulnerabilities": {
        "some-pkg": {
            "name": "some-pkg",
            "severity": "high",
            "via": [{"url": "https://github.com/advisories/GHSA-zzzz-zzzz-zzzz", "title": "DoS — no CVE assigned yet"}],
            "fixAvailable": False,
            "range": "<=2.0.0",
        }
    }
}


# --- Unit tests for helpers ---

def test_extract_npm_package_npx_scoped():
    result = _extract_npm_package("npx -y @modelcontextprotocol/server-filesystem /tmp")
    assert result == "@modelcontextprotocol/server-filesystem"


def test_extract_npm_package_npx_simple():
    result = _extract_npm_package("npx some-package --flag value")
    assert result == "some-package"


def test_extract_npm_package_npm_exec():
    result = _extract_npm_package("npm exec -- @modelcontextprotocol/server-memory")
    assert result == "@modelcontextprotocol/server-memory"


def test_extract_npm_package_python_returns_none():
    assert _extract_npm_package("python3 my_server.py") is None


def test_extract_npm_package_empty_returns_none():
    assert _extract_npm_package("") is None


def test_parse_audit_critical():
    findings = _parse_audit(_NPM_AUDIT_CRITICAL, "@modelcontextprotocol/server-filesystem")
    assert findings
    assert findings[0].severity == Severity.CRITICAL
    assert "CVE-2021-23337" in findings[0].evidence
    assert findings[0].owasp_category == OWASPCategory.MCP04_SUPPLY_CHAIN
    assert findings[0].tool_name is None


def test_parse_audit_high_cve_from_url():
    findings = _parse_audit(_NPM_AUDIT_HIGH, "some-package")
    assert findings
    assert findings[0].severity == Severity.HIGH


def test_parse_audit_empty_no_findings():
    findings = _parse_audit(_NPM_AUDIT_EMPTY, "some-package")
    assert findings == []


def test_cascade_advisory_is_filtered():
    """Cascade advisories (via=list of strings) must be skipped — only the direct dep is reported."""
    findings = _parse_audit(_NPM_AUDIT_CASCADE, "@modelcontextprotocol/server-github")
    names = [f.title for f in findings]
    # The cascade wrapper (server-github@*) must NOT appear
    assert not any("server-github" in n for n in names), f"Cascade advisory leaked: {names}"
    # The direct advisory (sdk) must appear
    assert any("sdk" in n for n in names), f"Direct advisory missing: {names}"


def test_direct_advisory_no_cve_has_confidence_65():
    """Direct advisories without a CVE get confidence=65, not 90."""
    findings = _parse_audit(_NPM_AUDIT_NO_CVE, "some-pkg")
    assert findings, "Expected a finding for direct advisory without CVE"
    assert findings[0].confidence == 65, f"Expected confidence=65, got {findings[0].confidence}"


# --- E2E tests (monkeypatched) ---

@pytest.mark.asyncio
async def test_supply_chain_detects_critical_vuln(monkeypatch):
    async def mock_audit(pkg: str) -> dict:
        return _NPM_AUDIT_CRITICAL

    monkeypatch.setattr(
        "corvus.modules.static.supply_chain._run_npm_audit", mock_audit
    )

    session = ScanSession(
        "npx -y @modelcontextprotocol/server-filesystem /tmp", "stdio", Path("/tmp/corvus-test")
    )
    findings = await SupplyChainModule().run(None, None, session)

    assert findings, "Expected findings for package with critical vuln"
    assert findings[0].severity == Severity.CRITICAL
    assert "CVE-2021-23337" in findings[0].evidence


@pytest.mark.asyncio
async def test_supply_chain_skips_http_transport():
    session = ScanSession("http://localhost:8080/mcp", "http", Path("/tmp/corvus-test"))
    findings = await SupplyChainModule().run(None, None, session)
    assert findings == []


@pytest.mark.asyncio
async def test_supply_chain_skips_non_npm_cmd():
    session = ScanSession("python3 my_server.py", "stdio", Path("/tmp/corvus-test"))
    findings = await SupplyChainModule().run(None, None, session)
    assert findings == []


@pytest.mark.asyncio
async def test_supply_chain_no_findings_on_clean_audit(monkeypatch):
    async def mock_audit(pkg: str) -> dict:
        return _NPM_AUDIT_EMPTY

    monkeypatch.setattr(
        "corvus.modules.static.supply_chain._run_npm_audit", mock_audit
    )

    session = ScanSession("npx -y @modelcontextprotocol/server-memory", "stdio", Path("/tmp/corvus-test"))
    findings = await SupplyChainModule().run(None, None, session)
    assert findings == []
