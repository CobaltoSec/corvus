"""Tests for github_advisory.py (GitHubAdvisoryModule) — V28."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from corvus.core.models import MCPSurface, OWASPCategory, Severity
from corvus.core.session import ScanSession
from corvus.modules.static.github_advisory import (
    GitHubAdvisoryModule,
    _cvss_to_severity,
    _parse_advisory,
    _query_gh_advisories,
    _read_deps,
)


def _session(transport: str = "stdio", target: str = "npx test-server") -> ScanSession:
    return ScanSession(target, transport, Path("/tmp/corvus-test"))


def _surface() -> MCPSurface:
    return MCPSurface(server_name="test-server")


def _advisory(ghsa_id: str, cvss_score: float | None = None, cve_ids: list[str] | None = None) -> dict:
    adv: dict = {"ghsa_id": ghsa_id, "summary": f"Test advisory {ghsa_id}"}
    if cvss_score is not None:
        adv["cvss"] = {"score": cvss_score}
    adv["cve_ids"] = [{"value": c} for c in (cve_ids or [])]
    return adv


# ── Module metadata ───────────────────────────────────────────────────────────

def test_module_name_and_owasp():
    m = GitHubAdvisoryModule()
    assert m.name == "github-advisory"
    assert m.owasp_id == "MCP04"
    assert m.is_static is True


# ── Skip for HTTP ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_skips_http_target():
    """HTTP transport → return [] immediately."""
    session = _session(transport="http", target="http://localhost:8000/mcp")
    findings = await GitHubAdvisoryModule().run(_surface(), None, session)
    assert findings == []


# ── No advisory ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_no_advisory_for_package(tmp_path):
    """Package with no advisories → no findings."""
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(json.dumps({"dependencies": {"safe-pkg": "^1.0.0"}}))

    session = _session(target=str(tmp_path / "server.js"))

    with patch("corvus.modules.static.github_advisory._find_package_json", return_value=pkg_json), \
         patch("corvus.modules.static.github_advisory._query_gh_advisories", return_value=[]):
        findings = await GitHubAdvisoryModule().run(_surface(), None, session)

    assert findings == []


# ── Advisory detected ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_high_severity_advisory_detected(tmp_path):
    """Package with CVSS 8.5 advisory → HIGH finding."""
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(json.dumps({"dependencies": {"vuln-pkg": "^2.0.0"}}))

    session = _session(target=str(tmp_path / "server.js"))
    adv = _advisory("GHSA-test-0001", cvss_score=8.5, cve_ids=["CVE-2024-12345"])

    with patch("corvus.modules.static.github_advisory._find_package_json", return_value=pkg_json), \
         patch("corvus.modules.static.github_advisory._query_gh_advisories", return_value=[adv]):
        findings = await GitHubAdvisoryModule().run(_surface(), None, session)

    assert findings
    assert findings[0].severity == Severity.HIGH
    assert findings[0].owasp_category == OWASPCategory.MCP04_SUPPLY_CHAIN
    assert "GHSA-test-0001" in findings[0].title
    assert "vuln-pkg" in findings[0].title


@pytest.mark.asyncio
async def test_critical_advisory(tmp_path):
    """Package with CVSS 9.5 → CRITICAL finding."""
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(json.dumps({"dependencies": {"critical-pkg": "^1.0.0"}}))

    session = _session(target=str(tmp_path / "server.js"))
    adv = _advisory("GHSA-crit-0001", cvss_score=9.5, cve_ids=["CVE-2025-99999"])

    with patch("corvus.modules.static.github_advisory._find_package_json", return_value=pkg_json), \
         patch("corvus.modules.static.github_advisory._query_gh_advisories", return_value=[adv]):
        findings = await GitHubAdvisoryModule().run(_surface(), None, session)

    assert findings
    assert findings[0].severity == Severity.CRITICAL


# ── Graceful error handling ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_graceful_on_api_error(tmp_path):
    """Network error querying GitHub API → no findings, no exception."""
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(json.dumps({"dependencies": {"some-pkg": "^1.0.0"}}))

    session = _session(target=str(tmp_path / "server.js"))

    with patch("corvus.modules.static.github_advisory._find_package_json", return_value=pkg_json), \
         patch("corvus.modules.static.github_advisory._query_gh_advisories",
               side_effect=Exception("connection refused")):
        findings = await GitHubAdvisoryModule().run(_surface(), None, session)

    assert findings == []


# ── Package limit ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_limits_to_30_packages(tmp_path):
    """Module reads at most 30 packages from package.json."""
    deps = {f"pkg-{i}": "^1.0.0" for i in range(50)}
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(json.dumps({"dependencies": deps}))

    session = _session(target=str(tmp_path / "server.js"))
    queried: list[str] = []

    async def mock_query(pkg_name):
        queried.append(pkg_name)
        return []

    with patch("corvus.modules.static.github_advisory._find_package_json", return_value=pkg_json), \
         patch("corvus.modules.static.github_advisory._query_gh_advisories", side_effect=mock_query):
        await GitHubAdvisoryModule().run(_surface(), None, session)

    assert len(queried) <= 30


# ── Unit: _cvss_to_severity ───────────────────────────────────────────────────

def test_cvss_to_severity_critical():
    assert _cvss_to_severity(9.5) == Severity.CRITICAL

def test_cvss_to_severity_high():
    assert _cvss_to_severity(7.5) == Severity.HIGH

def test_cvss_to_severity_medium():
    assert _cvss_to_severity(5.0) == Severity.MEDIUM

def test_cvss_to_severity_low():
    assert _cvss_to_severity(2.0) == Severity.LOW

def test_cvss_to_severity_none():
    assert _cvss_to_severity(None) == Severity.INFO
