"""Tests for token_exposure.py — HTTP header checks added in V28; FP calibration v3."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from corvus.core.models import MCPSurface, OWASPCategory, Severity
from corvus.modules.dynamic.token_exposure import (
    TokenExposureModule,
    _check_http_headers,
    _is_missing_credential_context,
    _is_type_annotation_match,
)
from corvus.transport.http import HttpTransport


def _surface() -> MCPSurface:
    return MCPSurface(server_name="test-server")


def _http_transport(url: str = "http://localhost:9999/mcp", headers: dict | None = None) -> MagicMock:
    t = MagicMock(spec=HttpTransport)
    t.url = url
    t._extra_headers = headers or {}
    return t


def _build_response(status: int = 200, headers: dict | None = None) -> httpx.Response:
    """Build a fake httpx.Response with given headers."""
    raw_headers = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    return httpx.Response(status_code=status, headers=raw_headers)


# ── HTTP header checks ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_server_header_detected():
    """'Server: nginx/1.2.3' in response → INFO finding."""
    t = _http_transport()
    fake_response = _build_response(headers={"Server": "nginx/1.2.3"})

    with patch("corvus.modules.dynamic.token_exposure.httpx.AsyncClient") as MockClient:
        instance = AsyncMock()
        instance.__aenter__ = AsyncMock(return_value=instance)
        instance.__aexit__ = AsyncMock(return_value=False)
        instance.post = AsyncMock(return_value=fake_response)
        MockClient.return_value = instance

        findings = await _check_http_headers(t)

    server_findings = [f for f in findings if "server version" in f.title.lower()]
    assert server_findings, f"Expected server header finding; got {[f.title for f in findings]}"
    assert server_findings[0].severity == Severity.INFO
    assert server_findings[0].owasp_category == OWASPCategory.MCP01_TOKEN_EXPOSURE


@pytest.mark.asyncio
async def test_debug_token_header_detected():
    """'x-debug-token: abc123' in response → HIGH finding."""
    t = _http_transport()
    fake_response = _build_response(headers={"X-Debug-Token": "abc123secret"})

    with patch("corvus.modules.dynamic.token_exposure.httpx.AsyncClient") as MockClient:
        instance = AsyncMock()
        instance.__aenter__ = AsyncMock(return_value=instance)
        instance.__aexit__ = AsyncMock(return_value=False)
        instance.post = AsyncMock(return_value=fake_response)
        MockClient.return_value = instance

        findings = await _check_http_headers(t)

    debug_findings = [f for f in findings if "debug token" in f.title.lower()]
    assert debug_findings, f"Expected debug token finding; got {[f.title for f in findings]}"
    assert debug_findings[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_no_finding_on_clean_headers():
    """Response with no sensitive headers → no header findings."""
    t = _http_transport()
    fake_response = _build_response(
        headers={"Content-Type": "application/json", "Cache-Control": "no-cache"}
    )

    with patch("corvus.modules.dynamic.token_exposure.httpx.AsyncClient") as MockClient:
        instance = AsyncMock()
        instance.__aenter__ = AsyncMock(return_value=instance)
        instance.__aexit__ = AsyncMock(return_value=False)
        instance.post = AsyncMock(return_value=fake_response)
        MockClient.return_value = instance

        findings = await _check_http_headers(t)

    assert findings == []


# ── FP calibration v3: crypto ticker ─────────────────────────────────────────

@pytest.mark.parametrize("match_text", [
    '"token": "BTC"',
    '"token": "BTC",',
    '"token": "ETH"}',
    '"TOKEN": "USDC"',
    'token: BTC',
    '"secret": "USD"',
])
def test_type_annotation_crypto_ticker_suppressed(match_text):
    """Short uppercase alpha values (crypto tickers) must be suppressed as FP."""
    assert _is_type_annotation_match(match_text), (
        f"Expected FP suppression for crypto ticker: {match_text!r}"
    )


@pytest.mark.parametrize("match_text", [
    '"token": "sk-abc123XYZ"',
    '"TOKEN": "eyJhbGciOiJIUzI1NiJ9.abc"',
    '"API_KEY": "ghp_xxxxxxxxxxx"',
])
def test_type_annotation_real_credential_not_suppressed(match_text):
    """Real credentials (long mixed-case values) must NOT be suppressed."""
    assert not _is_type_annotation_match(match_text), (
        f"Expected no FP suppression for real credential: {match_text!r}"
    )


# ── FP calibration v3: bot token missing ─────────────────────────────────────

@pytest.mark.parametrize("text", [
    "Discord bot token is not set. Please set DISCORD_BOT_TOKEN env var.",
    "Error: DISCORD_BOT_TOKEN environment variable not configured",
    "Token is missing — please configure via environment variable",
    "API_KEY is required but not provided",
    "TOKEN must be set before starting the bot",
    "Bot token not found, check your environment variables",
])
def test_missing_credential_context_detected(text):
    """Missing/unconfigured credential error messages must be detected as FP context."""
    assert _is_missing_credential_context(text), (
        f"Expected missing-credential context: {text!r}"
    )


@pytest.mark.parametrize("text", [
    'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.xxxxx',
    '"token": "sk-proj-abcdefghijklmnop"',
    'SECRET=ghp_RealGitHubTokenHere12345',
])
def test_missing_credential_context_not_suppressed_for_real_leaks(text):
    """Real credential leaks must NOT match the missing-credential filter."""
    assert not _is_missing_credential_context(text), (
        f"Expected no missing-credential context for real leak: {text!r}"
    )
