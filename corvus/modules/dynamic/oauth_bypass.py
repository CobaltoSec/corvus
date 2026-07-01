"""oauth_bypass.py — HTTP transport authentication bypass probe (MCP07)."""
from __future__ import annotations

import urllib.parse

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...transport.base import MCPTransport
from ...transport.http import HttpTransport

_AUTH_HEADER_KEYS = frozenset({
    "authorization",
    "x-api-key",
    "x-auth-token",
    "x-token",
    "x-access-token",
    "api-key",
})

_AUTH_QUERY_PARAMS = frozenset({
    "token",
    "api_key",
    "access_token",
    "apikey",
    "auth",
    "key",
})

_INVALID_BEARER = "Bearer CORVUS_BYPASS_TEST_INVALID_TOKEN"


async def _try_tools_list(url: str, timeout: float, headers: dict[str, str]) -> bool:
    """Send tools/list with given headers. Returns True if server returns a result."""
    probe = HttpTransport(url=url, timeout=min(timeout, 10.0), headers=headers)
    try:
        async with probe:
            await probe.send_request("tools/list")
            return True
    except Exception:
        return False


def _detect_auth_headers(headers: dict[str, str]) -> list[str]:
    return [k for k in headers if k.lower() in _AUTH_HEADER_KEYS]


def _detect_auth_in_url(url: str) -> list[str]:
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    return [p for p in params if p.lower() in _AUTH_QUERY_PARAMS]


def _redact_url(url: str, params_to_redact: list[str]) -> str:
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    redact_set = {p.lower() for p in params_to_redact}
    parts: list[str] = []
    for k, vals in qs.items():
        if k.lower() in redact_set:
            parts.append(f"{k}=<REDACTED>")
        else:
            parts.extend(f"{k}={v}" for v in vals)
    return urllib.parse.urlunparse(parsed._replace(query="&".join(parts)))


class OAuthBypassModule(ScanModule):
    owasp_id = "MCP07"
    category = "Authentication & Authorization Bypass"
    name = "oauth-bypass"
    description = (
        "Tests HTTP transport endpoints for authentication bypass: "
        "missing Authorization header, invalid Bearer tokens, and credentials in URLs."
    )
    is_static = False

    async def run(
        self,
        surface: MCPSurface,
        transport: MCPTransport,
        session: ScanSession,
    ) -> list[Finding]:
        if not isinstance(transport, HttpTransport):
            return []

        findings: list[Finding] = []

        # Static check: credentials in URL query string
        auth_params = _detect_auth_in_url(transport.url)
        if auth_params:
            exposed = ", ".join(auth_params)
            findings.append(Finding(
                owasp_category=OWASPCategory.MCP07_AUTH_AUDIT,
                severity=Severity.HIGH,
                title=f"Credentials exposed in URL query string ({exposed})",
                description=(
                    f"The MCP server URL contains authentication credentials in the query "
                    f"string ({exposed}). Query parameters appear in server access logs, "
                    f"browser history, and HTTP referrer headers."
                ),
                evidence=_redact_url(transport.url, auth_params),
                confidence=90,
                remediation=(
                    "Move credentials to HTTP headers (Authorization: Bearer <token>) "
                    "and remove them from the URL."
                ),
            ))

        auth_headers = _detect_auth_headers(transport._extra_headers)
        if not auth_headers:
            return findings

        url = transport.url
        timeout = transport.timeout

        # Probe 1: request without any auth headers
        stripped = {k: v for k, v in transport._extra_headers.items()
                    if k.lower() not in _AUTH_HEADER_KEYS}
        if await _try_tools_list(url, timeout, stripped):
            findings.append(Finding(
                owasp_category=OWASPCategory.MCP07_AUTH_AUDIT,
                severity=Severity.CRITICAL,
                title="Auth bypass — server accepts requests without credentials",
                description=(
                    "The MCP server accepted a tools/list request with all authentication "
                    "headers removed, allowing unauthenticated access to the JSON-RPC endpoint."
                ),
                payload=f"tools/list (no auth headers: {', '.join(auth_headers)})",
                evidence="tools/list succeeded with no auth headers",
                exploitation_confirmed=True,
                confidence=95,
                remediation=(
                    "Enforce authentication on all MCP endpoints. "
                    "Return HTTP 401 with WWW-Authenticate for unauthenticated requests."
                ),
            ))
            return findings  # if no auth required at all, probe 2 is redundant

        # Probe 2: invalid Bearer token
        auth_key = next(
            (k for k in transport._extra_headers if k.lower() == "authorization"), None
        )
        if auth_key:
            invalid_headers = {**transport._extra_headers, auth_key: _INVALID_BEARER}
            if await _try_tools_list(url, timeout, invalid_headers):
                findings.append(Finding(
                    owasp_category=OWASPCategory.MCP07_AUTH_AUDIT,
                    severity=Severity.CRITICAL,
                    title="Auth bypass — server accepts invalid Bearer token",
                    description=(
                        "The MCP server accepted tools/list with a deliberately invalid "
                        "Bearer token (CORVUS_BYPASS_TEST_INVALID_TOKEN). "
                        "The server may be ignoring the Authorization header entirely."
                    ),
                    payload=f"Authorization: {_INVALID_BEARER}",
                    evidence="tools/list succeeded with invalid Bearer token",
                    exploitation_confirmed=True,
                    confidence=92,
                    remediation=(
                        "Validate Bearer tokens on every request: verify signature, "
                        "expiry, and issuer. Return HTTP 401 for invalid tokens."
                    ),
                ))

        return findings
