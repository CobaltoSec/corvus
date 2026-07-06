from __future__ import annotations

import re
from typing import Any

import httpx

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...payloads.engine import PayloadEngine
from ...transport.base import MCPTransport
from ...transport.http import HttpTransport

# Each entry: (compiled pattern, label, severity, confidence)
_SIGNALS: list[tuple[re.Pattern[str], str, Severity, int]] = [
    (re.compile(r'"?(API_KEY|TOKEN|SECRET|PASSWORD|PASSWD|AUTH_KEY)"?\s*[=:]\s*"?\S+', re.I),
     "credential in response", Severity.CRITICAL, 85),
    (re.compile(r"postgres://|mysql://|mongodb://|redis://", re.I),
     "database connection string", Severity.CRITICAL, 85),
    (re.compile(r"/home/\w+/"),
     "home directory path", Severity.MEDIUM, 80),
    (re.compile(r"/etc/(passwd|shadow|hosts|ssh)"),
     "sensitive system file path", Severity.HIGH, 85),
    (re.compile(r"C:\\Users\\", re.I),
     "Windows user path", Severity.MEDIUM, 80),
    (re.compile(r"Traceback \(most recent call last\)"),
     "Python stack trace", Severity.MEDIUM, 80),
    (re.compile(r"(Error|Exception) at .+\.py:\d+"),
     "source file reference in error", Severity.LOW, 70),
    (re.compile(r"\b(127\.0\.0\.1|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)\b"),
     "internal IP address", Severity.LOW, 70),  # filtered by _is_connection_error_text below
    (re.compile(r'-----BEGIN (RSA |EC )?PRIVATE KEY-----'),
     "private key material", Severity.CRITICAL, 85),
    (re.compile(r"(Flask|Express|FastAPI|uvicorn|starlette|Django)/\d+\.\d+", re.I),
     "framework version string", Severity.INFO, 70),
]


_CONNECTION_ERROR_RE = re.compile(
    r"cannot connect|connection failed|not running|check your configuration|default port|configure",
    re.I,
)

_CREDENTIAL_MISSING_RE = re.compile(
    r"\bnot\s+set\b|\bnot\s+configured\b|\bnot\s+provided\b|\bnot\s+found\b"
    r"|\bmissing\b|\bplease\s+set\b|\benv(?:ironment)?\s+var(?:iable)?\b"
    r"|\bis\s+required\b|\bmust\s+be\s+set\b",
    re.I,
)


def _is_connection_error_text(text: str) -> bool:
    """Return True if text is a connection-error help message, not a real credential leak."""
    return bool(_CONNECTION_ERROR_RE.search(text))


def _is_missing_credential_context(text: str) -> bool:
    """Return True if text is an error about a missing/unconfigured credential.

    Catches bot token / API key missing errors like 'Discord bot token is not set.
    Please set DISCORD_BOT_TOKEN env var.' — these contain the token NAME but not
    a real credential value.
    """
    return bool(_CREDENTIAL_MISSING_RE.search(text))


class TokenExposureModule(ScanModule):
    owasp_id = "MCP01"
    category = "Token Mismanagement & Secret Exposure"
    name = "token-exposure"
    description = "Detects sensitive data leaked in tool responses (credentials, paths, stack traces)"
    is_static = False

    def __init__(self):
        self.engine = PayloadEngine()

    async def run(
        self,
        surface: MCPSurface,
        transport: MCPTransport,
        session: ScanSession,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for tool in surface.tools:
            seen_signals: set[str] = set()  # dedup: one finding per (tool, signal label)
            schema = tool.input_schema
            properties: dict[str, Any] = schema.get("properties", {})
            required: list[str] = schema.get("required", [])

            # Collect responses to analyse: benign call + error-provoking calls (A4)
            texts_to_check: list[str] = []

            # Standard benign call
            benign_args = {
                p: self.engine.benign_default(s.get("type", "string"))
                for p, s in properties.items()
                if p in required
            }
            try:
                result = await transport.send_request(
                    "tools/call", {"name": tool.name, "arguments": benign_args}
                )
                texts_to_check.append(_extract_text(result))
            except Exception:
                pass

            # A4: error-provoking — call with missing required args
            if required:
                try:
                    result = await transport.send_request(
                        "tools/call", {"name": tool.name, "arguments": {}}
                    )
                    texts_to_check.append(_extract_text(result))
                except Exception:
                    pass

            # A4: error-provoking — call with an oversized string in first string param
            first_str_param = next(
                (p for p, s in properties.items() if s.get("type", "string") == "string"),
                None,
            )
            if first_str_param:
                oversized_args = dict(benign_args)
                oversized_args[first_str_param] = "A" * 10_000
                try:
                    result = await transport.send_request(
                        "tools/call", {"name": tool.name, "arguments": oversized_args}
                    )
                    texts_to_check.append(_extract_text(result))
                except Exception:
                    pass

            for text in texts_to_check:
                if _is_html_catch_all(text):  # A6: skip SPA catch-all HTML responses
                    continue
                text = _strip_code_blocks(text)
                for pattern, label, severity, conf in _SIGNALS:
                    m = pattern.search(text)
                    if m:
                        if label == "credential in response":
                            if _is_type_annotation_match(m.group(0)):
                                continue  # TypeScript type annotation, not a real credential
                            if _is_missing_credential_context(text):
                                continue  # missing/unconfigured token error, not a real leak
                        if label == "internal IP address" and _is_connection_error_text(text):
                            continue  # IP in connection-error help text — not a real leak
                        if label in seen_signals:
                            break  # already reported this signal for this tool (A1: dedup across response texts)
                        seen_signals.add(label)
                        findings.append(Finding(
                            owasp_category=OWASPCategory.MCP01_TOKEN_EXPOSURE,
                            severity=severity,
                            title=f"Token Exposure — {label} in '{tool.name}'",
                            description=f"Tool response contains {label}.",
                            tool_name=tool.name,
                            evidence=text[:400],
                            confidence=conf,
                            remediation=(
                                "Strip sensitive data from tool responses. "
                                "Never return raw environment variables, credentials, or internal paths."
                            ),
                        ))
                        break  # one finding per signal per response text

        if isinstance(transport, HttpTransport):
            findings.extend(await _check_http_headers(transport))

        return findings


def _extract_text(result: Any) -> str:
    if not result:
        return ""
    content = result.get("content", []) if isinstance(result, dict) else []
    return " ".join(c.get("text", "") for c in content if isinstance(c, dict))


# TypeScript primitive type keywords — bare values like TOKEN: string or SECRET: boolean
_TS_PRIMITIVE_TYPES = frozenset({
    "string", "number", "boolean", "null", "undefined",
    "void", "never", "any", "unknown", "object",
})

# TypeScript access / modifier keywords — bare values like TOKEN: readonly or SECRET: static
_TS_MODIFIER_WORDS = frozenset({
    "readonly", "optional", "abstract", "override", "protected", "public", "private",
    "static", "declare", "const", "let", "var",
})


def _is_type_annotation_match(match_text: str) -> bool:
    """Return True if the regex match looks like a TypeScript/Vue.js type annotation.

    Prevents false positives when tool documentation returns TypeScript interface
    definitions that happen to contain field names like TOKEN or SECRET followed
    by a type reference (e.g. 'TOKEN: MaybeRefOrGetter<boolean>', 'SECRET: string').
    """
    parts = re.split(r'[=:]\s*', match_text, maxsplit=1)
    if len(parts) < 2:
        return False
    value = parts[1].strip('"\'').strip()
    # Array type shorthand check BEFORE stripping (rstrip would eat the `]`)
    if value.endswith('[]'):
        return True
    # Strip trailing JSON punctuation (comma, closing brace/bracket/paren)
    value = value.rstrip('",}])')
    # Template literal type: starts with backtick (e.g. TOKEN: `${string}`)
    if value.startswith('`'):
        return True
    # TypeScript generic type: contains < or > (e.g. MaybeRefOrGetter<boolean>)
    if '<' in value or '>' in value:
        return True
    # Union or intersection type: contains | or & (e.g. string | null)
    if '|' in value or '&' in value:
        return True
    # Array type shorthand: ends with [] (e.g. TOKEN: string[])
    if value.endswith('[]'):
        return True
    # PascalCase identifier with no digits or special chars — likely a type name
    if re.match(r'^[A-Z][a-zA-Z]{2,}$', value):
        return True
    # TypeScript primitive type keyword (e.g. TOKEN: string, SECRET: boolean)
    if value.lower() in _TS_PRIMITIVE_TYPES:
        return True
    # TypeScript modifier/access keyword (e.g. TOKEN: readonly, SECRET: static)
    if value.lower() in _TS_MODIFIER_WORDS:
        return True
    return False


_CODE_BLOCK_RE = re.compile(r"```.*?```", re.DOTALL)
_INLINE_CODE_RE = re.compile(r"`[^`\n]+`")


def _strip_code_blocks(text: str) -> str:
    """Remove markdown fenced and inline code blocks to avoid FPs on documentation responses.

    Type annotations and technical keywords inside code blocks are not credentials.
    We preserve the surrounding prose context so real credentials embedded outside
    code blocks are still detected.
    """
    text = _CODE_BLOCK_RE.sub(" ", text)
    text = _INLINE_CODE_RE.sub(" ", text)
    return text


_SENSITIVE_HEADER_SIGNALS: list[tuple[str, str, Severity]] = [
    ("x-powered-by", "framework version disclosure", Severity.INFO),
    ("server", "server version disclosure", Severity.INFO),
    ("x-debug", "debug header exposed", Severity.MEDIUM),
    ("x-debug-token", "debug token in header", Severity.HIGH),
    ("x-internal", "internal header exposed", Severity.LOW),
    ("x-backend", "backend info disclosure", Severity.LOW),
]

_COOKIE_SECRET_RE = re.compile(
    r"(token|secret|key|auth|session)[^;]*=\s*[A-Za-z0-9+/]{20,}", re.I
)


async def _check_http_headers(transport: HttpTransport) -> list[Finding]:
    findings: list[Finding] = []
    try:
        body = {"jsonrpc": "2.0", "id": 9700, "method": "tools/list", "params": {}}
        async with httpx.AsyncClient(timeout=10.0, headers=transport._extra_headers) as client:
            resp = await client.post(transport.url, json=body)

        for header_name, label, severity in _SENSITIVE_HEADER_SIGNALS:
            val = resp.headers.get(header_name, "")
            if val:
                findings.append(Finding(
                    owasp_category=OWASPCategory.MCP01_TOKEN_EXPOSURE,
                    severity=severity,
                    title=f"Token Exposure — {label} in HTTP response headers",
                    description=(
                        f"HTTP response header '{header_name}: {val[:100]}' discloses internal information."
                    ),
                    evidence=f"{header_name}: {val[:200]}",
                    confidence=75,
                    remediation=f"Remove the '{header_name}' response header in production.",
                ))

        www_auth = resp.headers.get("www-authenticate", "")
        if www_auth and re.search(r"(realm|charset)=", www_auth, re.I):
            findings.append(Finding(
                owasp_category=OWASPCategory.MCP01_TOKEN_EXPOSURE,
                severity=Severity.INFO,
                title="Token Exposure — WWW-Authenticate header exposes auth realm",
                description=(
                    f"WWW-Authenticate header reveals authentication configuration: {www_auth[:200]}"
                ),
                evidence=www_auth[:300],
                confidence=70,
                remediation="Minimize information in WWW-Authenticate headers.",
            ))

        for cookie in resp.headers.getlist("set-cookie"):
            if _COOKIE_SECRET_RE.search(cookie):
                findings.append(Finding(
                    owasp_category=OWASPCategory.MCP01_TOKEN_EXPOSURE,
                    severity=Severity.HIGH,
                    title="Token Exposure — credential-like value in Set-Cookie header",
                    description="HTTP response Set-Cookie header contains a credential-like value.",
                    evidence=cookie[:300],
                    confidence=75,
                    remediation="Audit cookies for sensitive credential exposure.",
                ))
    except Exception:
        pass
    return findings


def _is_html_catch_all(text: str) -> bool:
    """Return True if the response looks like an HTML SPA catch-all page.

    These are common in HTTP-transport targets where every path returns the
    React/Next.js index.html. They should not produce info-disclosure findings
    even if they happen to contain strings like '/etc/passwd' in a path reference.
    """
    stripped = text.lstrip()
    return stripped.startswith("<!DOCTYPE") or stripped.startswith("<html")
