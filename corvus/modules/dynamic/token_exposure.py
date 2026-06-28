from __future__ import annotations

import re
from typing import Any

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...payloads.engine import PayloadEngine
from ...transport.base import MCPTransport

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
     "internal IP address", Severity.LOW, 70),
    (re.compile(r'-----BEGIN (RSA |EC )?PRIVATE KEY-----'),
     "private key material", Severity.CRITICAL, 85),
    (re.compile(r"(Flask|Express|FastAPI|uvicorn|starlette|Django)/\d+\.\d+", re.I),
     "framework version string", Severity.INFO, 70),
]


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
                for pattern, label, severity, conf in _SIGNALS:
                    m = pattern.search(text)
                    if m:
                        if label == "credential in response" and _is_type_annotation_match(m.group(0)):
                            continue  # TypeScript type annotation, not a real credential
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

        return findings


def _extract_text(result: Any) -> str:
    if not result:
        return ""
    content = result.get("content", []) if isinstance(result, dict) else []
    return " ".join(c.get("text", "") for c in content if isinstance(c, dict))


def _is_type_annotation_match(match_text: str) -> bool:
    """Return True if the regex match looks like a TypeScript/Vue.js type annotation.

    Prevents false positives when tool documentation returns TypeScript interface
    definitions that happen to contain field names like TOKEN or SECRET followed
    by a type reference (e.g. 'TOKEN: MaybeRefOrGetter<boolean>').
    """
    parts = re.split(r'[=:]\s*', match_text, maxsplit=1)
    if len(parts) < 2:
        return False
    value = parts[1].strip('"\'').strip()
    # TypeScript generic type: contains < or > (e.g. MaybeRefOrGetter<boolean>)
    if '<' in value or '>' in value:
        return True
    # PascalCase identifier with no digits or special chars — likely a type name
    if re.match(r'^[A-Z][a-zA-Z]{2,}$', value):
        return True
    return False


def _is_html_catch_all(text: str) -> bool:
    """Return True if the response looks like an HTML SPA catch-all page.

    These are common in HTTP-transport targets where every path returns the
    React/Next.js index.html. They should not produce info-disclosure findings
    even if they happen to contain strings like '/etc/passwd' in a path reference.
    """
    stripped = text.lstrip()
    return stripped.startswith("<!DOCTYPE") or stripped.startswith("<html")
