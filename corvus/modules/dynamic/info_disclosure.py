from __future__ import annotations

import re
from typing import Any

from ..base import ScanModule
from ...core.models import Finding, MCPSurface, OWASPCategory, Severity
from ...core.session import ScanSession
from ...payloads.engine import PayloadEngine
from ...transport.base import MCPTransport

# Each entry: (compiled pattern, label, severity)
_SIGNALS: list[tuple[re.Pattern[str], str, Severity]] = [
    (re.compile(r'"?(API_KEY|TOKEN|SECRET|PASSWORD|PASSWD|AUTH_KEY)"?\s*[=:]\s*"?\S+', re.I),
     "credential in response", Severity.CRITICAL),
    (re.compile(r"postgres://|mysql://|mongodb://|redis://", re.I),
     "database connection string", Severity.CRITICAL),
    (re.compile(r"/home/\w+/"),
     "home directory path", Severity.MEDIUM),
    (re.compile(r"/etc/(passwd|shadow|hosts|ssh)"),
     "sensitive system file path", Severity.HIGH),
    (re.compile(r"C:\\Users\\", re.I),
     "Windows user path", Severity.MEDIUM),
    (re.compile(r"Traceback \(most recent call last\)"),
     "Python stack trace", Severity.MEDIUM),
    (re.compile(r"(Error|Exception) at .+\.py:\d+"),
     "source file reference in error", Severity.LOW),
    (re.compile(r"\b(127\.0\.0\.1|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)\b"),
     "internal IP address", Severity.LOW),
    (re.compile(r'-----BEGIN (RSA |EC )?PRIVATE KEY-----'),
     "private key material", Severity.CRITICAL),
]


class InfoDisclosureModule(ScanModule):
    owasp_id = "MCP04"
    category = "Information Disclosure"
    name = "info-disclosure"
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

            # Call with benign default args
            args = {
                p: self.engine.benign_default(s.get("type", "string"))
                for p, s in properties.items()
                if p in required
            }
            try:
                result = await transport.send_request(
                    "tools/call", {"name": tool.name, "arguments": args}
                )
                text = _extract_text(result)
                for pattern, label, severity in _SIGNALS:
                    m = pattern.search(text)
                    if m:
                        findings.append(Finding(
                            owasp_category=OWASPCategory.MCP04_INFO_DISCLOSURE,
                            severity=severity,
                            title=f"Info Disclosure — {label} in '{tool.name}'",
                            description=f"Tool response contains {label}.",
                            tool_name=tool.name,
                            evidence=text[:400],
                            remediation=(
                                "Strip sensitive data from tool responses. "
                                "Never return raw environment variables, credentials, or internal paths."
                            ),
                        ))
            except Exception:
                pass

        return findings


def _extract_text(result: Any) -> str:
    if not result:
        return ""
    content = result.get("content", []) if isinstance(result, dict) else []
    return " ".join(c.get("text", "") for c in content if isinstance(c, dict))
